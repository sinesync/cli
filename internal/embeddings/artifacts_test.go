package embeddings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sinesync/cli/internal/owneronly"
)

// #1 #2 #3 #5: the model and ONNX runtime are fetched over the network and the
// runtime is loaded into this process as a native library, so what lands on disk
// is executable code. These cover the four ways that went wrong: unbounded
// fetches, a temp file on the wrong filesystem, a partial extraction left in
// place, and artifacts trusted because they exist rather than because they
// verify.

func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func serving(t *testing.T, body []byte) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestDownloadStagesInTheDestinationDirectory(t *testing.T) {
	// #3: the caller renames the result into place. A temp file in $TMPDIR fails
	// with EXDEV whenever that is a different filesystem, which on Linux it
	// usually is.
	dir := t.TempDir()
	body := []byte("payload")
	srv := serving(t, body)

	path, sum, err := downloadToTempIn(context.Background(), srv.URL, dir, 1<<20)
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if got := filepath.Dir(path); got != dir {
		t.Fatalf("staged in %s, want %s", got, dir)
	}
	if sum != digestOf(body) {
		t.Fatalf("digest %s, want %s", sum, digestOf(body))
	}
}

func TestDownloadCreatesTheDestinationDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "lib")
	srv := serving(t, []byte("x"))

	if _, _, err := downloadToTempIn(context.Background(), srv.URL, dir, 1<<20); err != nil {
		t.Fatalf("download: %v", err)
	}
}

func TestDownloadRefusesAnOversizedBody(t *testing.T) {
	// #2: without a ceiling an endless response fills the disk before the digest
	// is ever consulted.
	dir := t.TempDir()
	srv := serving(t, make([]byte, 4096))

	_, _, err := downloadToTempIn(context.Background(), srv.URL, dir, 1024)
	if !errors.Is(err, errArtifactTooLarge) {
		t.Fatalf("error %v, want errArtifactTooLarge", err)
	}
}

func TestDownloadLeavesNothingBehindWhenRefused(t *testing.T) {
	dir := t.TempDir()
	srv := serving(t, make([]byte, 4096))

	_, _, _ = downloadToTempIn(context.Background(), srv.URL, dir, 1024)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused download left %d files behind", len(entries))
	}
}

func TestDownloadAcceptsExactlyTheLimit(t *testing.T) {
	// The ceiling must not reject a legitimate artifact that happens to sit on
	// it, or a version bump becomes a mysterious failure.
	dir := t.TempDir()
	body := make([]byte, 1024)
	srv := serving(t, body)

	if _, sum, err := downloadToTempIn(context.Background(), srv.URL, dir, 1024); err != nil {
		t.Fatalf("download of exactly the limit was refused: %v", err)
	} else if sum != digestOf(body) {
		t.Fatal("digest mismatch at the limit")
	}
}

func TestDownloadRefusesAnOversizedContentLength(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999999")
		w.Write(make([]byte, 999999))
	}))
	t.Cleanup(srv.Close)

	_, _, err := downloadToTempIn(context.Background(), srv.URL, dir, 1024)
	if !errors.Is(err, errArtifactTooLarge) {
		t.Fatalf("error %v, want errArtifactTooLarge", err)
	}
}

func TestDownloadHonoursACancelledContext(t *testing.T) {
	// #2: this runs synchronously while the daemon starts, so a server that
	// accepts and then says nothing must not hang startup forever.
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, _, err := downloadToTempIn(ctx, srv.URL, dir, 1<<20)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled response returned success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("download ignored the cancelled context")
	}
}

func TestDownloadRejectsNonOK(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	if _, _, err := downloadToTempIn(context.Background(), srv.URL, dir, 1<<20); err == nil {
		t.Fatal("a 404 was accepted")
	}
}

func TestVerifiedAgainstRejectsWhatDoesNotHash(t *testing.T) {
	// #5: existence is not evidence.
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	body := []byte("real contents")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if !verifiedAgainst(path, digestOf(body)) {
		t.Fatal("a matching file failed verification")
	}
	if verifiedAgainst(path, digestOf([]byte("something else"))) {
		t.Fatal("a substituted file passed verification")
	}
	if verifiedAgainst(filepath.Join(dir, "absent"), digestOf(body)) {
		t.Fatal("a missing file passed verification")
	}
	if verifiedAgainst(path, "") {
		t.Fatal("an empty expectation passed verification")
	}
}

func TestVerifiedAgainstRejectsATruncatedFile(t *testing.T) {
	// The exact case that persisted on Windows: a short file that exists.
	dir := t.TempDir()
	path := filepath.Join(dir, "lib")
	full := []byte(strings.Repeat("A", 4096))
	if err := os.WriteFile(path, full[:100], 0o600); err != nil {
		t.Fatal(err)
	}

	if verifiedAgainst(path, digestOf(full)) {
		t.Fatal("a truncated file passed verification")
	}
}

func TestInstalledDigestMatchesOnlyAfterInstall(t *testing.T) {
	// #5: an artifact with no recorded digest predates this check, or was left
	// by an extraction that died, and must be replaced rather than trusted.
	dir := t.TempDir()
	src := filepath.Join(dir, "staged")
	dest := filepath.Join(dir, "installed")
	body := []byte("library bytes")
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(dest, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if installedDigestMatches(dest) {
		t.Fatal("a file with no recorded digest was treated as verified")
	}

	os.Remove(dest)
	if err := installFile(src, dest); err != nil {
		t.Fatalf("install: %v", err)
	}
	if !installedDigestMatches(dest) {
		t.Fatal("a freshly installed file did not verify")
	}
}

func TestInstalledDigestRejectsPostInstallTampering(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged")
	dest := filepath.Join(dir, "installed")
	if err := os.WriteFile(src, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := installFile(src, dest); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(dest, []byte("swapped!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if installedDigestMatches(dest) {
		t.Fatal("a file replaced after install still verified")
	}
}

func TestInstallFileIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "staged")
	dest := filepath.Join(dir, "installed")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := installFile(src, dest); err != nil {
		t.Fatal(err)
	}

	private, err := owneronly.IsOwnerOnly(dest)
	if err != nil {
		t.Fatalf("checking permissions: %v", err)
	}
	if !private {
		t.Fatal("the installed library is readable by more than its owner")
	}
}

func TestPromoteStagedLibsMovesFilesAndRecordsThem(t *testing.T) {
	// #1: extraction happens in staging and only complete results are promoted,
	// so a failure part way never leaves something the next start would trust.
	libDir := t.TempDir()
	staging := filepath.Join(libDir, ".staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}

	body := []byte("libonnxruntime")
	if err := os.WriteFile(filepath.Join(staging, "libonnxruntime.so.1.23.2"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("libonnxruntime.so.1.23.2", filepath.Join(staging, "libonnxruntime.so")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := promoteStagedLibs(staging, libDir); err != nil {
		t.Fatalf("promote: %v", err)
	}

	real := filepath.Join(libDir, "libonnxruntime.so.1.23.2")
	if !installedDigestMatches(real) {
		t.Fatal("the promoted library has no usable recorded digest")
	}

	// The loader opens the library through the link, so that name is the one
	// that has to verify on the next start.
	link := filepath.Join(libDir, "libonnxruntime.so")
	if !installedDigestMatches(link) {
		t.Fatal("the link the loader uses has no usable recorded digest")
	}
}

func TestPromoteStagedLibsRefusesAnEmptyExtraction(t *testing.T) {
	// An archive that yielded nothing must be an error, not a silent success
	// that leaves the daemon with no library and no complaint.
	libDir := t.TempDir()
	staging := filepath.Join(libDir, ".staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := promoteStagedLibs(staging, libDir); err == nil {
		t.Fatal("an empty extraction was accepted")
	}
}

func TestPromoteStagedLibsReplacesAnExistingLibrary(t *testing.T) {
	libDir := t.TempDir()
	dest := filepath.Join(libDir, "libonnxruntime.so.1.23.2")
	if err := os.WriteFile(dest, []byte("old and truncated"), 0o600); err != nil {
		t.Fatal(err)
	}

	staging := filepath.Join(libDir, ".staging")
	if err := os.MkdirAll(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	fresh := []byte("complete new library")
	if err := os.WriteFile(filepath.Join(staging, "libonnxruntime.so.1.23.2"), fresh, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := promoteStagedLibs(staging, libDir); err != nil {
		t.Fatalf("promote: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(fresh) {
		t.Fatalf("library was not replaced: %q", got)
	}
	if !installedDigestMatches(dest) {
		t.Fatal("replacement was not recorded")
	}
}

func TestArtifactCeilingsAreAboveTheRealArtifacts(t *testing.T) {
	// A ceiling below a real asset would turn a legitimate download into a
	// permanent failure, which is worse than the unbounded read it replaced.
	for _, tc := range []struct {
		name  string
		limit int64
		least int64
	}{
		{"model", maxModelBytes, 100 << 20},
		{"vocab", maxVocabBytes, 1 << 20},
		{"archive", maxArchiveBytes, 300 << 20},
	} {
		if tc.limit < tc.least {
			t.Errorf("%s ceiling %d is below the %d a real artifact can reach", tc.name, tc.limit, tc.least)
		}
	}
	fmt.Fprint(os.Stderr, "")
}

func TestDownloadBoundsAnEndlessResponse(t *testing.T) {
	// The ceiling checks after the copy cannot help here: with no Content-Length
	// and no end to the body, only the reader itself stops the write. Without it
	// this call runs until the context expires, having written whatever it could
	// in the meantime.
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, _ := w.(http.Flusher)
		chunk := make([]byte, 4096)
		for {
			select {
			case <-r.Context().Done():
				return
			default:
			}
			if _, err := w.Write(chunk); err != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, _, err := downloadToTempIn(ctx, srv.URL, dir, 64<<10)
	if !errors.Is(err, errArtifactTooLarge) {
		t.Fatalf("an endless response ended with %v, want errArtifactTooLarge", err)
	}
}
