// ABOUTME: Asserts exact filesystem modes for the plaintext JSON storage paths.
// ABOUTME: Covers new writes, permissive leftovers, existing dirs, and migration artifacts.
package storage

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/config"
)

// skipIfWindows guards the mode assertions. Go's Chmod on Windows sets only the
// read-only attribute, so 0600 and 0700 are not values a Windows file can hold
// and asserting them there would test the OS, not this package.
func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not represented on Windows")
	}
}

// wantMode fails if path is not at exactly want.
func wantMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s is %04o, want %04o", path, got, want)
	}
}

// writeAt creates a file at exactly mode, defeating the umask, so a test can
// stage the permissive leftovers an older build would have written.
func writeAt(t *testing.T, path string, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// mkdirAt creates a directory at exactly mode, likewise.
func mkdirAt(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(path, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestSaveCreatesPrivateDirAndFile is the baseline: a fresh install must not
// produce a world-readable observation store in the first place.
func TestSaveCreatesPrivateDirAndFile(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	s := &LocalStorage{baseDir: base}

	if err := s.Save("observation", "obs-1", map[string]string{"text": "private"}); err != nil {
		t.Fatal(err)
	}

	wantMode(t, filepath.Join(base, "observation"), 0o700)
	wantMode(t, filepath.Join(base, "observation", "obs-1.json"), 0o600)
}

// TestSaveTightensPermissiveExistingFile is the case os.WriteFile silently gets
// wrong: its mode argument applies only on create, so rewriting a file an older
// build left at 0644 would leave it at 0644 forever.
func TestSaveTightensPermissiveExistingFile(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)
	path := filepath.Join(obsDir, "obs-1.json")
	writeAt(t, path, `{"id":"obs-1","stale":true}`, 0o644)

	s := &LocalStorage{baseDir: base}
	if err := s.Save("observation", "obs-1", map[string]string{"text": "rewritten"}); err != nil {
		t.Fatal(err)
	}

	wantMode(t, path, 0o600)

	// The rewrite must be a rewrite, not a truncation that lost the write.
	item, err := s.Get("observation", "obs-1")
	if err != nil {
		t.Fatalf("observation unreadable after rewrite: %v", err)
	}
	data, ok := item.Data.(map[string]interface{})
	if !ok || data["text"] != "rewritten" {
		t.Errorf("observation content not preserved through the private write: %#v", item.Data)
	}
}

// TestSaveTightensPermissiveExistingDir covers the half MkdirAll cannot do:
// it leaves the mode of an existing directory completely alone.
func TestSaveTightensPermissiveExistingDir(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	s := &LocalStorage{baseDir: base}
	if err := s.Save("observation", "obs-1", map[string]string{"text": "private"}); err != nil {
		t.Fatal(err)
	}

	wantMode(t, obsDir, 0o700)
}

// TestSavePreservesExistingObservations checks the tightening did not become a
// wipe: other files in the directory survive a Save untouched, and get tightened
// only when they are themselves rewritten.
func TestSavePreservesExistingObservations(t *testing.T) {
	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	s := &LocalStorage{baseDir: base}
	if err := s.Save("observation", "obs-keep", map[string]string{"text": "keep me"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("observation", "obs-other", map[string]string{"text": "other"}); err != nil {
		t.Fatal(err)
	}

	item, err := s.Get("observation", "obs-keep")
	if err != nil {
		t.Fatalf("earlier observation lost: %v", err)
	}
	data, ok := item.Data.(map[string]interface{})
	if !ok || data["text"] != "keep me" {
		t.Errorf("earlier observation altered: %#v", item.Data)
	}
}

// legacyTree stages the exact thing the migration inherits: a directory and
// files at the modes the pre-hardening build created them with.
func legacyTree(t *testing.T, base string) (obsDir string, files map[string]string) {
	t.Helper()
	obsDir = filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	files = map[string]string{
		"obs-1.json": `{"id":"obs-1"}`,
		"obs-2.json": `{"id":"obs-2"}`,
		"notes.txt":  "not json, still the user's data",
	}
	for name, content := range files {
		writeAt(t, filepath.Join(obsDir, name), content, 0o644)
	}

	// A nested directory, so the walk is proven to descend rather than just
	// chmod the top level.
	nested := filepath.Join(obsDir, "nested")
	mkdirAt(t, nested, 0o755)
	writeAt(t, filepath.Join(nested, "obs-3.json"), `{"id":"obs-3"}`, 0o644)

	return obsDir, files
}

// TestHardenTreeLeavesSymlinksAlone pins the deliberate exclusion: os.Chmod
// follows symlinks, so tightening one would change the mode of its target,
// which need not be inside the tree at all.
func TestHardenTreeLeavesSymlinksAlone(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	outside := filepath.Join(base, "outside.json")
	writeAt(t, outside, `{"id":"outside"}`, 0o644)

	tree := filepath.Join(base, "tree")
	mkdirAt(t, tree, 0o755)
	if err := os.Symlink(outside, filepath.Join(tree, "link.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if err := HardenTree(tree); err != nil {
		t.Fatal(err)
	}

	wantMode(t, tree, 0o700)
	wantMode(t, outside, 0o644)
}

// TestSyncManifestSaveIsPrivate covers the other plaintext file in the data
// directory: an index of every observation ID and when it was synced. Older
// builds wrote it at 0644, so the force matters as much as the mode.
func TestSyncManifestSaveIsPrivate(t *testing.T) {
	skipIfWindows(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	path := syncManifestPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	// A manifest left behind by a build that wrote 0644.
	writeAt(t, path, `{"observations":{}}`, 0o644)

	// Constructed directly rather than through GetSyncManifest, whose sync.Once
	// would bind the singleton to whichever test ran first.
	m := &SyncManifest{Items: map[string]string{"obs-1": "abc"}}
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}

	wantMode(t, path, 0o600)
	if _, err := os.ReadFile(path); err != nil {
		t.Errorf("manifest unreadable after the private write: %v", err)
	}
}

// skipIfRoot guards tests that create an unwritable directory. Root ignores the
// permission bits, so the failure they are built around never happens.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission failures cannot be provoked")
	}
}

// TestWriteFilePrivateKeepsContentWhenItFails is the regression test for a
// hardening bug: the first version opened the target with O_TRUNC before
// chmod'ing it, so any failure after that point left the user with an empty
// file where an observation used to be. Correct permissions are not worth
// losing data for.
func TestWriteFilePrivateKeepsContentWhenItFails(t *testing.T) {
	skipIfWindows(t)
	skipIfRoot(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "obs-1.json")
	const original = `{"id":"obs-1","text":"the only copy"}`
	writeAt(t, path, original, 0o644)

	// An unwritable directory: the replacement cannot be staged, so the write
	// has to fail. Restored afterwards so TempDir can clean up.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	if err := writeFilePrivate(path, []byte(`{"id":"obs-1","text":"replacement"}`), 0o600); err == nil {
		t.Fatal("writeFilePrivate succeeded in an unwritable directory; the test cannot prove anything")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("original file gone after a failed write: %v", err)
	}
	if string(got) != original {
		t.Errorf("failed write damaged the existing observation:\n got %q\nwant %q", got, original)
	}
}

// TestWriteFilePrivateReplacesReadOnlyFile pins the strategy itself. Rename
// replaces the destination whatever its mode, so an observation left read-only
// is still rewritten and still ends up at 0600 — where any implementation that
// opens the target for writing would fail with EACCES and leave 0400 behind.
func TestWriteFilePrivateReplacesReadOnlyFile(t *testing.T) {
	skipIfWindows(t)
	skipIfRoot(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "obs-1.json")
	writeAt(t, path, `{"id":"obs-1","text":"old"}`, 0o400)

	const replacement = `{"id":"obs-1","text":"new"}`
	if err := writeFilePrivate(path, []byte(replacement), 0o600); err != nil {
		t.Fatalf("writeFilePrivate could not replace a read-only file: %v", err)
	}

	wantMode(t, path, 0o600)
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != replacement {
		t.Errorf("content not replaced: got %q, want %q", got, replacement)
	}
}

// TestWriteFilePrivateLeavesNoTemporaries checks the staging file is cleaned up
// on both paths. A stray temp file beside the observations is litter on the
// success path and a plaintext copy of an observation on the failure path.
func TestWriteFilePrivateLeavesNoTemporaries(t *testing.T) {
	skipIfWindows(t)
	skipIfRoot(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "obs-1.json")

	if err := writeFilePrivate(path, []byte(`{"id":"obs-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	assertOnlyFile(t, dir, "obs-1.json")

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := writeFilePrivate(path, []byte(`{"id":"obs-1","v":2}`), 0o600); err == nil {
		t.Fatal("expected the write to fail in an unwritable directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	assertOnlyFile(t, dir, "obs-1.json")
}

// assertOnlyFile fails if dir contains anything other than the named entry.
func assertOnlyFile(t *testing.T, dir, name string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != name {
			t.Errorf("unexpected leftover in %s: %s", dir, e.Name())
		}
	}
}

// TestHardenLegacyPlaintextCoversBothTrees checks the preflight knows about
// both names an older build could have left plaintext under, and descends.
func TestHardenLegacyPlaintextCoversBothTrees(t *testing.T) {
	skipIfWindows(t)

	base := t.TempDir()
	obsDir, files := legacyTree(t, base)

	migrated := filepath.Join(base, "observation.migrated")
	mkdirAt(t, migrated, 0o755)
	writeAt(t, filepath.Join(migrated, "archived.json"), `{"id":"archived"}`, 0o644)

	if err := HardenLegacyPlaintext(base); err != nil {
		t.Fatal(err)
	}

	wantMode(t, obsDir, 0o700)
	wantMode(t, filepath.Join(obsDir, "nested"), 0o700)
	for name := range files {
		wantMode(t, filepath.Join(obsDir, name), 0o600)
	}
	wantMode(t, migrated, 0o700)
	wantMode(t, filepath.Join(migrated, "archived.json"), 0o600)
}

// TestHardenLegacyPlaintextIgnoresAbsentTrees covers the ordinary case — a
// current install with no legacy data — which must be a no-op, not an error.
func TestHardenLegacyPlaintextIgnoresAbsentTrees(t *testing.T) {
	if err := HardenLegacyPlaintext(t.TempDir()); err != nil {
		t.Errorf("preflight failed with no legacy trees present: %v", err)
	}
}

// TestHardenLegacyPlaintextReportsTheExactPath pins what the user gets when the
// preflight cannot do its job: the specific directory, and something to run
// against it. "Permission denied" with no path is not a remedy.
func TestHardenLegacyPlaintextReportsTheExactPath(t *testing.T) {
	skipIfWindows(t)
	skipIfRoot(t)

	base := t.TempDir()
	obsDir := filepath.Join(base, "observation")
	mkdirAt(t, obsDir, 0o755)

	// Unsearchable parent: the tree cannot even be looked at, let alone chmod'd.
	if err := os.Chmod(base, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(base, 0o700) })

	err := HardenLegacyPlaintext(base)
	if err == nil {
		t.Fatal("preflight succeeded against an unreadable data dir; the test cannot prove anything")
	}

	var lp *LegacyPlaintextError
	if !errors.As(err, &lp) {
		t.Fatalf("error is not a *LegacyPlaintextError, so no caller can name the path: %T %v", err, err)
	}
	if lp.Path != obsDir {
		t.Errorf("Path = %q, want %q", lp.Path, obsDir)
	}
	if !strings.Contains(err.Error(), obsDir) {
		t.Errorf("message does not name the directory: %q", err)
	}
	for _, want := range []string{obsDir, "owner-only"} {
		if !strings.Contains(lp.Remedy(), want) {
			t.Errorf("remedy is missing %q: %q", want, lp.Remedy())
		}
	}
}

// TestResolveBackendRunsThePreflightBeforeTheKeychain pins the ordering on the
// CLI side. If the preflight ran after the key lookup, a machine with no
// reachable keychain would return early and leave the plaintext as it found it.
func TestResolveBackendRunsThePreflightBeforeTheKeychain(t *testing.T) {
	skipIfWindows(t)
	skipIfRoot(t)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Guarantees the key lookup would fail if it were reached first.
	t.Setenv("SINESYNC_NO_KEYCHAIN", "1")

	dataDir := config.DataDir()
	obsDir := filepath.Join(dataDir, "observation")
	mkdirAt(t, obsDir, 0o755)
	if err := os.Chmod(dataDir, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dataDir, 0o700) })

	_, err := ResolveBackend()
	if err == nil {
		t.Fatal("ResolveBackend succeeded with an unreadable data dir")
	}
	// The preflight's failure, not the keychain's: proof it ran first.
	var lp *LegacyPlaintextError
	if !errors.As(err, &lp) {
		t.Fatalf("ResolveBackend reported %v, not the preflight failure — the preflight did not run before the key lookup", err)
	}
	if !strings.Contains(err.Error(), lp.Remedy()) {
		t.Errorf("ResolveBackend dropped the remedy from the error: %q", err)
	}
}
