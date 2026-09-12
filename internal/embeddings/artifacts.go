package embeddings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Bounds on fetching model and runtime artifacts.
//
// The default http.Get has neither a timeout nor a limit on what it will write,
// and this runs synchronously while the daemon is starting: a stalled response
// hangs startup indefinitely, and an endless one fills the disk before the
// digest is ever checked. The digest catches the wrong bytes, but only once all
// of them have been written.
const (
	// Generous, because these archives reach 240 MB on a slow link. It bounds
	// the pathological case rather than the ordinary one.
	artifactDownloadTimeout = 30 * time.Minute

	// Per-artifact ceilings, comfortably above the real sizes so a legitimate
	// asset is never refused, and far below "until the disk is full".
	maxModelBytes   = 512 << 20
	maxVocabBytes   = 16 << 20
	maxArchiveBytes = 768 << 20
)

// artifactHTTPClient bounds each phase separately. A single overall timeout
// either cuts off a large but healthy download or tolerates a server that
// accepts the connection and then says nothing.
var artifactHTTPClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	},
}

// errArtifactTooLarge is returned when a response exceeds its ceiling.
var errArtifactTooLarge = fmt.Errorf("artifact exceeds its maximum allowed size")

// downloadToTempIn streams url to a temporary file inside dir, returning the
// path and the SHA-256 of what was written.
//
// The temporary file goes in dir, not the system temp directory, because the
// caller renames it into place: with $TMPDIR on a different filesystem the
// rename fails with EXDEV every time, on every attempt, which is common on Linux
// where /tmp is frequently tmpfs.
//
// Hashed while streaming so the bytes verified are the bytes stored.
func downloadToTempIn(ctx context.Context, url, dir string, maxBytes int64) (path string, sum string, err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("create dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, artifactDownloadTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", fmt.Errorf("download: %w", err)
	}

	resp, err := artifactHTTPClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	// Cheap pre-check when the server is honest about the length; the reader
	// below is what actually enforces it.
	if resp.ContentLength > maxBytes {
		return "", "", fmt.Errorf("%w: %s advertises %d bytes, limit %d", errArtifactTooLarge, url, resp.ContentLength, maxBytes)
	}

	tmp, err := os.CreateTemp(dir, ".sinesync-download-*")
	if err != nil {
		return "", "", fmt.Errorf("creating temporary file: %w", err)
	}
	defer tmp.Close()

	// Close before removing. Windows refuses to delete a file that still has an
	// open handle, and os.CreateTemp does not ask for FILE_SHARE_DELETE -- so
	// leaving the close to the deferred call above means the remove runs first,
	// fails, and has its error discarded. Every refused download then leaves its
	// temp file in the library directory permanently. Unix hides this: unlinking
	// an open file is allowed there, so the same code cleans up correctly.
	discard := func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}

	// One byte past the ceiling, so exceeding it is distinguishable from
	// stopping exactly at it.
	limited := io.LimitReader(resp.Body, maxBytes+1)

	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmp, h), limited)
	if err != nil {
		discard()
		return "", "", fmt.Errorf("downloading %s: %w", url, err)
	}
	if written > maxBytes {
		discard()
		return "", "", fmt.Errorf("%w: %s exceeded %d bytes", errArtifactTooLarge, url, maxBytes)
	}

	return tmp.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// fileDigest returns the SHA-256 of the file at path.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifiedAgainst reports whether the file at path hashes to want.
//
// Existence is not evidence. Digest verification previously applied to fresh
// downloads only, so an artifact already on disk — written before that check
// existed, or left behind by an extraction that failed part way — was trusted
// purely because it was there. On Windows this was sharpest: an existing
// onnxruntime.dll skipped the download entirely, so a truncated one persisted
// indefinitely.
func verifiedAgainst(path, want string) bool {
	if want == "" {
		return false
	}
	got, err := fileDigest(path)
	if err != nil {
		return false
	}
	return got == want
}

// digestSidecarPath names the file recording what an installed artifact hashed
// to when it was installed.
//
// Used for the ONNX runtime library, whose digest cannot be pinned at build
// time: what is pinned is the archive, and the library is extracted from it, so
// its own digest is only known once extraction has happened. An artifact with no
// sidecar is treated as unverified and replaced, which is what retires anything
// installed before this check existed.
func digestSidecarPath(path string) string {
	return path + ".sha256"
}

func recordInstalledDigest(path string) error {
	sum, err := fileDigest(path)
	if err != nil {
		return err
	}
	return os.WriteFile(digestSidecarPath(path), []byte(sum+"\n"), 0o600)
}

func installedDigestMatches(path string) bool {
	raw, err := os.ReadFile(digestSidecarPath(path))
	if err != nil {
		return false
	}
	return verifiedAgainst(path, strings.TrimSpace(string(raw)))
}

// installFile moves src to dest and records what was installed.
//
// Rename is atomic within a filesystem, so a reader either sees the previous
// file or the complete new one, never a partial write. The sidecar is written
// after the rename: if the process dies between them the artifact is treated as
// unverified and replaced next time, which is the safe direction.
func installFile(src, dest string) error {
	if err := os.Chmod(src, 0o600); err != nil {
		return fmt.Errorf("securing %s: %w", filepath.Base(dest), err)
	}
	if err := os.Rename(src, dest); err != nil {
		return fmt.Errorf("installing %s: %w", filepath.Base(dest), err)
	}
	return recordInstalledDigest(dest)
}
