package cli

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no inode information on this platform")
	}
	return uint64(st.Ino)
}

// The update destroyed a real install: copyFile opened the destination with
// O_TRUNC and then copied, so replacing a running binary — which fails on
// macOS — left a zero-byte file where the tool used to be, and the program
// that would have repaired it was the one just destroyed.
//
// Replacing by rename cannot half-happen. The inode changing is the direct
// evidence that the destination was swapped rather than emptied in place.
func TestReplacementSwapsTheFileRatherThanTruncatingIt(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "sinesync")
	src := filepath.Join(dir, "new-binary")

	if err := os.WriteFile(dst, []byte("the old binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("the new binary, which is longer"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := inodeOf(t, dst)

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	if after := inodeOf(t, dst); after == before {
		t.Error("the destination was written in place; a failure part-way would leave it truncated")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "the new binary, which is longer" {
		t.Errorf("destination = %q", got)
	}
}

// A failure before the rename must leave the previous binary exactly as it was,
// rather than a partial or empty one.
func TestAFailedReplacementLeavesTheOldBinaryIntact(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "sinesync")
	original := []byte("the old binary, still working")

	if err := os.WriteFile(dst, original, 0o755); err != nil {
		t.Fatal(err)
	}

	// A source that cannot be read at all: the copy must fail before touching
	// the destination.
	if err := copyFile(filepath.Join(dir, "does-not-exist"), dst); err == nil {
		t.Fatal("copying a missing source should fail")
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("the destination is gone after a failed replacement: %v", err)
	}
	if string(got) != string(original) {
		t.Errorf("destination = %q, want the untouched original", got)
	}
}

func TestReplacementIsExecutable(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "sinesync")
	src := filepath.Join(dir, "new-binary")

	if err := os.WriteFile(src, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o111 == 0 {
		t.Errorf("mode %v is not executable", info.Mode().Perm())
	}
}

// The temporary file must not survive, or a directory accumulates one per
// update.
func TestNoTemporaryFileIsLeftBehind(t *testing.T) {
	dir := t.TempDir()
	dst := filepath.Join(dir, "sinesync")
	src := filepath.Join(dir, "new-binary")

	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) > 0 && e.Name()[0] == '.' {
			t.Errorf("left a temporary file behind: %s", e.Name())
		}
	}
}
