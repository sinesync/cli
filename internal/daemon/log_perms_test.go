package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// The previous version of this test used an unrelated linkDir and linkFile, so
// it never exercised the pairing that actually occurs: a symlinked log
// DIRECTORY with the real log name inside it. That let a bug through where the
// directory check refused the link and the very next operation traversed it.
// This version uses dir/<name>, the way the daemon does.
func TestOpenDaemonLogRefusesSymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "not-ours")
	if err := os.MkdirAll(victim, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	inside := filepath.Join(victim, "daemon.log")
	if err := os.WriteFile(inside, []byte("someone else's file\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	linkDir := filepath.Join(root, "logs")
	if err := os.Symlink(victim, linkDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if f, err := openDaemonLog(linkDir, filepath.Join(linkDir, "daemon.log")); err == nil {
		f.Close()
		t.Fatal("opened a log through a symlinked directory")
	}

	if di, _ := os.Stat(victim); di.Mode().Perm() != 0o755 {
		t.Errorf("changed the mode of a directory it does not own: %04o", di.Mode().Perm())
	}
	if fi, _ := os.Stat(inside); fi.Mode().Perm() != 0o644 {
		t.Errorf("changed the mode of a file it does not own: %04o", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(inside); string(b) != "someone else's file\n" {
		t.Error("wrote daemon output into a file it does not own")
	}
}

// O_NOFOLLOW must refuse a symlink at the log file itself — the case where the
// old code logged a refusal and then appended through the link anyway.
func TestOpenDaemonLogRefusesSymlinkedFile(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("original\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}
	dir := filepath.Join(root, "logs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("setup: %v", err)
	}
	link := filepath.Join(dir, "daemon.log")
	if err := os.Symlink(victim, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	if f, err := openDaemonLog(dir, link); err == nil {
		f.Close()
		t.Fatal("opened the log through a symlink")
	}
	if b, _ := os.ReadFile(victim); string(b) != "original\n" {
		t.Error("wrote through the symlink into an unrelated file")
	}
}

// The ordinary case still works and lands at 0600 in a 0700 directory.
func TestOpenDaemonLogCreatesOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	path := filepath.Join(dir, "daemon.log")
	f, err := openDaemonLog(dir, path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()

	if di, err := os.Stat(dir); err != nil || di.Mode().Perm() != 0o700 {
		t.Errorf("log directory mode = %v (err %v), want 0700", di.Mode().Perm(), err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("log file mode = %v (err %v), want 0600", fi.Mode().Perm(), err)
	}
}
