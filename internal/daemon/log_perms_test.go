package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sinesync/cli/internal/owneronly"
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

	// Recorded rather than assumed. The modes above are what was requested, and
	// Windows treats that as advisory -- it produces 0777 and 0666 whatever is
	// asked for. Comparing to the request tests the platform; comparing before
	// with after tests the property, which is that the daemon leaves alone what
	// it does not own.
	dirBefore, err := os.Stat(victim)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	fileBefore, err := os.Stat(inside)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}

	if f, err := openDaemonLog(linkDir, filepath.Join(linkDir, "daemon.log")); err == nil {
		f.Close()
		t.Fatal("opened a log through a symlinked directory")
	}

	if di, _ := os.Stat(victim); di.Mode().Perm() != dirBefore.Mode().Perm() {
		t.Errorf("changed the mode of a directory it does not own: %04o -> %04o",
			dirBefore.Mode().Perm(), di.Mode().Perm())
	}
	if fi, _ := os.Stat(inside); fi.Mode().Perm() != fileBefore.Mode().Perm() {
		t.Errorf("changed the mode of a file it does not own: %04o -> %04o",
			fileBefore.Mode().Perm(), fi.Mode().Perm())
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

	for _, target := range []string{dir, path} {
		private, err := owneronly.IsOwnerOnly(target)
		if err != nil {
			t.Fatalf("checking permissions of %s: %v", target, err)
		}
		if !private {
			t.Errorf("%s is readable by more than its owner", target)
		}
	}
}
