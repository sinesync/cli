package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// The daemon log records observation ids, project names and transcript paths,
// so its mode is a privacy control rather than housekeeping. MkdirAll and
// OpenFile apply their mode only when CREATING, which means an install made by
// an earlier build keeps 0755/0644 forever unless something forces it — so the
// upgrade case is the one worth testing, not the fresh one.
func TestTightenLogPermissionsFixesAnOlderInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil { // as an older build left it
		t.Fatalf("setup: %v", err)
	}
	file := filepath.Join(dir, "daemon-2026-01-01.log")
	if err := os.WriteFile(file, []byte("[capture] Saved: id=x project=secret\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	tightenLogPermissions(dir, file)

	di, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := di.Mode().Perm(); got != 0o700 {
		t.Errorf("log directory mode = %04o, want 0700", got)
	}

	fi, err := os.Stat(file)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("log file mode = %04o, want 0600", got)
	}
}

// It must not fail when there is nothing to tighten: a first start has no log
// yet, and a daemon that refused to start because it could not chmod a file
// that does not exist would be a worse bug than the one being fixed.
func TestTightenLogPermissionsToleratesMissingPaths(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	tightenLogPermissions(missing, filepath.Join(missing, "daemon.log"))
}

// The first version of tightenLogPermissions used os.Stat and os.Chmod, which
// follow symlinks — so a symlinked log directory meant daemon startup chmod'd
// whatever it pointed at. A privacy fix that rewrites modes elsewhere on the
// filesystem is worse than the readable log it closes.
func TestTightenLogPermissionsRefusesSymlinks(t *testing.T) {
	root := t.TempDir()

	// A directory the daemon does not own, at a mode it must not change.
	victimDir := filepath.Join(root, "someone-elses-dir")
	if err := os.MkdirAll(victimDir, 0o755); err != nil {
		t.Fatalf("setup: %v", err)
	}
	victimFile := filepath.Join(root, "someone-elses-file")
	if err := os.WriteFile(victimFile, []byte("not ours\n"), 0o644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	linkDir := filepath.Join(root, "logs")
	linkFile := filepath.Join(root, "daemon.log")
	if err := os.Symlink(victimDir, linkDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(victimFile, linkFile); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	tightenLogPermissions(linkDir, linkFile)

	if di, err := os.Stat(victimDir); err != nil {
		t.Fatalf("stat victim dir: %v", err)
	} else if got := di.Mode().Perm(); got != 0o755 {
		t.Errorf("followed the symlink and changed an unrelated directory to %04o", got)
	}
	if fi, err := os.Stat(victimFile); err != nil {
		t.Fatalf("stat victim file: %v", err)
	} else if got := fi.Mode().Perm(); got != 0o644 {
		t.Errorf("followed the symlink and changed an unrelated file to %04o", got)
	}
}
