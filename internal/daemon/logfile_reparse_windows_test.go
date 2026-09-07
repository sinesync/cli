//go:build windows

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// #4: the Unix build gets this refusal from the kernel via O_NOFOLLOW. Windows
// has no such flag, so the guarantee has to be reconstructed from
// FILE_FLAG_OPEN_REPARSE_POINT plus an inspection of the handle. These check the
// reconstruction actually refuses.
//
// Windows only, so it does not run on the Linux CI runner or on a developer's
// Mac. It runs in the release build's Windows job and for anyone testing on
// Windows.

func TestOpenLogFileNoFollowRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "daemon.log")
	if err := os.Symlink(target, link); err != nil {
		// Unprivileged Windows without Developer Mode cannot create one.
		t.Skipf("cannot create a symlink here: %v", err)
	}

	f, err := openLogFileNoFollow(link)
	if err == nil {
		f.Close()
		t.Fatal("opened the log through a symlink instead of refusing it")
	}
	if !strings.Contains(err.Error(), "reparse point") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// The refusal must not have written through the link either.
	after, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(after) != "original\n" {
		t.Fatalf("the target was modified: %q", after)
	}
}

func TestOpenLogFileNoFollowRefusesAJunction(t *testing.T) {
	// A junction is the reparse point an unprivileged user can actually create
	// on Windows, so it is the realistic version of this attack.
	dir := t.TempDir()
	targetDir := filepath.Join(dir, "target")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}

	junction := filepath.Join(dir, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, targetDir).CombinedOutput(); err != nil {
		t.Skipf("cannot create a junction here: %v (%s)", err, out)
	}

	if f, err := openLogFileNoFollow(junction); err == nil {
		f.Close()
		t.Fatal("opened a junction instead of refusing it")
	}
}

func TestOpenLogFileNoFollowOpensAnOrdinaryFileForAppend(t *testing.T) {
	// The refusal is worthless if it also refuses the ordinary case.
	dir := t.TempDir()
	path := filepath.Join(dir, "daemon.log")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := openLogFileNoFollow(path)
	if err != nil {
		t.Fatalf("refused an ordinary file: %v", err)
	}
	if _, err := f.WriteString("second\n"); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Appended, not truncated: FILE_APPEND_DATA is what gives O_APPEND
	// semantics on Windows.
	if string(got) != "first\nsecond\n" {
		t.Fatalf("log contents %q, want append", got)
	}
}

func TestOpenLogFileNoFollowCreatesAMissingLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new.log")

	f, err := openLogFileNoFollow(path)
	if err != nil {
		t.Fatalf("could not create the log: %v", err)
	}
	f.Close()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("log was not created: %v", err)
	}
}
