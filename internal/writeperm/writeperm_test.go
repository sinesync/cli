package writeperm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMessageRootOwnedFile(t *testing.T) {
	msg := Message(Foreign{
		Path: "/home/alice/.sinesync/daemon.pid", OwnerUID: 0, ProcessUID: 501,
		Mode: 0o600, OwnerName: "root", ProcessName: "alice",
	})
	for _, want := range []string{
		"/home/alice/.sinesync/daemon.pid",
		"root (uid 0)",
		"alice (uid 501)",
		"\nThis usually means the daemon was started with sudo, which left a root-owned file behind.\n",
		"\n    sudo rm /home/alice/.sinesync/daemon.pid\n",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "chown") {
		t.Errorf("file message suggests chown:\n%s", msg)
	}
}

func TestMessageUnresolvedNamesFallBackToUIDs(t *testing.T) {
	msg := Message(Foreign{Path: "/x/sync-manifest.json", OwnerUID: 4242, ProcessUID: 501, Mode: 0o600})
	for _, want := range []string{"owned by uid 4242", "running as uid 501", "sudo rm /x/sync-manifest.json"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "root") {
		t.Errorf("non-root owner described as root:\n%s", msg)
	}
}

func TestMessageQuotesUnsafePaths(t *testing.T) {
	msg := Message(Foreign{Path: "/Users/a b/it's; rm -rf ~/daemon.pid", OwnerUID: 0, ProcessUID: 501, Mode: 0o600})
	want := `sudo rm '/Users/a b/it'\''s; rm -rf ~/daemon.pid'`
	if !strings.Contains(msg, want) {
		t.Errorf("message missing %q:\n%s", want, msg)
	}
}

func TestExplainLeavesOtherErrorsAlone(t *testing.T) {
	orig := fmt.Errorf("disk full")
	if got := Explain("/nonexistent", orig); got != orig {
		t.Errorf("non-permission error changed: %v", got)
	}
	if Explain("/nonexistent", nil) != nil {
		t.Error("nil error became non-nil")
	}
}

// A file the process owns but cannot write — 0400 — is a permission error, and
// it must stay the terse one. Claiming another account owns it would send the
// user to sudo for a file that is already theirs.
func TestExplainOwnReadOnlyFileIsNotForeign(t *testing.T) {
	path := filepath.Join(t.TempDir(), "daemon.pid")
	if err := os.WriteFile(path, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	werr := os.WriteFile(path, []byte("{}"), 0o600)
	if werr == nil {
		t.Skip("write to a 0400 file succeeded (running as root?)")
	}
	if !errors.Is(werr, fs.ErrPermission) {
		t.Fatalf("expected a permission error, got %v", werr)
	}
	got := Explain(path, werr)
	if got != werr {
		t.Errorf("own 0400 file explained as foreign-owned:\n%v", got)
	}
	var e *Error
	if errors.As(got, &e) {
		t.Errorf("returned *Error for a file the process owns: %+v", e.Foreign)
	}
}

// A target that does not exist keeps the original error, even though the
// write failed with a permission error. Only the exact failed path is
// inspected; the directory around it is not.
func TestExplainMissingTargetKeepsOriginalError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	path := filepath.Join(dir, "sync-manifest.json")
	werr := os.WriteFile(path, []byte("{}"), 0o600)
	if werr == nil {
		t.Skip("write into a 0500 directory succeeded (running as root, or Windows)")
	}
	if !errors.Is(werr, fs.ErrPermission) {
		t.Fatalf("expected a permission error, got %v", werr)
	}
	if got := Explain(path, werr); got != werr {
		t.Errorf("missing target explained:\n%v", got)
	}
}

func TestErrorUnwrapsToPermission(t *testing.T) {
	e := &Error{Foreign: Foreign{Path: "/x", OwnerUID: 0, ProcessUID: 1}, Err: fs.ErrPermission}
	if !errors.Is(e, fs.ErrPermission) {
		t.Error("*Error does not unwrap to fs.ErrPermission")
	}
	if !strings.HasPrefix(e.Error(), fs.ErrPermission.Error()) {
		t.Errorf("original error not kept first: %q", e.Error())
	}
}
