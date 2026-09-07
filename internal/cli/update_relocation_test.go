package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// pathPrecedes decides whether relocating the install is safe to do at all.
// Installing into a directory PATH consults AFTER the current one leaves the
// old binary winning every lookup, so the update would appear to do nothing.
// That is worse than needing sudo, because it is silent.
func TestPathPrecedes(t *testing.T) {
	sep := string(filepath.ListSeparator)

	cases := []struct {
		name   string
		path   string
		first  string
		second string
		want   bool
	}{
		{
			name:   "first is earlier, so relocating wins lookups",
			path:   "/home/me/.local/bin" + sep + "/usr/local/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   true,
		},
		{
			name:   "first is later, so the old binary would still win",
			path:   "/usr/local/bin" + sep + "/home/me/.local/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   false,
		},
		{
			name:   "first is absent from PATH entirely",
			path:   "/usr/local/bin" + sep + "/usr/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   false,
		},
		{
			// The current install can sit outside PATH — invoked by absolute
			// path, say — and anything on PATH then wins by default.
			name:   "second is absent, so anything on PATH precedes it",
			path:   "/home/me/.local/bin" + sep + "/usr/bin",
			first:  "/home/me/.local/bin",
			second: "/opt/weird/bin",
			want:   true,
		},
		{
			name:   "entries are compared cleaned, not textually",
			path:   "/home/me/.local/bin/" + sep + "/usr/local/bin",
			first:  "/home/me/.local/bin",
			second: "/usr/local/bin",
			want:   true,
		},
		{
			name:   "neither is on PATH",
			path:   "/usr/bin",
			first:  "/a",
			second: "/b",
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			if got := pathPrecedes(tc.first, tc.second); got != tc.want {
				t.Errorf("pathPrecedes(%q, %q) with PATH=%q = %v, want %v",
					tc.first, tc.second, tc.path, got, tc.want)
			}
		})
	}
}

func TestUserBinDirIsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".local", "bin")
	if got := userBinDir(); got != want {
		t.Errorf("userBinDir() = %q, want %q", got, want)
	}
}

// An install that is already writable must return silently: no prompt, and no
// stopping the daemon. The offer became reachable when there is nothing to
// install (#161), so this gate is what keeps the ordinary `update` on a
// user-writable install unchanged.
func TestNoRelocationOfferWhenTheInstallIsAlreadyWritable(t *testing.T) {
	dir := t.TempDir() // writable by definition
	binary := filepath.Join(dir, "sinesync")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Silence is the property. Without the gate this still returns nil — the
	// no-terminal check downstream catches it — but it prints a tip about
	// relocating to an install that has nothing to fix. So the test watches
	// stdout rather than the error.
	out := captureStdout(t, func() {
		if err := relocateIfInstallNeedsRoot(binary); err != nil {
			t.Errorf("writable install returned %v, want nil", err)
		}
	})

	if out != "" {
		t.Errorf("writable install produced output, want silence:\n%s", out)
	}
}

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r)
		done <- buf.String()
	}()

	fn()

	os.Stdout = saved
	w.Close()
	return <-done
}

// isWritable is what that gate rests on, so it is worth pinning directly.
func TestIsWritableDistinguishesTheTwoCases(t *testing.T) {
	writable := t.TempDir()
	if !isWritable(writable) {
		t.Error("a temp dir should be writable")
	}

	locked := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root, where every directory is writable")
	}
	if isWritable(locked) {
		t.Error("a dir without write permission should not report writable")
	}
}
