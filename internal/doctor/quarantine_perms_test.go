// ABOUTME: Asserts doctor --fix quarantines corrupted observations privately.
// ABOUTME: os.Rename carries a file's old mode with it, so the move must be followed by a chmod.
package doctor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/config"
)

// TestQuarantineIsPrivate covers the third way a plaintext observation moves to
// a new home: doctor --fix renames corrupted ones into ~/.sinesync/quarantine.
// A rename preserves the file's mode, so without an explicit chmod a 0644
// observation stays 0644 in a directory nothing will ever rewrite.
func TestQuarantineIsPrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not represented on Windows")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	obsDir := filepath.Join(config.DataDir(), "observation")
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Corrupted on purpose: this is what gets quarantined.
	bad := filepath.Join(obsDir, "broken.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o644); err != nil {
		t.Fatal(err)
	}

	result := checkJSONIntegrity(context.Background(), true)
	if !result.FixApplied {
		t.Fatalf("doctor did not quarantine the corrupted file: %+v", result)
	}

	quarantine := filepath.Join(config.ConfigDir(), "quarantine")
	quarantined := filepath.Join(quarantine, "broken.json")

	for _, c := range []struct {
		path string
		want os.FileMode
	}{
		{quarantine, 0o700},
		{quarantined, 0o600},
	} {
		fi, err := os.Stat(c.path)
		if err != nil {
			t.Fatalf("stat %s: %v", c.path, err)
		}
		if got := fi.Mode().Perm(); got != c.want {
			t.Errorf("%s is %04o, want %04o", c.path, got, c.want)
		}
	}

	// Quarantine moves data aside; it must not destroy it.
	got, err := os.ReadFile(quarantined)
	if err != nil {
		t.Fatalf("quarantined file lost: %v", err)
	}
	if string(got) != "{not json" {
		t.Errorf("quarantined file altered: %q", got)
	}
}

// TestQuarantineFailureIsNotReportedAsFixed is the regression test for a
// doctor that told the user it had fixed something it had not. The old code
// counted only successful renames, ignored the failures entirely, and reported
// [FIXED] with "Quarantined 0/1" — which reads as done and tells the user to
// stop looking, while a corrupted plaintext observation is still sitting in the
// live directory.
func TestQuarantineFailureIsNotReportedAsFixed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not represented on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission failures cannot be provoked")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	obsDir := filepath.Join(config.DataDir(), "observation")
	if err := os.MkdirAll(obsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(obsDir, "broken.json")
	if err := os.WriteFile(bad, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bad, 0o644); err != nil {
		t.Fatal(err)
	}

	// Moving a file out of a directory needs write permission on that
	// directory. Chmod of the file inside it does not. So this fails the move
	// and nothing else.
	if err := os.Chmod(obsDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(obsDir, 0o700) })

	result := checkJSONIntegrity(context.Background(), true)

	if result.Status == StatusFixed {
		t.Errorf("doctor reported StatusFixed while the file was never quarantined: %q", result.Message)
	}
	if result.Status != StatusFail {
		t.Errorf("status = %v, want StatusFail: %q", result.Status, result.Message)
	}
	if result.FixApplied {
		t.Errorf("FixApplied is true although nothing was quarantined: %q", result.Message)
	}
	if !strings.Contains(result.Message, "could not be quarantined") {
		t.Errorf("message does not say what went unfixed: %q", result.Message)
	}

	// The file could not be moved, but it could be secured, and that happened
	// before the move was attempted — so it is owner-only where it sits.
	fi, err := os.Stat(bad)
	if err != nil {
		t.Fatalf("corrupted file lost by a failed quarantine: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("%s is %04o, want 0600 — it must be secured before the move is attempted", bad, got)
	}
	got, err := os.ReadFile(bad)
	if err != nil || string(got) != "{not json" {
		t.Errorf("corrupted file altered by a failed quarantine: %q, %v", got, err)
	}
}
