package keychain

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A false negative from the guard is not a safe default: it disables encryption
// and hides an existing encrypted database behind a fresh plaintext one. So the
// probe must not fail for any reason other than "there is genuinely no default
// keychain". Resolving the `security` binary through $PATH was one such reason —
// go-keyring reaches the same binary by absolute path, so any $PATH that broke
// lookup made this guard disagree with the library it stands in front of, in the
// same process.

// baselineOrSkip reports the guard's verdict with an untampered environment.
// If the machine genuinely has no default keychain (a CI runner, say) there is
// no "true" to regress away from, so these tests have nothing to prove.
func baselineOrSkip(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("the $PATH-resolved probe is the darwin branch only")
	}
	t.Setenv("SINESYNC_NO_KEYCHAIN", "")
	if !detectUsable() {
		t.Skip("no default keychain on this machine, so there is no true verdict to preserve")
	}
}

func TestDetectUsableDoesNotDependOnPATH(t *testing.T) {
	baselineOrSkip(t)

	for _, path := range []string{
		"",                                   // no lookup directories at all
		"/nonexistent-directory-for-testing", // lookup that cannot resolve
	} {
		t.Setenv("PATH", path)
		if !detectUsable() {
			t.Errorf("detectUsable() = false with PATH=%q; go-keyring would still have "+
				"reached /usr/bin/security, so the guard is dropping the user to plaintext "+
				"storage over a $PATH the library does not consult", path)
		}
	}
}

// The other half of $PATH lookup: an entry Go refuses to run. An empty PATH
// element means "the current directory", and since Go 1.19 exec resolves a
// relative match but returns ErrDot rather than executing it. The probe used to
// surface that refusal as "no keychain". The planted file must never run either
// way — a guard that executes whatever is sitting in the working directory would
// be a far worse defect than the one being fixed.
func TestDetectUsableIgnoresPlantedSecurityInWorkingDir(t *testing.T) {
	baselineOrSkip(t)

	dir := t.TempDir()
	sentinel := filepath.Join(dir, "planted-binary-ran")
	planted := "#!/bin/sh\ntouch " + sentinel + "\necho \"planted\"\n"
	if err := os.WriteFile(filepath.Join(dir, "security"), []byte(planted), 0o755); err != nil {
		t.Fatalf("plant security binary: %v", err)
	}

	t.Chdir(dir)
	t.Setenv("PATH", ":/usr/bin") // leading empty element == the working directory

	if !detectUsable() {
		t.Error("detectUsable() = false with an empty leading $PATH element; the probe " +
			"should not be consulting $PATH at all")
	}
	if _, err := os.Stat(sentinel); err == nil {
		t.Error("the planted ./security was executed; the probe must only ever run /usr/bin/security")
	}
}
