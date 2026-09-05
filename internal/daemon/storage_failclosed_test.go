// ABOUTME: Proves the daemon refuses to start when encrypted storage is unavailable.
// ABOUTME: Runs NewServer in a child process so the keychain probe and HOME are real.
package daemon

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// failClosedChildEnv marks the re-executed test binary as the child that
// actually calls NewServer.
const failClosedChildEnv = "SINESYNC_TEST_FAILCLOSED_CHILD"

const (
	markerErrStart = "---FAILCLOSED-ERROR-START---"
	markerErrEnd   = "---FAILCLOSED-ERROR-END---"
	markerNoError  = "---FAILCLOSED-UNEXPECTED-SUCCESS---"
)

// TestFailClosedHelper is not a test. It is the child half of
// TestDaemonFailsClosedWithoutKeychain: it calls NewServer once and prints
// whatever came back.
//
// A child process rather than t.Setenv, for two reasons. The keychain's
// availability probe is a sync.OnceValue, so SINESYNC_NO_KEYCHAIN only decides
// the answer in a process that has not already asked — setting it in-process
// would pass today and quietly stop testing anything the moment some earlier
// test in this package touches the keychain. And HOME has to be a scratch
// directory for the whole process, because that is what makes "no plaintext was
// written" checkable: config.DataDir() hangs off it.
func TestFailClosedHelper(t *testing.T) {
	if os.Getenv(failClosedChildEnv) != "1" {
		t.Skip("helper process for TestDaemonFailsClosedWithoutKeychain")
	}

	srv, err := NewServer(0)
	if err == nil {
		if srv != nil && srv.backend != nil {
			srv.backend.Close()
		}
		fmt.Println(markerNoError)
		return
	}
	fmt.Println(markerErrStart)
	fmt.Println(err.Error())
	fmt.Println(markerErrEnd)
}

// runFailClosedChild re-executes this test binary with SINESYNC_NO_KEYCHAIN=1
// and HOME pointed at home, and returns the error NewServer produced there.
func runFailClosedChild(t *testing.T, home string) string {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^TestFailClosedHelper$")
	// Rebuild the environment rather than appending, so there is exactly one
	// HOME and one SINESYNC_NO_KEYCHAIN no matter what the outer shell set.
	env := []string{}
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "HOME", "USERPROFILE", "SINESYNC_NO_KEYCHAIN", failClosedChildEnv:
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"SINESYNC_NO_KEYCHAIN=1",
		failClosedChildEnv+"=1",
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process failed: %v\n%s", err, out)
	}
	text := string(out)

	if strings.Contains(text, markerNoError) {
		t.Fatalf("NewServer succeeded with SINESYNC_NO_KEYCHAIN=1; the daemon must refuse to start rather than fall back to plaintext storage\n%s", text)
	}
	start := strings.Index(text, markerErrStart)
	end := strings.Index(text, markerErrEnd)
	if start < 0 || end < 0 {
		t.Fatalf("helper produced no error and no success marker; NewServer may not have run at all\n%s", text)
	}
	return strings.TrimSpace(text[start+len(markerErrStart) : end])
}

// TestDaemonFailsClosedWithoutKeychain is the regression test for the fallback
// that used to live in NewServer: when the DB key could not be resolved, the
// daemon wrote observations as plaintext JSON and logged a warning. A warning
// in a log file nobody reads is not consent.
func TestDaemonFailsClosedWithoutKeychain(t *testing.T) {
	home := t.TempDir()

	msg := runFailClosedChild(t, home)
	t.Logf("daemon refusal:\n%s", msg)

	// Every fact a user needs before they can act on this, and the fact that
	// the message is worthless without: an error saying only "storage failed"
	// cannot be told apart from data loss by the person reading it.
	required := []struct {
		phrase string
		why    string
	}{
		{"encrypted storage is unavailable", "says what is wrong"},
		{"refused to start", "says the daemon stopped rather than degraded"},
		{"no plaintext was written", "rules out the old fallback's behaviour"},
		{"nothing was lost", "rules out data loss"},
		{"still on disk, unchanged", "says what happens to anything that could not be verified"},
		{"nothing in it was replaced", "rules out an overwrite inside the encrypted database"},
		{"tightened to owner-only permissions", "is honest about what the refusal does change"},
		{"contents are untouched", "bounds that change to permissions, not data"},
		{"unset sinesync_no_keychain", "the first remedy, for the case that caused this"},
		{"desktop session", "the second remedy: where the keychain is reachable"},
		{"login keychain", "names what has to be unlocked"},
		{"retry", "says the user should try again afterwards"},
	}
	lower := strings.ToLower(msg)
	for _, r := range required {
		if !strings.Contains(lower, r.phrase) {
			t.Errorf("refusal message is missing %q, which %s:\n%s", r.phrase, r.why, msg)
		}
	}

	// No plaintext: nothing under the data dir, and specifically no
	// observation/*.json, which is where the fallback used to write.
	dataDir := filepath.Join(home, ".sinesync", "data")
	obsDir := filepath.Join(dataDir, "observation")
	if entries, err := os.ReadDir(obsDir); err == nil {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("%s exists after a refused start (%v); the daemon must not create a plaintext observation store", obsDir, names)
	}
	for _, path := range jsonFilesUnder(t, dataDir) {
		t.Errorf("plaintext JSON written during a refused start: %s", path)
	}
}

// TestDaemonRefusalHardensLegacyDataWithoutTouchingIt pins both halves of what
// a refused start promises about data already on disk.
//
// Nothing may be deleted, rewritten, re-encrypted, or renamed — the
// legacy-JSON migration in NewServer runs close enough to this path to be worth
// holding down. And the one thing the refusal does change must actually happen:
// the plaintext an older build left at 0755/0644 comes out owner-only, because
// a daemon that will not start is exactly when nobody is coming back to fix it.
func TestDaemonRefusalHardensLegacyDataWithoutTouchingIt(t *testing.T) {
	skipIfWindows(t)

	home := t.TempDir()
	dataDir := filepath.Join(home, ".sinesync", "data")

	// Both legacy trees, staged at the modes the pre-hardening build wrote:
	// observation/ is the live legacy store, observation.migrated/ is what a
	// completed migration renamed it to and then never touched again.
	obsDir := filepath.Join(dataDir, "observation")
	migratedDir := filepath.Join(dataDir, "observation.migrated")
	nestedDir := filepath.Join(migratedDir, "nested")
	for _, dir := range []string{obsDir, migratedDir, nestedDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	seeded := map[string][]byte{
		filepath.Join(obsDir, "legacy.json"):        []byte(`{"id":"legacy","type":"observation"}`),
		filepath.Join(obsDir, "notes.txt"):          []byte("not json, still the user's data"),
		filepath.Join(migratedDir, "archived.json"): []byte(`{"id":"archived","type":"observation"}`),
		filepath.Join(nestedDir, "deep.json"):       []byte(`{"id":"deep","type":"observation"}`),
	}
	for path, content := range seeded {
		if err := os.WriteFile(path, content, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// The encrypted database is not a legacy plaintext tree; the preflight must
	// not touch it at all, mode included.
	dbPath := filepath.Join(dataDir, "memory.db")
	dbContent := []byte("SQLite format 3\x00 not really, but it must not be touched")
	if err := os.WriteFile(dbPath, dbContent, 0o600); err != nil {
		t.Fatal(err)
	}

	runFailClosedChild(t, home)

	// Byte-identical.
	for path, want := range seeded {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s is gone after a refused start: %v", path, err)
			continue
		}
		if sha256.Sum256(got) != sha256.Sum256(want) {
			t.Errorf("%s was modified during a refused start:\n got %q\nwant %q", path, got, want)
		}
	}
	if got, err := os.ReadFile(dbPath); err != nil || sha256.Sum256(got) != sha256.Sum256(dbContent) {
		t.Errorf("memory.db was modified during a refused start: %v", err)
	}

	// Unrenamed: observation/ is still observation/, and no new archive appeared
	// beside the one that was already there.
	if _, err := os.Stat(obsDir); err != nil {
		t.Errorf("observation/ was renamed or removed during a refused start: %v", err)
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		switch e.Name() {
		case "observation", "observation.migrated", "memory.db":
		default:
			t.Errorf("a refused start created %s in the data dir", e.Name())
		}
	}

	// Exactly owner-only, everywhere in both trees.
	for _, dir := range []string{obsDir, migratedDir, nestedDir} {
		assertPerm(t, dir, 0o700)
	}
	for path := range seeded {
		assertPerm(t, path, 0o600)
	}
	assertPerm(t, dbPath, 0o600)
}

// assertPerm fails if path is not at exactly want.
func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Errorf("stat %s: %v", path, err)
		return
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s is %04o after a refused start, want %04o", path, got, want)
	}
}

// skipIfWindows guards the mode assertions: Go's Chmod on Windows sets only the
// read-only attribute, so 0600 and 0700 are not values a file can hold there.
func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes are not represented on Windows")
	}
}

// jsonFilesUnder returns every .json file below dir. Missing dir means none.
func jsonFilesUnder(t *testing.T, dir string) []string {
	t.Helper()
	var found []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			found = append(found, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
	return found
}
