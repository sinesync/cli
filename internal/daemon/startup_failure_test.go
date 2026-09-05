// ABOUTME: Proves `sinesync daemon start` reports why the child daemon died.
// ABOUTME: Covers the log-tail mark, the composed error, and waitForHealth end to end.
package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/storage"
)

// startupChildEnv marks the re-executed test binary as the stand-in daemon.
const startupChildEnv = "SINESYNC_TEST_STARTUP_CHILD"

// TestStartupFailureHelper is not a test. It is the process waitForHealth
// watches: it prints the real encryption refusal the way cobra would, then
// exits, which is exactly what `daemon run` does when storage is unavailable.
//
// It builds the message by calling NewServer rather than pasting a copy, so if
// the refusal wording ever changes, this test follows it instead of asserting
// against a string that no longer ships.
func TestStartupFailureHelper(t *testing.T) {
	if os.Getenv(startupChildEnv) != "1" {
		t.Skip("helper process for TestStartFailureSurfacesDaemonRefusal")
	}
	_, err := NewServer(0)
	if err == nil {
		fmt.Fprintln(os.Stderr, "helper: NewServer unexpectedly succeeded")
		return
	}
	// cobra's own format for a RunE error, since that is what lands in the log.
	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
}

// closedPort returns a port with nothing listening on it, so IsHealthy fails
// fast instead of waiting out the health timeout.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// TestStartFailureSurfacesDaemonRefusal drives the real waitForHealth against a
// real child that really refuses to start, and checks the terminal error the
// user would see. Before this, every one of those failures printed the same six
// words — "daemon process died during startup" — and the explanation sat in a
// log file the user was never told about.
func TestStartFailureSurfacesDaemonRefusal(t *testing.T) {
	home := t.TempDir()
	logPath := filepath.Join(home, "daemon.log")

	// Stale content, from some earlier run. It must not appear in the error.
	const stale = "2026-09-04 old run: everything was fine\nstale-marker-do-not-report\n"
	if err := os.WriteFile(logPath, []byte(stale), 0o644); err != nil {
		t.Fatal(err)
	}

	tail := markLogTail(logPath)

	logFd, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer logFd.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestStartupFailureHelper$")
	cmd.Stdout = logFd
	cmd.Stderr = logFd
	env := []string{}
	for _, kv := range os.Environ() {
		switch strings.SplitN(kv, "=", 2)[0] {
		case "HOME", "USERPROFILE", "SINESYNC_NO_KEYCHAIN", startupChildEnv:
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env,
		"HOME="+home,
		"USERPROFILE="+home,
		"SINESYNC_NO_KEYCHAIN=1",
		startupChildEnv+"=1",
	)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Reap it, exactly as spawnDaemon does. A zombie answers signal 0, so
	// without this the process would read as alive and the test would sit out
	// the full startup timeout before failing for the wrong reason.
	waited := make(chan struct{})
	go func() {
		cmd.Wait()
		close(waited)
	}()
	<-waited

	err = waitForHealth(closedPort(t), cmd.Process.Pid, tail)
	if err == nil {
		t.Fatal("waitForHealth returned nil for a daemon that died during startup")
	}
	msg := err.Error()
	t.Logf("terminal error:\n%s", msg)

	required := []struct {
		phrase string
		why    string
	}{
		{"died during startup", "keeps the startup context the parent observed"},
		{"encrypted storage is unavailable", "the child's actual reason, not a generic failure"},
		{"refused to start", "says the daemon stopped rather than degraded"},
		{"no plaintext was written", "rules out the old plaintext fallback"},
		{"nothing was lost", "rules out data loss"},
		{"contents are untouched", "bounds the permission change to modes, not data"},
		{"unset sinesync_no_keychain", "recovery step 1"},
		{"login keychain", "recovery step 2"},
		{"retry", "recovery step 3"},
		{strings.ToLower(logPath), "tells the user where the full log is"},
	}
	lower := strings.ToLower(msg)
	for _, r := range required {
		if !strings.Contains(lower, r.phrase) {
			t.Errorf("startup error is missing %q, which %s:\n%s", r.phrase, r.why, msg)
		}
	}

	if strings.Contains(msg, "stale-marker-do-not-report") {
		t.Errorf("startup error quoted log content written before this attempt:\n%s", msg)
	}
}

// TestLogTailReportsOnlyThisAttempt is the unit-level version of the same
// promise: a mark taken before the spawn excludes everything already in the log.
func TestLogTailReportsOnlyThisAttempt(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "daemon.log")
	if err := os.WriteFile(logPath, []byte("older entry\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tail := markLogTail(logPath)

	if got := tail.sinceMark(); got != "" {
		t.Errorf("sinceMark() = %q before the child wrote anything, want empty", got)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("newer entry\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	got := tail.sinceMark()
	if got != "newer entry" {
		t.Errorf("sinceMark() = %q, want only the appended line", got)
	}
	if strings.Contains(got, "older entry") {
		t.Errorf("sinceMark() reported pre-existing log content: %q", got)
	}
}

// TestLogTailOnAbsentLog covers the first start on a fresh install, where the
// log does not exist when the mark is taken.
func TestLogTailOnAbsentLog(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "daemon.log")

	tail := markLogTail(logPath)
	if tail.offset != 0 {
		t.Errorf("offset = %d for a log that does not exist, want 0", tail.offset)
	}
	if got := tail.sinceMark(); got != "" {
		t.Errorf("sinceMark() = %q for a log that does not exist, want empty", got)
	}

	if err := os.WriteFile(logPath, []byte("first line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := tail.sinceMark(); got != "first line" {
		t.Errorf("sinceMark() = %q after the log appeared, want the whole file", got)
	}
}

// TestLogTailCapsQuotedOutput keeps a chatty daemon from pasting a megabyte of
// its own log into the terminal, and keeps the end — where the refusal is.
func TestLogTailCapsQuotedOutput(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "daemon.log")
	tail := markLogTail(logPath)

	noise := strings.Repeat("noise noise noise\n", maxLogTailBytes/6)
	if err := os.WriteFile(logPath, []byte(noise+"the refusal is the last thing written"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := tail.sinceMark()
	if len(got) > maxLogTailBytes {
		t.Errorf("sinceMark() returned %d bytes, want at most %d", len(got), maxLogTailBytes)
	}
	if !strings.HasSuffix(got, "the refusal is the last thing written") {
		t.Errorf("sinceMark() dropped the end of the log, which is the part that explains the failure")
	}
}

// TestStartupFailureWithoutLogOutput pins the degraded case: a child that died
// without saying anything still gets the parent's own reason and the log path,
// never an empty error.
func TestStartupFailureWithoutLogOutput(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "daemon.log")
	err := startupFailure("daemon process died during startup", markLogTail(logPath))
	msg := err.Error()

	if !strings.Contains(msg, "daemon process died during startup") {
		t.Errorf("lost the startup context: %q", msg)
	}
	if !strings.Contains(msg, logPath) {
		t.Errorf("did not tell the user where the log is: %q", msg)
	}
	if strings.Contains(msg, "The daemon reported:") {
		t.Errorf("claimed the daemon reported something when it wrote nothing: %q", msg)
	}
}

// TestQuarantineNoticesComeFromThisStartOnly covers how a successful start
// reports what the child set aside. The daemon writes those lines to its log
// and exits nothing; without this the user is never told that some of their
// data did not migrate.
func TestQuarantineNoticesComeFromThisStartOnly(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "daemon.log")

	// An earlier run's quarantine. It must not be reported as this one's.
	stale := storage.QuarantineLogMarker + " /old/quarantine/a.json (was /old/observation/a.json): from last week\n"
	if err := os.WriteFile(logPath, []byte("2026-09-04 something\n"+stale), 0o644); err != nil {
		t.Fatal(err)
	}

	tail := markLogTail(logPath)

	if got := quarantineNotices(tail); len(got) != 0 {
		t.Errorf("reported %v before this start wrote anything", got)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(f, "2026-09-05 unrelated daemon chatter\n")
	fmt.Fprintf(f, "2026/09/05 06:00:00 %s /q/broken.json (was /data/observation/broken.json): is not valid stored-item JSON\n", storage.QuarantineLogMarker)
	fmt.Fprintf(f, "2026/09/05 06:00:00 %s /q/notes.txt (was /data/observation/notes.txt): not a .json file\n", storage.QuarantineLogMarker)
	f.Close()

	got := quarantineNotices(tail)
	if len(got) != 2 {
		t.Fatalf("got %d notices, want 2: %v", len(got), got)
	}
	for i, want := range []string{
		"/q/broken.json (was /data/observation/broken.json): is not valid stored-item JSON",
		"/q/notes.txt (was /data/observation/notes.txt): not a .json file",
	} {
		if got[i] != want {
			t.Errorf("notice %d = %q, want %q", i, got[i], want)
		}
	}
	for _, n := range got {
		if strings.Contains(n, "from last week") {
			t.Errorf("an earlier run's quarantine was reported as this start's: %q", n)
		}
	}
}
