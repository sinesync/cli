package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/storage"
)

// findProcess wraps os.FindProcess for use by platform-specific code
func findProcess(pid int) (*os.Process, error) {
	return os.FindProcess(pid)
}

// RedirectStderrToLog reopens stderr to the daemon log file.
// Called by "daemon run" to ensure all output (Go + C libraries) goes to the log.
func RedirectStderrToLog() {
	redirectStderrToLog()
}

// PIDInfo stores daemon process information
type PIDInfo struct {
	PID       int       `json:"pid"`
	Port      int       `json:"port"`
	StartedAt time.Time `json:"startedAt"`
	Version   string    `json:"version"`
}

const (
	DefaultPort     = 5741 // "SINE"
	HealthTimeout   = 2 * time.Second
	StartupTimeout  = 10 * time.Second
	StartupInterval = 200 * time.Millisecond
)

// PIDFilePath returns the path to the PID file
func PIDFilePath() string {
	return filepath.Join(config.DataDir(), "daemon.pid")
}

// LogDir returns the path to the log directory
func LogDir() string {
	return filepath.Join(config.DataDir(), "logs")
}

// TodayLogFile returns the path to today's log file
func TodayLogFile() string {
	return filepath.Join(LogDir(), fmt.Sprintf("daemon-%s.log", time.Now().Format("2006-01-02")))
}

// ReadPIDInfo reads the PID file
func ReadPIDInfo() (*PIDInfo, error) {
	data, err := os.ReadFile(PIDFilePath())
	if err != nil {
		return nil, err
	}

	var info PIDInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// WritePIDInfo writes the PID file
func WritePIDInfo(info *PIDInfo) error {
	if err := os.MkdirAll(config.DataDir(), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(PIDFilePath(), data, 0600)
}

// RemovePIDFile removes the PID file
func RemovePIDFile() {
	os.Remove(PIDFilePath())
}

// IsProcessAlive checks if a process is running
func IsProcessAlive(pid int) bool {
	return isProcessAlive(pid)
}

// IsHealthy checks if the daemon is responding to health checks
func IsHealthy(port int) bool {
	client := &http.Client{Timeout: HealthTimeout}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/health", port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// IsRunning checks if the daemon is running and healthy
func IsRunning() (bool, *PIDInfo) {
	info, err := ReadPIDInfo()
	if err != nil {
		return false, nil
	}

	if !IsProcessAlive(info.PID) {
		RemovePIDFile()
		return false, nil
	}

	if !IsHealthy(info.Port) {
		return false, info
	}

	return true, info
}

// Start starts the daemon in the background.
//
// The notices it returns are things the child process reported that the user
// needs to see but never would: the daemon's own output goes to a log file, so
// a successful start says nothing at all. Legacy files that had to be
// quarantined during migration come back this way.
func Start(port int) (notices []string, err error) {
	if port == 0 {
		port = DefaultPort
	}

	// Check if already running
	if running, info := IsRunning(); running {
		if info.Port == port {
			return nil, nil // Already running on correct port
		}
		// Running on different port, stop it first
		Stop()
	}

	// Ensure log directory exists
	if err := os.MkdirAll(LogDir(), 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Get the executable path
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// Start based on platform. The spawn itself is identical everywhere — the
	// only platform difference is sysProcAttr(), which already has its own
	// per-OS file — so both used to run through two copies of the same forty
	// lines. Diagnostics added to one copy silently did not exist on the other.
	return spawnDaemon(exePath, port)
}

// maxLogTailBytes caps how much of the daemon log a startup failure quotes back.
// The refusal is written immediately before the child exits, so when the log is
// larger than this the end is the part worth keeping.
const maxLogTailBytes = 8 << 10

// logTail marks a position in the daemon log so that a failed startup reports
// what THIS attempt wrote and nothing older.
//
// Without the mark, quoting the log means quoting whatever happened to be in it
// — yesterday's crash, or the successful run before this one — and attributing
// it to the start the user just ran. A stale message that looks like a
// diagnosis is worse than no message at all.
type logTail struct {
	path   string
	offset int64
}

// markLogTail records the log's current length. A log that does not exist yet
// marks at zero, which is correct: there is nothing older to exclude.
func markLogTail(path string) logTail {
	var offset int64
	if fi, err := os.Stat(path); err == nil {
		offset = fi.Size()
	}
	return logTail{path: path, offset: offset}
}

// sinceMark returns what the child appended after the mark, trimmed and capped.
// It returns "" when nothing was appended or the log cannot be read — callers
// must degrade to their own message rather than inventing one.
func (t logTail) sinceMark() string {
	if t.path == "" {
		return ""
	}
	f, err := os.Open(t.path)
	if err != nil {
		return ""
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return ""
	}
	// A log that shrank was rotated or truncated under us; everything in it now
	// postdates the mark, so read it whole rather than seeking past the end.
	start := t.offset
	if fi.Size() < start {
		start = 0
	}
	if fi.Size()-start > maxLogTailBytes {
		start = fi.Size() - maxLogTailBytes
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(buf))
}

// startupFailure joins what went wrong mechanically with what the child said
// about it.
//
// reason is the startup context — the daemon died, or never answered — and it
// stays, because it is the only part that describes the parent's own
// observation. What the child wrote goes underneath it verbatim: when that is
// the encryption refusal, it already carries the cause and the recovery steps,
// and paraphrasing it here would mean maintaining the same wording twice.
func startupFailure(reason string, tail logTail) error {
	var b strings.Builder
	b.WriteString(reason)
	if out := tail.sinceMark(); out != "" {
		// Labelled, because the next thing the user reads is the child's own
		// "Error:" line and two unattributed error prefixes in a row look like
		// one command failing twice.
		b.WriteString("\n\nThe daemon reported:\n\n")
		b.WriteString(out)
	}
	if tail.path != "" {
		b.WriteString("\n\nFull daemon log: ")
		b.WriteString(tail.path)
	}
	return errors.New(b.String())
}

// spawnDaemon launches `daemon run` detached, with stdout and stderr pointed at
// today's log, and waits for it to answer on the health endpoint.
func spawnDaemon(exePath string, port int) ([]string, error) {
	if err := os.MkdirAll(LogDir(), 0700); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}
	logFile := TodayLogFile()

	// Mark the log before the child can write to it, so a failure quotes only
	// this attempt.
	tail := markLogTail(logFile)

	// 0600, not 0644. The daemon log is not diagnostics-only: it records
	// observation ids, types and project names on every capture, transcript
	// paths on subagent stops, and the titles of deleted observations. On a
	// shared machine that is a readable index of what the user works on, which
	// is the same disclosure the encrypted database exists to prevent.
	//
	// MkdirAll and OpenFile only apply their mode when CREATING, so an install
	// made by an earlier build keeps 0755/0644 forever unless the modes are
	// forced. tightenLogPermissions does that on every start.
	tightenLogPermissions(LogDir(), logFile)

	logFd, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	cmd := exec.Command(exePath, "daemon", "run", "--port", strconv.Itoa(port))
	cmd.Stdout = logFd
	cmd.Stderr = logFd
	cmd.SysProcAttr = sysProcAttr()

	if err := cmd.Start(); err != nil {
		logFd.Close()
		return nil, fmt.Errorf("failed to start daemon: %w", err)
	}

	// Don't wait for the process. The Wait still has to happen, though: without
	// it a child that exits stays a zombie, and a zombie answers signal 0, so
	// IsProcessAlive would report a dead daemon as running until the deadline.
	go func() {
		cmd.Wait()
		logFd.Close()
	}()

	if err := waitForHealth(port, cmd.Process.Pid, tail); err != nil {
		return nil, err
	}
	// The daemon is up. Anything it flagged on the way is in the slice of log
	// it just wrote, and nowhere the user will ever look.
	return quarantineNotices(tail), nil
}

// quarantineNotices pulls the quarantine lines out of what this startup wrote.
//
// Reading them back out of the log rather than inventing a side channel keeps
// one source of truth: the same lines the user finds in `sinesync daemon logs`
// are the ones printed to the terminal, and the mark taken before the spawn
// means an older run's quarantines are not reported as this one's.
func quarantineNotices(tail logTail) []string {
	var notices []string
	for _, line := range strings.Split(tail.sinceMark(), "\n") {
		if i := strings.Index(line, storage.QuarantineLogMarker); i >= 0 {
			notices = append(notices, strings.TrimSpace(line[i+len(storage.QuarantineLogMarker):]))
		}
	}
	return notices
}

func waitForHealth(port, pid int, tail logTail) error {
	deadline := time.Now().Add(StartupTimeout)

	for time.Now().Before(deadline) {
		// Check if process died
		if !IsProcessAlive(pid) {
			return startupFailure("daemon process died during startup", tail)
		}

		// Check if healthy
		if IsHealthy(port) {
			return nil
		}

		time.Sleep(StartupInterval)
	}

	return startupFailure(
		fmt.Sprintf("daemon failed to become healthy within %v", StartupTimeout),
		tail,
	)
}

// Stop stops the daemon
func Stop() error {
	info, err := ReadPIDInfo()
	if err != nil {
		return nil // Not running
	}

	// Try graceful shutdown via HTTP endpoint first (works on all platforms).
	// /api/shutdown requires the hook secret; without it the daemon answers 401,
	// this loop waits out the full five seconds and then falls back to signalling
	// the process — so a missing header turns every stop into a hard kill.
	if IsHealthy(info.Port) {
		client := &http.Client{Timeout: 2 * time.Second}
		req, reqErr := http.NewRequest(
			http.MethodPost,
			fmt.Sprintf("http://127.0.0.1:%d/api/shutdown", info.Port),
			nil,
		)
		if reqErr != nil {
			return reqErr
		}
		if secret := ReadHookSecret(); secret != "" {
			req.Header.Set("X-Hook-Secret", secret)
		}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			// Wait for graceful shutdown
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if !IsProcessAlive(info.PID) {
					RemovePIDFile()
					return nil
				}
				time.Sleep(200 * time.Millisecond)
			}
		}
	}

	// Graceful shutdown didn't work, send signal/kill
	process, err := os.FindProcess(info.PID)
	if err != nil {
		RemovePIDFile()
		return nil
	}

	signalTerminate(info.PID)

	// Wait a bit for shutdown, then force kill
	time.Sleep(2 * time.Second)
	if IsProcessAlive(info.PID) {
		process.Kill()
	}

	RemovePIDFile()
	return nil
}

// EnsureRunning ensures the daemon is running, starting it if necessary
func EnsureRunning() (*PIDInfo, error) {
	if running, info := IsRunning(); running {
		return info, nil
	}

	if _, err := Start(DefaultPort); err != nil {
		return nil, err
	}

	// Wait for daemon to become healthy (up to 5 seconds)
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if running, info := IsRunning(); running && info != nil {
			return info, nil
		}
	}

	// Return info even if not fully healthy yet
	_, info := IsRunning()
	if info == nil {
		return nil, fmt.Errorf("daemon started but not responding")
	}
	return info, nil
}

// Status returns the daemon status
func Status() (running bool, info *PIDInfo, uptime string) {
	running, info = IsRunning()
	if running && info != nil {
		uptime = formatUptime(info.StartedAt)
	}
	return
}

func formatUptime(startedAt time.Time) string {
	d := time.Since(startedAt)

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// tightenLogPermissions forces owner-only modes onto the log directory and
// today's log file, including ones an earlier build created world-readable.
// Failures are deliberately ignored: a daemon that will not start because it
// could not chmod its own log is a worse outcome than a readable log, and the
// files it goes on to create will carry the right mode regardless.
func tightenLogPermissions(dir, file string) {
	if info, err := os.Stat(dir); err == nil && info.Mode().Perm() != 0o700 {
		_ = os.Chmod(dir, 0o700)
	}
	if info, err := os.Stat(file); err == nil && info.Mode().Perm() != 0o600 {
		_ = os.Chmod(file, 0o600)
	}
}
