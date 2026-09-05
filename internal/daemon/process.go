package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/sinesync/cli/internal/config"
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
	if err := os.MkdirAll(config.DataDir(), 0755); err != nil {
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

// Start starts the daemon in the background
func Start(port int) error {
	if port == 0 {
		port = DefaultPort
	}

	// Check if already running
	if running, info := IsRunning(); running {
		if info.Port == port {
			return nil // Already running on correct port
		}
		// Running on different port, stop it first
		Stop()
	}

	// Ensure log directory exists
	if err := os.MkdirAll(LogDir(), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Get the executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Start based on platform
	if runtime.GOOS == "windows" {
		return startWindows(exePath, port)
	}
	return startUnix(exePath, port)
}

func startUnix(exePath string, port int) error {
	if err := os.MkdirAll(LogDir(), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logFile := filepath.Join(LogDir(), fmt.Sprintf("daemon-%s.log", time.Now().Format("2006-01-02")))

	// Open log file
	logFd, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	cmd := exec.Command(exePath, "daemon", "run", "--port", strconv.Itoa(port))
	cmd.Stdout = logFd
	cmd.Stderr = logFd
	cmd.SysProcAttr = sysProcAttr()

	if err := cmd.Start(); err != nil {
		logFd.Close()
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Don't wait for the process
	go func() {
		cmd.Wait()
		logFd.Close()
	}()

	// Wait for daemon to become healthy
	return waitForHealth(port, cmd.Process.Pid)
}

func startWindows(exePath string, port int) error {
	if err := os.MkdirAll(LogDir(), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}
	logFile := filepath.Join(LogDir(), fmt.Sprintf("daemon-%s.log", time.Now().Format("2006-01-02")))

	// Open log file for stdout+stderr redirection
	logFd, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	cmd := exec.Command(exePath, "daemon", "run", "--port", strconv.Itoa(port))
	cmd.Stdout = logFd
	cmd.Stderr = logFd
	cmd.SysProcAttr = sysProcAttr()

	if err := cmd.Start(); err != nil {
		logFd.Close()
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Don't wait for the process
	go func() {
		cmd.Wait()
		logFd.Close()
	}()

	return waitForHealth(port, cmd.Process.Pid)
}

func waitForHealth(port, pid int) error {
	deadline := time.Now().Add(StartupTimeout)

	for time.Now().Before(deadline) {
		// Check if process died
		if !IsProcessAlive(pid) {
			return fmt.Errorf("daemon process died during startup")
		}

		// Check if healthy
		if IsHealthy(port) {
			return nil
		}

		time.Sleep(StartupInterval)
	}

	return fmt.Errorf("daemon failed to become healthy within %v", StartupTimeout)
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

	if err := Start(DefaultPort); err != nil {
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
