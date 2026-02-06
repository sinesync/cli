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
	"syscall"
	"time"

	"github.com/miclip/sinesync/internal/config"
)

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

	return os.WriteFile(PIDFilePath(), data, 0644)
}

// RemovePIDFile removes the PID file
func RemovePIDFile() {
	os.Remove(PIDFilePath())
}

// IsProcessAlive checks if a process is running
func IsProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// On Unix, FindProcess always succeeds, so we need to send signal 0
	if runtime.GOOS != "windows" {
		err = process.Signal(syscall.Signal(0))
		return err == nil
	}

	// On Windows, FindProcess succeeds only if process exists
	return true
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
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Create new session, detach from terminal
	}

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

	// Use PowerShell to start detached process
	psCmd := fmt.Sprintf(
		`Start-Process -FilePath '%s' -ArgumentList 'daemon','run','--port','%d' -WindowStyle Hidden -RedirectStandardOutput '%s' -RedirectStandardError '%s' -PassThru | Select-Object -ExpandProperty Id`,
		exePath, port, logFile, logFile,
	)

	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to start daemon via PowerShell: %w", err)
	}

	pid, err := strconv.Atoi(string(output))
	if err != nil {
		return fmt.Errorf("failed to parse PID: %w", err)
	}

	return waitForHealth(port, pid)
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

	process, err := os.FindProcess(info.PID)
	if err != nil {
		RemovePIDFile()
		return nil
	}

	// Send SIGTERM (or equivalent on Windows)
	if runtime.GOOS == "windows" {
		// On Windows, Kill() is the only option
		process.Kill()
	} else {
		process.Signal(syscall.SIGTERM)

		// Wait a bit for graceful shutdown
		time.Sleep(2 * time.Second)

		// Force kill if still running
		if IsProcessAlive(info.PID) {
			process.Kill()
		}
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
