//go:build !windows

package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setsid: true,
	}
}

func signalTerminate(pid int) {
	process, err := findProcess(pid)
	if err != nil {
		return
	}
	process.Signal(syscall.SIGTERM)
}

func isProcessAlive(pid int) bool {
	process, err := findProcess(pid)
	if err != nil {
		return false
	}
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

// redirectStderrToLog reopens fd 2 to point at the daemon log file,
// ensuring C libraries (CoreML, ONNX) that write to fd 2 directly
// go to the log file instead of leaking to the parent terminal.
func redirectStderrToLog() {
	logDir := LogDir()
	// 0700/0600 here too. `sinesync daemon run` reaches this directly without
	// going through Start, so the permission fix applied there did not cover the
	// path a user takes when running the daemon in the foreground.
	if err := os.MkdirAll(logDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: failed to create log dir %s: %v\n", logDir, err)
		return
	}
	logFile := filepath.Join(logDir, fmt.Sprintf("daemon-%s.log", time.Now().Format("2006-01-02")))
	tightenLogPermissions(logDir, logFile)
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: failed to open log file %s: %v\n", logFile, err)
		return
	}
	// Dup2 the log file onto fd 2 (stderr) — unix.Dup2 works on both macOS and Linux
	if err := unix.Dup2(int(f.Fd()), 2); err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: failed to redirect stderr: %v\n", err)
		f.Close()
		return
	}
	os.Stderr = f
}
