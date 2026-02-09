//go:build !windows

package daemon

import (
	"syscall"
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
