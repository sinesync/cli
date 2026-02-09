//go:build windows

package daemon

import (
	"syscall"
)

func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		HideWindow: true,
	}
}

func signalTerminate(pid int) {
	process, err := findProcess(pid)
	if err != nil {
		return
	}
	process.Kill()
}

func isProcessAlive(pid int) bool {
	_, err := findProcess(pid)
	return err == nil
}
