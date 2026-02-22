//go:build windows

package daemon

import (
	"syscall"
	"unsafe"
)

var (
	modkernel32            = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess        = modkernel32.NewProc("OpenProcess")
	procGetExitCodeProcess = modkernel32.NewProc("GetExitCodeProcess")
)

const (
	processQueryLimitedInfo = 0x1000
	stillActive             = 259
)

func sysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
		HideWindow:    true,
	}
}

func signalTerminate(pid int) {
	// On Windows there's no SIGTERM. Force kill the process.
	// Graceful shutdown is handled by Stop() via HTTP /api/shutdown.
	process, err := findProcess(pid)
	if err != nil {
		return
	}
	process.Kill()
}

func isProcessAlive(pid int) bool {
	handle, _, _ := procOpenProcess.Call(
		uintptr(processQueryLimitedInfo),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var exitCode uint32
	ret, _, _ := procGetExitCodeProcess.Call(handle, uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 {
		return false
	}
	return exitCode == stillActive
}
