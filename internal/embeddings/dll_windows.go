//go:build windows

package embeddings

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	procSetDllDirectoryW = kernel32.NewProc("SetDllDirectoryW")
)

// addDLLDirectory adds a directory to the Windows DLL search path so that
// transitive dependencies of onnxruntime.dll can be found by LoadLibrary.
// SetDllDirectoryW inserts the directory into the LoadLibrary search order
// between the application directory and the system directory.
func addDLLDirectory(dir string) {
	dirW, err := syscall.UTF16PtrFromString(dir)
	if err == nil {
		procSetDllDirectoryW.Call(uintptr(unsafe.Pointer(dirW)))
	}
	// Also prepend to PATH as a fallback
	path := os.Getenv("PATH")
	os.Setenv("PATH", dir+";"+path)
}
