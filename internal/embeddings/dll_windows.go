//go:build windows

package embeddings

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procSetDllDirectoryW  = kernel32.NewProc("SetDllDirectoryW")
	procAddDllDirectory   = kernel32.NewProc("AddDllDirectory")
)

// addDLLDirectory adds a directory to the Windows DLL search path so that
// transitive dependencies of onnxruntime.dll can be found.
func addDLLDirectory(dir string) {
	// Try AddDllDirectory first (Windows 8+, more targeted)
	dirW, err := syscall.UTF16PtrFromString(dir)
	if err != nil {
		return
	}
	ret, _, _ := procAddDllDirectory.Call(uintptr(unsafe.Pointer(dirW)))
	if ret != 0 {
		return
	}

	// Fallback: prepend to PATH so LoadLibrary can find dependencies
	path := os.Getenv("PATH")
	os.Setenv("PATH", dir+";"+path)
}
