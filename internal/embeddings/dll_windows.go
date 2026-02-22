//go:build windows

package embeddings

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procLoadLibraryExW     = kernel32.NewProc("LoadLibraryExW")
	procSetDllDirectoryW   = kernel32.NewProc("SetDllDirectoryW")
)

const loadWithAlteredSearchPath = 0x00000008

// addDLLDirectory pre-loads onnxruntime.dll using LoadLibraryExW with
// LOAD_WITH_ALTERED_SEARCH_PATH. This flag tells Windows to search the
// DLL's own directory for its dependencies (like onnxruntime_providers_shared.dll),
// which plain LoadLibrary does not do.
// Once pre-loaded, onnxruntime_go's subsequent LoadLibrary call returns
// the already-loaded handle.
func addDLLDirectory(dir string) {
	// Set DLL directory and PATH as additional measures
	dirW, err := syscall.UTF16PtrFromString(dir)
	if err == nil {
		procSetDllDirectoryW.Call(uintptr(unsafe.Pointer(dirW)))
	}
	path := os.Getenv("PATH")
	os.Setenv("PATH", dir+";"+path)

	// Pre-load onnxruntime.dll with LOAD_WITH_ALTERED_SEARCH_PATH
	dllPath := filepath.Join(dir, "onnxruntime.dll")
	dllPathW, err := syscall.UTF16PtrFromString(dllPath)
	if err != nil {
		return
	}
	handle, _, loadErr := procLoadLibraryExW.Call(
		uintptr(unsafe.Pointer(dllPathW)),
		0,
		loadWithAlteredSearchPath,
	)
	if handle == 0 {
		fmt.Fprintf(os.Stderr, "sine~sync: pre-load onnxruntime.dll failed: %v\n", loadErr)
	}
	// Don't FreeLibrary — keep it loaded so onnxruntime_go reuses the handle
}
