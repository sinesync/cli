//go:build windows

package embeddings

import "os"

// addDLLDirectory adds a directory to the Windows DLL search path so that
// transitive dependencies of onnxruntime.dll can be found by LoadLibrary.
func addDLLDirectory(dir string) {
	path := os.Getenv("PATH")
	os.Setenv("PATH", dir+";"+path)
}
