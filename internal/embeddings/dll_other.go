//go:build !windows

package embeddings

// addDLLDirectory is a no-op on non-Windows platforms.
func addDLLDirectory(dir string) {}
