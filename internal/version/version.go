package version

import "sync"

var (
	mu      sync.RWMutex
	ver     = "dev"
	commit  = "unknown"
)

// Set stores the version and commit from build-time ldflags.
func Set(version, commitHash string) {
	mu.Lock()
	defer mu.Unlock()
	ver = version
	commit = commitHash
}

// Get returns the short version string (e.g. "0.2.0").
func Get() string {
	mu.RLock()
	defer mu.RUnlock()
	return ver
}

// Full returns version with commit (e.g. "0.2.0 (abc1234)").
func Full() string {
	mu.RLock()
	defer mu.RUnlock()
	return ver + " (" + commit + ")"
}
