package version

import (
	"strconv"
	"strings"
	"sync"
)

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

// Compare compares two semver strings. Returns -1 if a < b, 0 if equal, 1 if a > b.
// Strips leading "v" prefix and ignores pre-release suffixes.
// "dev" and malformed versions are always considered older than any valid release.
func Compare(a, b string) int {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")

	aIsDev := a == "dev"
	bIsDev := b == "dev"

	// Strip pre-release suffix (e.g. "0.2.0-rc1" -> "0.2.0")
	aParts, aOk := parseSemver(strings.SplitN(a, "-", 2)[0])
	bParts, bOk := parseSemver(strings.SplitN(b, "-", 2)[0])

	// Treat malformed versions the same as "dev" (older than everything)
	if !aOk {
		aIsDev = true
	}
	if !bOk {
		bIsDev = true
	}

	if aIsDev && bIsDev {
		return 0
	}
	if aIsDev {
		return -1
	}
	if bIsDev {
		return 1
	}

	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		na, nb := 0, 0
		if i < len(aParts) {
			na = aParts[i]
		}
		if i < len(bParts) {
			nb = bParts[i]
		}
		if na < nb {
			return -1
		}
		if na > nb {
			return 1
		}
	}
	return 0
}

// IsNewer returns true if remote is a newer version than local.
func IsNewer(remote, local string) bool {
	return Compare(remote, local) > 0
}

// parseSemver splits a version core (e.g. "1.2.3") into numeric parts.
// Returns (nil, false) if any segment is not a valid non-negative integer.
func parseSemver(v string) ([]int, bool) {
	parts := strings.Split(v, ".")
	result := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		result[i] = n
	}
	return result, true
}
