package version

import (
	"strconv"
	"strings"
	"sync"
)

var (
	mu     sync.RWMutex
	ver    = "dev"
	commit = "unknown"
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

// IsPrerelease reports whether v carries a semver prerelease suffix
// (v1.2.3-rc.1). Compare deliberately ignores that suffix when ordering, which
// makes a prerelease compare EQUAL to its stable version and therefore newer
// than anything before it — so a stable client offered v0.3.0-rc.1 would take
// it. Callers deciding whether to INSTALL must ask this separately from asking
// which version is newer.
func IsPrerelease(v string) bool {
	v = strings.TrimPrefix(v, "v")
	core, suffix, found := strings.Cut(v, "-")
	if !found || suffix == "" {
		return false
	}
	_, ok := parseSemver(core)
	return ok
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

	// Cores are equal, so the prerelease suffix decides. Semver orders
	// 1.0.0-rc.1 BELOW 1.0.0, and ignoring that stranded prerelease users:
	// v0.2.1-rc.3 compared equal to v0.2.1, so `sinesync update` answered
	// "Already up to date" and never offered the finished release. A user who
	// helped test a release candidate would have stayed on it indefinitely.
	return comparePrerelease(prereleaseOf(a), prereleaseOf(b))
}

// prereleaseOf returns the suffix after the first "-", or "" for a release.
func prereleaseOf(v string) string {
	_, suffix, found := strings.Cut(v, "-")
	if !found {
		return ""
	}
	return suffix
}

// comparePrerelease orders two prerelease suffixes by semver precedence: a
// release (empty suffix) outranks any prerelease, numeric identifiers compare
// numerically, numeric ranks below alphanumeric, and a shorter run of
// identifiers ranks below a longer one that matches on the shared prefix.
func comparePrerelease(a, b string) int {
	if a == b {
		return 0
	}
	if a == "" {
		return 1 // a is the release, b is a prerelease of it
	}
	if b == "" {
		return -1
	}

	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		if i >= len(as) {
			return -1
		}
		if i >= len(bs) {
			return 1
		}
		x, y := as[i], bs[i]
		xn, xNum := strconv.Atoi(x)
		yn, yNum := strconv.Atoi(y)
		switch {
		case xNum == nil && yNum == nil:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xNum == nil:
			return -1 // numeric identifiers rank below alphanumeric ones
		case yNum == nil:
			return 1
		default:
			if x != y {
				if x < y {
					return -1
				}
				return 1
			}
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
