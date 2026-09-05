package version

import "testing"

// A prerelease must order BELOW its own release and ABOVE what came before it.
// Getting only half of that right is what stranded RC users: the gate stopping a
// stable install taking a prerelease worked, while the same comparison told an
// RC user they were already up to date when the finished release existed.
func TestPrereleaseOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
		why  string
	}{
		{"v0.2.1-rc.3", "v0.2.1", -1, "a prerelease is older than its release"},
		{"v0.2.1", "v0.2.1-rc.3", 1, "the release is newer than its prerelease"},
		{"v0.3.0-rc.1", "v0.2.0", 1, "a prerelease of a later version still beats an earlier release"},
		{"v0.2.1-rc.1", "v0.2.1-rc.2", -1, "numeric identifiers compare numerically"},
		{"v0.2.1-rc.2", "v0.2.1-rc.10", -1, "10 is after 2, not before it lexically"},
		{"v0.2.1-alpha", "v0.2.1-beta", -1, "alphanumeric identifiers compare lexically"},
		{"v0.2.1-rc", "v0.2.1-rc.1", -1, "fewer identifiers rank lower"},
		{"v0.2.1", "v0.2.1", 0, "identical releases"},
		{"v0.2.1-rc.3", "v0.2.1-rc.3", 0, "identical prereleases"},
	} {
		if got := Compare(tc.a, tc.b); got != tc.want {
			t.Errorf("Compare(%q, %q) = %d, want %d — %s", tc.a, tc.b, got, tc.want, tc.why)
		}
	}
}

// The case codex found: an RC user must be offered the finished release.
func TestPrereleaseUserIsOfferedTheStableRelease(t *testing.T) {
	if !IsNewer("v0.2.1", "v0.2.1-rc.3") {
		t.Fatal("v0.2.1 must be newer than v0.2.1-rc.3, or RC testers never leave the release candidate")
	}
	if IsNewer("v0.2.1-rc.3", "v0.2.1") {
		t.Fatal("the RC must not be offered to someone already on the release")
	}
}

func TestIsPrerelease(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"v0.2.0", false},
		{"0.2.0", false},
		{"v0.2.1-rc.1", true},
		{"v0.2.1-rc.3", true},
		{"0.2.1-beta.2", true},
		{"v1.0.0-alpha", true},
		{"dev", false},
		{"", false},
		{"v0.2.0-", false},      // empty suffix is not a prerelease
		{"garbage-rc.1", false}, // non-semver core is not a prerelease
	} {
		if got := IsPrerelease(tc.in); got != tc.want {
			t.Errorf("IsPrerelease(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
