package version

import "testing"

// Compare deliberately ignores the prerelease suffix, so a prerelease orders as
// newer than the stable release before it. That is why IsPrerelease exists: the
// question "is this newer" and the question "should this be installed" have
// different answers, and conflating them let a bucket writer move every stable
// install onto a signed release candidate.
func TestPrereleaseComparesAsNewerThanStable(t *testing.T) {
	if !IsNewer("v0.3.0-rc.1", "v0.2.0") {
		t.Fatal("expected the prerelease to compare as newer; if this changed, the update gate's reasoning needs revisiting")
	}
	if !IsPrerelease("v0.3.0-rc.1") {
		t.Error("v0.3.0-rc.1 should be recognised as a prerelease")
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
