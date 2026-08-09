package keychain

import (
	"testing"
)

// The guard is a macOS-specific device. It exists to avoid a panel whose primary
// button erases the user's secrets, which has to be avoided before the call
// because it is not an error you can handle after it. No other platform has
// anything like it, so no other platform is gated.
//
// The Linux branch that used to live here tried to predict whether godbus could
// find a session bus. It could not win: go-keyring reaches godbus through
// dbus.SessionBus, which autolaunches `dbus-launch` when discovery comes up
// empty, and a probe cannot spawn a daemon to answer a question. Being a subset
// of the library means false negatives, and a false negative here disables
// encryption and hides an existing database.
//
// These tests drive detectUsableFor directly with a platform string, so the
// non-darwin answer is checked from any machine — including this one, which
// cannot run Linux.

func TestDetectUsableIsUngatedOffDarwin(t *testing.T) {
	t.Setenv("SINESYNC_NO_KEYCHAIN", "")

	// D-Bus state must make no difference on any of them. If reintroducing a
	// Linux probe ever makes one of these false, that is the regression: the
	// daemon would fall back to plaintext on a box where go-keyring works.
	envCases := []struct {
		name  string
		value string
	}{
		{"bus address unset", ""},
		{"bus address set", "unix:path=/run/user/1000/bus"},
		{"bus address literally autolaunch:", "autolaunch:"},
	}

	for _, goos := range []string{"linux", "windows", "freebsd", "openbsd", "netbsd"} {
		for _, env := range envCases {
			t.Run(goos+"/"+env.name, func(t *testing.T) {
				t.Setenv("DBUS_SESSION_BUS_ADDRESS", env.value)
				if !detectUsableFor(goos) {
					t.Errorf("detectUsableFor(%q) = false; %s must not gate the keychain, "+
						"go-keyring reports its own failure there", goos, goos)
				}
			})
		}
	}
}

// The opt-out is the one escape hatch that has to survive on every platform:
// removing the Linux gate would otherwise leave a headless box with no way to
// say "stop trying".
func TestOptOutAppliesOnEveryPlatform(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "windows", "freebsd"} {
		t.Run(goos, func(t *testing.T) {
			t.Setenv("SINESYNC_NO_KEYCHAIN", "1")
			if detectUsableFor(goos) {
				t.Errorf("detectUsableFor(%q) = true with SINESYNC_NO_KEYCHAIN=1", goos)
			}
		})
	}
}

// detectUsable must keep delegating with the real platform, or the darwin probe
// silently stops running where it is the whole point.
func TestDetectUsableDelegatesToRuntimeGOOS(t *testing.T) {
	t.Setenv("SINESYNC_NO_KEYCHAIN", "1")
	if detectUsable() {
		t.Error("detectUsable() ignored the opt-out, so it is not routing through detectUsableFor")
	}
}
