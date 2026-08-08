package keychain

import (
	"errors"
	"runtime"
	"testing"
)

// The guard exists to stop a headless process raising a modal "Keychain Not
// Found" panel whose primary button erases the user's stored secrets. These
// tests pin the two behaviours that make it work: an explicit opt-out, and a
// refusal to invent a replacement key when the keychain merely could not be
// reached.

func TestDetectUsableHonoursOptOut(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"1", false},
		{"true", false},
		{"anything", false},
		{"0", true}, // explicit off means "do use the keychain"
		{"", true},  // unset falls through to platform detection
	}
	for _, tc := range cases {
		t.Run("SINESYNC_NO_KEYCHAIN="+tc.value, func(t *testing.T) {
			t.Setenv("SINESYNC_NO_KEYCHAIN", tc.value)
			got := detectUsable()
			if !tc.want && got {
				t.Errorf("detectUsable() = true, want false — the opt-out was ignored")
			}
			// The `want == true` cases fall through to platform detection, whose
			// answer depends on the machine running the test. Asserting it would
			// make this fail in CI, which has no keychain — exactly the
			// environment the guard is for.
			if tc.want && !got && runtime.GOOS == "darwin" {
				t.Logf("platform detection reported no keychain; expected on a headless runner")
			}
		})
	}
}

// The important one. A read failure must never be read as "no key exists",
// because responding by generating one leaves an existing encrypted database
// undecryptable — the user's memories become unreachable.
func TestGetOrCreateDBKeyRefusesWithoutASession(t *testing.T) {
	original := usable
	t.Cleanup(func() { usable = original })
	usable = func() bool { return false }

	key, err := GetOrCreateDBKey()
	if err == nil {
		t.Fatal("GetOrCreateDBKey succeeded with no keychain session; it must not invent a key")
	}
	if !errors.Is(err, ErrNoKeychainSession) {
		t.Errorf("got %v, want ErrNoKeychainSession so callers can distinguish it from a real failure", err)
	}
	if key != nil {
		t.Errorf("got a key back (%d bytes) alongside the error", len(key))
	}
}

// Available must be answerable from any context without touching the keychain,
// since that is the whole point — a probe that prompts defeats the guard.
func TestAvailableDoesNotPanicOrPrompt(t *testing.T) {
	t.Setenv("SINESYNC_NO_KEYCHAIN", "1")
	if detectUsable() {
		t.Error("detectUsable() = true with the opt-out set")
	}
}
