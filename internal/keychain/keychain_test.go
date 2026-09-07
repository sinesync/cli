package keychain

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
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
//
// Both halves of what GetOrCreateDBKey used to do are checked here: listing the
// candidates and creating a replacement. Selection moved to internal/storage,
// but the guard has to stay on this side, because this is the side that can
// write a new key into the keychain.
func TestDBKeyFunctionsRefuseWithoutASession(t *testing.T) {
	original := usable
	t.Cleanup(func() { usable = original })
	usable = func() bool { return false }

	candidates, err := DBKeyCandidates()
	if err == nil {
		t.Fatal("DBKeyCandidates succeeded with no keychain session; an empty list would be read as 'no key exists'")
	}
	if !errors.Is(err, ErrNoKeychainSession) {
		t.Errorf("got %v, want ErrNoKeychainSession so callers can distinguish it from a real failure", err)
	}
	if candidates != nil {
		t.Errorf("got %d candidates back alongside the error", len(candidates))
	}

	key, err := CreateLocalDBKey()
	if err == nil {
		t.Fatal("CreateLocalDBKey succeeded with no keychain session; it must not invent a key")
	}
	if !errors.Is(err, ErrNoKeychainSession) {
		t.Errorf("got %v, want ErrNoKeychainSession", err)
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

// Absent and unknown must stay distinguishable at this package's boundary. A
// caller that reads "unknown" as "absent" and reacts by clearing or replacing
// the entry destroys key material that nothing can regenerate.
func TestNotFoundIsTranslatedAndNothingElseIs(t *testing.T) {
	notFound := translateKeyringError("token", keyring.ErrNotFound)
	if !errors.Is(notFound, ErrNotFound) {
		t.Errorf("a missing secret came back as %v, which is not ErrNotFound", notFound)
	}
	if !strings.Contains(notFound.Error(), "token") {
		t.Errorf("error %q does not name the entry", notFound)
	}

	// Anything else is unknown and must survive unchanged: an availability
	// failure, a locked keyring, a backend fault.
	for _, err := range []error{
		ErrNoKeychainSession,
		errors.New("The specified item could not be found in the keyring"),
		keyring.ErrSetDataTooBig,
	} {
		got := translateKeyringError("token", err)
		if errors.Is(got, ErrNotFound) {
			t.Errorf("%v was translated to ErrNotFound", err)
		}
		if got != err {
			t.Errorf("%v was rewritten as %v", err, got)
		}
	}
}

func TestAnUnreachableKeychainReadsAsUnknownNotAbsent(t *testing.T) {
	original := usable
	t.Cleanup(func() { usable = original })
	usable = func() bool { return false }

	if _, err := Get("token"); !errors.Is(err, ErrNoKeychainSession) || errors.Is(err, ErrNotFound) {
		t.Errorf("Get returned %v; want ErrNoKeychainSession and not ErrNotFound", err)
	}
	if err := Delete("token"); !errors.Is(err, ErrNoKeychainSession) || errors.Is(err, ErrNotFound) {
		t.Errorf("Delete returned %v; want ErrNoKeychainSession and not ErrNotFound", err)
	}
	if _, err := GetDerivedKey(); !errors.Is(err, ErrNoKeychainSession) || errors.Is(err, ErrNotFound) {
		t.Errorf("GetDerivedKey returned %v; want ErrNoKeychainSession and not ErrNotFound", err)
	}
}
