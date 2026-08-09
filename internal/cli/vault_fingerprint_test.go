package cli

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/miclip/sinesync/internal/encryption"
)

// The invitee's fingerprint is the only thing anchoring an invite to a key the
// server did not choose. If deriving it fails, the failure has to reach the
// human, and it has to name the right cause: a keychain this process cannot
// read is routine and locally fixable, whereas a server withholding the key
// material or handing back material that will not decrypt are the two shapes of
// the attack this control exists to catch.

func TestFingerprintFailureSeparatesLocalFromServerCauses(t *testing.T) {
	cases := []struct {
		name string
		err  error
		// A phrase the cause must contain, so a future edit cannot quietly
		// collapse two causes into one wording.
		wantCause string
	}{
		{
			name:      "no master key on this machine",
			err:       encryption.ErrNoKey,
			wantCause: "cannot read its own encryption key",
		},
		{
			name:      "no master key, wrapped by a caller",
			err:       fmt.Errorf("decrypt private key: %w", encryption.ErrNoKey),
			wantCause: "cannot read its own encryption key",
		},
		{
			name:      "server returned a non-200",
			err:       fmt.Errorf("%w: keypair fetch returned status 500", errKeypairUnavailable),
			wantCause: "server did not return your key material",
		},
		{
			name:      "server body did not parse",
			err:       fmt.Errorf("%w: keypair response did not parse: %w", errKeypairUnavailable, errors.New("unexpected EOF")),
			wantCause: "server did not return your key material",
		},
		{
			name:      "key material did not decrypt",
			err:       encryption.ErrDecryptFailed,
			wantCause: "did not decrypt to a usable key",
		},
		{
			name:      "key material decrypted but is not a usable key",
			err:       fmt.Errorf("%w: private key is 7 bytes, want 32", errKeyMaterialUnusable),
			wantCause: "did not decrypt to a usable key",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cause, advice := fingerprintFailure(tc.err)
			if !strings.Contains(cause, tc.wantCause) {
				t.Errorf("cause = %q, want it to contain %q", cause, tc.wantCause)
			}
			if len(advice) == 0 {
				t.Error("no advice returned; a failure the user cannot act on is close to no message at all")
			}
		})
	}
}

// A locked keychain must not be described as an attack, and a server failure
// must not be described as benign. Getting these backwards is worse than a
// generic message.
func TestFingerprintFailureAdviceMatchesTheThreat(t *testing.T) {
	_, local := fingerprintFailure(encryption.ErrNoKey)
	localText := strings.ToLower(strings.Join(local, " "))
	if !strings.Contains(localText, "nothing here points at an attacker") {
		t.Errorf("local keychain advice should say no attacker is implied, got: %q", localText)
	}

	_, server := fingerprintFailure(fmt.Errorf("%w: status 500", errKeypairUnavailable))
	serverText := strings.ToLower(strings.Join(server, " "))
	if !strings.Contains(serverText, "do not confirm") {
		t.Errorf("server-failure advice should tell the invitee not to confirm, got: %q", serverText)
	}

	_, substituted := fingerprintFailure(encryption.ErrDecryptFailed)
	substitutedText := strings.ToLower(strings.Join(substituted, " "))
	if !strings.Contains(substitutedText, "suspicious") {
		t.Errorf("undecryptable key material should be called suspicious, got: %q", substitutedText)
	}
}

// An unrecognised error must land on the suspicious branch, not on a reassuring
// one. Fail-safe: an unclassified failure is not evidence of safety.
func TestFingerprintFailureDefaultsToSuspicious(t *testing.T) {
	cause, advice := fingerprintFailure(errors.New("something nobody anticipated"))
	if !strings.Contains(cause, "did not decrypt to a usable key") {
		t.Errorf("unknown cause = %q, want the suspicious branch", cause)
	}
	if !strings.Contains(strings.ToLower(strings.Join(advice, " ")), "do not accept or confirm") {
		t.Error("unknown cause must still tell the invitee not to confirm")
	}
}
