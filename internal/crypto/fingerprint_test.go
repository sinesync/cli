package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// The fingerprint's only job is to make a substituted key visibly different from
// a genuine one to a human comparing two screens. These tests pin the properties
// that job depends on.

func TestKeyFingerprintIsStable(t *testing.T) {
	pub, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	first, err := KeyFingerprint(pub)
	if err != nil {
		t.Fatalf("KeyFingerprint: %v", err)
	}
	second, err := KeyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("same key gave %q then %q; the two devices would never agree", first, second)
	}
	if first == "" {
		t.Fatal("empty fingerprint")
	}
}

// A different key must produce a different fingerprint, or substitution is
// invisible and the whole mechanism is decorative.
func TestKeyFingerprintDiffersPerKey(t *testing.T) {
	seen := map[string]string{}
	for i := 0; i < 200; i++ {
		pub, _, err := GenerateX25519Keypair()
		if err != nil {
			t.Fatal(err)
		}
		fp, err := KeyFingerprint(pub)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[fp]; dup {
			t.Fatalf("two distinct keys share fingerprint %q (%q and %q)", fp, prev, pub)
		}
		seen[fp] = pub
	}
}

// A single flipped bit must change the output. Fingerprinting the key bytes
// directly rather than a hash of them would leave a visible prefix an attacker
// could aim at while varying the rest.
func TestKeyFingerprintIsSensitiveToEveryByte(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	base, err := KeyFingerprint(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}

	for i := range raw {
		flipped := make([]byte, 32)
		copy(flipped, raw)
		flipped[i] ^= 0x01
		got, err := KeyFingerprint(base64.StdEncoding.EncodeToString(flipped))
		if err != nil {
			t.Fatal(err)
		}
		if got == base {
			t.Errorf("flipping byte %d left the fingerprint unchanged; that byte is not covered", i)
		}
	}
}

func TestKeyFingerprintFormat(t *testing.T) {
	pub, _, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	fp, err := KeyFingerprint(pub)
	if err != nil {
		t.Fatal(err)
	}

	if want := "XXXX-XXXX-XXXX"; len(fp) != len(want) {
		t.Errorf("fingerprint %q has length %d, want %d (%s)", fp, len(fp), len(want), want)
	}
	groups := strings.Split(fp, "-")
	if len(groups) != 3 {
		t.Errorf("fingerprint %q has %d groups, want 3", fp, len(groups))
	}
	for _, g := range groups {
		if len(g) != 4 {
			t.Errorf("group %q is %d chars, want 4", g, len(g))
		}
	}

	// Characters a person will read aloud or retype must not be ambiguous.
	for _, c := range strings.ReplaceAll(fp, "-", "") {
		if !isValidBase32Char(byte(c)) {
			t.Errorf("fingerprint %q contains %q, which is outside the unambiguous alphabet", fp, c)
		}
		if strings.ContainsRune("IO01", c) {
			t.Errorf("fingerprint %q contains %q, easily confused when read aloud", fp, c)
		}
	}
}

func TestKeyFingerprintRejectsBadInput(t *testing.T) {
	cases := []struct{ name, key string }{
		{"empty", ""},
		{"not base64", "!!!!"},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 64))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := KeyFingerprint(tc.key); err == nil {
				t.Errorf("KeyFingerprint(%q) succeeded; a malformed key must not yield a fingerprint "+
					"that looks comparable", tc.key)
			}
		})
	}
}

// Deriving the public key locally is what makes the fingerprint meaningful: a
// fingerprint the server reports would match on both sides even when the server
// substituted the key, because it would report the substituted one to everyone.
func TestPublicKeyFromPrivateMatchesGeneratedPair(t *testing.T) {
	for i := 0; i < 50; i++ {
		pub, priv, err := GenerateX25519Keypair()
		if err != nil {
			t.Fatal(err)
		}
		derived, err := PublicKeyFromPrivate(priv)
		if err != nil {
			t.Fatalf("PublicKeyFromPrivate: %v", err)
		}
		if derived != pub {
			t.Fatalf("derived %q from the private half, but the pair's public key is %q", derived, pub)
		}

		// And therefore the two sides compute the same fingerprint.
		fromPub, err := KeyFingerprint(pub)
		if err != nil {
			t.Fatal(err)
		}
		fromPriv, err := KeyFingerprint(derived)
		if err != nil {
			t.Fatal(err)
		}
		if fromPub != fromPriv {
			t.Fatalf("fingerprints disagree: %q vs %q", fromPub, fromPriv)
		}
	}
}

func TestPublicKeyFromPrivateRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, key string }{
		{"empty", ""},
		{"not base64", "!!!!"},
		{"wrong length", base64.StdEncoding.EncodeToString(make([]byte, 16))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := PublicKeyFromPrivate(tc.key); err == nil {
				t.Error("accepted a malformed private key")
			}
		})
	}
}
