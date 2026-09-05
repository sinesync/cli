package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sinesync "github.com/sinesync/cli"
)

// Release verification is a two-gate chain: an Ed25519 signature over
// checksums.txt, then the SHA256 in checksums.txt over the archive. These tests
// generate a throwaway keypair rather than depending on the embedded production
// key, so they hold regardless of what is committed at the module root.

const testArchiveName = "sinesync-v9.9.9-linux-amd64.tar.gz"

// releaseFixture is a signed release laid out on disk the way the updater
// downloads one.
type releaseFixture struct {
	dir           string
	archivePath   string
	checksumsPath string
	sigPath       string
	pub           ed25519.PublicKey
}

// newReleaseFixture builds a valid signed release: an archive, a checksums.txt
// naming its real SHA256, and a base64 detached signature over that file.
func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	dir := t.TempDir()
	archivePath := filepath.Join(dir, testArchiveName)
	archive := []byte("pretend this is a gzipped tarball")
	if err := os.WriteFile(archivePath, archive, 0644); err != nil {
		t.Fatalf("write archive: %v", err)
	}

	sum := sha256.Sum256(archive)
	checksums := hex.EncodeToString(sum[:]) + "  " + testArchiveName + "\n"
	checksumsPath := filepath.Join(dir, "checksums.txt")
	if err := os.WriteFile(checksumsPath, []byte(checksums), 0644); err != nil {
		t.Fatalf("write checksums: %v", err)
	}

	sigPath := filepath.Join(dir, "checksums.txt.sig")
	writeSig(t, sigPath, ed25519.Sign(priv, []byte(checksums)))

	return &releaseFixture{
		dir:           dir,
		archivePath:   archivePath,
		checksumsPath: checksumsPath,
		sigPath:       sigPath,
		pub:           pub,
	}
}

func writeSig(t *testing.T, path string, sig []byte) {
	t.Helper()
	// Trailing newline included: whatever writes this in CI will add one, and
	// the verifier must tolerate it.
	enc := base64.StdEncoding.EncodeToString(sig) + "\n"
	if err := os.WriteFile(path, []byte(enc), 0644); err != nil {
		t.Fatalf("write signature: %v", err)
	}
}

func TestVerifyChecksumsSignature(t *testing.T) {
	cases := []struct {
		name string
		// mutate corrupts the fixture after signing; nil leaves it valid.
		mutate  func(t *testing.T, f *releaseFixture)
		wantErr error // nil means the signature must verify
	}{
		{
			name:    "valid signature verifies",
			mutate:  nil,
			wantErr: nil,
		},
		{
			name: "checksums.txt tampered after signing",
			mutate: func(t *testing.T, f *releaseFixture) {
				// Swap in an attacker's SHA256 — the signature no longer covers it.
				evil := make([]byte, 32)
				line := hex.EncodeToString(evil) + "  " + testArchiveName + "\n"
				if err := os.WriteFile(f.checksumsPath, []byte(line), 0644); err != nil {
					t.Fatalf("rewrite checksums: %v", err)
				}
			},
			wantErr: errBadSignature,
		},
		{
			name: "signature from a different key",
			mutate: func(t *testing.T, f *releaseFixture) {
				_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				data, err := os.ReadFile(f.checksumsPath)
				if err != nil {
					t.Fatalf("read checksums: %v", err)
				}
				writeSig(t, f.sigPath, ed25519.Sign(otherPriv, data))
			},
			wantErr: errBadSignature,
		},
		{
			name: "signature file missing",
			mutate: func(t *testing.T, f *releaseFixture) {
				if err := os.Remove(f.sigPath); err != nil {
					t.Fatalf("remove signature: %v", err)
				}
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "signature not valid base64",
			mutate: func(t *testing.T, f *releaseFixture) {
				if err := os.WriteFile(f.sigPath, []byte("not!valid!base64!"), 0644); err != nil {
					t.Fatalf("write signature: %v", err)
				}
			},
			wantErr: errMalformedSignature,
		},
		{
			name: "signature truncated to 63 bytes",
			mutate: func(t *testing.T, f *releaseFixture) {
				data, err := os.ReadFile(f.checksumsPath)
				if err != nil {
					t.Fatalf("read checksums: %v", err)
				}
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				writeSig(t, f.sigPath, ed25519.Sign(priv, data)[:ed25519.SignatureSize-1])
			},
			wantErr: errMalformedSignature,
		},
		{
			name: "raw binary signature is rejected, not guessed at",
			mutate: func(t *testing.T, f *releaseFixture) {
				data, err := os.ReadFile(f.checksumsPath)
				if err != nil {
					t.Fatalf("read checksums: %v", err)
				}
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("generate key: %v", err)
				}
				// Raw 64 bytes, deliberately not base64-encoded.
				if err := os.WriteFile(f.sigPath, ed25519.Sign(priv, data), 0644); err != nil {
					t.Fatalf("write signature: %v", err)
				}
			},
			wantErr: errMalformedSignature,
		},
		{
			name: "empty signature file",
			mutate: func(t *testing.T, f *releaseFixture) {
				if err := os.WriteFile(f.sigPath, nil, 0644); err != nil {
					t.Fatalf("write signature: %v", err)
				}
			},
			wantErr: errMalformedSignature,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newReleaseFixture(t)
			if tc.mutate != nil {
				tc.mutate(t, f)
			}

			err := verifyChecksumsSignature(f.checksumsPath, f.sigPath, f.pub)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("got error %v, want success", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("got success, want error %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got error %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestVerifyChecksumsSignatureRejectsUnusableKey covers the case where the
// caller has no real key — a build carrying a placeholder must refuse rather
// than skip verification.
func TestVerifyChecksumsSignatureRejectsUnusableKey(t *testing.T) {
	f := newReleaseFixture(t)

	for _, key := range []struct {
		name string
		pub  ed25519.PublicKey
	}{
		{"nil key", nil},
		{"empty key", ed25519.PublicKey{}},
		{"short key", ed25519.PublicKey(make([]byte, 31))},
	} {
		t.Run(key.name, func(t *testing.T) {
			err := verifyChecksumsSignature(f.checksumsPath, f.sigPath, key.pub)
			if !errors.Is(err, errNoReleaseKey) {
				t.Errorf("got %v, want it to wrap %v", err, errNoReleaseKey)
			}
		})
	}
}

func TestParseReleasePublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	valid := base64.StdEncoding.EncodeToString(pub)

	cases := []struct {
		name    string
		encoded string
		wantErr error
	}{
		{"valid key", valid, nil},
		{"valid key with surrounding whitespace", "\n  " + valid + "  \n", nil},
		{"empty file", "", errNoReleaseKey},
		{"whitespace only", "   \n\t ", errNoReleaseKey},
		{"placeholder", "PLACEHOLDER — replace with the real key", errNoReleaseKey},
		{"not base64", "@@@not base64@@@", errMalformedKey},
		{"too short", base64.StdEncoding.EncodeToString(make([]byte, 31)), errMalformedKey},
		{"too long", base64.StdEncoding.EncodeToString(make([]byte, 33)), errMalformedKey},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseReleasePublicKey(tc.encoded)

			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("got error %v, want success", err)
				}
				if len(got) != ed25519.PublicKeySize {
					t.Errorf("got key of %d bytes, want %d", len(got), ed25519.PublicKeySize)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got error %v, want it to wrap %v", err, tc.wantErr)
			}
		})
	}
}

// TestBothGatesMustPass is the end-to-end shape of the trust chain: a correct
// signature over checksums.txt does not excuse a tampered archive.
//
// Note the error classes. Tampering with checksums.txt is caught by the
// signature gate; tampering with the archive is caught by the checksum gate,
// because the signature covers checksums.txt and the SHA256 chain covers the
// archive. Both reject — only the class differs.
func TestBothGatesMustPass(t *testing.T) {
	t.Run("untampered release passes both gates", func(t *testing.T) {
		f := newReleaseFixture(t)
		if err := verifyChecksumsSignature(f.checksumsPath, f.sigPath, f.pub); err != nil {
			t.Fatalf("signature gate: %v", err)
		}
		if err := verifyChecksum(f.archivePath, f.checksumsPath, testArchiveName); err != nil {
			t.Fatalf("checksum gate: %v", err)
		}
	})

	t.Run("archive tampered after signing passes signature, fails checksum", func(t *testing.T) {
		f := newReleaseFixture(t)
		if err := os.WriteFile(f.archivePath, []byte("malicious payload"), 0644); err != nil {
			t.Fatalf("rewrite archive: %v", err)
		}

		// The signature still verifies — checksums.txt itself was not touched.
		if err := verifyChecksumsSignature(f.checksumsPath, f.sigPath, f.pub); err != nil {
			t.Fatalf("signature gate should still pass: %v", err)
		}
		// The checksum gate is what catches it.
		if err := verifyChecksum(f.archivePath, f.checksumsPath, testArchiveName); err == nil {
			t.Fatal("checksum gate accepted a tampered archive")
		}
	})

	t.Run("checksums tampered to match a tampered archive fails signature", func(t *testing.T) {
		f := newReleaseFixture(t)

		// The full attack: swap the archive AND rewrite checksums.txt so the
		// SHA256 matches. Only the signature stands in the way.
		evil := []byte("malicious payload")
		if err := os.WriteFile(f.archivePath, evil, 0644); err != nil {
			t.Fatalf("rewrite archive: %v", err)
		}
		sum := sha256.Sum256(evil)
		line := hex.EncodeToString(sum[:]) + "  " + testArchiveName + "\n"
		if err := os.WriteFile(f.checksumsPath, []byte(line), 0644); err != nil {
			t.Fatalf("rewrite checksums: %v", err)
		}

		// The checksum gate alone would be fooled.
		if err := verifyChecksum(f.archivePath, f.checksumsPath, testArchiveName); err != nil {
			t.Fatalf("precondition: attacker's checksums should match their archive: %v", err)
		}
		// The signature gate is what catches it — and it runs first.
		if err := verifyChecksumsSignature(f.checksumsPath, f.sigPath, f.pub); !errors.Is(err, errBadSignature) {
			t.Errorf("got %v, want it to wrap %v", err, errBadSignature)
		}
	})
}

// TestEmbeddedReleaseKeyIsUsableOrAbsent asserts the embedded key is in exactly
// one of two acceptable states: a valid 32-byte key, or cleanly absent
// (errNoReleaseKey, which makes `sinesync update` refuse to install). Anything
// in between — present but malformed — is a build that can never verify a
// release, and fails here.
//
// This is written to survive the real key landing: both states pass, so the
// test needs no edit when sinesync-release-ed25519.pub is replaced.
func TestEmbeddedReleaseKeyIsUsableOrAbsent(t *testing.T) {
	key, err := releasePublicKey()

	switch {
	case err == nil:
		if len(key) != ed25519.PublicKeySize {
			t.Errorf("embedded key parsed without error but is %d bytes, want %d",
				len(key), ed25519.PublicKeySize)
		}
		t.Log("this build carries a usable release signing key")
	case errors.Is(err, errNoReleaseKey):
		t.Log("this build carries a placeholder; sinesync update will refuse to install")
	default:
		// Explicitly including errMalformedKey: a key that is present but
		// unparseable means someone replaced the file incorrectly.
		t.Errorf("embedded release key is present but unusable: %v", err)
	}
}

// TestCommittedReleaseKeyIsReal pins today's committed state: a real key is
// present and update verification is live.
//
// This replaces TestCommittedPlaceholderRefusesUpdates, which asserted the
// opposite and skipped itself once a real key landed. Having served its purpose
// it was pinning nothing, and the direction that now needs pinning is the
// reverse: a revert of sinesync-release-ed25519.pub to a placeholder or an empty
// file would disable updates for every client, and
// TestEmbeddedReleaseKeyIsUsableOrAbsent deliberately passes in both states, so
// without this test that regression ships with a green suite.
//
// Scope, honestly: this proves a usable key is committed, NOT that it is the
// right key. Any 32 bytes parse. Substituting a well-formed key whose private
// half an attacker holds is not detectable here — it is caught at release time
// by tools/signrelease, which compares this file against the CI signing secret
// and fails the release if they disagree.
func TestCommittedReleaseKeyIsReal(t *testing.T) {
	raw := strings.TrimSpace(sinesync.ReleaseEd25519PublicKey)

	if raw == "" {
		t.Fatal("sinesync-release-ed25519.pub is empty — every client would refuse to update")
	}
	if strings.HasPrefix(raw, placeholderKeyPrefix) {
		t.Fatalf("sinesync-release-ed25519.pub reverted to a placeholder (%q) — "+
			"every client would refuse to update", raw)
	}

	key, err := releasePublicKey()
	if err != nil {
		t.Fatalf("committed key does not resolve to a usable key: %v", err)
	}
	if len(key) != ed25519.PublicKeySize {
		t.Fatalf("committed key is %d bytes, want %d", len(key), ed25519.PublicKeySize)
	}

	// The committed file must be exactly the key material: one line of standard
	// base64, nothing else. tools/signrelease reads the same file and applies the
	// same expectation.
	if _, err := base64.StdEncoding.DecodeString(raw); err != nil {
		t.Errorf("committed key is not a single line of standard base64: %v", err)
	}
}
