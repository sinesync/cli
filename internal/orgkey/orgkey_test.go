package orgkey

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/crypto"
)

// #104: the credentials file carries an organization's whole decryption
// capability out of our infrastructure. These cover the properties that decide
// whether a leaked or altered file is usable, rather than the happy path alone.

func newOrgKey(t *testing.T) (pub string, priv []byte) {
	t.Helper()
	pubKey, privKey, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return pubKey, []byte(privKey)
}

func TestOrgKeyExportRoundTrip(t *testing.T) {
	pub, priv := newOrgKey(t)

	file, err := Build("org-a", pub, priv, "correct horse battery staple")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	got, err := Open(file, "correct horse battery staple")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != string(priv) {
		t.Fatalf("round trip changed the key")
	}
}

func TestOrgKeyExportNeverHoldsThePlaintextKey(t *testing.T) {
	pub, priv := newOrgKey(t)

	file, err := Build("org-a", pub, priv, "pass")
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	encoded, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The whole point of the file: possessing it must not be possessing the key.
	if strings.Contains(string(encoded), string(priv)) {
		t.Fatal("the private key appears in the file in the clear")
	}
	if strings.Contains(string(encoded), "pass") {
		t.Fatal("the passphrase appears in the file")
	}
}

func TestOrgKeyExportRejectsWrongPassphrase(t *testing.T) {
	pub, priv := newOrgKey(t)
	file, _ := Build("org-a", pub, priv, "right")

	if _, err := Open(file, "wrong"); err == nil {
		t.Fatal("a wrong passphrase opened the file")
	}
}

func TestOrgKeyExportRejectsFileFromAnotherOrg(t *testing.T) {
	// The org id is bound into the AEAD, so a ciphertext lifted from one org's
	// file cannot be presented as another's.
	pub, priv := newOrgKey(t)
	fileA, _ := Build("org-a", pub, priv, "pass")

	transplanted := *fileA
	transplanted.OrgID = "org-b"

	if _, err := Open(&transplanted, "pass"); err == nil {
		t.Fatal("a file relabelled to another org still opened")
	}
}

func TestOrgKeyExportRejectsAlteredCiphertext(t *testing.T) {
	pub, priv := newOrgKey(t)
	file, _ := Build("org-a", pub, priv, "pass")

	raw, err := base64.StdEncoding.DecodeString(file.EncryptedOrgPrivateKey)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw[len(raw)-1] ^= 0x01
	file.EncryptedOrgPrivateKey = base64.StdEncoding.EncodeToString(raw)

	if _, err := Open(file, "pass"); err == nil {
		t.Fatal("an altered file still opened")
	}
}

func TestOrgKeyExportSaysNothingAboutWhichPartWasWrong(t *testing.T) {
	// A different message for "wrong passphrase" and "tampered" tells an
	// attacker which one they got right.
	pub, priv := newOrgKey(t)
	file, _ := Build("org-a", pub, priv, "pass")

	_, wrongPass := Open(file, "nope")

	raw, _ := base64.StdEncoding.DecodeString(file.EncryptedOrgPrivateKey)
	raw[0] ^= 0x01
	file.EncryptedOrgPrivateKey = base64.StdEncoding.EncodeToString(raw)
	_, tampered := Open(file, "pass")

	if wrongPass == nil || tampered == nil {
		t.Fatal("expected both to fail")
	}
	if wrongPass.Error() != tampered.Error() {
		t.Fatalf("the two cases are distinguishable:\n  %v\n  %v", wrongPass, tampered)
	}
}

func TestOrgKeyExportRejectsMismatchedPublicKey(t *testing.T) {
	// A file assembled from parts: real ciphertext, someone else's public key.
	pub, priv := newOrgKey(t)
	otherPub, _ := newOrgKey(t)

	file, _ := Build("org-a", pub, priv, "pass")
	file.OrgPublicKey = otherPub

	_, err := Open(file, "pass")
	if err == nil {
		t.Fatal("a file naming the wrong public key still opened")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestOrgKeyExportRejectsUnknownVersion(t *testing.T) {
	pub, priv := newOrgKey(t)
	file, _ := Build("org-a", pub, priv, "pass")
	file.Version = Version + 1

	if _, err := Open(file, "pass"); err == nil {
		t.Fatal("a future version opened instead of being refused")
	}
}

func TestOrgKeyExportRequiresItsInputs(t *testing.T) {
	pub, priv := newOrgKey(t)

	if _, err := Build("", pub, priv, "pass"); err == nil {
		t.Error("an export with no org id was allowed")
	}
	if _, err := Build("org-a", pub, nil, "pass"); err == nil {
		t.Error("an export with no key was allowed")
	}
	if _, err := Build("org-a", pub, priv, ""); err == nil {
		t.Error("an export with no passphrase was allowed")
	}
}

func TestWriteOrgKeyExportIsOwnerOnlyAndRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sinesync-org.key")

	pub, priv := newOrgKey(t)
	file, _ := Build("org-a", pub, priv, "pass")

	if err := Write(path, file); err != nil {
		t.Fatalf("write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// A world-readable credentials file would undo the passphrase for anyone
	// already on the host.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials file is mode %o, want 600", perm)
	}

	// Overwriting would strand a deployed daemon on a key nobody has any more.
	if err := Write(path, file); err == nil {
		t.Fatal("an existing credentials file was overwritten")
	}
}

func TestOrgKeyExportUsesAFreshSaltEachTime(t *testing.T) {
	// Reusing a salt would mean the same passphrase derives the same file key
	// across exports, so one cracked passphrase opens every file ever made.
	pub, priv := newOrgKey(t)

	first, _ := Build("org-a", pub, priv, "pass")
	second, _ := Build("org-a", pub, priv, "pass")

	if first.KDF.Salt == second.KDF.Salt {
		t.Fatal("two exports share a salt")
	}
	if first.EncryptedOrgPrivateKey == second.EncryptedOrgPrivateKey {
		t.Fatal("two exports produced identical ciphertext")
	}
}
