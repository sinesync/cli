package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/encryption"
)

// The org private key is the root of every vault key in the organization. It is
// uploaded to the server sealed, so the only thing standing between the server
// and the whole org's plaintext is the choice of who it is sealed to. That
// choice must not come from the server.

// keypairServer stands in for a compromised /users/keypair: it returns a public
// key belonging to an attacker alongside the user's genuine encrypted private
// key. A server can do exactly this — the public key is a bare field it fills
// in, while the private key is encrypted to a master key it never sees.
func keypairServer(t *testing.T, publicKey, encryptedPrivateKey string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/keypair" {
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"publicKey":           publicKey,
			"encryptedPrivateKey": encryptedPrivateKey,
		})
	}))
	t.Cleanup(srv.Close)

	t.Setenv("SINESYNC_API_URL", srv.URL)
}

// useLocalMasterKey gives this process a master key without touching the OS
// keychain, and returns it. Writing to the real keychain here would overwrite
// the developer's own derived key.
func useLocalMasterKey(t *testing.T) {
	t.Helper()

	key, err := crypto.GenerateKey(32)
	if err != nil {
		t.Fatalf("generate master key: %v", err)
	}
	// The encryption manager is a process-wide singleton, so this key outlives
	// the test. No other test in this package depends on the manager's state.
	if err := encryption.GetManager().SetKeyInMemory(key); err != nil {
		t.Fatalf("set master key: %v", err)
	}
}

func TestSealOrgPrivateKeyIgnoresServerSuppliedPublicKey(t *testing.T) {
	useLocalMasterKey(t)

	adminPub, adminPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate admin keypair: %v", err)
	}
	attackerPub, attackerPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate attacker keypair: %v", err)
	}

	// The admin's real private key, encrypted to their master key exactly as the
	// server stores it.
	encryptedAdminPriv, err := encryption.GetManager().EncryptUserPrivateKey([]byte(adminPriv))
	if err != nil {
		t.Fatalf("encrypt admin private key: %v", err)
	}

	keypairServer(t, attackerPub, encryptedAdminPriv)

	_, orgPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate org keypair: %v", err)
	}

	sealed, err := sealOrgPrivateKeyToSelf("test-token", orgPriv)
	if err != nil {
		t.Fatalf("sealOrgPrivateKeyToSelf: %v", err)
	}

	// The ciphertext that would be uploaded must open with the key the admin
	// actually holds.
	opened, err := crypto.X25519Open(sealed, adminPriv)
	if err != nil {
		t.Fatalf("org private key does not open with the admin's own key: %v", err)
	}
	if string(opened) != orgPriv {
		t.Fatalf("org private key round-tripped to %q, want %q", string(opened), orgPriv)
	}

	// And it must not open with the key the server tried to substitute. If it
	// does, whoever supplied that key can decrypt every vault key in the org.
	if _, err := crypto.X25519Open(sealed, attackerPriv); err == nil {
		t.Fatal("org private key opened with the server-supplied key: it was sealed to the attacker, not the admin")
	}

	// Belt and braces: the recipient is the locally derived public key, and it
	// is not the one the server named.
	derivedPub, err := crypto.PublicKeyFromPrivate(adminPriv)
	if err != nil {
		t.Fatalf("derive admin public key: %v", err)
	}
	if derivedPub != adminPub {
		t.Fatalf("derived public key %q != generated %q", derivedPub, adminPub)
	}
	if adminPub == attackerPub {
		t.Fatal("test is not exercising a substitution: the two keypairs are identical")
	}
}

// A server that substitutes the private key too cannot get a usable ciphertext
// out of this path either. The substituted key is not encrypted to the admin's
// master key, so it fails to decrypt and nothing is sealed or uploaded.
func TestSealOrgPrivateKeyFailsWhenKeyMaterialIsNotOurs(t *testing.T) {
	useLocalMasterKey(t)

	attackerPub, attackerPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate attacker keypair: %v", err)
	}

	// Encrypted to a master key that is not this user's.
	foreign := encryption.NewManager()
	foreignKey, err := crypto.GenerateKey(32)
	if err != nil {
		t.Fatalf("generate foreign master key: %v", err)
	}
	if err := foreign.SetKeyInMemory(foreignKey); err != nil {
		t.Fatalf("set foreign master key: %v", err)
	}
	foreignBlob, err := foreign.EncryptUserPrivateKey([]byte(attackerPriv))
	if err != nil {
		t.Fatalf("encrypt foreign private key: %v", err)
	}

	keypairServer(t, attackerPub, foreignBlob)

	_, orgPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate org keypair: %v", err)
	}

	sealed, err := sealOrgPrivateKeyToSelf("test-token", orgPriv)
	if err == nil {
		t.Fatalf("sealed the org private key from key material that is not ours: %q", sealed)
	}
	if sealed != "" {
		t.Errorf("returned ciphertext %q alongside an error; nothing should be uploadable", sealed)
	}
}
