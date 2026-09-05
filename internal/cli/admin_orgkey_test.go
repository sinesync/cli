package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/encryption"
)

// A new org vault key is sealed to the org public key and to nothing else. Every
// member later provisioned for that vault receives a copy of the same key, so if
// it was sealed to a key the server chose, the server reads that vault from the
// moment it is created and no later check catches it. The org public key
// therefore has to come from the org private key this admin can actually open,
// not from what the server advertises.

// orgKeyServer serves the two endpoints ensureOrgKeypair reads, and counts the
// vault-key uploads that must not happen when they disagree.
type orgKeyServer struct {
	vaultKeyUploads int
	lastVaultKey    string
}

// advertisedPublicKey is what the server claims the org public key is;
// encryptedOrgPrivateKey is the genuine org private key sealed to the admin.
func startOrgKeyServer(t *testing.T, s *orgKeyServer, encryptedAdminPriv, advertisedPublicKey, encryptedOrgPrivateKey string) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/keypair":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"encryptedPrivateKey": encryptedAdminPriv,
			})

		case strings.HasSuffix(r.URL.Path, "/org-key"):
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"orgPublicKey": advertisedPublicKey,
				"keyHolder": map[string]string{
					"orgId":                  "org-1",
					"userId":                 "admin-1",
					"encryptedOrgPrivateKey": encryptedOrgPrivateKey,
				},
			})

		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/vaults/"):
			body, _ := io.ReadAll(r.Body)
			var parsed map[string]string
			_ = json.Unmarshal(body, &parsed)
			s.vaultKeyUploads++
			s.lastVaultKey = parsed["encryptedVaultKey"]
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true}`))

		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv("SINESYNC_API_URL", srv.URL)
}

// orgKeyFixture wires up an admin who holds a genuine org private key.
type orgKeyFixture struct {
	adminPriv          string
	encryptedAdminPriv string
	orgPub             string
	orgPriv            string
	encryptedOrgPriv   string
	attackerPub        string
}

func newOrgKeyFixture(t *testing.T) orgKeyFixture {
	t.Helper()
	useLocalMasterKey(t)

	adminPub, adminPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate admin keypair: %v", err)
	}
	encryptedAdminPriv, err := encryption.GetManager().EncryptUserPrivateKey([]byte(adminPriv))
	if err != nil {
		t.Fatalf("encrypt admin private key: %v", err)
	}

	orgPub, orgPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate org keypair: %v", err)
	}
	encryptedOrgPriv, err := crypto.X25519Seal([]byte(orgPriv), adminPub)
	if err != nil {
		t.Fatalf("seal org private key: %v", err)
	}

	attackerPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate attacker keypair: %v", err)
	}

	return orgKeyFixture{
		adminPriv:          adminPriv,
		encryptedAdminPriv: encryptedAdminPriv,
		orgPub:             orgPub,
		orgPriv:            orgPriv,
		encryptedOrgPriv:   encryptedOrgPriv,
		attackerPub:        attackerPub,
	}
}

func oneKeylessVault() []OrgVaultResponse {
	return []OrgVaultResponse{{ID: "vault-1", Name: "Team", EncryptedVaultKey: ""}}
}

// The advertised org public key is the attacker's. The admin's own key holder
// record still opens the real org private key, so the disagreement is visible
// here — and must stop the upload rather than warn about it.
func TestInitVaultKeysAbortsOnSubstitutedOrgPublicKey(t *testing.T) {
	cases := []struct {
		name         string
		orgInfoKey   func(f orgKeyFixture) string
		orgRecordKey func(f orgKeyFixture) string
	}{
		{
			name:         "both advertised places substituted",
			orgInfoKey:   func(f orgKeyFixture) string { return f.attackerPub },
			orgRecordKey: func(f orgKeyFixture) string { return f.attackerPub },
		},
		{
			name:         "only the org info substituted",
			orgInfoKey:   func(f orgKeyFixture) string { return f.attackerPub },
			orgRecordKey: func(f orgKeyFixture) string { return f.orgPub },
		},
		{
			name:         "only the org key record substituted",
			orgInfoKey:   func(f orgKeyFixture) string { return f.orgPub },
			orgRecordKey: func(f orgKeyFixture) string { return f.attackerPub },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newOrgKeyFixture(t)
			var srv orgKeyServer
			startOrgKeyServer(t, &srv, f.encryptedAdminPriv, tc.orgRecordKey(f), f.encryptedOrgPriv)

			orgInfo := &OrgInfo{OrgID: "org-1", Role: "admin", OrgPublicKey: tc.orgInfoKey(f)}

			var out bytes.Buffer
			initialized, keys, err := initMissingVaultKeys(&out, "test-token", orgInfo, oneKeylessVault(), nil)
			if err == nil {
				t.Fatal("initMissingVaultKeys returned no error for a substituted org public key")
			}
			if srv.vaultKeyUploads != 0 {
				t.Errorf("vault key was uploaded %d time(s) despite the mismatch", srv.vaultKeyUploads)
			}
			if initialized != 0 {
				t.Errorf("initialized = %d, want 0", initialized)
			}
			if keys != nil {
				t.Error("returned an org keypair from a failed verification")
			}
			if !strings.Contains(err.Error(), "does not belong to the org private key you hold") {
				t.Errorf("error does not explain the mismatch: %v", err)
			}
		})
	}
}

// When the advertised key agrees, the vault key must still be sealed to the
// DERIVED key — so it opens with the org private key the admin holds.
func TestInitVaultKeysSealsToTheDerivedOrgKey(t *testing.T) {
	f := newOrgKeyFixture(t)
	var srv orgKeyServer
	startOrgKeyServer(t, &srv, f.encryptedAdminPriv, f.orgPub, f.encryptedOrgPriv)

	orgInfo := &OrgInfo{OrgID: "org-1", Role: "admin", OrgPublicKey: f.orgPub}
	vaults := oneKeylessVault()

	var out bytes.Buffer
	initialized, keys, err := initMissingVaultKeys(&out, "test-token", orgInfo, vaults, nil)
	if err != nil {
		t.Fatalf("initMissingVaultKeys: %v", err)
	}
	if initialized != 1 || srv.vaultKeyUploads != 1 {
		t.Fatalf("initialized %d with %d uploads; want 1 and 1", initialized, srv.vaultKeyUploads)
	}
	if keys == nil || keys.publicKey != f.orgPub {
		t.Fatalf("derived org public key = %v, want %s", keys, f.orgPub)
	}
	if _, err := crypto.X25519Open(srv.lastVaultKey, f.orgPriv); err != nil {
		t.Errorf("uploaded vault key does not open with the org private key: %v", err)
	}
	// The caller's slice is updated so later provisioning can use the new key.
	if vaults[0].EncryptedVaultKey != srv.lastVaultKey {
		t.Error("the vault slice was not updated with the new key")
	}
}

// A cached keypair is one this run already opened or generated locally. It must
// be used as-is: no fetch, and so nothing for a server to substitute.
func TestInitVaultKeysUsesTheCachedKeypairWithoutAsking(t *testing.T) {
	f := newOrgKeyFixture(t)
	var srv orgKeyServer
	// Every read endpoint here would hand back the attacker's key. Reaching one
	// at all is the failure.
	startOrgKeyServer(t, &srv, f.encryptedAdminPriv, f.attackerPub, f.encryptedOrgPriv)

	orgInfo := &OrgInfo{OrgID: "org-1", Role: "admin", OrgPublicKey: f.attackerPub}
	cached := &orgKeypair{publicKey: f.orgPub, privateKey: []byte(f.orgPriv)}

	var out bytes.Buffer
	initialized, keys, err := initMissingVaultKeys(&out, "test-token", orgInfo, oneKeylessVault(), cached)
	if err != nil {
		t.Fatalf("initMissingVaultKeys: %v", err)
	}
	if initialized != 1 || keys != cached {
		t.Fatalf("initialized %d, keys reused = %v; want 1 and the cached pair", initialized, keys == cached)
	}
	if _, err := crypto.X25519Open(srv.lastVaultKey, f.orgPriv); err != nil {
		t.Errorf("vault key was not sealed to the cached org key: %v", err)
	}
}

// Nothing to do means nothing loaded: no private key is decrypted for an org
// whose vaults all have keys.
func TestInitVaultKeysSkipsLoadingWhenNoVaultNeedsAKey(t *testing.T) {
	f := newOrgKeyFixture(t)
	var srv orgKeyServer
	startOrgKeyServer(t, &srv, f.encryptedAdminPriv, f.attackerPub, f.encryptedOrgPriv)

	orgInfo := &OrgInfo{OrgID: "org-1", Role: "admin", OrgPublicKey: f.attackerPub}
	vaults := []OrgVaultResponse{{ID: "vault-1", Name: "Team", EncryptedVaultKey: "already-set"}}

	var out bytes.Buffer
	initialized, keys, err := initMissingVaultKeys(&out, "test-token", orgInfo, vaults, nil)
	if err != nil {
		t.Fatalf("initMissingVaultKeys: %v", err)
	}
	if initialized != 0 || keys != nil || srv.vaultKeyUploads != 0 {
		t.Errorf("initialized %d, keys %v, uploads %d; want 0, nil, 0", initialized, keys, srv.vaultKeyUploads)
	}
}

// zero() must actually clear the private key, since the command relies on it in
// a defer.
func TestOrgKeypairZeroClearsThePrivateKey(t *testing.T) {
	_, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	k := &orgKeypair{publicKey: "pub", privateKey: []byte(priv)}
	k.zero()
	for i, b := range k.privateKey {
		if b != 0 {
			t.Fatalf("byte %d of the private key survived zeroing", i)
		}
	}
	var nilPair *orgKeypair
	nilPair.zero() // must not panic: the command defers this before loading
}
