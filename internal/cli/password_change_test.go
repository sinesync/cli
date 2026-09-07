package cli

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/vaultroute"
)

// A password change re-derives the master key, so every key wrapped under the
// old one has to be re-wrapped in the same step. Anything missed is unreadable
// afterwards and unrecoverable, which is why these tests care as much about what
// happens on failure as about the happy path.

// newTestManager returns a manager holding a key for this process only.
// SetKeyInMemory keeps every one of these tests off the developer's real
// keychain, where the stored derived key is the only thing that opens their
// database.
func newTestManager(t *testing.T, seed byte) *encryption.Manager {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = seed + byte(i)
	}
	m := encryption.NewManager()
	if err := m.SetKeyInMemory(key); err != nil {
		t.Fatalf("SetKeyInMemory: %v", err)
	}
	return m
}

const testPrivateKey = "MC4CAQAwBQYDK2VuBCIEIHRoaXMtaXMtYS1mYWtlLXByaXZhdGUta2V5ISE="

// threeVaults builds a config whose vault keys are wrapped under mgr, with
// metadata that must survive the round trip untouched.
func threeVaults(t *testing.T, mgr *encryption.Manager) (*vaultroute.Config, map[string][]byte) {
	t.Helper()

	plaintexts := map[string][]byte{}
	cfg := &vaultroute.Config{}

	for _, v := range []vaultroute.Vault{
		{VaultID: "vault-personal", Name: "Personal", Projects: []string{"alpha", "beta"}, IsDefault: true},
		{VaultID: "vault-team", Name: "Team", Projects: []string{"gamma"}, IsOrgVault: true, OrgID: "org-7"},
		{VaultID: "vault-archive", Name: "Archive", Projects: nil},
	} {
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = byte(len(plaintexts)*7 + i)
		}
		wrapped, err := mgr.EncryptVaultKey(raw)
		if err != nil {
			t.Fatalf("EncryptVaultKey: %v", err)
		}
		v.EncryptedVaultKey = wrapped
		plaintexts[v.VaultID] = raw
		cfg.Vaults = append(cfg.Vaults, v)
	}
	return cfg, plaintexts
}

func encryptedPrivateKeyFor(t *testing.T, mgr *encryption.Manager) string {
	t.Helper()
	enc, err := mgr.EncryptUserPrivateKey([]byte(testPrivateKey))
	if err != nil {
		t.Fatalf("EncryptUserPrivateKey: %v", err)
	}
	return enc
}

func TestEveryVaultKeyIsRewrappedUnderTheNewPassword(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 1), newTestManager(t, 100)
	cfg, plaintexts := threeVaults(t, oldMgr)

	payload, newCfg, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg)
	if err != nil {
		t.Fatalf("rewrapForNewPassword: %v", err)
	}

	if len(payload.VaultKeys) != len(cfg.Vaults) {
		t.Fatalf("payload carries %d vault keys, config has %d vaults", len(payload.VaultKeys), len(cfg.Vaults))
	}

	// The point of the whole operation: the new key opens everything, and opens
	// it to the same plaintext as before.
	priv, err := newMgr.DecryptUserPrivateKey(payload.EncryptedPrivateKey)
	if err != nil {
		t.Fatalf("the new key cannot open the re-wrapped private key: %v", err)
	}
	if priv != testPrivateKey {
		t.Errorf("private key came back as %q", priv)
	}

	for i, entry := range payload.VaultKeys {
		if entry.VaultID != cfg.Vaults[i].VaultID {
			t.Errorf("payload entry %d is vault %q, config has %q", i, entry.VaultID, cfg.Vaults[i].VaultID)
		}
		got, err := newMgr.DecryptVaultKey(entry.EncryptedVaultKey)
		if err != nil {
			t.Fatalf("the new key cannot open vault %s: %v", entry.VaultID, err)
		}
		if !reflect.DeepEqual(got, plaintexts[entry.VaultID]) {
			t.Errorf("vault %s re-wrapped a different key than it held", entry.VaultID)
		}
		if entry.EncryptedVaultKey != newCfg.Vaults[i].EncryptedVaultKey {
			t.Errorf("vault %s: the payload and the new config disagree about the key", entry.VaultID)
		}
		// A ciphertext that did not change would mean the vault is still sealed
		// under the old password.
		if entry.EncryptedVaultKey == cfg.Vaults[i].EncryptedVaultKey {
			t.Errorf("vault %s kept its old ciphertext", entry.VaultID)
		}
		if _, err := oldMgr.DecryptVaultKey(entry.EncryptedVaultKey); err == nil {
			t.Errorf("vault %s is still readable with the old key", entry.VaultID)
		}
	}
}

func TestOnlyTheEncryptedKeysChangeInTheCopiedConfig(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 2), newTestManager(t, 200)
	cfg, _ := threeVaults(t, oldMgr)

	_, newCfg, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg)
	if err != nil {
		t.Fatalf("rewrapForNewPassword: %v", err)
	}

	if len(newCfg.Vaults) != len(cfg.Vaults) {
		t.Fatalf("copied config has %d vaults, want %d", len(newCfg.Vaults), len(cfg.Vaults))
	}
	for i := range cfg.Vaults {
		want, got := cfg.Vaults[i], newCfg.Vaults[i]
		// Blank the one field that is meant to differ and compare everything
		// else, so a field added later is covered without editing this test.
		want.EncryptedVaultKey, got.EncryptedVaultKey = "", ""
		if !reflect.DeepEqual(want, got) {
			t.Errorf("vault %d changed beyond its key:\n old: %+v\n new: %+v", i, want, got)
		}
	}
}

func TestTheInputConfigIsNeverTouched(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 3), newTestManager(t, 30)
	cfg, _ := threeVaults(t, oldMgr)

	before := make([]vaultroute.Vault, len(cfg.Vaults))
	for i, v := range cfg.Vaults {
		before[i] = v
		before[i].Projects = append([]string(nil), v.Projects...)
	}

	_, newCfg, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg)
	if err != nil {
		t.Fatalf("rewrapForNewPassword: %v", err)
	}

	// The caller still holds the old config; writing through the returned copy
	// must not reach it. Projects is the field that would share an array.
	newCfg.Vaults[0].Name = "renamed"
	newCfg.Vaults[0].Projects[0] = "overwritten"

	for i, v := range cfg.Vaults {
		if v.VaultID != before[i].VaultID || v.Name != before[i].Name ||
			v.EncryptedVaultKey != before[i].EncryptedVaultKey ||
			!reflect.DeepEqual(v.Projects, before[i].Projects) {
			t.Errorf("input vault %d was modified:\n was: %+v\n now: %+v", i, before[i], v)
		}
	}
}

func TestACorruptVaultKeyInTheMiddleAbandonsTheWholeChange(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 4), newTestManager(t, 40)
	cfg, _ := threeVaults(t, oldMgr)

	// Valid base64, so it fails at the AEAD rather than at decoding — the shape
	// a truncated or foreign key would have.
	cfg.Vaults[1].EncryptedVaultKey = crypto.EncodeBase64([]byte("this is not a vault key at all, not even close"))

	payload, newCfg, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg)
	if err == nil {
		t.Fatal("a vault key that cannot be read was accepted")
	}
	// Nothing partial escapes: the first vault was already re-wrapped in memory
	// when the second failed, and sending or saving that state would leave the
	// third vault sealed under a password that no longer exists.
	if payload != nil {
		t.Errorf("a payload was returned alongside the error: %+v", payload)
	}
	if newCfg != nil {
		t.Errorf("a config was returned alongside the error: %+v", newCfg)
	}
	if !strings.Contains(err.Error(), "vault-team") {
		t.Errorf("error %q does not name the vault that failed", err)
	}
}

func TestAVaultWithNoKeyIsRefusedRatherThanSkipped(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 5), newTestManager(t, 50)
	cfg, _ := threeVaults(t, oldMgr)
	cfg.Vaults[1].EncryptedVaultKey = ""

	// Skipping it would send the change through and leave that vault with a key
	// nothing can re-wrap afterwards.
	if _, _, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg); err == nil {
		t.Fatal("a vault entry with no encrypted key was accepted")
	}
}

func TestAnUnreadablePrivateKeyStopsBeforeAnyVault(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 6), newTestManager(t, 60)
	cfg, _ := threeVaults(t, oldMgr)

	// The private key was wrapped under some other key — a stale copy, or the
	// wrong account.
	foreign := newTestManager(t, 77)

	payload, newCfg, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, foreign), cfg)
	if err == nil {
		t.Fatal("a private key that cannot be read was accepted")
	}
	if payload != nil || newCfg != nil {
		t.Error("something was returned alongside the error")
	}
}

func TestAnAccountWithNoVaultsStillRewrapsThePrivateKey(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 7), newTestManager(t, 70)

	for _, cfg := range []*vaultroute.Config{nil, {}} {
		payload, newCfg, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg)
		if err != nil {
			t.Fatalf("rewrapForNewPassword(%v): %v", cfg, err)
		}
		if len(payload.VaultKeys) != 0 || len(newCfg.Vaults) != 0 {
			t.Errorf("vault keys appeared from nowhere: %+v", payload.VaultKeys)
		}
		if _, err := newMgr.DecryptUserPrivateKey(payload.EncryptedPrivateKey); err != nil {
			t.Errorf("private key not re-wrapped: %v", err)
		}
	}
}

func TestTheSRPFieldsAreLeftForTheCaller(t *testing.T) {
	oldMgr, newMgr := newTestManager(t, 8), newTestManager(t, 80)

	payload, _, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), &vaultroute.Config{})
	if err != nil {
		t.Fatalf("rewrapForNewPassword: %v", err)
	}
	if payload.ClientPublic != "" || payload.ClientProof != "" || payload.SRPSalt != "" || payload.SRPVerifier != "" {
		t.Errorf("the helper invented SRP fields: %+v", payload)
	}
}

// The network layer. These tests run against an httptest server via
// SINESYNC_API_URL and never touch the keychain or the real config directory.

// passwordChangeServer records what the client sent and controls what comes back.
type passwordChangeServer struct {
	calls       int
	method      string
	path        string
	authHeader  string
	contentType string
	body        []byte

	status   int    // 0 means 200
	response string // raw body to return; empty means the standard success body
}

func startPasswordChangeServer(t *testing.T, s *passwordChangeServer) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls++
		s.method, s.path = r.Method, r.URL.Path
		s.authHeader = r.Header.Get("Authorization")
		s.contentType = r.Header.Get("Content-Type")
		s.body, _ = io.ReadAll(r.Body)

		if s.status != 0 && s.status != http.StatusOK {
			w.WriteHeader(s.status)
			_, _ = w.Write([]byte(s.response))
			return
		}
		if s.response != "" {
			_, _ = w.Write([]byte(s.response))
			return
		}
		_, _ = w.Write([]byte(`{"token":"new-access","refreshToken":"new-refresh","expiresAt":"2099-01-01T00:00:00Z"}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SINESYNC_API_URL", srv.URL)
}

// realisticPayload is what the pure layer produces, with the SRP fields the
// caller fills in.
func realisticPayload(t *testing.T) (*changePasswordPayload, *vaultroute.Config) {
	t.Helper()
	oldMgr, newMgr := newTestManager(t, 11), newTestManager(t, 110)
	cfg, _ := threeVaults(t, oldMgr)

	payload, _, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKeyFor(t, oldMgr), cfg)
	if err != nil {
		t.Fatalf("rewrapForNewPassword: %v", err)
	}
	payload.ClientPublic = "A-hex"
	payload.ClientProof = "M1-hex"
	payload.SRPSalt = "new-salt"
	payload.SRPVerifier = "new-verifier"
	return payload, cfg
}

func TestPasswordChangeIsPostedWithTheBearerTokenAndEveryVault(t *testing.T) {
	srv := &passwordChangeServer{}
	startPasswordChangeServer(t, srv)
	payload, _ := realisticPayload(t)

	if _, err := postPasswordChange("session-token", payload); err != nil {
		t.Fatalf("postPasswordChange: %v", err)
	}

	if srv.calls != 1 {
		t.Fatalf("server called %d times, want 1", srv.calls)
	}
	if srv.method != "POST" || srv.path != "/auth/change-password" {
		t.Errorf("sent %s %s", srv.method, srv.path)
	}
	// A password change authenticates as the session AND proves the old
	// password; the bearer token is half of that and its absence would be a 401
	// the user could not explain.
	if srv.authHeader != "Bearer session-token" {
		t.Errorf("Authorization = %q", srv.authHeader)
	}
	if srv.contentType != "application/json" {
		t.Errorf("Content-Type = %q", srv.contentType)
	}

	// The body must be exactly what the server's schema accepts, with every
	// vault present and in order. A vault missing here is a vault sealed under
	// a password that will not exist in a moment.
	var got map[string]interface{}
	if err := json.Unmarshal(srv.body, &got); err != nil {
		t.Fatalf("body did not parse: %v\n%s", err, srv.body)
	}
	want := map[string]interface{}{
		"clientPublic":        "A-hex",
		"clientProof":         "M1-hex",
		"srpSalt":             "new-salt",
		"srpVerifier":         "new-verifier",
		"encryptedPrivateKey": payload.EncryptedPrivateKey,
		"vaultKeys": []interface{}{
			map[string]interface{}{"vaultId": "vault-personal", "encryptedVaultKey": payload.VaultKeys[0].EncryptedVaultKey},
			map[string]interface{}{"vaultId": "vault-team", "encryptedVaultKey": payload.VaultKeys[1].EncryptedVaultKey},
			map[string]interface{}{"vaultId": "vault-archive", "encryptedVaultKey": payload.VaultKeys[2].EncryptedVaultKey},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("request body:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestTheNewSessionIsReadBackFromTheResponse(t *testing.T) {
	srv := &passwordChangeServer{}
	startPasswordChangeServer(t, srv)
	payload, _ := realisticPayload(t)

	result, err := postPasswordChange("session-token", payload)
	if err != nil {
		t.Fatalf("postPasswordChange: %v", err)
	}
	if result.Token != "new-access" || result.RefreshToken != "new-refresh" || result.ExpiresAt != "2099-01-01T00:00:00Z" {
		t.Errorf("decoded %+v", result)
	}
}

func TestARejectedChangeReturnsNoUsableResult(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		response string
		wantIn   string
	}{
		{"wrong current password", http.StatusUnauthorized, `{"error":"Invalid credentials","code":"INVALID_CREDENTIALS"}`, "INVALID_CREDENTIALS"},
		{"server error", http.StatusInternalServerError, `{"error":"boom"}`, "boom"},
		{"accepted but no session", http.StatusOK, `{"expiresAt":"2099-01-01T00:00:00Z"}`, "no session"},
		{"accepted but unparseable", http.StatusOK, `not json`, "did not parse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := &passwordChangeServer{status: tc.status, response: tc.response}
			startPasswordChangeServer(t, srv)
			payload, _ := realisticPayload(t)

			result, err := postPasswordChange("session-token", payload)
			if err == nil {
				t.Fatal("a rejected change came back as success")
			}
			if result != nil {
				t.Errorf("a result was returned alongside the error: %+v", result)
			}
			// The reason has to survive: "it failed" is not something a user can
			// act on, and a wrong current password is the common case.
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error %q does not carry %q", err, tc.wantIn)
			}
		})
	}
}

func TestPostingAChangeWritesNothingLocally(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	srv := &passwordChangeServer{}
	startPasswordChangeServer(t, srv)
	payload, _ := realisticPayload(t)

	if _, err := postPasswordChange("session-token", payload); err != nil {
		t.Fatalf("postPasswordChange: %v", err)
	}

	// Credentials and vaults.json live under ~/.sinesync. Nothing may be written
	// there before the caller decides the change actually succeeded.
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("the network layer wrote to the config home: %v", entries)
	}
}

// The keypair fetch was split so a password change can get the wrapped private
// key; the decrypting caller has to keep working unchanged.

func TestTheKeypairFetchReturnsTheKeyStillWrapped(t *testing.T) {
	wrapped := "some-base64-ciphertext-the-server-holds"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer session-token" {
			t.Errorf("Authorization = %q", got)
		}
		if r.URL.Path != "/users/keypair" {
			t.Errorf("path = %q", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"encryptedPrivateKey": wrapped})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SINESYNC_API_URL", srv.URL)

	got, err := fetchEncryptedPrivateKey("session-token")
	if err != nil {
		t.Fatalf("fetchEncryptedPrivateKey: %v", err)
	}
	// Still wrapped: decrypting here would put the private key somewhere the
	// password change does not need it.
	if got != wrapped {
		t.Errorf("got %q, want the server's ciphertext %q", got, wrapped)
	}
}

func TestTheDecryptingFetchStillWorksThroughTheSplit(t *testing.T) {
	// encryption.GetManager is process-global; SetKeyInMemory keeps this off the
	// real keychain, as the other tests in this package do.
	mgr := encryption.GetManager()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(200 - i)
	}
	if err := mgr.SetKeyInMemory(key); err != nil {
		t.Fatal(err)
	}
	wrapped, err := mgr.EncryptUserPrivateKey([]byte(testPrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"encryptedPrivateKey": wrapped})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SINESYNC_API_URL", srv.URL)

	got, err := fetchAndDecryptPrivateKey("session-token")
	if err != nil {
		t.Fatalf("fetchAndDecryptPrivateKey: %v", err)
	}
	if got != testPrivateKey {
		t.Errorf("got %q, want the decrypted key", got)
	}
}

func TestAKeypairFetchTheServerRefusesIsStillTagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SINESYNC_API_URL", srv.URL)

	// vault.go switches on this to tell "the server gave us nothing" apart from
	// "we cannot decrypt", so the tag has to survive the split.
	_, err := fetchEncryptedPrivateKey("session-token")
	if !errors.Is(err, errKeypairUnavailable) {
		t.Errorf("error %v is not tagged errKeypairUnavailable", err)
	}
	if _, err := fetchAndDecryptPrivateKey("session-token"); !errors.Is(err, errKeypairUnavailable) {
		t.Errorf("error %v is not tagged errKeypairUnavailable", err)
	}
}
