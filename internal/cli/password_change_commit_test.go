package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/vaultroute"
)

// The commit is the step with no safe middle. These tests fail every one of its
// writes in turn and check that the device comes back byte for byte, because a
// device left half-committed holds a derived key that opens nothing.

// commitStore is a passwordChangeStore with a real temp directory behind the
// files and a map behind the keychain, so nothing here reaches the developer's
// real keychain. failOn names the single step that fails.
type commitStore struct {
	secrets map[string]string
	key     []byte
	hasKey  bool
	mgr     *encryption.Manager

	// failures maps a step name to which call of it fails (1-based), so a test
	// can let a write succeed and fail the compensation that undoes it.
	failures map[string]int
	// errors overrides what a failing step returns; the default is stepError.
	errors map[string]error
	calls  []string
}

type stepError struct{ step string }

func (e stepError) Error() string { return "injected failure in " + e.step }

func (s *commitStore) step(name string) error {
	s.calls = append(s.calls, name)

	nth, wanted := s.failures[name]
	if !wanted {
		return nil
	}
	seen := 0
	for _, c := range s.calls {
		if c == name {
			seen++
		}
	}
	if seen == nth {
		if err, ok := s.errors[name]; ok {
			return err
		}
		return stepError{name}
	}
	return nil
}

// failWith makes the next call of a step fail with a specific error, so a test
// can inject the errors the real keychain package returns.
func (s *commitStore) failWith(step string, err error) {
	if s.errors == nil {
		s.errors = map[string]error{}
	}
	s.errors[step] = err
	s.failAt(step, 1)
}

// failAt makes the nth call of a step fail.
func (s *commitStore) failAt(step string, nth int) {
	if s.failures == nil {
		s.failures = map[string]int{}
	}
	s.failures[step] = nth
}

func (s *commitStore) DerivedKey() ([]byte, error) {
	// A read can fail for reasons that are not "absent": the step hook stands in
	// for a locked keyring, a headless session, a value that will not decode.
	if err := s.step("read-derived-key"); err != nil {
		return nil, err
	}
	if !s.hasKey {
		return nil, fmt.Errorf("derived-key: %w", keychain.ErrNotFound)
	}
	return append([]byte(nil), s.key...), nil
}

func (s *commitStore) SetDerivedKey(k []byte) error {
	if err := s.step("set-derived-key"); err != nil {
		return err
	}
	s.key, s.hasKey = append([]byte(nil), k...), true
	return nil
}

func (s *commitStore) ClearDerivedKey() error {
	if err := s.step("clear-derived-key"); err != nil {
		return err
	}
	if !s.hasKey {
		return fmt.Errorf("derived-key: %w", keychain.ErrNotFound)
	}
	s.key, s.hasKey = nil, false
	return nil
}

func (s *commitStore) Secret(name string) (string, error) {
	if err := s.step("read-secret-" + name); err != nil {
		return "", err
	}
	v, ok := s.secrets[name]
	if !ok {
		return "", fmt.Errorf("%s: %w", name, keychain.ErrNotFound)
	}
	return v, nil
}

func (s *commitStore) SetSecret(name, value string) error {
	if err := s.step("set-secret-" + name); err != nil {
		return err
	}
	s.secrets[name] = value
	return nil
}

func (s *commitStore) ClearSecret(name string) error {
	if err := s.step("clear-secret-" + name); err != nil {
		return err
	}
	if _, ok := s.secrets[name]; !ok {
		return fmt.Errorf("%s: %w", name, keychain.ErrNotFound)
	}
	delete(s.secrets, name)
	return nil
}

func (s *commitStore) ActivateKey(k []byte) error {
	if err := s.step("activate"); err != nil {
		return err
	}
	return s.mgr.SetKeyInMemory(k)
}

func (s *commitStore) ReadFile(path string) ([]byte, error) {
	if err := s.step("read-" + filepath.Base(path)); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func (s *commitStore) WriteFileAtomic(path string, data []byte) error {
	if err := s.step("write-" + filepath.Base(path)); err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

func (s *commitStore) RemoveFile(path string) error {
	if err := s.step("remove-" + filepath.Base(path)); err != nil {
		return err
	}
	return os.Remove(path)
}

// deviceState is everything the commit is allowed to change, captured so it can
// be compared byte for byte afterwards.
type deviceState struct {
	key        []byte
	hasKey     bool
	secrets    map[string]string
	authJSON   []byte
	vaultsJSON []byte
	hadVaults  bool
	managerKey []byte
}

func captureDevice(t *testing.T, s *commitStore) deviceState {
	t.Helper()

	state := deviceState{secrets: map[string]string{}}
	if s.hasKey {
		state.key, state.hasKey = append([]byte(nil), s.key...), true
	}
	for k, v := range s.secrets {
		state.secrets[k] = v
	}

	var err error
	if state.authJSON, err = os.ReadFile(authConfigPath()); err != nil {
		t.Fatalf("reading auth.json: %v", err)
	}
	if state.vaultsJSON, err = os.ReadFile(vaultroute.Path()); err == nil {
		state.hadVaults = true
	}
	if key, err := s.mgr.GetKey(); err == nil {
		state.managerKey = append([]byte(nil), key...)
	}
	return state
}

func (want deviceState) assertUnchanged(t *testing.T, s *commitStore) {
	t.Helper()
	got := captureDevice(t, s)

	if got.hasKey != want.hasKey || string(got.key) != string(want.key) {
		t.Errorf("the stored derived key was not restored")
	}
	if len(got.secrets) != len(want.secrets) {
		t.Errorf("secrets = %v, want %v", got.secrets, want.secrets)
	}
	for k, v := range want.secrets {
		if got.secrets[k] != v {
			t.Errorf("secret %q = %q, want %q", k, got.secrets[k], v)
		}
	}
	if string(got.authJSON) != string(want.authJSON) {
		t.Errorf("auth.json was not restored byte for byte:\n got: %s\nwant: %s", got.authJSON, want.authJSON)
	}
	if got.hadVaults != want.hadVaults || string(got.vaultsJSON) != string(want.vaultsJSON) {
		t.Errorf("vaults.json was not restored byte for byte:\n got: %s (present=%v)\nwant: %s (present=%v)",
			got.vaultsJSON, got.hadVaults, want.vaultsJSON, want.hadVaults)
	}
	if string(got.managerKey) != string(want.managerKey) {
		t.Errorf("the running process changed keys despite the failure")
	}
}

const (
	existingAuthJSON = `{
  "userId": "user-1",
  "email": "user@example.com",
  "expiresAt": "2020-01-01T00:00:00Z",
  "deviceId": "device-1",
  "authMethod": "srp"
}`
	existingVaultsJSON = `{"vaults":[{"vaultId":"vault-personal","name":"Personal","encryptedVaultKey":"old-key","projects":["alpha"],"isDefault":true}]}`
)

// setupDevice points the config directory at a temp home and lays down the
// files and secrets a logged-in device has.
func setupDevice(t *testing.T, withVaults bool) *commitStore {
	t.Helper()

	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".sinesync"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(authConfigPath(), []byte(existingAuthJSON), 0600); err != nil {
		t.Fatal(err)
	}
	if withVaults {
		if err := os.WriteFile(vaultroute.Path(), []byte(existingVaultsJSON), 0600); err != nil {
			t.Fatal(err)
		}
	}

	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i)
	}
	mgr := encryption.NewManager()
	if err := mgr.SetKeyInMemory(oldKey); err != nil {
		t.Fatal(err)
	}

	return &commitStore{
		secrets: map[string]string{authEntryToken: "old-access", authEntryRefreshToken: "old-refresh"},
		key:     oldKey,
		hasKey:  true,
		mgr:     mgr,
	}
}

func newKeyAndResult() ([]byte, *changePasswordResult, *vaultroute.Config) {
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(255 - i)
	}
	result := &changePasswordResult{
		Token:        "new-access",
		RefreshToken: "new-refresh",
		ExpiresAt:    "2099-01-01T00:00:00Z",
	}
	cfg := &vaultroute.Config{Vaults: []vaultroute.Vault{
		{VaultID: "vault-personal", Name: "Personal", EncryptedVaultKey: "rewrapped-1", Projects: []string{"alpha"}, IsDefault: true},
		{VaultID: "vault-team", Name: "Team", EncryptedVaultKey: "rewrapped-2", Projects: []string{"gamma"}, IsOrgVault: true, OrgID: "org-7"},
	}}
	return newKey, result, cfg
}

func TestASuccessfulCommitPersistsEverythingAndSwitchesTheProcessLast(t *testing.T) {
	store := setupDevice(t, true)
	newKey, result, cfg := newKeyAndResult()

	if err := commitPasswordChange(store, newKey, result, cfg); err != nil {
		t.Fatalf("commitPasswordChange: %v", err)
	}

	if string(store.key) != string(newKey) {
		t.Error("the new derived key was not stored")
	}
	if store.secrets[authEntryToken] != "new-access" || store.secrets[authEntryRefreshToken] != "new-refresh" {
		t.Errorf("tokens not stored: %v", store.secrets)
	}

	var authCfg AuthConfig
	authBytes, err := os.ReadFile(authConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(authBytes, &authCfg); err != nil {
		t.Fatal(err)
	}
	if authCfg.ExpiresAt != "2099-01-01T00:00:00Z" {
		t.Errorf("expiry = %q", authCfg.ExpiresAt)
	}
	// Identity is not session: the change must not rewrite who this device is.
	if authCfg.UserID != "user-1" || authCfg.Email != "user@example.com" || authCfg.DeviceID != "device-1" || authCfg.AuthMethod != "srp" {
		t.Errorf("auth.json lost identity fields: %+v", authCfg)
	}
	// Tokens live in the keychain; they must not be written to the file.
	if strings.Contains(string(authBytes), "new-access") || strings.Contains(string(authBytes), "new-refresh") {
		t.Errorf("auth.json contains tokens:\n%s", authBytes)
	}

	// vaults.json is written from the routing config directly, and must load
	// back through the reader the rest of the CLI uses.
	loaded, err := vaultroute.Load()
	if err != nil {
		t.Fatalf("vaultroute.Load: %v", err)
	}
	if len(loaded.Vaults) != 2 || loaded.Vaults[0].EncryptedVaultKey != "rewrapped-1" || loaded.Vaults[1].EncryptedVaultKey != "rewrapped-2" {
		t.Errorf("vaults.json round-tripped as %+v", loaded.Vaults)
	}
	if loaded.Vaults[1].OrgID != "org-7" || !loaded.Vaults[1].IsOrgVault || !loaded.Vaults[0].IsDefault {
		t.Errorf("vault metadata lost: %+v", loaded.Vaults)
	}
	// The same file has to parse as the CLI's own type, since both read it.
	local, err := loadLocalVaultConfig()
	if err != nil || len(local.Vaults) != 2 || local.Vaults[1].OrgID != "org-7" {
		t.Errorf("loadLocalVaultConfig read %+v (err %v)", local, err)
	}

	key, err := store.mgr.GetKey()
	if err != nil || string(key) != string(newKey) {
		t.Errorf("the process is not using the new key")
	}
	// Activation is last: every durable write precedes it.
	if last := store.calls[len(store.calls)-1]; last != "activate" {
		t.Errorf("last step was %q, want activate", last)
	}
}

func TestEveryCommitStepThatFailsRestoresTheDeviceExactly(t *testing.T) {
	for _, step := range []string{
		"set-derived-key",
		"set-secret-token",
		"set-secret-refreshToken",
		"write-auth.json",
		"write-vaults.json",
		"activate",
	} {
		t.Run(step, func(t *testing.T) {
			store := setupDevice(t, true)
			before := captureDevice(t, store)
			store.failAt(step, 1)
			newKey, result, cfg := newKeyAndResult()

			err := commitPasswordChange(store, newKey, result, cfg)
			if err == nil {
				t.Fatal("a failed commit reported success")
			}
			if !strings.Contains(err.Error(), "injected failure in "+step) {
				t.Errorf("error %q does not carry the failure", err)
			}
			// The rollback succeeded, so the user is told the local state is
			// intact and what to do about the server-side change.
			if !strings.Contains(err.Error(), "restored") {
				t.Errorf("error %q does not say the device was restored", err)
			}
			before.assertUnchanged(t, store)
		})
	}
}

func TestAFailedCommitRemovesAVaultsFileThatDidNotExistBefore(t *testing.T) {
	// A device with no vaults.json yet: the compensation is deletion, not a
	// restore, and leaving the new file behind would route observations with
	// keys the account no longer has.
	store := setupDevice(t, false)
	before := captureDevice(t, store)
	store.failAt("activate", 1)
	newKey, result, cfg := newKeyAndResult()

	if err := commitPasswordChange(store, newKey, result, cfg); err == nil {
		t.Fatal("a failed commit reported success")
	}
	if _, err := os.Stat(vaultroute.Path()); !os.IsNotExist(err) {
		t.Errorf("vaults.json survived a rollback that should have removed it (%v)", err)
	}
	before.assertUnchanged(t, store)
}

func TestARollbackThatItselfFailsSaysSoLoudly(t *testing.T) {
	store := setupDevice(t, true)
	// The last step fails, and restoring the derived key — the first thing the
	// rollback has to undo — fails too. The device is now in neither state, the
	// one case the user has to be told about explicitly rather than left to
	// retry.
	store.failAt("activate", 1)
	store.failAt("set-derived-key", 2)
	newKey, result, cfg := newKeyAndResult()
	err := commitPasswordChange(store, newKey, result, cfg)
	if err == nil {
		t.Fatal("a failed commit reported success")
	}
	if !strings.Contains(err.Error(), "could not be undone") {
		t.Errorf("error %q does not announce a failed rollback", err)
	}
	if !strings.Contains(err.Error(), "sinesync login") {
		t.Errorf("error %q does not tell the user what to do", err)
	}
}

func TestTheCommitRefusesWithoutAConfirmedServerResult(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result *changePasswordResult
	}{
		{"no result at all", nil},
		{"no access token", &changePasswordResult{RefreshToken: "r"}},
		{"no refresh token", &changePasswordResult{Token: "t"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := setupDevice(t, true)
			before := captureDevice(t, store)
			newKey, _, cfg := newKeyAndResult()

			if err := commitPasswordChange(store, newKey, tc.result, cfg); err == nil {
				t.Fatal("the commit ran without a confirmed server result")
			}
			if len(store.calls) != 0 {
				t.Errorf("it touched the device before refusing: %v", store.calls)
			}
			before.assertUnchanged(t, store)
		})
	}
}

func TestACommitOnADeviceThatIsNotLoggedInTouchesNothing(t *testing.T) {
	store := setupDevice(t, true)
	if err := os.Remove(authConfigPath()); err != nil {
		t.Fatal(err)
	}
	newKey, result, cfg := newKeyAndResult()

	err := commitPasswordChange(store, newKey, result, cfg)
	if err == nil {
		t.Fatal("the commit ran without an auth.json")
	}
	for _, call := range store.calls {
		if strings.HasPrefix(call, "set-") || strings.HasPrefix(call, "write-") {
			t.Errorf("it wrote %q before noticing there is no auth.json", call)
		}
	}
}

// No API may persist the new key before the server has confirmed the change.
// Enforced structurally rather than by review: a future helper that writes to
// the store without a changePasswordResult in hand is the exact mistake that
// locks an account's data behind a password the server does not know.
func TestNoWriteEscapesTheConfirmedCommit(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "password_change.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	mutators := map[string]bool{
		"SetDerivedKey": true, "ClearDerivedKey": true, "SetSecret": true,
		"ClearSecret": true, "WriteFileAtomic": true, "RemoveFile": true,
		"ActivateKey": true, "SetKeyInMemory": true, "SetKeyDirect": true,
	}

	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// The commit itself, and the store implementation it calls through.
		if fn.Name.Name == "commitPasswordChange" || fn.Recv != nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if mutators[sel.Sel.Name] {
				t.Errorf("%s calls %s outside commitPasswordChange, which can persist a new key "+
					"before the server has confirmed the change", fn.Name.Name, sel.Sel.Name)
			}
			return true
		})
	}
}

func TestAtomicWritesLeaveNoDebrisAndReplaceInPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vaults.json")

	if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(path, []byte("replacement")); err != nil {
		t.Fatalf("writeFileAtomic: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil || string(got) != "replacement" {
		t.Errorf("file holds %q (err %v)", got, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("mode = %v, want 0600 — this file holds key material", info.Mode().Perm())
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

// A read that fails is not a read that found nothing. The compensation for
// "there was nothing here" is a delete, so mistaking an unreachable keychain for
// an empty one turns a rollback into the destruction of the user's derived key —
// the one thing that opens their database and cannot be regenerated.

func TestAnUnreadableSnapshotAbortsBeforeTheFirstWrite(t *testing.T) {
	for _, read := range []string{"read-derived-key", "read-secret-token", "read-secret-refreshToken"} {
		t.Run(read, func(t *testing.T) {
			store := setupDevice(t, true)
			before := captureDevice(t, store)
			store.failAt(read, 1)
			newKey, result, cfg := newKeyAndResult()

			err := commitPasswordChange(store, newKey, result, cfg)
			if err == nil {
				t.Fatal("an unreadable snapshot was treated as a usable one")
			}
			if !strings.Contains(err.Error(), "injected failure in "+read) {
				t.Errorf("error %q does not carry the read failure", err)
			}
			assertNoMutations(t, store)
			before.assertUnchanged(t, store)
		})
	}
}

// The same thing through the error the keychain package actually returns when it
// cannot be reached at all.
func TestAnUnreachableKeychainAbortsRatherThanLookingEmpty(t *testing.T) {
	for _, read := range []string{"read-derived-key", "read-secret-token", "read-secret-refreshToken"} {
		t.Run(read, func(t *testing.T) {
			store := setupDevice(t, true)
			before := captureDevice(t, store)
			store.failWith(read, keychain.ErrNoKeychainSession)
			newKey, result, cfg := newKeyAndResult()

			err := commitPasswordChange(store, newKey, result, cfg)
			if err == nil {
				t.Fatal("an unreachable keychain was treated as an empty one")
			}
			if !errors.Is(err, keychain.ErrNoKeychainSession) {
				t.Errorf("error %v does not carry ErrNoKeychainSession", err)
			}
			assertNoMutations(t, store)
			before.assertUnchanged(t, store)
		})
	}
}

// ErrNoKeychainSession must never be mistaken for ErrNotFound; that confusion is
// exactly what this whole distinction exists to prevent.
func TestUnreachableIsNotTheSameAsAbsent(t *testing.T) {
	if errors.Is(keychain.ErrNoKeychainSession, keychain.ErrNotFound) {
		t.Error("an unreachable keychain satisfies errors.Is(err, ErrNotFound)")
	}
	if errors.Is(keychain.ErrNotFound, keychain.ErrNoKeychainSession) {
		t.Error("a missing entry satisfies errors.Is(err, ErrNoKeychainSession)")
	}
}

// A genuinely empty keychain is a normal state — a device whose tokens live only
// in auth.json, or a fresh SSO install — and the commit has to proceed and, on
// failure, put the emptiness back.
func TestAGenuinelyAbsentEntryIsAcceptedAndClearedOnRollback(t *testing.T) {
	store := setupDevice(t, true)
	store.hasKey, store.key = false, nil
	delete(store.secrets, authEntryRefreshToken)
	before := captureDevice(t, store)

	newKey, result, cfg := newKeyAndResult()
	store.failAt("activate", 1)

	err := commitPasswordChange(store, newKey, result, cfg)
	if err == nil {
		t.Fatal("a failed commit reported success")
	}
	// Clearing an entry that is already gone is the state the clear asked for,
	// not a rollback failure.
	if strings.Contains(err.Error(), "could not be undone") {
		t.Errorf("clearing absent entries was reported as a failed rollback: %v", err)
	}
	if store.hasKey {
		t.Error("a derived key that did not exist before was left behind")
	}
	if _, ok := store.secrets[authEntryRefreshToken]; ok {
		t.Error("a refresh token that did not exist before was left behind")
	}
	before.assertUnchanged(t, store)
}

func TestACommitWithNoStoredKeyAtAllStillSucceeds(t *testing.T) {
	store := setupDevice(t, true)
	store.hasKey, store.key = false, nil
	store.secrets = map[string]string{}

	newKey, result, cfg := newKeyAndResult()
	if err := commitPasswordChange(store, newKey, result, cfg); err != nil {
		t.Fatalf("commitPasswordChange: %v", err)
	}
	if string(store.key) != string(newKey) {
		t.Error("the new key was not stored on a device that had none")
	}
}

// assertNoMutations fails if the store was written to in any way.
func assertNoMutations(t *testing.T, s *commitStore) {
	t.Helper()
	for _, call := range s.calls {
		switch {
		case strings.HasPrefix(call, "read-"):
			continue
		default:
			t.Errorf("the commit performed %q despite an unusable snapshot", call)
		}
	}
}

// Rollback tolerates an entry that is already gone. The commit created it, so
// only something outside this process — a concurrent 'sinesync logout', a user
// clearing the keychain — can have removed it, and in that case the clear has
// already got what it wanted. Reporting it as a failed rollback would tell the
// user their device is in neither state when it is in exactly the right one.
func TestAClearThatFindsNothingIsNotARollbackFailure(t *testing.T) {
	store := setupDevice(t, true)
	store.hasKey, store.key = false, nil
	delete(store.secrets, authEntryRefreshToken)

	newKey, result, cfg := newKeyAndResult()
	store.failAt("activate", 1)
	// The entry vanished between the commit writing it and the rollback
	// clearing it.
	store.failWith("clear-secret-"+authEntryRefreshToken, keychain.ErrNotFound)

	err := commitPasswordChange(store, newKey, result, cfg)
	if err == nil {
		t.Fatal("a failed commit reported success")
	}
	if strings.Contains(err.Error(), "could not be undone") {
		t.Errorf("an entry that was already gone was reported as a rollback failure: %v", err)
	}
	if !strings.Contains(err.Error(), "restored") {
		t.Errorf("error %q does not say the device was restored", err)
	}
}
