package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/httputil"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/vaultroute"
)

// Changing a password changes the derived key, and the derived key is what wraps
// the user's X25519 private key and every vault key in vaults.json. Nothing the
// server holds can re-wrap them — it never sees the password — so the client has
// to open all of them under the old key and seal all of them under the new one.
//
// The dangerous shape here is a partial re-wrap: if the password changes while
// one vault key is still sealed under the old derived key, that vault is
// unreadable from then on and nothing in this repo can recover it. So this
// helper is all-or-nothing and pure — it decides the whole new state before the
// caller sends or writes anything, and it touches neither the network, the
// keychain, nor its arguments.

// changePasswordVaultKey is one entry of the vaultKeys array the server expects.
type changePasswordVaultKey struct {
	VaultID           string `json:"vaultId"`
	EncryptedVaultKey string `json:"encryptedVaultKey"`
}

// changePasswordPayload is the body of POST /auth/change-password.
//
// The SRP fields are the caller's to fill: ClientPublic and ClientProof prove
// the current password (see requestSRPChallenge), and SRPSalt/SRPVerifier come
// from an srp.Client built on the new one. rewrapForNewPassword fills only the
// two fields that are re-encryptions.
type changePasswordPayload struct {
	ClientPublic string `json:"clientPublic"`
	ClientProof  string `json:"clientProof"`

	SRPSalt     string `json:"srpSalt"`
	SRPVerifier string `json:"srpVerifier"`

	EncryptedPrivateKey string                   `json:"encryptedPrivateKey"`
	VaultKeys           []changePasswordVaultKey `json:"vaultKeys"`
}

// rewrapForNewPassword opens the user's private key and every local vault key
// with oldMgr and re-seals them with newMgr.
//
// It returns the payload for /auth/change-password and a copy of cfg in which
// only EncryptedVaultKey has changed — vault order, names, project assignments,
// default and org flags are carried over untouched, because that file is also
// what routes observations and reordering it would move data.
//
// cfg is not modified. If any key cannot be read, nothing is returned at all:
// a caller cannot accidentally send or save a half-re-wrapped state, which is
// the one failure here that permanently loses data.
func rewrapForNewPassword(oldMgr, newMgr *encryption.Manager, encryptedPrivateKey string, cfg *vaultroute.Config) (*changePasswordPayload, *vaultroute.Config, error) {
	if oldMgr == nil || newMgr == nil {
		return nil, nil, fmt.Errorf("rewrap: both the old and new key managers are required")
	}
	if encryptedPrivateKey == "" {
		return nil, nil, fmt.Errorf("rewrap: no encrypted private key to re-wrap")
	}

	privateKey, err := oldMgr.DecryptUserPrivateKey(encryptedPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("rewrap private key: %w", err)
	}
	newEncryptedPrivateKey, err := newMgr.EncryptUserPrivateKey([]byte(privateKey))
	if err != nil {
		return nil, nil, fmt.Errorf("rewrap private key: %w", err)
	}

	// Everything is computed into fresh values first; cfg and its slices are
	// only ever read.
	newCfg := &vaultroute.Config{}
	payload := &changePasswordPayload{EncryptedPrivateKey: newEncryptedPrivateKey}

	if cfg != nil && len(cfg.Vaults) > 0 {
		newCfg.Vaults = make([]vaultroute.Vault, 0, len(cfg.Vaults))
		payload.VaultKeys = make([]changePasswordVaultKey, 0, len(cfg.Vaults))

		for _, v := range cfg.Vaults {
			// Local vault keys are always AES-GCM under the derived key —
			// normalizeVaultKey converts an invited member's X25519-sealed key
			// before it is ever written here — so an entry that will not open is
			// a real problem and not a second format to handle.
			if v.EncryptedVaultKey == "" {
				return nil, nil, fmt.Errorf("rewrap vault %s (%s): no encrypted key to re-wrap", v.VaultID, v.Name)
			}

			vaultKey, err := oldMgr.DecryptVaultKey(v.EncryptedVaultKey)
			if err != nil {
				return nil, nil, fmt.Errorf("rewrap vault %s (%s): %w", v.VaultID, v.Name, err)
			}
			rewrapped, err := newMgr.EncryptVaultKey(vaultKey)
			if err != nil {
				return nil, nil, fmt.Errorf("rewrap vault %s (%s): %w", v.VaultID, v.Name, err)
			}

			copied := v
			copied.EncryptedVaultKey = rewrapped
			if v.Projects != nil {
				copied.Projects = make([]string, len(v.Projects))
				copy(copied.Projects, v.Projects)
			}

			newCfg.Vaults = append(newCfg.Vaults, copied)
			payload.VaultKeys = append(payload.VaultKeys, changePasswordVaultKey{
				VaultID:           v.VaultID,
				EncryptedVaultKey: rewrapped,
			})
		}
	}

	return payload, newCfg, nil
}

// changePasswordResult is the fresh session /auth/change-password issues.
//
// The server rotates the single refresh token as part of the change, so every
// other device is signed out and the token this device already holds stops
// working. Losing this response means being signed out by your own password
// change.
type changePasswordResult struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refreshToken"`
	ExpiresAt    string `json:"expiresAt"`
}

// postPasswordChange sends the re-wrapped key material to /auth/change-password
// and returns the session the server issues in reply.
//
// Network only: it writes nothing locally. Whether the new credentials are
// stored, and what happens to vaults.json, is the caller's decision — and it is
// a decision that can only be made after the server has confirmed the swap.
func postPasswordChange(token string, payload *changePasswordPayload) (*changePasswordResult, error) {
	if payload == nil {
		return nil, fmt.Errorf("change password: no payload")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}

	req, err := http.NewRequest("POST", getAPIBase()+"/auth/change-password", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("change password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The body carries why — a wrong current password comes back as 401
		// with a code, and swallowing it leaves the user with "it failed".
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("change password: server returned %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var result changePasswordResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("change password: response did not parse: %w", err)
	}

	// A 200 with no session in it is not a success this caller can act on: the
	// old token is already dead, so storing an empty one signs the user out
	// silently. Refuse it rather than return half a session.
	if result.Token == "" || result.RefreshToken == "" {
		return nil, fmt.Errorf("change password: server returned no session")
	}

	return &result, nil
}

// The local commit.
//
// By the time this runs the server has already accepted the change: the old
// password is gone, the old refresh token is retired, and the key material on
// disk is wrapped under a key that no longer matches the account. Everything
// below must therefore either complete or leave the device exactly as it was —
// there is no third state a user can recover from, because a half-committed
// device holds a derived key that opens nothing and a session token that the
// server has already replaced.
//
// So: snapshot first, write in a fixed order, and on any failure restore every
// snapshotted value and file byte for byte. The in-process manager is switched
// last, once the durable writes have all succeeded, so a crash cannot leave the
// running process using a key that was never stored.

// Keychain entries the commit replaces. Named here because they are also what
// gets restored.
const (
	authEntryToken        = "token"
	authEntryRefreshToken = "refreshToken"
)

// passwordChangeStore is every piece of state outside this function that the
// commit touches. It exists to be substituted: a test must be able to fail any
// single step, and must never reach the developer's real keychain, where the
// stored derived key is the only thing that opens their database.
type passwordChangeStore interface {
	// DerivedKey and Secret report a missing entry as an error satisfying
	// errors.Is(err, keychain.ErrNotFound). Every other error means the value
	// is unknown, not absent — see snapshotSecret.
	DerivedKey() ([]byte, error)
	SetDerivedKey(key []byte) error
	ClearDerivedKey() error

	Secret(name string) (string, error)
	SetSecret(name, value string) error
	ClearSecret(name string) error

	// ActivateKey switches the running process to the new key. Separate from
	// SetDerivedKey because storing a key and using it are different moments:
	// this one happens last, when every durable write has already succeeded.
	ActivateKey(key []byte) error

	ReadFile(path string) ([]byte, error)
	// WriteFileAtomic replaces path as a single step, so an interrupted write
	// cannot leave a truncated auth.json or vaults.json behind.
	WriteFileAtomic(path string, data []byte) error
	RemoveFile(path string) error
}

// keychainStore is the production passwordChangeStore: the OS keychain, the
// config directory, and the process-wide encryption manager.
type keychainStore struct {
	mgr *encryption.Manager
}

// newPasswordChangeStore returns the store a real password change uses.
func newPasswordChangeStore() keychainStore {
	return keychainStore{mgr: encryption.GetManager()}
}

func (s keychainStore) ActivateKey(k []byte) error { return s.mgr.SetKeyInMemory(k) }

func (keychainStore) DerivedKey() ([]byte, error)       { return keychain.GetDerivedKey() }
func (keychainStore) SetDerivedKey(k []byte) error      { return keychain.SetDerivedKey(k) }
func (keychainStore) ClearDerivedKey() error            { return keychain.ClearDerivedKey() }
func (keychainStore) Secret(n string) (string, error)   { return keychain.Get(n) }
func (keychainStore) SetSecret(n, v string) error       { return keychain.Set(n, v) }
func (keychainStore) ClearSecret(n string) error        { return keychain.Delete(n) }
func (keychainStore) ReadFile(p string) ([]byte, error) { return os.ReadFile(p) }
func (keychainStore) RemoveFile(p string) error         { return os.Remove(p) }

func (keychainStore) WriteFileAtomic(path string, data []byte) error {
	return writeFileAtomic(path, data)
}

// writeFileAtomic writes data to a temporary file in the same directory and
// renames it over path, so a reader never sees a partial file and a failed
// write leaves the previous contents intact.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Any early return from here leaves nothing behind; the remove is harmless
	// once the rename has succeeded.
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}

// commitPasswordChange makes the change local, after the server has confirmed it.
//
// result is required: there is deliberately no way to reach any of these writes
// without one, because persisting a new derived key before the server has
// accepted the new verifier would lock the account's data away behind a
// password the server does not know.
func commitPasswordChange(store passwordChangeStore, newDerivedKey []byte, result *changePasswordResult, newCfg *vaultroute.Config) error {
	if store == nil {
		return fmt.Errorf("commit password change: a store is required")
	}
	if result == nil || result.Token == "" || result.RefreshToken == "" {
		return fmt.Errorf("commit password change: refusing to write before the server has confirmed the change")
	}
	if len(newDerivedKey) != 32 {
		return fmt.Errorf("commit password change: new derived key must be 32 bytes, got %d", len(newDerivedKey))
	}

	authPath, vaultsPath := authConfigPath(), vaultroute.Path()

	// The new auth.json is computed before anything is written, so a malformed
	// or missing one fails while the device is still untouched.
	authBytes, err := store.ReadFile(authPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("commit password change: %s is missing — this device is not logged in", authPath)
		}
		return fmt.Errorf("commit password change: read %s: %w", authPath, err)
	}

	var authCfg AuthConfig
	if err := json.Unmarshal(authBytes, &authCfg); err != nil {
		return fmt.Errorf("commit password change: %s did not parse: %w", authPath, err)
	}
	// Only the expiry moves; the tokens themselves live in the keychain and the
	// rest of the file is identity, not session.
	authCfg.Token, authCfg.RefreshToken, authCfg.DeviceToken = "", "", ""
	authCfg.ExpiresAt = result.ExpiresAt
	newAuthBytes, err := json.MarshalIndent(authCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("commit password change: %w", err)
	}

	newVaultsBytes, err := marshalVaultConfig(newCfg)
	if err != nil {
		return fmt.Errorf("commit password change: %w", err)
	}

	// Snapshot. Anything absent now must be absent again if this fails — and
	// "absent" has to mean absent, not unreadable: see snapshotSecret.
	oldKeyValue, hadKey, err := snapshotSecret("the stored derived key", func() ([]byte, error) {
		return store.DerivedKey()
	})
	if err != nil {
		return fmt.Errorf("commit password change: %w", err)
	}
	oldKey := oldKeyValue

	oldTokenValue, hadToken, err := snapshotSecret("the stored access token", func() ([]byte, error) {
		v, err := store.Secret(authEntryToken)
		return []byte(v), err
	})
	if err != nil {
		return fmt.Errorf("commit password change: %w", err)
	}
	oldToken := string(oldTokenValue)

	oldRefreshValue, hadRefresh, err := snapshotSecret("the stored refresh token", func() ([]byte, error) {
		v, err := store.Secret(authEntryRefreshToken)
		return []byte(v), err
	})
	if err != nil {
		return fmt.Errorf("commit password change: %w", err)
	}
	oldRefresh := string(oldRefreshValue)

	oldVaultsBytes, err := store.ReadFile(vaultsPath)
	hadVaults := err == nil
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("commit password change: read %s: %w", vaultsPath, err)
	}

	// Compensations, applied in reverse order of the writes they undo.
	var undo []func() error
	rollback := func(cause error) error {
		var failures []error
		for i := len(undo) - 1; i >= 0; i-- {
			if err := undo[i](); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) > 0 {
			// The device is now in neither state. Say so as loudly as an error
			// can: this is the case where a user needs to know exactly what to
			// do next rather than to retry.
			return fmt.Errorf("commit password change failed AND could not be undone — "+
				"your password was changed on the server; run 'sinesync login' to re-establish this device: %w",
				errors.Join(append([]error{cause}, failures...)...))
		}
		return fmt.Errorf("commit password change: %w (local state was restored; "+
			"your password has already changed on the server — run 'sinesync login')", cause)
	}

	if err := store.SetDerivedKey(newDerivedKey); err != nil {
		return rollback(fmt.Errorf("store the new derived key: %w", err))
	}
	undo = append(undo, func() error {
		if !hadKey {
			return ignoreNotFound(store.ClearDerivedKey())
		}
		return store.SetDerivedKey(oldKey)
	})

	if err := store.SetSecret(authEntryToken, result.Token); err != nil {
		return rollback(fmt.Errorf("store the new access token: %w", err))
	}
	undo = append(undo, func() error {
		if !hadToken {
			return ignoreNotFound(store.ClearSecret(authEntryToken))
		}
		return store.SetSecret(authEntryToken, oldToken)
	})

	if err := store.SetSecret(authEntryRefreshToken, result.RefreshToken); err != nil {
		return rollback(fmt.Errorf("store the new refresh token: %w", err))
	}
	undo = append(undo, func() error {
		if !hadRefresh {
			return ignoreNotFound(store.ClearSecret(authEntryRefreshToken))
		}
		return store.SetSecret(authEntryRefreshToken, oldRefresh)
	})

	if err := store.WriteFileAtomic(authPath, newAuthBytes); err != nil {
		return rollback(fmt.Errorf("write %s: %w", authPath, err))
	}
	undo = append(undo, func() error { return store.WriteFileAtomic(authPath, authBytes) })

	if err := store.WriteFileAtomic(vaultsPath, newVaultsBytes); err != nil {
		return rollback(fmt.Errorf("write %s: %w", vaultsPath, err))
	}
	undo = append(undo, func() error {
		if !hadVaults {
			return store.RemoveFile(vaultsPath)
		}
		return store.WriteFileAtomic(vaultsPath, oldVaultsBytes)
	})

	// Durable writes are done; only now does the running process switch keys.
	if err := store.ActivateKey(newDerivedKey); err != nil {
		return rollback(fmt.Errorf("activate the new key in this process: %w", err))
	}

	return nil
}

// marshalVaultConfig renders vaults.json from the routing config.
//
// The CLI's LocalVaultConfig and vaultroute.Config are the same fields with the
// same JSON tags, so this writes the file the rest of the CLI already reads
// without converting between two spellings of one type — a conversion is one
// more place for the two to drift apart.
func marshalVaultConfig(cfg *vaultroute.Config) ([]byte, error) {
	out := vaultroute.Config{Vaults: []vaultroute.Vault{}}
	if cfg != nil && cfg.Vaults != nil {
		out.Vaults = cfg.Vaults
	}
	return json.MarshalIndent(out, "", "  ")
}

// snapshotSecret reads one keychain value for the rollback to restore.
//
// The distinction it enforces is the whole point. A keychain that is merely
// unreachable — no GUI session, a locked keyring, a backend fault — returns an
// error, and so does an entry that genuinely does not exist. Treating the first
// as the second would record "there was nothing here", and the compensation for
// "nothing was here" is to DELETE the entry: a rollback would then destroy the
// user's real derived key, which is the only thing that opens their database and
// is not recoverable from anywhere.
//
// So only keychain.ErrNotFound counts as absent. Every other error aborts the
// commit before the first mutation, while the device is still untouched.
func snapshotSecret(what string, read func() ([]byte, error)) (value []byte, present bool, err error) {
	v, err := read()
	if err == nil {
		return v, true, nil
	}
	if errors.Is(err, keychain.ErrNotFound) {
		return nil, false, nil
	}
	return nil, false, fmt.Errorf("read %s: %w", what, err)
}

// ignoreNotFound treats "there is no such entry" as a successful clear, since
// that is the state the clear was asking for.
func ignoreNotFound(err error) error {
	if err != nil && errors.Is(err, keychain.ErrNotFound) {
		return nil
	}
	return err
}
