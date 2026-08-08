package keychain

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const serviceName = "sinesync"

// ErrNoKeychainSession means this process cannot reach an OS keychain without
// blocking on user interaction, so no keychain call was attempted.
//
// Callers must treat it as "unknown", never as "absent". Reacting by creating a
// replacement key would orphan a database encrypted with the real one.
var ErrNoKeychainSession = errors.New("no keychain session available in this context")

// usable reports whether the OS keychain can be reached without raising UI.
//
// This exists because of a specific, destructive failure. When a process with no
// GUI session touches the macOS keychain — a daemon started via nohup, an MCP
// server spawned by an agent, anything over SSH, CI — the Security framework
// does not return an error. It puts a modal "Keychain Not Found" panel on
// screen whose primary button is "Reset To Defaults", which would discard the
// user's stored secret key and session tokens. A headless process must
// therefore decide BEFORE calling, not handle an error afterwards.
//
// Probed once: the answer cannot change within a process lifetime, and the
// darwin probe shells out.
var usable = sync.OnceValue(detectUsable)

func detectUsable() bool {
	// Explicit override, for containers and anywhere the heuristics are wrong.
	if v := os.Getenv("SINESYNC_NO_KEYCHAIN"); v != "" && v != "0" {
		return false
	}

	switch runtime.GOOS {
	case "darwin":
		// Probe the exact condition that fails: no DEFAULT keychain. That is
		// what raised the modal — the process had a perfectly good GUI session,
		// it just could not resolve a keychain, because it had been started with
		// an environment whose HOME did not point at one. Session-type checks
		// like `launchctl managername` return "Aqua" in that case and miss it.
		//
		// Probing through the `security` CLI rather than in-process is the whole
		// trick. It is a subprocess with no GUI connection, so the same
		// condition comes back as text on stderr and a non-zero result instead
		// of a panel offering to reset the user's keychain.
		out, err := exec.Command("security", "default-keychain").CombinedOutput()
		if err != nil {
			return false
		}
		// `security` exits 0 even when it cannot find one, so read the output.
		// On success it prints the default keychain's path; on failure it prints
		// a SecKeychainCopyDefault error. Match the failure, not the success —
		// the keychain's filename is user-configurable, so requiring it to look
		// a particular way would reject valid custom keychains and drop the user
		// to plaintext storage for no reason.
		text := strings.TrimSpace(string(out))
		if text == "" ||
			strings.Contains(text, "could not be found") ||
			strings.Contains(text, "SecKeychainCopyDefault") {
			return false
		}
		// Deliberately NOT also rejecting a locked keychain, though
		// `security show-keychain-info` could detect one. A locked keychain
		// raises an ordinary unlock prompt: expected, benign, and dismissible
		// by unlocking. What this guard exists to prevent is the panel raised
		// when there is no default keychain at all, whose primary button erases
		// the user's stored secrets. Rejecting locked keychains too would trade
		// a benign prompt for more false negatives, and a false negative here
		// silently drops the user to plaintext storage — the worse outcome.
		return true

	case "linux":
		// go-keyring talks to the Secret Service over the session bus. Without
		// one it errors rather than prompting, so this is about a clear message
		// instead of an obscure D-Bus failure.
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
			return true
		}
		// Mirror godbus's own discovery, not a subset of it. A false negative
		// here is not a harmless "be careful" — it disables encryption and hides
		// an existing database, so the check must not be stricter than the
		// library it is standing in front of.
		uid := os.Getuid()
		for _, path := range []string{
			fmt.Sprintf("/run/user/%d/bus", uid),
			fmt.Sprintf("/run/user/%d/dbus-session", uid),
		} {
			if _, err := os.Stat(path); err == nil {
				return true
			}
		}
		return false

	default:
		// Windows Credential Manager works without a desktop session.
		return true
	}
}

// Available reports whether keychain operations will be attempted at all.
// Unlike the old IsAvailable it performs no keychain call, so it is safe to ask
// from any context.
func Available() bool { return usable() }

// Get, Set and Delete are the ONLY paths from this codebase to the OS keychain.
//
// They exist because a guard is worth nothing if callers can route around it,
// and they could: the daemon and CLI previously reached for go-keyring directly
// with the same "sinesync" service name, so the availability check protected
// database-key resolution and nothing else. Session tokens and sync credentials
// went straight to the Security framework and could still raise the modal these
// functions exist to prevent.
//
// Nothing outside this package should import go-keyring.

func Get(key string) (string, error) {
	if !usable() {
		return "", ErrNoKeychainSession
	}
	return keyring.Get(serviceName, key)
}

func Set(key, value string) error {
	if !usable() {
		return ErrNoKeychainSession
	}
	return keyring.Set(serviceName, key, value)
}

func Delete(key string) error {
	if !usable() {
		return ErrNoKeychainSession
	}
	return keyring.Delete(serviceName, key)
}

// IsAvailable checks if the keychain is available and reachable.
//
// Deprecated: prefer Available. This still performs a real keychain read, so it
// must only be called once Available reports true.
func IsAvailable() bool {
	if !usable() {
		return false
	}
	_, err := keyring.Get(serviceName, "test")
	// If error is not "not found", keychain is not available
	if err != nil && err != keyring.ErrNotFound {
		return false
	}
	return true
}

// Session token
func GetSessionToken() (string, error) {
	return Get("session-token")
}

func SetSessionToken(token string) error {
	return Set("session-token", token)
}

// User salt
func GetUserSalt() ([]byte, error) {
	encoded, err := Get("user-salt")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetUserSalt(salt []byte) error {
	encoded := base64.StdEncoding.EncodeToString(salt)
	return Set("user-salt", encoded)
}

// Secret key
func GetSecretKey() (string, error) {
	return Get("secret-key")
}

func SetSecretKey(key string) error {
	return Set("secret-key", key)
}

// Derived key
func GetDerivedKey() ([]byte, error) {
	encoded, err := Get("derived-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetDerivedKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return Set("derived-key", encoded)
}

func ClearDerivedKey() error {
	return Delete("derived-key")
}

// Last auth timestamp
func GetLastAuth() (time.Time, error) {
	ts, err := Get("last-auth")
	if err != nil {
		return time.Time{}, err
	}
	epoch, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(epoch, 0), nil
}

func SetLastAuth(t time.Time) error {
	return Set("last-auth", strconv.FormatInt(t.Unix(), 10))
}

// NeedsReauth checks if re-authentication is needed (24 hours)
func NeedsReauth() bool {
	lastAuth, err := GetLastAuth()
	if err != nil {
		return true
	}
	return time.Since(lastAuth) > 24*time.Hour
}

// Local DB key (for SQLCipher encryption before login)
func GetLocalDBKey() ([]byte, error) {
	encoded, err := Get("local-db-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetLocalDBKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return Set("local-db-key", encoded)
}

// GetOrCreateDBKey resolves the encryption key for SQLCipher.
// Priority: derived key (authenticated) → local DB key → generate new local DB key.
// Only generates a new key when both are genuinely missing (ErrNotFound),
// not on other errors like decode failures, to avoid making an existing DB inaccessible.
func GetOrCreateDBKey() ([]byte, error) {
	// Guard the whole function, not just the reads. The create path below
	// responds to "not found" by generating a replacement key — correct when the
	// keychain is genuinely empty, catastrophic when it merely could not be
	// reached, because the existing database would no longer decrypt. In a
	// context with no keychain session, "not found" carries no information.
	if !usable() {
		return nil, ErrNoKeychainSession
	}

	// Try derived key first (authenticated user)
	key, err := GetDerivedKey()
	if err == nil && len(key) > 0 {
		return key, nil
	}
	if err != nil && err != keyring.ErrNotFound {
		return nil, fmt.Errorf("derived key unreadable: %w", err)
	}

	// Try local DB key (unauthenticated user)
	key, err = GetLocalDBKey()
	if err == nil && len(key) > 0 {
		return key, nil
	}
	if err != nil && err != keyring.ErrNotFound {
		return nil, fmt.Errorf("local DB key unreadable: %w", err)
	}

	// Both keys genuinely missing — generate a new local DB key
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	if err := SetLocalDBKey(key); err != nil {
		return nil, fmt.Errorf("store key: %w", err)
	}
	return key, nil
}

// Device key (for SSO credential bundle encryption)

func GetDeviceKey() ([]byte, error) {
	encoded, err := Get("device-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetDeviceKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return Set("device-key", encoded)
}

func DeleteDeviceKey() error {
	return Delete("device-key")
}

func HasDeviceKey() bool {
	key, err := GetDeviceKey()
	return err == nil && len(key) > 0
}

// Clear removes all stored credentials
func Clear() error {
	return ClearExcept(nil)
}

// ClearExcept removes all stored credentials except those in the keep list.
func ClearExcept(keep []string) error {
	allKeys := []string{"session-token", "user-salt", "secret-key", "derived-key", "last-auth", "local-db-key", "device-key"}
	keepSet := make(map[string]bool, len(keep))
	for _, k := range keep {
		keepSet[k] = true
	}
	// Through the guarded Delete, not keyring.Delete. Teardown and stale-login
	// cleanup both reach here, and both can run headless — deleting is exactly
	// as capable of raising the modal as reading.
	for _, key := range allKeys {
		if !keepSet[key] {
			_ = Delete(key) // best effort: a key that was never set is not an error
		}
	}
	return nil
}
