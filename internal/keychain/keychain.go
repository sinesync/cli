package keychain

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"time"

	"github.com/zalando/go-keyring"
)

const serviceName = "sinesync"

// IsAvailable checks if keychain is available
func IsAvailable() bool {
	_, err := keyring.Get(serviceName, "test")
	// If error is not "not found", keychain is not available
	if err != nil && err != keyring.ErrNotFound {
		return false
	}
	return true
}

// Session token
func GetSessionToken() (string, error) {
	return keyring.Get(serviceName, "session-token")
}

func SetSessionToken(token string) error {
	return keyring.Set(serviceName, "session-token", token)
}

// User salt
func GetUserSalt() ([]byte, error) {
	encoded, err := keyring.Get(serviceName, "user-salt")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetUserSalt(salt []byte) error {
	encoded := base64.StdEncoding.EncodeToString(salt)
	return keyring.Set(serviceName, "user-salt", encoded)
}

// Secret key
func GetSecretKey() (string, error) {
	return keyring.Get(serviceName, "secret-key")
}

func SetSecretKey(key string) error {
	return keyring.Set(serviceName, "secret-key", key)
}

// Derived key
func GetDerivedKey() ([]byte, error) {
	encoded, err := keyring.Get(serviceName, "derived-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetDerivedKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(serviceName, "derived-key", encoded)
}

func ClearDerivedKey() error {
	return keyring.Delete(serviceName, "derived-key")
}

// Last auth timestamp
func GetLastAuth() (time.Time, error) {
	ts, err := keyring.Get(serviceName, "last-auth")
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
	return keyring.Set(serviceName, "last-auth", strconv.FormatInt(t.Unix(), 10))
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
	encoded, err := keyring.Get(serviceName, "local-db-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetLocalDBKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(serviceName, "local-db-key", encoded)
}

// GetOrCreateDBKey resolves the encryption key for SQLCipher.
// Priority: derived key (authenticated) → local DB key → generate new local DB key.
// Only generates a new key when both are genuinely missing (ErrNotFound),
// not on other errors like decode failures, to avoid making an existing DB inaccessible.
func GetOrCreateDBKey() ([]byte, error) {
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
	encoded, err := keyring.Get(serviceName, "device-key")
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func SetDeviceKey(key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	return keyring.Set(serviceName, "device-key", encoded)
}

func DeleteDeviceKey() error {
	return keyring.Delete(serviceName, "device-key")
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
	for _, key := range allKeys {
		if !keepSet[key] {
			keyring.Delete(serviceName, key) // Ignore errors
		}
	}
	return nil
}
