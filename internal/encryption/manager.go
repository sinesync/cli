package encryption

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/miclip/sinesync/internal/crypto"
	"github.com/miclip/sinesync/internal/keychain"
	"github.com/miclip/sinesync/internal/storage"
)

const (
	// AAD strings for different encrypted data types
	AADObservation = "sinesync-observation-v1"
	AADTestBlob    = "sinesync-test-blob-v1"

	// KeyTestString is the known string encrypted for key verification
	KeyTestString = "sinesync-key-test-v1"
)

var (
	ErrNoKey          = errors.New("no encryption key available")
	ErrInvalidKey     = errors.New("invalid encryption key")
	ErrDecryptFailed  = errors.New("decryption failed")
	ErrKeyMismatch    = errors.New("encryption key does not match")
)

// Manager handles encryption key lifecycle and encryption/decryption operations
type Manager struct {
	derivedKey []byte
}

// NewManager creates a new encryption manager
func NewManager() *Manager {
	return &Manager{}
}

// SetupFirstDevice generates a new secret key and derives the encryption key
// This is called during signup on the first device
// Returns the secret key that must be shown to the user (Emergency Kit)
func (m *Manager) SetupFirstDevice(password string) (secretKey string, salt []byte, testBlob []byte, err error) {
	// Generate secret key (256-bit)
	secretKey, err = crypto.GenerateSecretKey()
	if err != nil {
		return "", nil, nil, fmt.Errorf("generate secret key: %w", err)
	}

	// Generate salt (128-bit)
	salt, err = crypto.GenerateSalt()
	if err != nil {
		return "", nil, nil, fmt.Errorf("generate salt: %w", err)
	}

	// Derive key from password + secret key
	m.derivedKey = crypto.DeriveKey(password, secretKey, salt)

	// Create test blob for key verification
	testBlob, err = m.createTestBlob()
	if err != nil {
		return "", nil, nil, fmt.Errorf("create test blob: %w", err)
	}

	// Store in keychain
	if err := keychain.SetSecretKey(secretKey); err != nil {
		return "", nil, nil, fmt.Errorf("store secret key: %w", err)
	}
	if err := keychain.SetUserSalt(salt); err != nil {
		return "", nil, nil, fmt.Errorf("store salt: %w", err)
	}
	if err := keychain.SetDerivedKey(m.derivedKey); err != nil {
		return "", nil, nil, fmt.Errorf("store derived key: %w", err)
	}

	return secretKey, salt, testBlob, nil
}

// SetupNewDevice derives the encryption key using the provided secret key
// This is called during login on a new device where the user provides their secret key
func (m *Manager) SetupNewDevice(password, secretKey string, salt, testBlob []byte) error {
	// Validate secret key format
	if !crypto.ValidateSecretKey(secretKey) {
		return ErrInvalidKey
	}

	// Derive key from password + secret key
	m.derivedKey = crypto.DeriveKey(password, secretKey, salt)

	// Verify key by decrypting test blob
	if !m.VerifyKey(testBlob) {
		return ErrKeyMismatch
	}

	// Store in keychain
	if err := keychain.SetSecretKey(secretKey); err != nil {
		return fmt.Errorf("store secret key: %w", err)
	}
	if err := keychain.SetUserSalt(salt); err != nil {
		return fmt.Errorf("store salt: %w", err)
	}
	if err := keychain.SetDerivedKey(m.derivedKey); err != nil {
		return fmt.Errorf("store derived key: %w", err)
	}

	return nil
}

// SetupExistingDevice re-derives the key using credentials from keychain
// This is called during login on a device that already has the secret key
func (m *Manager) SetupExistingDevice(password string) error {
	// Get secret key from keychain
	secretKey, err := keychain.GetSecretKey()
	if err != nil {
		return fmt.Errorf("get secret key: %w", err)
	}

	// Get salt from keychain
	salt, err := keychain.GetUserSalt()
	if err != nil {
		return fmt.Errorf("get salt: %w", err)
	}

	// Derive key
	m.derivedKey = crypto.DeriveKey(password, secretKey, salt)

	// Store derived key
	if err := keychain.SetDerivedKey(m.derivedKey); err != nil {
		return fmt.Errorf("store derived key: %w", err)
	}

	return nil
}

// LoadKey loads the derived key from keychain
func (m *Manager) LoadKey() error {
	key, err := keychain.GetDerivedKey()
	if err != nil {
		return ErrNoKey
	}
	m.derivedKey = key
	return nil
}

// GetKey returns the current derived key
func (m *Manager) GetKey() ([]byte, error) {
	if len(m.derivedKey) == 0 {
		// Try to load from keychain
		if err := m.LoadKey(); err != nil {
			return nil, ErrNoKey
		}
	}
	return m.derivedKey, nil
}

// HasKey checks if a derived key is available
func (m *Manager) HasKey() bool {
	if len(m.derivedKey) > 0 {
		return true
	}
	key, err := keychain.GetDerivedKey()
	if err == nil && len(key) > 0 {
		m.derivedKey = key
		return true
	}
	return false
}

// VerifyKey verifies the key by decrypting the test blob
func (m *Manager) VerifyKey(testBlob []byte) bool {
	if len(m.derivedKey) == 0 {
		return false
	}
	if len(testBlob) == 0 {
		return false
	}

	plaintext, err := crypto.Decrypt(testBlob, m.derivedKey, AADTestBlob)
	if err != nil {
		return false
	}

	return string(plaintext) == KeyTestString
}

// createTestBlob creates an encrypted blob of the known test string
func (m *Manager) createTestBlob() ([]byte, error) {
	return crypto.Encrypt([]byte(KeyTestString), m.derivedKey, AADTestBlob)
}

// EncryptObservation encrypts an observation for cloud storage
func (m *Manager) EncryptObservation(obs *storage.Observation) ([]byte, error) {
	key, err := m.GetKey()
	if err != nil {
		return nil, err
	}

	// Serialize to JSON
	jsonData, err := json.Marshal(obs)
	if err != nil {
		return nil, fmt.Errorf("marshal observation: %w", err)
	}

	// Compress
	compressed, err := compress(jsonData)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	// Encrypt
	encrypted, err := crypto.Encrypt(compressed, key, AADObservation)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return encrypted, nil
}

// DecryptObservation decrypts an observation from cloud storage
func (m *Manager) DecryptObservation(encrypted []byte) (*storage.Observation, error) {
	key, err := m.GetKey()
	if err != nil {
		return nil, err
	}

	// Decrypt
	compressed, err := crypto.Decrypt(encrypted, key, AADObservation)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	// Decompress
	jsonData, err := decompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	// Unmarshal
	var obs storage.Observation
	if err := json.Unmarshal(jsonData, &obs); err != nil {
		return nil, fmt.Errorf("unmarshal observation: %w", err)
	}

	return &obs, nil
}

// EncryptData encrypts arbitrary data for cloud storage
func (m *Manager) EncryptData(data []byte, aad string) ([]byte, error) {
	key, err := m.GetKey()
	if err != nil {
		return nil, err
	}

	compressed, err := compress(data)
	if err != nil {
		return nil, fmt.Errorf("compress: %w", err)
	}

	encrypted, err := crypto.Encrypt(compressed, key, aad)
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	return encrypted, nil
}

// DecryptData decrypts arbitrary data from cloud storage
func (m *Manager) DecryptData(encrypted []byte, aad string) ([]byte, error) {
	key, err := m.GetKey()
	if err != nil {
		return nil, err
	}

	compressed, err := crypto.Decrypt(encrypted, key, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	data, err := decompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	return data, nil
}

// compress uses gzip compression
func compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := gzip.NewWriter(&buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decompress uses gzip decompression
func decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Global encryption manager instance
var globalManager *Manager

// GetManager returns the global encryption manager
func GetManager() *Manager {
	if globalManager == nil {
		globalManager = NewManager()
	}
	return globalManager
}

// HasSecretKeyInKeychain checks if a secret key exists in the keychain
func HasSecretKeyInKeychain() bool {
	key, err := keychain.GetSecretKey()
	return err == nil && key != ""
}

// HasSaltInKeychain checks if a user salt exists in the keychain
func HasSaltInKeychain() bool {
	salt, err := keychain.GetUserSalt()
	return err == nil && len(salt) > 0
}

// AAD for vault key encryption
const AADVaultKey = "sinesync-vault-key-v1"

// EncryptVaultKey encrypts a vault key with the user's derived key
// Returns base64-encoded encrypted vault key
func (m *Manager) EncryptVaultKey(vaultKey []byte) (string, error) {
	key, err := m.GetKey()
	if err != nil {
		return "", err
	}

	encrypted, err := crypto.Encrypt(vaultKey, key, AADVaultKey)
	if err != nil {
		return "", fmt.Errorf("encrypt vault key: %w", err)
	}

	return crypto.EncodeBase64(encrypted), nil
}

// DecryptVaultKey decrypts a vault key using the user's derived key
// Takes base64-encoded encrypted vault key, returns raw vault key bytes
func (m *Manager) DecryptVaultKey(encryptedVaultKey string) ([]byte, error) {
	key, err := m.GetKey()
	if err != nil {
		return nil, err
	}

	encrypted, err := crypto.DecodeBase64(encryptedVaultKey)
	if err != nil {
		return nil, fmt.Errorf("decode vault key: %w", err)
	}

	vaultKey, err := crypto.Decrypt(encrypted, key, AADVaultKey)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return vaultKey, nil
}

// AAD for user private key encryption
const AADUserPrivateKey = "sinesync-user-private-key-v1"

// EncryptUserPrivateKey encrypts the user's X25519 private key with their derived key
// Returns base64-encoded encrypted private key
func (m *Manager) EncryptUserPrivateKey(privateKey []byte) (string, error) {
	key, err := m.GetKey()
	if err != nil {
		return "", err
	}

	encrypted, err := crypto.Encrypt(privateKey, key, AADUserPrivateKey)
	if err != nil {
		return "", fmt.Errorf("encrypt private key: %w", err)
	}

	return crypto.EncodeBase64(encrypted), nil
}

// DecryptUserPrivateKey decrypts the user's X25519 private key
// Takes base64-encoded encrypted private key, returns raw private key string
func (m *Manager) DecryptUserPrivateKey(encryptedPrivateKey string) (string, error) {
	key, err := m.GetKey()
	if err != nil {
		return "", err
	}

	encrypted, err := crypto.DecodeBase64(encryptedPrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}

	privateKey, err := crypto.Decrypt(encrypted, key, AADUserPrivateKey)
	if err != nil {
		return "", ErrDecryptFailed
	}

	return string(privateKey), nil
}
