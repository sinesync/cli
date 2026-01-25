package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	// Key derivation parameters (Argon2id)
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	keyLength    = 32 // 256 bits

	// AES-GCM parameters
	nonceSize = 12
	tagSize   = 16
)

// DeriveKey derives an encryption key from password and secret key using Argon2id
func DeriveKey(password, secretKey string, salt []byte) []byte {
	// Combine password and secret key
	combined := password + ":" + secretKey

	return argon2.IDKey(
		[]byte(combined),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		keyLength,
	)
}

// GenerateSalt generates a random salt for key derivation
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// GenerateSecretKey generates a new secret key (for display to user)
func GenerateSecretKey() (string, error) {
	bytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}
	return encodeBase32(bytes), nil
}

// Encrypt encrypts data using AES-256-GCM
func Encrypt(plaintext, key []byte, aad string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt with AAD (additional authenticated data)
	var additionalData []byte
	if aad != "" {
		additionalData = []byte(aad)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, additionalData)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-256-GCM
func Decrypt(ciphertext, key []byte, aad string) ([]byte, error) {
	if len(ciphertext) < nonceSize+tagSize {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	var additionalData []byte
	if aad != "" {
		additionalData = []byte(aad)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// Hash computes SHA-256 hash
func Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// encodeBase32 encodes bytes to a user-friendly base32 string
func encodeBase32(data []byte) string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // No I, O, 0, 1

	result := make([]byte, 0, len(data)*8/5+1)
	buffer := 0
	bitsLeft := 0

	for _, b := range data {
		buffer = (buffer << 8) | int(b)
		bitsLeft += 8

		for bitsLeft >= 5 {
			bitsLeft -= 5
			result = append(result, alphabet[(buffer>>bitsLeft)&0x1F])
		}
	}

	if bitsLeft > 0 {
		result = append(result, alphabet[(buffer<<(5-bitsLeft))&0x1F])
	}

	// Format with dashes for readability: XXXX-XXXX-XXXX-XXXX
	formatted := ""
	for i, c := range result {
		if i > 0 && i%4 == 0 {
			formatted += "-"
		}
		formatted += string(c)
	}

	return formatted
}
