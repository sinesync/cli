package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/box"
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

	// Secret key format: base32 with dashes
	// 32 bytes = 256 bits, base32 encodes to ~52 chars, with dashes every 4 = 64 total
	secretKeyLength      = 64 // 13 groups of 4 chars (52) + 12 dashes = 64
	secretKeyBase32Chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
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

// DeriveKeyFromCode derives an encryption key from a short code (e.g., 6-digit device link code).
// Uses Argon2id with the same parameters as DeriveKey.
func DeriveKeyFromCode(code string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(code),
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

// ValidateSecretKey validates the format of a secret key
func ValidateSecretKey(key string) bool {
	if len(key) != secretKeyLength {
		return false
	}

	charIndex := 0
	for i, c := range key {
		// Every 5th char (index 4, 9, 14, ...) should be a dash
		if (i+1)%5 == 0 {
			if c != '-' {
				return false
			}
		} else {
			// Must be a valid base32 character
			if !isValidBase32Char(byte(c)) {
				return false
			}
			charIndex++
		}
	}

	return true
}

// isValidBase32Char checks if a character is in our base32 alphabet
func isValidBase32Char(c byte) bool {
	for i := 0; i < len(secretKeyBase32Chars); i++ {
		if secretKeyBase32Chars[i] == c {
			return true
		}
	}
	return false
}

// DecodeSecretKey decodes a formatted secret key to bytes
func DecodeSecretKey(formatted string) ([]byte, error) {
	if !ValidateSecretKey(formatted) {
		return nil, errors.New("invalid secret key format")
	}

	// Remove dashes
	clean := ""
	for _, c := range formatted {
		if c != '-' {
			clean += string(c)
		}
	}

	return decodeBase32(clean)
}

// decodeBase32 decodes a base32 string to bytes
func decodeBase32(data string) ([]byte, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

	charMap := make(map[byte]int)
	for i := 0; i < len(alphabet); i++ {
		charMap[alphabet[i]] = i
	}

	result := make([]byte, 0, len(data)*5/8)
	buffer := 0
	bitsLeft := 0

	for i := 0; i < len(data); i++ {
		val, ok := charMap[data[i]]
		if !ok {
			return nil, errors.New("invalid character in secret key")
		}

		buffer = (buffer << 5) | val
		bitsLeft += 5

		for bitsLeft >= 8 {
			bitsLeft -= 8
			result = append(result, byte((buffer>>bitsLeft)&0xFF))
		}
	}

	return result, nil
}

// NormalizeSecretKey normalizes a secret key by removing spaces and converting to uppercase
func NormalizeSecretKey(key string) string {
	result := ""
	for _, c := range key {
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c >= 'a' && c <= 'z' {
			c = c - 'a' + 'A'
		}
		result += string(c)
	}
	return result
}

// EncodeBase32 encodes bytes to a user-friendly base32 string with dashes (XXXX-XXXX-...)
func EncodeBase32(data []byte) string {
	return encodeBase32(data)
}

// EncodeBase64 encodes bytes to standard base64 string
func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeBase64 decodes a standard base64 string to bytes
func DecodeBase64(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// GenerateKey generates a random key of the specified length
func GenerateKey(length int) ([]byte, error) {
	key := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// X25519 Key Exchange and Encryption Functions

// GenerateX25519Keypair generates a new X25519 keypair for vault sharing
// Returns public key and private key as base64-encoded strings
func GenerateX25519Keypair() (publicKey, privateKey string, err error) {
	pubKey, privKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate keypair: %w", err)
	}

	return base64.StdEncoding.EncodeToString(pubKey[:]),
		base64.StdEncoding.EncodeToString(privKey[:]),
		nil
}

// X25519Seal encrypts plaintext using the recipient's public key
// Uses NaCl box which combines X25519 + XSalsa20-Poly1305
// The sender's ephemeral keypair is generated internally
func X25519Seal(plaintext []byte, recipientPublicKey string) (string, error) {
	pubKeyBytes, err := base64.StdEncoding.DecodeString(recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("decode public key: %w", err)
	}
	if len(pubKeyBytes) != 32 {
		return "", errors.New("invalid public key length")
	}

	var recipientPubKey [32]byte
	copy(recipientPubKey[:], pubKeyBytes)

	// Generate ephemeral keypair for this encryption
	ephemeralPubKey, ephemeralPrivKey, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Generate random nonce
	var nonce [24]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	// Seal the plaintext
	// Output format: ephemeral_pubkey (32) + nonce (24) + ciphertext
	sealed := box.Seal(nil, plaintext, &nonce, &recipientPubKey, ephemeralPrivKey)

	// Prepend ephemeral public key and nonce
	result := make([]byte, 32+24+len(sealed))
	copy(result[:32], ephemeralPubKey[:])
	copy(result[32:56], nonce[:])
	copy(result[56:], sealed)

	return base64.StdEncoding.EncodeToString(result), nil
}

// X25519Open decrypts ciphertext using the recipient's private key
func X25519Open(ciphertext string, privateKey string) ([]byte, error) {
	privKeyBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privKeyBytes) != 32 {
		return nil, errors.New("invalid private key length")
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}

	// Minimum length: ephemeral_pubkey (32) + nonce (24) + auth_tag (16)
	if len(ciphertextBytes) < 32+24+16 {
		return nil, errors.New("ciphertext too short")
	}

	// Extract components
	var senderPubKey [32]byte
	var nonce [24]byte
	var recipientPrivKey [32]byte

	copy(senderPubKey[:], ciphertextBytes[:32])
	copy(nonce[:], ciphertextBytes[32:56])
	copy(recipientPrivKey[:], privKeyBytes)

	sealed := ciphertextBytes[56:]

	// Open the box
	plaintext, ok := box.Open(nil, sealed, &nonce, &senderPubKey, &recipientPrivKey)
	if !ok {
		return nil, errors.New("decryption failed: ciphertext may be corrupted or encrypted with a different key")
	}

	return plaintext, nil
}

// Invite Code Functions

// GenerateInviteCode generates a random invite code with high entropy.
// Format: XXXX-XXXX-XXXX-XXXX (16 characters = ~80 bits from base32)
// Uses 12 bytes of random data for 96 bits of input entropy.
func GenerateInviteCode() (string, error) {
	// Generate 12 random bytes (96 bits of entropy)
	bytes := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return "", err
	}

	// Encode to base32
	encoded := encodeBase32(bytes)
	// Remove dashes and take first 16 characters
	clean := ""
	for _, c := range encoded {
		if c != '-' {
			clean += string(c)
		}
		if len(clean) >= 16 {
			break
		}
	}

	// Ensure we have exactly 16 characters
	if len(clean) < 16 {
		return "", fmt.Errorf("failed to generate invite code: insufficient characters")
	}

	// Format as XXXX-XXXX-XXXX-XXXX
	return clean[:4] + "-" + clean[4:8] + "-" + clean[8:12] + "-" + clean[12:16], nil
}

// DeriveInviteKey derives an encryption key from email code and invite code
// Uses Argon2id with the provided salt
func DeriveInviteKey(emailCode, inviteCode string, salt []byte) []byte {
	combined := emailCode + ":" + inviteCode
	return argon2.IDKey(
		[]byte(combined),
		salt,
		argonTime,
		argonMemory,
		argonThreads,
		keyLength,
	)
}

// HashCode computes SHA256 hash of a code and returns hex-encoded string
func HashCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}
