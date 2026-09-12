package orgkey

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/owneronly"
)

// The credentials file a self-hosted export daemon reads (#104).
//
// Modelled on 1Password Connect: a file downloaded once at setup carries the
// decryption capability, and a separately issued service account token carries
// API access. Neither is useful alone, and the token can be revoked without
// touching the file.
//
// Unlike Connect's, this file is passphrase-encrypted. Connect relies on
// filesystem secrecy; here a leaked file would expose every org vault
// retroactively until the org key is rotated, so the operator supplies a
// passphrase to the daemon out of band. Storing the key alongside its own
// ciphertext would be obfuscation rather than encryption, so it is a real
// passphrase or nothing.
const Version = 1

// Bound into the AEAD so a file cannot be presented as another org's: an
// attacker who swaps ciphertexts between two exports gets a decryption failure
// rather than a key that opens the wrong vaults.
func aad(orgID string) string {
	return fmt.Sprintf("sinesync-org-key-export:v%d:%s", Version, orgID)
}

type KDF struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
}

type File struct {
	Version int    `json:"version"`
	OrgID   string `json:"orgId"`
	// Recorded so the daemon can verify what it decrypted is the key it expects,
	// rather than trusting whatever the file happens to contain.
	OrgPublicKey           string `json:"orgPublicKey"`
	KDF                    KDF    `json:"kdf"`
	EncryptedOrgPrivateKey string `json:"encryptedOrgPrivateKey"`
	CreatedAt              string `json:"createdAt"`
}

// Build encrypts an org private key under a passphrase.
//
// Separated from the command so the format can be tested without a session, a
// server, or a terminal.
func Build(orgID, orgPublicKey string, orgPrivateKey []byte, passphrase string) (*File, error) {
	if orgID == "" {
		return nil, fmt.Errorf("org id is required")
	}
	if len(orgPrivateKey) == 0 {
		return nil, fmt.Errorf("org private key is empty")
	}
	if passphrase == "" {
		return nil, fmt.Errorf("passphrase is required")
	}

	salt, err := crypto.GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// No secret key here: the passphrase is the only secret, so it takes the
	// whole burden and the second argument stays empty by design.
	fileKey := crypto.DeriveKey(passphrase, "", salt)
	defer zeroBytes(fileKey)

	ciphertext, err := crypto.Encrypt(orgPrivateKey, fileKey, aad(orgID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt org private key: %w", err)
	}

	return &File{
		Version:                Version,
		OrgID:                  orgID,
		OrgPublicKey:           orgPublicKey,
		KDF:                    KDF{Algorithm: "argon2id", Salt: base64.StdEncoding.EncodeToString(salt)},
		EncryptedOrgPrivateKey: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:              time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// Open is the daemon's side of the format. It lives here so the two
// halves cannot drift apart, and so a round trip is testable.
func Open(file *File, passphrase string) ([]byte, error) {
	if file.Version != Version {
		return nil, fmt.Errorf("unsupported credentials file version %d (expected %d)", file.Version, Version)
	}

	salt, err := base64.StdEncoding.DecodeString(file.KDF.Salt)
	if err != nil {
		return nil, fmt.Errorf("credentials file has an unreadable salt: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(file.EncryptedOrgPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("credentials file has an unreadable key: %w", err)
	}

	fileKey := crypto.DeriveKey(passphrase, "", salt)
	defer zeroBytes(fileKey)

	plaintext, err := crypto.Decrypt(ciphertext, fileKey, aad(file.OrgID))
	if err != nil {
		// Wrong passphrase and a tampered file are the same answer on purpose:
		// distinguishing them tells an attacker which one they got right.
		return nil, fmt.Errorf("could not decrypt the credentials file — wrong passphrase, or the file has been altered")
	}

	// The file says which public key this private key belongs to. If they
	// disagree, the file has been assembled from parts.
	if file.OrgPublicKey != "" {
		derived, err := crypto.PublicKeyFromPrivate(string(plaintext))
		if err != nil {
			zeroBytes(plaintext)
			return nil, fmt.Errorf("the credentials file does not contain a usable key: %w", err)
		}
		if derived != file.OrgPublicKey {
			zeroBytes(plaintext)
			return nil, fmt.Errorf(
				"the credentials file's key does not match the public key it names (names %s, contains %s)",
				file.OrgPublicKey, derived)
		}
	}

	return plaintext, nil
}

// Write writes the file readable only by its owner. A credentials
// file left world-readable would undo the passphrase.
func Write(path string, file *File) error {
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials file: %w", err)
	}

	// O_EXCL: refuse to overwrite. Silently replacing an existing credentials
	// file would strand a deployed daemon on a key nobody has any more.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		// 0o600 is the whole story on unix and none of it on Windows, where
		// Chmod moves the read-only bit and leaves the file readable by
		// everyone. This holds key material.
		if aerr := owneronly.Apply(path); aerr != nil {
			f.Close()
			os.Remove(path)
			return aerr
		}
	}
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists — move it aside first, or a deployed daemon may be relying on it", path)
		}
		return err
	}
	defer f.Close()

	if _, err := f.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return nil
}

// zeroBytes overwrites a buffer holding key material. Its own copy rather than
// the CLI's, so this package does not depend on the command layer it serves.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
