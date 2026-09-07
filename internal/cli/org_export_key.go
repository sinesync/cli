package cli

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sinesync/cli/internal/crypto"
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
const orgKeyExportVersion = 1

// Bound into the AEAD so a file cannot be presented as another org's: an
// attacker who swaps ciphertexts between two exports gets a decryption failure
// rather than a key that opens the wrong vaults.
func orgKeyExportAAD(orgID string) string {
	return fmt.Sprintf("sinesync-org-key-export:v%d:%s", orgKeyExportVersion, orgID)
}

type orgKeyExportKDF struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
}

type orgKeyExportFile struct {
	Version int    `json:"version"`
	OrgID   string `json:"orgId"`
	// Recorded so the daemon can verify what it decrypted is the key it expects,
	// rather than trusting whatever the file happens to contain.
	OrgPublicKey           string          `json:"orgPublicKey"`
	KDF                    orgKeyExportKDF `json:"kdf"`
	EncryptedOrgPrivateKey string          `json:"encryptedOrgPrivateKey"`
	CreatedAt              string          `json:"createdAt"`
}

// buildOrgKeyExport encrypts an org private key under a passphrase.
//
// Separated from the command so the format can be tested without a session, a
// server, or a terminal.
func buildOrgKeyExport(orgID, orgPublicKey string, orgPrivateKey []byte, passphrase string) (*orgKeyExportFile, error) {
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

	ciphertext, err := crypto.Encrypt(orgPrivateKey, fileKey, orgKeyExportAAD(orgID))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt org private key: %w", err)
	}

	return &orgKeyExportFile{
		Version:                orgKeyExportVersion,
		OrgID:                  orgID,
		OrgPublicKey:           orgPublicKey,
		KDF:                    orgKeyExportKDF{Algorithm: "argon2id", Salt: base64.StdEncoding.EncodeToString(salt)},
		EncryptedOrgPrivateKey: base64.StdEncoding.EncodeToString(ciphertext),
		CreatedAt:              time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// openOrgKeyExport is the daemon's side of the format. It lives here so the two
// halves cannot drift apart, and so a round trip is testable.
func openOrgKeyExport(file *orgKeyExportFile, passphrase string) ([]byte, error) {
	if file.Version != orgKeyExportVersion {
		return nil, fmt.Errorf("unsupported credentials file version %d (expected %d)", file.Version, orgKeyExportVersion)
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

	plaintext, err := crypto.Decrypt(ciphertext, fileKey, orgKeyExportAAD(file.OrgID))
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

// writeOrgKeyExport writes the file readable only by its owner. A credentials
// file left world-readable would undo the passphrase.
func writeOrgKeyExport(path string, file *orgKeyExportFile) error {
	encoded, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to encode credentials file: %w", err)
	}

	// O_EXCL: refuse to overwrite. Silently replacing an existing credentials
	// file would strand a deployed daemon on a key nobody has any more.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
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

func newOrgExportKeyCmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "export-key",
		Short: "Export the organization decryption key for a self-hosted export daemon",
		Long: "Writes a passphrase-encrypted credentials file containing the organization's\n" +
			"private key, for a self-hosted export daemon to decrypt observations locally.\n\n" +
			"The key is unwrapped on this machine and never sent anywhere. Pair the file with\n" +
			"a service account token, which is what grants API access and what you revoke if\n" +
			"the daemon is retired.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runOrgExportKey(cmd.OutOrStdout(), out)
		},
	}

	cmd.Flags().StringVar(&out, "out", "sinesync-org.key", "path to write the credentials file to")
	return cmd
}

func runOrgExportKey(w io.Writer, out string) error {
	if out == "" {
		return fmt.Errorf("--out is required")
	}
	// Checked before anything expensive or interactive, so an operator is not
	// asked for a passphrase only to be refused afterwards.
	if _, err := os.Stat(out); err == nil {
		return fmt.Errorf("%s already exists — move it aside first, or a deployed daemon may be relying on it", out)
	}

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	orgInfo, err := fetchUserOrgInfo(token)
	if err != nil || orgInfo == nil {
		return fmt.Errorf("you are not in an organization")
	}

	// Owners only. This file carries the whole org's decryption capability out
	// of our infrastructure, which is a narrower decision than admins make.
	if orgInfo.Role != "owner" {
		return fmt.Errorf("only the organization owner can export the decryption key (your role: %s)", orgInfo.Role)
	}

	// Unwrapped on this machine, from this owner's own key holder record. It is
	// never sent anywhere, which is what keeps the export zero-knowledge.
	keys, err := ensureOrgKeypair(token, orgInfo, nil)
	if err != nil {
		return err
	}
	defer keys.zero()

	passphrase, err := promptNewPassphrase(w)
	if err != nil {
		return err
	}
	defer zeroBytes(passphrase)

	file, err := buildOrgKeyExport(orgInfo.OrgID, keys.publicKey, keys.privateKey, string(passphrase))
	if err != nil {
		return err
	}

	if err := writeOrgKeyExport(out, file); err != nil {
		return err
	}

	fmt.Fprintf(w, "Wrote %s\n\n", out)
	fmt.Fprintf(w, "  Organization: %s\n", orgInfo.OrgID)
	fmt.Fprintf(w, "  Public key:   %s\n\n", keys.publicKey)
	fmt.Fprintln(w, "Keep this file and its passphrase apart. The file alone cannot be read,")
	fmt.Fprintln(w, "and neither can be recovered from us — the key was never sent to our servers.")
	fmt.Fprintln(w, "Pair it with a service account token, which is what you revoke to cut off")
	fmt.Fprintln(w, "a daemon without rotating the organization key.")
	return nil
}

// promptNewPassphrase asks twice and refuses a mismatch, because a typo here is
// only discovered when the daemon cannot start, by which time the file is the
// only copy.
func promptNewPassphrase(w io.Writer) ([]byte, error) {
	first, err := promptPassword(w, "Passphrase for the credentials file: ")
	if err != nil {
		return nil, err
	}

	second, err := promptPassword(w, "Confirm passphrase: ")
	if err != nil {
		zeroBytes(first)
		return nil, err
	}
	defer zeroBytes(second)

	if string(first) != string(second) {
		zeroBytes(first)
		return nil, fmt.Errorf("passphrases do not match")
	}
	if len(first) == 0 {
		return nil, fmt.Errorf("passphrase is required")
	}

	return first, nil
}
