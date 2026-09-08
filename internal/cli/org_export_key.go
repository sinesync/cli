package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sinesync/cli/internal/orgkey"
)

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

	file, err := orgkey.Build(orgInfo.OrgID, keys.publicKey, keys.privateKey, string(passphrase))
	if err != nil {
		return err
	}

	if err := orgkey.Write(out, file); err != nil {
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
