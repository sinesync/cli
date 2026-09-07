package cli

import (
	"fmt"
	"io"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/srp"
	"github.com/sinesync/cli/internal/vaultroute"
)

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Manage your sine~sync account",
	Args:  cobra.NoArgs,
}

func init() {
	accountCmd.AddCommand(accountChangePasswordCmd)
}

var accountChangePasswordCmd = &cobra.Command{
	Use:   "change-password",
	Short: "Change your account password",
	Long: `Change the password for your sine~sync account.

Your password protects the key that everything else is encrypted with, so
changing it re-encrypts your private key and every vault key on this device.
The server never sees any of it.

Changing your password signs out every other device.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runChangePassword(defaultPasswordChangeDeps(cmd.OutOrStdout()))
	},
}

// passwordChangeDeps is everything the flow reaches outside itself.
//
// All of it is injected for one reason: a test for this command must never
// prompt on a real terminal, talk to a real server, or touch the developer's
// keychain — and the ordering it enforces (nothing local changes until the
// server has confirmed) is only worth asserting if it can be asserted.
type passwordChangeDeps struct {
	out          io.Writer
	readPassword func(prompt string) ([]byte, error)

	apiBase    func() string
	authConfig func() (*AuthConfig, error)
	authToken  func() (string, error)
	secretKey  func() (string, error)
	userSalt   func() ([]byte, error)
	loadVaults func() (*vaultroute.Config, error)

	fetchEncryptedPrivateKey func(token string) (string, error)
	requestSRPChallenge      func(apiBase, email, password string) (*srpChallenge, error)
	postPasswordChange       func(token string, payload *changePasswordPayload) (*changePasswordResult, error)

	// commit is the only step that changes anything on this device, and it
	// cannot be reached without a confirmed server result.
	commit func(newDerivedKey []byte, result *changePasswordResult, cfg *vaultroute.Config) error
}

func defaultPasswordChangeDeps(out io.Writer) passwordChangeDeps {
	return passwordChangeDeps{
		out: out,
		readPassword: func(prompt string) ([]byte, error) {
			return promptPassword(out, prompt)
		},

		apiBase:    getAPIBase,
		authConfig: loadAuthConfig,
		authToken:  getAuthToken,
		secretKey:  keychain.GetSecretKey,
		userSalt:   keychain.GetUserSalt,
		loadVaults: vaultroute.Load,

		fetchEncryptedPrivateKey: fetchEncryptedPrivateKey,
		requestSRPChallenge:      requestSRPChallenge,
		postPasswordChange:       postPasswordChange,

		commit: func(newDerivedKey []byte, result *changePasswordResult, cfg *vaultroute.Config) error {
			return commitPasswordChange(newPasswordChangeStore(), newDerivedKey, result, cfg)
		},
	}
}

// promptPassword reads a password from the terminal without echoing it,
// writing the prompt to out rather than to global stdout so a caller can see
// what was asked.
func promptPassword(out io.Writer, prompt string) ([]byte, error) {
	return promptPasswordFrom(out, int(syscall.Stdin), prompt)
}

// promptPasswordFrom is promptPassword with the descriptor named, so a test can
// prompt against something that is not this process's terminal.
func promptPasswordFrom(out io.Writer, fd int, prompt string) ([]byte, error) {
	fmt.Fprint(out, prompt)
	password, err := term.ReadPassword(fd)
	// The newline the user's own (unechoed) Return did not produce. It belongs
	// after the read either way, so the next line does not run into the prompt.
	fmt.Fprintln(out)
	if err != nil {
		zeroBytes(password)
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	return password, nil
}

func runChangePassword(deps passwordChangeDeps) error {
	authCfg, err := deps.authConfig()
	if err != nil || authCfg == nil {
		return fmt.Errorf("not logged in — run 'sinesync login' first")
	}
	// Refused before anything is typed or sent: an SSO account has no password
	// here to change, and its key is not derived from one, so going through the
	// motions would end in a server rejection at best.
	if authCfg.AuthMethod == "saml" {
		return fmt.Errorf("this account signs in with SSO — change your password with your identity provider")
	}
	if authCfg.Email == "" {
		return fmt.Errorf("no account email is stored — run 'sinesync login' first")
	}

	token, err := deps.authToken()
	if err != nil {
		return err
	}

	// Each buffer is wiped on every path out of this function, including the
	// one where the read itself failed and still handed back bytes.
	currentBytes, err := deps.readPassword("Current password: ")
	defer zeroBytes(currentBytes)
	if err != nil {
		return err
	}
	if len(currentBytes) == 0 {
		return fmt.Errorf("current password is required")
	}

	newBytes, err := deps.readPassword("New password: ")
	defer zeroBytes(newBytes)
	if err != nil {
		return err
	}
	if len(newBytes) == 0 {
		return fmt.Errorf("new password is required")
	}

	confirmBytes, err := deps.readPassword("Confirm new password: ")
	defer zeroBytes(confirmBytes)
	if err != nil {
		return err
	}
	if string(confirmBytes) != string(newBytes) {
		return fmt.Errorf("passwords do not match")
	}

	// The secret key and salt do not change: the password is only one half of
	// what the master key is derived from, and the other half stays put.
	secretKey, err := deps.secretKey()
	if err != nil {
		return fmt.Errorf("could not read this device's secret key: %w", err)
	}
	salt, err := deps.userSalt()
	if err != nil {
		return fmt.Errorf("could not read this device's encryption salt: %w", err)
	}

	oldKey := crypto.DeriveKey(string(currentBytes), secretKey, salt)
	defer zeroBytes(oldKey)
	newKey := crypto.DeriveKey(string(newBytes), secretKey, salt)
	defer zeroBytes(newKey)

	oldMgr, newMgr := encryption.NewManager(), encryption.NewManager()
	if err := oldMgr.SetKeyInMemory(oldKey); err != nil {
		return err
	}
	if err := newMgr.SetKeyInMemory(newKey); err != nil {
		return err
	}

	vaults, err := deps.loadVaults()
	if err != nil {
		return fmt.Errorf("could not read the local vault configuration: %w", err)
	}

	encryptedPrivateKey, err := deps.fetchEncryptedPrivateKey(token)
	if err != nil {
		return err
	}

	// Proof of the current password, from the same exchange login uses.
	challenge, err := deps.requestSRPChallenge(deps.apiBase(), authCfg.Email, string(currentBytes))
	if err != nil {
		return err
	}

	// The new verifier. The server stores it and never learns the password it
	// came from.
	newSRPSalt, newVerifier := srp.NewClient(authCfg.Email, string(newBytes)).ComputeVerifier()

	payload, newVaults, err := rewrapForNewPassword(oldMgr, newMgr, encryptedPrivateKey, vaults)
	if err != nil {
		// Everything the old key opens fails together, and by far the likeliest
		// reason is a mistyped current password. Nothing has changed anywhere.
		return fmt.Errorf("%w\n\nIf your current password is correct, this device's key material is unreadable and no password change can proceed", err)
	}
	payload.ClientPublic = challenge.clientPublic
	payload.ClientProof = challenge.clientProof
	payload.SRPSalt = newSRPSalt
	payload.SRPVerifier = newVerifier

	fmt.Fprintln(deps.out, "Changing your password...")

	result, err := deps.postPasswordChange(token, payload)
	if err != nil {
		return err
	}

	// Confirmed. Only now does anything on this device change.
	if err := deps.commit(newKey, result, newVaults); err != nil {
		return err
	}

	fmt.Fprintf(deps.out, "\n✓ Password changed. %d vault key(s) re-encrypted.\n", len(payload.VaultKeys))
	fmt.Fprintln(deps.out, "  Every other device has been signed out — sign in there again with the new password.")
	return nil
}
