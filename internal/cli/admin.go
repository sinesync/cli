package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Organization admin commands",
	Long: `Manage org encryption, provision members, and reset member access.
These commands require admin or owner role in an organization.`,
}

var adminProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Provision vault keys for pending org members",
	Long: `Initialize org encryption and provision vault keys for pending members.

This is an admin-only command that:
  1. Initializes the org keypair (if not yet done)
  2. Generates vault keys for any vaults without them
  3. Provisions pending members with their encrypted vault keys

Requires you to be present. Steps 1 and 3 seal key material to public keys the
server hands over, so for each member and each admin you will be asked to type
back the fingerprint they read out from their own machine. Anything you do not
confirm is not sealed and not uploaded, which means this cannot run unattended:
with no one to answer the prompts it will provision nobody.

Example:
  sinesync admin provision                    # Provision all pending members`,
	RunE: runAdminProvision,
}

var adminResetKeysCmd = &cobra.Command{
	Use:   "reset-keys",
	Short: "Reset org encryption keys (recovery after admin loss)",
	Long: `Reset the org keypair and all vault encryption keys.

Use this when the admin who initialized encryption is no longer available.
After reset, run 'sinesync admin provision' to re-initialize.

WARNING: This clears all encrypted vault keys and member access records.
Members will need to be re-provisioned after the reset.`,
	RunE: runAdminResetKeys,
}

var adminResetMemberCmd = &cobra.Command{
	Use:   "reset-member <email>",
	Short: "Reset a member's encryption state (admin only)",
	Long: `Reset a member's SSO encryption state so they can re-bootstrap.

This clears the member's encryption keys, credential bundles, and vault access records.
The member will need to log in again and set up encryption from scratch.

Use this when a member has lost their account key or is locked out of their account.

Examples:
  sinesync admin reset-member alice@example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runAdminResetMember,
}

func init() {
	rootCmd.AddCommand(adminCmd)
	adminCmd.AddCommand(adminProvisionCmd)
	adminCmd.AddCommand(adminResetKeysCmd)
	adminCmd.AddCommand(adminResetMemberCmd)
}

func runAdminResetKeys(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	orgInfo, err := fetchUserOrgInfo(token)
	if err != nil || orgInfo == nil {
		return fmt.Errorf("you are not in an organization")
	}

	isAdmin := orgInfo.Role == "admin" || orgInfo.Role == "owner"
	if !isAdmin {
		return fmt.Errorf("only admins can reset org keys (your role: %s)", orgInfo.Role)
	}

	fmt.Println("WARNING: This will reset encryption for ALL org vaults.")
	fmt.Println()
	fmt.Println("  What will be cleared:")
	fmt.Println("    - Org keypair")
	fmt.Println("    - Encrypted keys for ALL org vaults")
	fmt.Println("    - ALL member vault access records")
	fmt.Println()
	fmt.Println("  After reset, run 'sinesync admin provision' to re-initialize everything.")
	fmt.Println("  Members will not be able to sync org vaults until re-provisioned.")
	fmt.Println()
	fmt.Print("Type 'RESET' to confirm: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	if strings.TrimSpace(input) != "RESET" {
		fmt.Println("Aborted.")
		return nil
	}

	if err := resetOrgKeypair(token, orgInfo.OrgID); err != nil {
		return fmt.Errorf("failed to reset org keys: %w", err)
	}

	fmt.Println()
	fmt.Println("✓ Org encryption keys have been reset")
	fmt.Println("  Run 'sinesync admin provision' to re-initialize encryption")

	return nil
}

func runAdminResetMember(cmd *cobra.Command, args []string) error {
	email := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	orgInfo, err := fetchUserOrgInfo(token)
	if err != nil || orgInfo == nil {
		return fmt.Errorf("you are not in an organization")
	}

	isAdmin := orgInfo.Role == "admin" || orgInfo.Role == "owner"
	if !isAdmin {
		return fmt.Errorf("only admins can reset member encryption (your role: %s)", orgInfo.Role)
	}

	// Look up user by email
	members, err := fetchOrgMembers(token, orgInfo.OrgID)
	if err != nil {
		return fmt.Errorf("failed to list org members: %w", err)
	}

	var targetUserID string
	for _, m := range members {
		if strings.EqualFold(m.Email, email) {
			targetUserID = m.UserID
			break
		}
	}
	if targetUserID == "" {
		return fmt.Errorf("no org member found with email: %s", email)
	}

	fmt.Printf("Reset encryption for %s?\n", email)
	fmt.Println("This will clear their encryption keys and vault access.")
	fmt.Println("They will need to log in again and re-bootstrap encryption.")
	fmt.Println()
	fmt.Print("Type 'RESET' to confirm: ")
	input, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}
	if strings.TrimSpace(input) != "RESET" {
		fmt.Println("Aborted.")
		return nil
	}

	if err := resetMemberEncryption(token, orgInfo.OrgID, targetUserID); err != nil {
		return fmt.Errorf("failed to reset member encryption: %w", err)
	}

	fmt.Println()
	fmt.Printf("✓ Encryption reset for %s\n", email)
	fmt.Println("  They can now log in and set up encryption again.")
	fmt.Println("  Run 'sinesync admin provision' afterwards to re-provision their vault access.")

	return nil
}

// errRecipientNotConfirmed means the operator did not confirm, out of band, that
// a server-supplied public key belongs to the person it is attributed to.
//
// Not an error condition in the usual sense — nothing failed. It is a refusal,
// and the only correct response to it is to seal nothing for that recipient.
var errRecipientNotConfirmed = errors.New("recipient key not confirmed")

// confirmRecipientKey makes the operator verify a public key the SERVER chose
// before anything is sealed to it.
//
// Provisioning takes the recipient's public key from the server's own listing:
// /org-key/pending for members, /org-key/admins-pending for admins. Whoever
// controls that response controls who the vault keys — and, for an admin, the
// org private key itself — end up readable by. The admin running this command
// sees a normal successful provision either way, and the member gets working
// access either way, because the attacker's key is a perfectly valid key. There
// is no later point at which this is caught.
//
// So the key has to be checked against something the server does not control,
// and the only such thing available is the person on the other end reading their
// own fingerprint off their own machine. That makes provisioning interactive; it
// is not possible to both provision unattended and know who you are provisioning
// to.
//
// The expected fingerprint is never printed before the prompt — see
// confirmFingerprintByTyping for why showing it first would hollow out the check.
func confirmRecipientKey(w io.Writer, r *bufio.Reader, who, publicKey, sealing string) error {
	fingerprint, err := crypto.KeyFingerprint(publicKey)
	if err != nil {
		// A key that will not even fingerprint cannot be confirmed by anyone, so
		// there is nothing to prompt about. Fail closed rather than fall through
		// to sealing something to it.
		return fmt.Errorf("the server sent an unusable public key for %s (%w); refusing to seal %s to it", who, err, sealing)
	}

	ok := confirmFingerprintByTyping(w, r, fingerprint, fingerprintPromptText{
		intro: []string{
			"",
			fmt.Sprintf("About to seal %s to the key this server holds for %s.", sealing, who),
			"Ask them to run 'sinesync vault pending' and read out the fingerprint it prints.",
			"Use a channel that is not this server — a phone call, in person.",
			"Then type it in exactly as they read it. Case, dashes and spaces do not matter.",
		},
		label:    "Fingerprint they read out: ",
		declined: []string{fmt.Sprintf("Not confirmed. Nothing was sealed for %s.", who)},
		mismatchHint: []string{
			"A fingerprint that does not match means the public key this server listed for them",
			"is not the one on their machine. Do not retry until you know why.",
		},
	})
	if !ok {
		return errRecipientNotConfirmed
	}
	return nil
}

// sealOrgPrivateKeyToSelf seals a freshly generated org private key to the
// admin running this command, using a public key derived from the private key
// they hold locally.
//
// This is the whole org's escrow, so the recipient has to be chosen locally.
// Asking the server who to seal to (GET /users/keypair's publicKey) let a
// malicious or compromised server answer with a key of its own choosing: the
// admin would upload an org private key sealed to the attacker, the server would
// hold the ciphertext, and every vault key derived from that org keypair would be
// readable by whoever supplied the substituted key. Nothing downstream would look
// wrong — provisioning succeeds, members get access, the admin sees no error.
// Deriving the public key from the admin's own private key removes the server's
// say in it: that private key is stored encrypted to the admin's master key, so a
// substituted one does not decrypt and this fails loudly instead.
func sealOrgPrivateKeyToSelf(token, orgPrivateKey string) (string, error) {
	adminPubKey, err := ownPublicKey(token)
	if err != nil {
		return "", fmt.Errorf("cannot derive your own public key to seal the org private key to: %w", err)
	}

	sealed, err := crypto.X25519Seal([]byte(orgPrivateKey), adminPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt org private key: %w", err)
	}
	return sealed, nil
}

// orgKeypair is the org keypair as this machine can actually verify it: a
// private key this admin opened for themselves, and the public key DERIVED from
// that private key.
//
// The distinction is the whole point of the type. The server also advertises an
// org public key, in two places, and sealing to that one means sealing to
// whatever it says — the vault key would encrypt to a key the server holds and
// every member provisioned from it inherits the compromise. A public key derived
// from a private key that decrypted under this admin's own master key cannot be
// chosen by the server.
type orgKeypair struct {
	publicKey  string
	privateKey []byte
}

func (k *orgKeypair) zero() {
	if k != nil {
		zeroBytes(k.privateKey)
	}
}

// ensureOrgKeypair returns the org keypair for this run, loading it on first use
// and reusing it afterwards.
//
// Loading means: decrypt this admin's own private key, use it to open the org
// private key from their key holder record, and derive the org public key from
// what came out. The derived key is then checked against both places the server
// advertises one, and a disagreement is fatal rather than a warning — if the
// server is publishing a public key that does not belong to the org private key
// the admin holds, then either the org keypair has been rotated out from under
// this record or someone is trying to have new key material sealed to a key of
// their choosing. Neither is a state to keep provisioning in.
func ensureOrgKeypair(token string, orgInfo *OrgInfo, cached *orgKeypair) (*orgKeypair, error) {
	if cached != nil {
		return cached, nil
	}

	adminPrivKey, err := fetchAndDecryptPrivateKey(token)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt admin private key: %w", err)
	}

	orgKey, err := fetchOrgKey(token, orgInfo.OrgID)
	if err != nil || orgKey == nil || orgKey.KeyHolder == nil {
		return nil, fmt.Errorf("org key holder not found — keypair may not be initialized")
	}

	privateKey, err := crypto.X25519Open(orgKey.KeyHolder.EncryptedOrgPrivateKey, adminPrivKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt org private key: %w", err)
	}

	publicKey, err := crypto.PublicKeyFromPrivate(string(privateKey))
	if err != nil {
		zeroBytes(privateKey)
		return nil, fmt.Errorf("the org private key stored for you is not a usable key (%w)", err)
	}

	for _, advertised := range []struct{ where, key string }{
		{"your org info", orgInfo.OrgPublicKey},
		{"the org key record", orgKey.OrgPublicKey},
	} {
		if advertised.key == "" || advertised.key == publicKey {
			continue
		}
		zeroBytes(privateKey)
		return nil, fmt.Errorf(
			"the org public key in %s does not belong to the org private key you hold — "+
				"refusing to seal anything until you know why (advertised %s, yours %s)",
			advertised.where, advertised.key, publicKey)
	}

	return &orgKeypair{publicKey: publicKey, privateKey: privateKey}, nil
}

// initMissingVaultKeys generates and uploads a key for every org vault that does
// not have one yet, sealed to the org public key this machine derived.
//
// It resolves the org keypair itself rather than taking a public key, because
// the two cannot be separated safely: a caller that already had a public key to
// hand would be free to pass the server's. Returns the keypair so the later
// provisioning steps reuse it instead of decrypting it a second time.
func initMissingVaultKeys(w io.Writer, token string, orgInfo *OrgInfo, orgVaults []OrgVaultResponse, keys *orgKeypair) (int, *orgKeypair, error) {
	needed := false
	for _, ov := range orgVaults {
		if ov.EncryptedVaultKey == "" {
			needed = true
			break
		}
	}
	if !needed {
		return 0, keys, nil
	}

	loaded, err := ensureOrgKeypair(token, orgInfo, keys)
	if err != nil {
		return 0, keys, err
	}
	keys = loaded

	initialized := 0
	for i, ov := range orgVaults {
		if ov.EncryptedVaultKey != "" {
			continue
		}

		vaultKey, err := crypto.GenerateKey(32)
		if err != nil {
			fmt.Fprintf(w, "  Warning: failed to generate vault key for %s: %v\n", ov.Name, err)
			continue
		}

		sealedKey, err := crypto.X25519Seal(vaultKey, keys.publicKey)
		zeroBytes(vaultKey)
		if err != nil {
			fmt.Fprintf(w, "  Warning: failed to seal vault key for %s: %v\n", ov.Name, err)
			continue
		}

		if err := updateOrgVaultKey(token, orgInfo.OrgID, ov.ID, sealedKey); err != nil {
			fmt.Fprintf(w, "  Warning: failed to set vault key for %s: %v\n", ov.Name, err)
			continue
		}

		orgVaults[i].EncryptedVaultKey = sealedKey
		initialized++
		fmt.Fprintf(w, "  ✓ Initialized vault key for %s\n", ov.Name)
	}

	return initialized, keys, nil
}

// provisionPendingMembers seals each pending member's vault keys to that
// member's key and submits the ones the operator confirmed.
//
// The confirmation is per recipient and happens BEFORE anything is sealed for
// them, so a refusal costs no ciphertext: an unconfirmed member contributes
// nothing to the batch, and if nobody is confirmed the upload does not happen at
// all. Returns how many members were provisioned and how many were refused.
func provisionPendingMembers(w io.Writer, r *bufio.Reader, token, orgID string, pending []PendingProvision, orgVaults []OrgVaultResponse, orgPrivKey string) (provisioned, unconfirmed int, err error) {
	fmt.Fprintf(w, "  Provisioning %d pending members...\n", len(pending))

	var provisions []map[string]interface{}

	for _, p := range pending {
		who := recipientName(p.UserID)

		// One prompt per recipient, ahead of any sealing for them.
		if err := confirmRecipientKey(w, r, who, p.PublicKey, "this org's vault keys"); err != nil {
			if errors.Is(err, errRecipientNotConfirmed) {
				unconfirmed++
				continue
			}
			// An unusable key is also a refusal to seal, just one nobody could
			// have confirmed. Report it and move on to the next member.
			fmt.Fprintf(w, "  %v\n", err)
			unconfirmed++
			continue
		}

		var memberVaults []map[string]interface{}
		for _, vaultID := range p.VaultIDs {
			// Find vault's encrypted key
			var vaultEncKey string
			for _, ov := range orgVaults {
				if ov.ID == vaultID {
					vaultEncKey = ov.EncryptedVaultKey
					break
				}
			}

			if vaultEncKey == "" {
				continue
			}

			// Decrypt vault key using org private key
			vaultKeyBytes, err := crypto.X25519Open(vaultEncKey, orgPrivKey)
			if err != nil {
				fmt.Fprintf(w, "  Warning: failed to decrypt vault key for %s: %v\n", vaultID, err)
				continue
			}

			// Seal vault key for the member's confirmed public key
			sealedKey, err := crypto.X25519Seal(vaultKeyBytes, p.PublicKey)
			zeroBytes(vaultKeyBytes)
			if err != nil {
				fmt.Fprintf(w, "  Warning: failed to seal key for user %s: %v\n", p.UserID, err)
				continue
			}

			memberVaults = append(memberVaults, map[string]interface{}{
				"vaultId":           vaultID,
				"encryptedVaultKey": sealedKey,
				"role":              "editor",
			})
		}

		if len(memberVaults) > 0 {
			provisions = append(provisions, map[string]interface{}{
				"userId": p.UserID,
				"vaults": memberVaults,
			})
		}
	}

	if len(provisions) == 0 {
		return 0, unconfirmed, nil
	}

	if err := submitProvisions(token, orgID, provisions); err != nil {
		return 0, unconfirmed, fmt.Errorf("failed to submit provisions: %w", err)
	}
	return len(provisions), unconfirmed, nil
}

// distributeOrgKeyToAdmins seals the org private key to each pending admin the
// operator confirms.
//
// This is the highest-value seal in the product: the org private key opens every
// vault key in the organization, so a substituted admin key here is not a
// per-member breach but a whole-org one. Same shape as the member path — confirm
// first, seal only what was confirmed, upload nothing if nothing was.
func distributeOrgKeyToAdmins(w io.Writer, r *bufio.Reader, token, orgID string, admins []AdminPendingHolder, orgPrivKey []byte) (distributed, unconfirmed int, err error) {
	fmt.Fprintf(w, "  Distributing org key to %d admin(s)...\n", len(admins))

	var holders []map[string]string
	for _, admin := range admins {
		who := recipientName(admin.UserID)

		if err := confirmRecipientKey(w, r, who, admin.PublicKey, "the org private key"); err != nil {
			if !errors.Is(err, errRecipientNotConfirmed) {
				fmt.Fprintf(w, "  %v\n", err)
			}
			unconfirmed++
			continue
		}

		sealed, err := crypto.X25519Seal(orgPrivKey, admin.PublicKey)
		if err != nil {
			fmt.Fprintf(w, "  Warning: failed to seal org key for admin %s: %v\n", admin.UserID, err)
			continue
		}
		holders = append(holders, map[string]string{
			"userId":                 admin.UserID,
			"encryptedOrgPrivateKey": sealed,
		})
	}

	if len(holders) == 0 {
		return 0, unconfirmed, nil
	}

	if err := submitKeyHolders(token, orgID, holders); err != nil {
		return 0, unconfirmed, fmt.Errorf("failed to submit key holders: %w", err)
	}
	return len(holders), unconfirmed, nil
}

// recipientName is how a provisioning recipient is named in the prompt.
//
// The listing endpoints return a user ID and nothing else, so that is what the
// operator gets. It is a poor label for a human — the admin has to know whose ID
// this is before they can phone them — but inventing a friendlier one is not
// available here, and a label is not what the check rests on: the fingerprint
// comes from the person, out of band, and disagrees no matter what the server
// called them.
func recipientName(userID string) string {
	return "user " + userID
}

func runAdminProvision(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// Fetch org info and verify admin
	orgInfo, err := fetchUserOrgInfo(token)
	if err != nil || orgInfo == nil {
		return fmt.Errorf("you are not in an organization")
	}

	isAdmin := orgInfo.Role == "admin" || orgInfo.Role == "owner"
	if !isAdmin {
		return fmt.Errorf("only admins can provision org vault keys (your role: %s)", orgInfo.Role)
	}

	fmt.Println("Provisioning org vault keys...")

	// One reader for the whole command. Each recipient is confirmed at its own
	// prompt, but a second bufio.Reader over the same os.Stdin would discard
	// whatever the first had already buffered — with several recipients that
	// silently eats typed input and turns a correct answer into a refusal.
	reader := bufio.NewReader(os.Stdin)

	var initKeypair, initVaultKeys, provisionedMembers int
	var unconfirmedMembers, unconfirmedAdmins int

	// The org private key, once this run has it. Loaded at most once, on the
	// first step that needs it, and held only for the length of the command.
	var orgKeys *orgKeypair
	defer func() { orgKeys.zero() }()

	// Step 1: Org keypair init (if no orgPublicKey)
	if orgInfo.OrgPublicKey == "" {
		fmt.Println("  Initializing org keypair...")

		pubKey, privKey, err := crypto.GenerateX25519Keypair()
		if err != nil {
			return fmt.Errorf("failed to generate org keypair: %w", err)
		}

		// Seal the org private key to this admin's own key, derived locally.
		encryptedOrgPrivKey, err := sealOrgPrivateKeyToSelf(token, privKey)
		if err != nil {
			return err
		}

		if err := initOrgKeypairAPI(token, orgInfo.OrgID, pubKey, encryptedOrgPrivKey); err != nil {
			return fmt.Errorf("failed to init org keypair: %w", err)
		}

		// Keep the pair that was just generated here. Nothing downstream then
		// has to ask the server what the org public key is, and re-deriving it
		// keeps the type's invariant true without exception: the public key in
		// an orgKeypair always comes from the private key beside it.
		derived, err := crypto.PublicKeyFromPrivate(privKey)
		if err != nil {
			return fmt.Errorf("generated an org private key that will not derive a public key: %w", err)
		}
		orgKeys = &orgKeypair{publicKey: derived, privateKey: []byte(privKey)}

		orgInfo.OrgPublicKey = pubKey
		initKeypair = 1
		fmt.Println("  ✓ Org keypair initialized")
	}

	// Step 2: Initialize vault keys for any vaults without them
	orgVaults, err := fetchOrgVaults(token, orgInfo.OrgID)
	if err != nil {
		return fmt.Errorf("failed to fetch org vaults: %w", err)
	}

	initVaultKeys, orgKeys, err = initMissingVaultKeys(os.Stdout, token, orgInfo, orgVaults, orgKeys)
	if err != nil {
		return err
	}

	// Check what needs the org private key
	pending, err := fetchPendingProvisions(token, orgInfo.OrgID)
	if err != nil {
		fmt.Printf("  Warning: failed to fetch pending provisions: %v\n", err)
		pending = nil
	}

	pendingAdmins, err := fetchAdminsPendingKeyHolders(token, orgInfo.OrgID)
	if err != nil {
		fmt.Printf("  Warning: failed to fetch pending admin holders: %v\n", err)
		pendingAdmins = nil
	}

	var distributedHolders int

	needOrgPrivKey := len(pending) > 0 || len(pendingAdmins) > 0
	if needOrgPrivKey {
		orgKeys, err = ensureOrgKeypair(token, orgInfo, orgKeys)
		if err != nil {
			return err
		}

		// Step 3: Provision pending members
		if len(pending) > 0 {
			provisionedMembers, unconfirmedMembers, err = provisionPendingMembers(
				os.Stdout, reader, token, orgInfo.OrgID, pending, orgVaults, string(orgKeys.privateKey))
			if err != nil {
				return err
			}
		}

		// Step 4: Distribute key holders to other admins
		if len(pendingAdmins) > 0 {
			distributedHolders, unconfirmedAdmins, err = distributeOrgKeyToAdmins(
				os.Stdout, reader, token, orgInfo.OrgID, pendingAdmins, orgKeys.privateKey)
			if err != nil {
				return err
			}
		}
	}

	// Summary
	fmt.Println()
	if initKeypair > 0 {
		fmt.Println("✓ Initialized org keypair")
	}
	if initVaultKeys > 0 {
		fmt.Printf("✓ Initialized %d vault key(s)\n", initVaultKeys)
	}
	if provisionedMembers > 0 {
		fmt.Printf("✓ Provisioned %d member(s)\n", provisionedMembers)
	}
	if distributedHolders > 0 {
		fmt.Printf("✓ Distributed org key to %d admin(s)\n", distributedHolders)
	}
	if initKeypair == 0 && initVaultKeys == 0 && provisionedMembers == 0 && distributedHolders == 0 &&
		unconfirmedMembers == 0 && unconfirmedAdmins == 0 {
		fmt.Println("✓ Nothing to provision — all members are up to date")
	}

	// A refused fingerprint is not a warning to scroll past. Reporting it in the
	// exit status means a wrapper script or a human who looked away still finds
	// out that someone was left unprovisioned, and why.
	if unconfirmed := unconfirmedMembers + unconfirmedAdmins; unconfirmed > 0 {
		fmt.Printf("✗ %d recipient(s) were not confirmed — nothing was sealed for them\n", unconfirmed)
		return fmt.Errorf("%d recipient(s) could not be confirmed; re-run once you know whose key the server is listing", unconfirmed)
	}

	return nil
}
