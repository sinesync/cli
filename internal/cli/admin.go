package cli

import (
	"bufio"
	"fmt"
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

Enterprises can run this on a schedule (e.g. cron) for automatic provisioning.

Examples:
  sinesync admin provision                    # Provision all pending members
  */5 * * * * sinesync admin provision        # Cron every 5 minutes`,
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

	var initKeypair, initVaultKeys, provisionedMembers int

	// Step 1: Org keypair init (if no orgPublicKey)
	if orgInfo.OrgPublicKey == "" {
		fmt.Println("  Initializing org keypair...")

		pubKey, privKey, err := crypto.GenerateX25519Keypair()
		if err != nil {
			return fmt.Errorf("failed to generate org keypair: %w", err)
		}

		// Fetch admin's public key to seal the org private key with X25519
		adminPubKey, err := fetchMyPublicKey(token)
		if err != nil {
			return fmt.Errorf("failed to fetch admin public key: %w", err)
		}

		encryptedOrgPrivKey, err := crypto.X25519Seal([]byte(privKey), adminPubKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt org private key: %w", err)
		}

		if err := initOrgKeypairAPI(token, orgInfo.OrgID, pubKey, encryptedOrgPrivKey); err != nil {
			return fmt.Errorf("failed to init org keypair: %w", err)
		}

		orgInfo.OrgPublicKey = pubKey
		initKeypair = 1
		fmt.Println("  ✓ Org keypair initialized")
	}

	// Step 2: Initialize vault keys for any vaults without them
	orgVaults, err := fetchOrgVaults(token, orgInfo.OrgID)
	if err != nil {
		return fmt.Errorf("failed to fetch org vaults: %w", err)
	}

	for i, ov := range orgVaults {
		if ov.EncryptedVaultKey == "" {
			vaultKey, err := crypto.GenerateKey(32)
			if err != nil {
				fmt.Printf("  Warning: failed to generate vault key for %s: %v\n", ov.Name, err)
				continue
			}

			sealedKey, err := crypto.X25519Seal(vaultKey, orgInfo.OrgPublicKey)
			zeroBytes(vaultKey)
			if err != nil {
				fmt.Printf("  Warning: failed to seal vault key for %s: %v\n", ov.Name, err)
				continue
			}

			if err := updateOrgVaultKey(token, orgInfo.OrgID, ov.ID, sealedKey); err != nil {
				fmt.Printf("  Warning: failed to set vault key for %s: %v\n", ov.Name, err)
				continue
			}

			orgVaults[i].EncryptedVaultKey = sealedKey
			initVaultKeys++
			fmt.Printf("  ✓ Initialized vault key for %s\n", ov.Name)
		}
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
		// Decrypt org private key using admin's X25519 private key
		adminPrivKey, err := fetchAndDecryptPrivateKey(token)
		if err != nil {
			return fmt.Errorf("failed to decrypt admin private key: %w", err)
		}

		orgKey, err := fetchOrgKey(token, orgInfo.OrgID)
		if err != nil || orgKey == nil || orgKey.KeyHolder == nil {
			return fmt.Errorf("org key holder not found — keypair may not be initialized")
		}

		orgPrivKeyBytes, err := crypto.X25519Open(orgKey.KeyHolder.EncryptedOrgPrivateKey, adminPrivKey)
		if err != nil {
			return fmt.Errorf("failed to decrypt org private key: %w", err)
		}
		defer zeroBytes(orgPrivKeyBytes)
		orgPrivKey := string(orgPrivKeyBytes)

		// Step 3: Provision pending members
		if len(pending) > 0 {
			fmt.Printf("  Provisioning %d pending members...\n", len(pending))

			var provisions []map[string]interface{}

			for _, p := range pending {
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
						fmt.Printf("  Warning: failed to decrypt vault key for %s: %v\n", vaultID, err)
						continue
					}

					// Seal vault key for the member's public key
					sealedKey, err := crypto.X25519Seal(vaultKeyBytes, p.PublicKey)
					zeroBytes(vaultKeyBytes)
					if err != nil {
						fmt.Printf("  Warning: failed to seal key for user %s: %v\n", p.UserID, err)
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

			if len(provisions) > 0 {
				if err := submitProvisions(token, orgInfo.OrgID, provisions); err != nil {
					return fmt.Errorf("failed to submit provisions: %w", err)
				}
				provisionedMembers = len(provisions)
			}
		}

		// Step 4: Distribute key holders to other admins
		if len(pendingAdmins) > 0 {
			fmt.Printf("  Distributing org key to %d admin(s)...\n", len(pendingAdmins))

			var holders []map[string]string
			for _, admin := range pendingAdmins {
				sealed, err := crypto.X25519Seal(orgPrivKeyBytes, admin.PublicKey)
				if err != nil {
					fmt.Printf("  Warning: failed to seal org key for admin %s: %v\n", admin.UserID, err)
					continue
				}
				holders = append(holders, map[string]string{
					"userId":                admin.UserID,
					"encryptedOrgPrivateKey": sealed,
				})
			}

			if len(holders) > 0 {
				if err := submitKeyHolders(token, orgInfo.OrgID, holders); err != nil {
					return fmt.Errorf("failed to submit key holders: %w", err)
				}
				distributedHolders = len(holders)
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
	if initKeypair == 0 && initVaultKeys == 0 && provisionedMembers == 0 && distributedHolders == 0 {
		fmt.Println("✓ Nothing to provision — all members are up to date")
	}

	return nil
}
