package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/daemon"
	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/httputil"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/storage"
	"github.com/spf13/cobra"
)

// Vault types matching backend
type Vault struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	OwnerID   string `json:"ownerId"`
	IsDefault bool   `json:"isDefault"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type VaultWithRole struct {
	Vault
	Role        string `json:"role"`
	MemberCount int    `json:"memberCount"`
}

type VaultMember struct {
	ID                string `json:"id"`
	VaultID           string `json:"vaultId"`
	UserID            string `json:"userId"`
	EncryptedVaultKey string `json:"encryptedVaultKey"`
	Role              string `json:"role"`
	JoinedAt          string `json:"joinedAt"`
}

type VaultInvite struct {
	ID                      string `json:"id"`
	VaultID                 string `json:"vaultId"`
	InviterUserID           string `json:"inviterUserId"`
	InviteeEmail            string `json:"inviteeEmail"`
	InviteType              string `json:"inviteType"`
	EncryptedVaultKey       string `json:"encryptedVaultKey"`
	EncryptedTempPrivateKey string `json:"encryptedTempPrivateKey,omitempty"`
	Salt                    string `json:"salt,omitempty"`
	Status                  string `json:"status"`
	ExpiresAt               string `json:"expiresAt"`
	CreatedAt               string `json:"createdAt"`
	VaultName               string `json:"vaultName,omitempty"` // Enriched field
}

// Local vault config stored on device
type LocalVaultConfig struct {
	Vaults []LocalVault `json:"vaults"`
}

type LocalVault struct {
	VaultID           string   `json:"vaultId"`
	Name              string   `json:"name"`
	EncryptedVaultKey string   `json:"encryptedVaultKey"`
	Projects          []string `json:"projects"`
	IsDefault         bool     `json:"isDefault"`
	IsOrgVault        bool     `json:"isOrgVault,omitempty"`
	OrgID             string   `json:"orgId,omitempty"`
}

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage vaults",
	Long: `Vaults are encrypted containers for your AI memories.

By default, you have a "Personal" vault. You can create additional vaults
and assign projects to them. Shared vaults allow team collaboration.

Examples:
  sinesync vault list                          # List all vaults
  sinesync vault create "Work Projects"        # Create a new vault
  sinesync vault add-project <id> myproject    # Add project to vault
  sinesync vault sync                          # Sync vault keys from server`,
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List your vaults",
	RunE:  runVaultList,
}

var vaultCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a new vault",
	Args:  cobra.ExactArgs(1),
	RunE:  runVaultCreate,
}

var vaultDeleteCmd = &cobra.Command{
	Use:   "delete <vault-id>",
	Short: "Delete a vault",
	Args:  cobra.ExactArgs(1),
	RunE:  runVaultDelete,
}

var vaultProjectsCmd = &cobra.Command{
	Use:   "projects <vault-id>",
	Short: "List projects in a vault",
	Args:  cobra.ExactArgs(1),
	RunE:  runVaultProjects,
}

var vaultAddProjectCmd = &cobra.Command{
	Use:   "add-project <vault-id> <project-name>",
	Short: "Add a project to a vault",
	Long: `Add a project to a vault for sync routing.

Use --migrate to also migrate existing observations for the project
to the vault (server-side, fast).

Example:
  sinesync vault add-project abc123 myproject
  sinesync vault add-project abc123 myproject --migrate`,
	Args: cobra.ExactArgs(2),
	RunE: runVaultAddProject,
}

var addProjectMigrate bool

var vaultRemoveProjectCmd = &cobra.Command{
	Use:   "remove-project <vault-id> <project-name>",
	Short: "Remove a project from a vault",
	Args:  cobra.ExactArgs(2),
	RunE:  runVaultRemoveProject,
}

var vaultMigrateProjectCmd = &cobra.Command{
	Use:   "migrate-project <project-name> <to-vault-id>",
	Short: "Migrate a project's observations to a different vault",
	Long: `Migrate all observations for a project to a new vault.

This uploads all observations to the target vault. The project is
then moved to the new vault.

Use --force to upload observations even if the project is already
in the target vault (useful for initial sync after adding a project).

Example:
  sinesync vault migrate-project myproject abc123-def456
  sinesync vault migrate-project myproject abc123 --force`,
	Args: cobra.ExactArgs(2),
	RunE: runVaultMigrateProject,
}

var migrateForce bool

var vaultSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync vault keys from server",
	Long:  `Fetch and store encrypted vault keys from the server.`,
	RunE:  runVaultSync,
}

var vaultShareCmd = &cobra.Command{
	Use:   "share <vault-id>",
	Short: "Share a vault with another user",
	Long: `Invite another user to access a vault.

The invitee will receive an email with a link to accept.
Once they accept, you'll need to confirm the invite using 'vault confirm'.

Flow:
  1. You run 'vault share' - invite is created, email sent
  2. Invitee clicks link, creates account (or logs in), accepts
  3. You run 'vault pending-confirm' to see who's waiting
  4. You run 'vault confirm <invite-id>' to complete the share

Examples:
  sinesync vault share abc123 --email alice@example.com`,
	Args: cobra.ExactArgs(1),
	RunE: runVaultShare,
}

var vaultPendingConfirmCmd = &cobra.Command{
	Use:   "pending-confirm",
	Short: "List invites awaiting your confirmation",
	Long: `List vault invites that have been accepted by invitees and are waiting
for you to confirm and share the vault key.

Run 'vault confirm <invite-id>' to complete the share.`,
	RunE: runVaultPendingConfirm,
}

var vaultConfirmCmd = &cobra.Command{
	Use:   "confirm <invite-id>",
	Short: "Confirm an invite and share the vault key",
	Long: `Confirm a vault invite after the invitee has accepted.

This encrypts the vault key with the invitee's public key and grants them access.

Use 'vault pending-confirm' to see invites waiting for confirmation.`,
	Args: cobra.ExactArgs(1),
	RunE: runVaultConfirm,
}

var vaultInvitesCmd = &cobra.Command{
	Use:   "invites <vault-id>",
	Short: "List pending invites for a vault",
	Args:  cobra.ExactArgs(1),
	RunE:  runVaultInvites,
}

var vaultCancelInviteCmd = &cobra.Command{
	Use:   "cancel-invite <invite-id>",
	Short: "Cancel a pending invite",
	Args:  cobra.ExactArgs(1),
	RunE:  runVaultCancelInvite,
}

var vaultAcceptCmd = &cobra.Command{
	Use:   "accept <invite-id>",
	Short: "Accept a vault invite",
	Long: `Accept an invitation to join a shared vault.

After accepting, the inviter will be notified and must confirm the share.
Once confirmed, you can sync to access the shared vault.`,
	Args: cobra.ExactArgs(1),
	RunE: runVaultAccept,
}

var vaultPendingCmd = &cobra.Command{
	Use:   "pending",
	Short: "List your pending vault invites",
	RunE:  runVaultPending,
}

var vaultSetupKeyCmd = &cobra.Command{
	Use:   "setup-key <vault-id>",
	Short: "Generate and upload encryption key for a vault",
	Long: `Generate a new encryption key for a vault and upload it to the server.

Use this to enable sharing for vaults created before vault key encryption was implemented.`,
	Args: cobra.ExactArgs(1),
	RunE: runVaultSetupKey,
}

var vaultReencryptCmd = &cobra.Command{
	Use:   "reencrypt <vault-id>",
	Short: "Re-encrypt vault observations with the vault key",
	Long: `Re-encrypt all observations in a vault using the vault's encryption key.

This is required for sharing vaults with other users. Observations encrypted
with your personal key cannot be decrypted by others - they must be re-encrypted
with the shared vault key.

Use --project to re-encrypt only observations for a specific project.

Example:
  sinesync vault reencrypt abc123-def456
  sinesync vault reencrypt abc123-def456 --project myproject`,
	Args: cobra.ExactArgs(1),
	RunE: runVaultReencrypt,
}

var reencryptProject string

var shareEmail string

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultCreateCmd)
	vaultCmd.AddCommand(vaultDeleteCmd)
	vaultCmd.AddCommand(vaultProjectsCmd)
	vaultCmd.AddCommand(vaultAddProjectCmd)
	vaultAddProjectCmd.Flags().BoolVarP(&addProjectMigrate, "migrate", "m", false, "Migrate existing observations to the vault")
	vaultCmd.AddCommand(vaultRemoveProjectCmd)
	vaultCmd.AddCommand(vaultMigrateProjectCmd)
	vaultMigrateProjectCmd.Flags().BoolVarP(&migrateForce, "force", "f", false, "Upload observations even if project is already in target vault")
	vaultCmd.AddCommand(vaultSyncCmd)
	vaultCmd.AddCommand(vaultShareCmd)
	vaultCmd.AddCommand(vaultPendingConfirmCmd)
	vaultCmd.AddCommand(vaultConfirmCmd)
	vaultCmd.AddCommand(vaultInvitesCmd)
	vaultCmd.AddCommand(vaultCancelInviteCmd)
	vaultCmd.AddCommand(vaultAcceptCmd)
	vaultCmd.AddCommand(vaultPendingCmd)
	vaultCmd.AddCommand(vaultSetupKeyCmd)
	vaultCmd.AddCommand(vaultReencryptCmd)
	vaultReencryptCmd.Flags().StringVarP(&reencryptProject, "project", "p", "", "Only re-encrypt observations for this project")

	// Share command flags
	vaultShareCmd.Flags().StringVarP(&shareEmail, "email", "e", "", "Email address of the invitee (required)")
	vaultShareCmd.MarkFlagRequired("email")
}

func runVaultList(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	orgInfo, _ := fetchUserOrgInfo(token)
	isOrgUser := orgInfo != nil

	// Personal vaults (skip for org users)
	if !isOrgUser {
		apiBase := getAPIBase()
		client := &http.Client{Timeout: 30 * time.Second}

		req, err := http.NewRequest("GET", apiBase+"/vaults", nil)
		if err != nil {
			return err
		}

		resp, err := doVaultRequest(client, req, &token)
		if err != nil {
			return fmt.Errorf("failed to fetch vaults: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error: %s", string(body))
		}

		var result struct {
			Vaults []VaultWithRole `json:"vaults"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		if len(result.Vaults) == 0 {
			fmt.Println("No vaults found.")
			return nil
		}

		fmt.Println("Your vaults:")
		fmt.Println()
		for _, v := range result.Vaults {
			defaultMarker := ""
			if v.IsDefault {
				defaultMarker = " (default)"
			}
			fmt.Printf("  %s%s\n", v.Name, defaultMarker)
			fmt.Printf("    ID: %s\n", v.ID)
			fmt.Printf("    Role: %s\n", v.Role)
			fmt.Printf("    Members: %d\n", v.MemberCount)
			fmt.Println()
		}
	}

	// Show org vaults
	if isOrgUser {
		orgVaults, err := fetchOrgVaults(token, orgInfo.OrgID)
		if err == nil && len(orgVaults) > 0 {
			fmt.Println("Organization vaults:")
			fmt.Println()
			for _, v := range orgVaults {
				fmt.Printf("  %s [org]\n", v.Name)
				fmt.Printf("    ID: %s\n", v.ID)
				if v.Role != "" {
					fmt.Printf("    Role: %s\n", v.Role)
				}
				if v.EncryptedVaultKey != "" {
					fmt.Printf("    Status: encrypted\n")
				} else {
					fmt.Printf("    Status: pending key setup\n")
				}
				fmt.Println()
			}
		} else if err != nil {
			return fmt.Errorf("failed to fetch org vaults: %w", err)
		} else {
			fmt.Println("No organization vaults found.")
			fmt.Println("Contact your organization administrator for vault access.")
		}
	}

	return nil
}

func runVaultCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// Org users cannot create personal vaults
	orgInfo, _ := fetchUserOrgInfo(token)
	if orgInfo != nil {
		return fmt.Errorf("organization members cannot create personal vaults")
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	// Create vault on server
	body, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", apiBase+"/vaults", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(respBody))
	}

	var vault Vault
	if err := json.NewDecoder(resp.Body).Decode(&vault); err != nil {
		return err
	}

	fmt.Printf("✓ Created vault: %s\n", vault.Name)
	fmt.Printf("  ID: %s\n", vault.ID)

	// Generate vault key and add self as member
	fmt.Println("Setting up encryption...")
	if err := setupVaultKey(token, vault.ID, vault.Name); err != nil {
		return fmt.Errorf("failed to setup vault key: %w", err)
	}

	fmt.Println("✓ Vault ready to use")
	return nil
}

func runVaultDelete(cmd *cobra.Command, args []string) error {
	vaultID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// Confirm deletion
	fmt.Printf("Are you sure you want to delete vault %s? This cannot be undone.\n", vaultID)
	fmt.Print("Type 'yes' to confirm: ")
	reader := bufio.NewReader(os.Stdin)
	confirm, _ := reader.ReadString('\n')
	if strings.TrimSpace(confirm) != "yes" {
		fmt.Println("Cancelled.")
		return nil
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("DELETE", apiBase+"/vaults/"+vaultID, nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to delete vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	// Remove from local config
	removeLocalVault(vaultID)

	fmt.Println("✓ Vault deleted")
	return nil
}

func runVaultProjects(cmd *cobra.Command, args []string) error {
	vaultID := args[0]

	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return fmt.Errorf("failed to load vault config: %w", err)
	}

	var vault *LocalVault
	for i := range cfg.Vaults {
		if cfg.Vaults[i].VaultID == vaultID {
			vault = &cfg.Vaults[i]
			break
		}
	}

	if vault == nil {
		return fmt.Errorf("vault not found - run 'sinesync vault sync' first")
	}

	if len(vault.Projects) == 0 {
		fmt.Printf("No projects assigned to vault '%s'.\n", vault.Name)
		fmt.Println("Use 'sinesync vault add-project' to assign projects.")
		return nil
	}

	fmt.Printf("Projects in vault '%s':\n", vault.Name)
	for _, p := range vault.Projects {
		fmt.Printf("  - %s\n", p)
	}

	return nil
}

func runVaultAddProject(cmd *cobra.Command, args []string) error {
	vaultID := args[0]
	projectName := args[1]

	// Verify vault exists locally
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return fmt.Errorf("failed to load vault config: %w", err)
	}

	var vaultName string
	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			vaultName = v.Name
			break
		}
	}
	if vaultName == "" {
		return fmt.Errorf("vault not found - run 'sinesync vault sync' first")
	}

	// Update local config only (project mappings are client-side)
	addProjectToLocalVault(vaultID, projectName)

	fmt.Printf("✓ Added project '%s' to vault '%s'\n", projectName, vaultName)

	// Migrate observations if requested
	if addProjectMigrate {
		token, err := getAuthTokenForVault()
		if err != nil {
			return fmt.Errorf("not logged in: %w", err)
		}
		fmt.Println()
		if err := migrateProjectObservations(projectName, vaultID, token); err != nil {
			fmt.Printf("Warning: migration failed: %v\n", err)
			fmt.Println("You can run 'sinesync vault migrate-project' later to retry")
		}
	}

	return nil
}

func runVaultRemoveProject(cmd *cobra.Command, args []string) error {
	vaultID := args[0]
	projectName := args[1]

	// Verify vault exists locally
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return fmt.Errorf("failed to load vault config: %w", err)
	}

	var vaultName string
	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			vaultName = v.Name
			break
		}
	}
	if vaultName == "" {
		return fmt.Errorf("vault not found - run 'sinesync vault sync' first")
	}

	// Update local config only (project mappings are client-side)
	removeProjectFromLocalVault(vaultID, projectName)

	fmt.Printf("✓ Removed project '%s' from vault '%s'\n", projectName, vaultName)
	return nil
}

func runVaultMigrateProject(cmd *cobra.Command, args []string) error {
	projectName := args[0]
	toVaultID := args[1]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// Find current vault for the project
	fromVaultID, err := GetVaultForProject(projectName)
	if err != nil || fromVaultID == "" {
		return fmt.Errorf("project '%s' is not in any vault - use 'vault add-project' first", projectName)
	}

	if fromVaultID == toVaultID && !migrateForce {
		return fmt.Errorf("project is already in vault %s (use --force to re-encrypt observations)", toVaultID)
	}

	// Verify target vault exists and get vault key
	cfg, _ := loadLocalVaultConfig()
	if cfg == nil {
		return fmt.Errorf("no vault configuration - run 'sinesync vault sync' first")
	}
	var targetVaultName string
	for _, v := range cfg.Vaults {
		if v.VaultID == toVaultID {
			targetVaultName = v.Name
			break
		}
	}
	if targetVaultName == "" {
		return fmt.Errorf("vault %s not found - run 'sinesync vault sync' first", toVaultID)
	}

	// Get the vault key for encryption
	vaultKey, err := GetVaultKey(toVaultID)
	if err != nil {
		return fmt.Errorf("failed to get vault key: %w\nRun 'sinesync vault setup-key %s' if the vault has no encryption key", err, toVaultID)
	}

	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available - please login again")
	}

	// Get local storage
	backend, err := storage.ResolveBackend()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer backend.Close()

	// Get observations for this project
	observations, err := backend.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to load observations: %w", err)
	}

	var projectObs []storage.Observation
	for _, obs := range observations {
		if obs.Core.Project == projectName {
			projectObs = append(projectObs, obs)
		}
	}

	if len(projectObs) == 0 {
		fmt.Printf("No local observations for project '%s'\n", projectName)
	} else {
		fmt.Printf("Found %d observations to re-encrypt and upload\n", len(projectObs))
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 300 * time.Second}

	// Re-encrypt and upload observations
	var uploaded, failed int
	var reasons map[string]int
	if len(projectObs) > 0 {
		fmt.Println("Re-encrypting with vault key and uploading...")

		uploaded, failed, reasons, err = reencryptAndUploadObservations(projectObs, vaultKey, toVaultID, token, apiBase, client, encMgr)
		if err != nil {
			return fmt.Errorf("re-encryption failed: %w", err)
		}
	}

	// Update server: remove from old vault, add to new vault (only if different vaults)
	if fromVaultID != toVaultID {
		// Remove from old vault
		delReq, _ := http.NewRequest("DELETE", apiBase+"/vaults/"+fromVaultID+"/projects/"+url.PathEscape(projectName), nil)
		doVaultRequest(client, delReq, &token)

		// Add to new vault
		addBody, _ := json.Marshal(map[string]string{"projectName": projectName})
		addReq, _ := http.NewRequest("POST", apiBase+"/vaults/"+toVaultID+"/projects", bytes.NewReader(addBody))
		addReq.Header.Set("Content-Type", "application/json")
		doVaultRequest(client, addReq, &token)

		// Update local config
		removeProjectFromLocalVault(fromVaultID, projectName)
		addProjectToLocalVault(toVaultID, projectName)

		fmt.Printf("✓ Migrated project '%s' to vault '%s'\n", projectName, targetVaultName)
	} else {
		fmt.Printf("✓ Re-encrypted observations for project '%s' in vault '%s'\n", projectName, targetVaultName)
	}
	if len(projectObs) > 0 {
		// Reported after the assignment is updated, not before: the routing
		// change is worth keeping even when some observations were refused,
		// and the caller still learns that they were.
		return reportMigrationOutcome(os.Stdout, uploaded, failed, reasons)
	}

	return nil
}

func runVaultReencrypt(cmd *cobra.Command, args []string) error {
	vaultID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// Verify vault exists and get vault key
	cfg, _ := loadLocalVaultConfig()
	if cfg == nil {
		return fmt.Errorf("no vault configuration - run 'sinesync vault sync' first")
	}
	var vaultName string
	var vaultProjects []string
	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			vaultName = v.Name
			vaultProjects = v.Projects
			break
		}
	}
	if vaultName == "" {
		return fmt.Errorf("vault %s not found - run 'sinesync vault sync' first", vaultID)
	}

	// Get the vault key for encryption
	vaultKey, err := GetVaultKey(vaultID)
	if err != nil {
		return fmt.Errorf("failed to get vault key: %w\nRun 'sinesync vault setup-key %s' if the vault has no encryption key", err, vaultID)
	}

	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available - please login again")
	}

	// Get local storage
	backend, err := storage.ResolveBackend()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer backend.Close()

	// Get observations
	observations, err := backend.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to load observations: %w", err)
	}

	// Filter observations belonging to this vault
	var vaultObs []storage.Observation
	projectSet := make(map[string]bool)
	for _, p := range vaultProjects {
		projectSet[p] = true
	}

	for _, obs := range observations {
		// If --project flag is set, only include that project
		if reencryptProject != "" {
			if obs.Core.Project == reencryptProject {
				vaultObs = append(vaultObs, obs)
			}
			continue
		}

		// Otherwise include all projects assigned to this vault
		if projectSet[obs.Core.Project] {
			vaultObs = append(vaultObs, obs)
		}
	}

	if len(vaultObs) == 0 {
		if reencryptProject != "" {
			fmt.Printf("No local observations for project '%s' in vault '%s'\n", reencryptProject, vaultName)
		} else {
			fmt.Printf("No local observations for vault '%s'\n", vaultName)
		}
		return nil
	}

	fmt.Printf("Found %d observations to re-encrypt in vault '%s'\n", len(vaultObs), vaultName)

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 300 * time.Second}

	fmt.Println("Re-encrypting with vault key and uploading...")

	uploaded, failed, reasons, err := reencryptAndUploadObservations(vaultObs, vaultKey, vaultID, token, apiBase, client, encMgr)
	if err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}

	if err := reportMigrationOutcome(os.Stdout, uploaded, failed, reasons); err != nil {
		return err
	}
	fmt.Println("\nVault observations are now encrypted with the vault key and can be shared.")

	return nil
}

// reencryptAndUploadObservations re-encrypts observations with a vault key and uploads them
func reencryptAndUploadObservations(observations []storage.Observation, vaultKey []byte, vaultID, token, apiBase string, client *http.Client, encMgr *encryption.Manager) (uploaded, errors int, reasons map[string]int, err error) {
	// Distinct refusal reasons and how often each occurred, so the caller can
	// say why rather than only how many.
	reasons = map[string]int{}
	batchSize := 50

	for i := 0; i < len(observations); i += batchSize {
		end := i + batchSize
		if end > len(observations) {
			end = len(observations)
		}
		batch := observations[i:end]

		// Prepare batch for upload
		type itemReq struct {
			ID        string `json:"id"`
			VaultID   string `json:"vaultId"`
			Type      string `json:"type"`
			SizeBytes int    `json:"sizeBytes"`
			Checksum  string `json:"checksum"`
		}

		var items []itemReq
		itemData := make(map[string][]byte)

		for _, obs := range batch {
			// Re-encrypt with vault key
			encrypted, err := encMgr.EncryptObservationWithKey(&obs, vaultKey)
			if err != nil {
				fmt.Printf("  Warning: encrypt failed for %s: %v\n", obs.ID, err)
				errors++
				continue
			}

			checksum := storage.Checksum(encrypted)[:16]
			items = append(items, itemReq{
				ID:        obs.ID,
				VaultID:   vaultID,
				Type:      "memory",
				SizeBytes: len(encrypted),
				Checksum:  checksum,
			})
			itemData[obs.ID] = encrypted
		}

		if len(items) == 0 {
			continue
		}

		// Get upload URLs
		body := map[string]interface{}{"items": items}
		bodyBytes, _ := json.Marshal(body)

		req, _ := http.NewRequest("POST", apiBase+"/sync/upload-urls", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			return uploaded, errors, reasons, fmt.Errorf("get upload URLs: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return uploaded, errors, reasons, fmt.Errorf("get upload URLs failed %d: %s", resp.StatusCode, string(respBody))
		}

		var urlResp struct {
			Items []struct {
				ID        string `json:"id"`
				UploadURL string `json:"uploadUrl"`
			} `json:"items"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&urlResp); err != nil {
			resp.Body.Close()
			return uploaded, errors, reasons, fmt.Errorf("decode upload URLs: %w", err)
		}
		resp.Body.Close()

		// Upload to GCS
		var confirmBodies []map[string]interface{}
		for _, urlItem := range urlResp.Items {
			data := itemData[urlItem.ID]
			if data == nil {
				continue
			}

			uploadReq, _ := http.NewRequest("PUT", urlItem.UploadURL, bytes.NewReader(data))
			uploadReq.Header.Set("Content-Type", "application/octet-stream")

			uploadResp, err := client.Do(uploadReq)
			if err != nil {
				errors++
				continue
			}
			uploadResp.Body.Close()

			if uploadResp.StatusCode == http.StatusOK || uploadResp.StatusCode == http.StatusCreated {
				confirmBodies = append(confirmBodies, map[string]interface{}{
					"id":        urlItem.ID,
					"vaultId":   vaultID,
					"type":      "memory",
					"sizeBytes": len(data),
					"checksum":  storage.Checksum(data)[:16],
				})
			} else {
				errors++
			}
		}

		if len(confirmBodies) == 0 {
			continue
		}

		// Confirm uploads
		confirmBody := map[string]interface{}{"items": confirmBodies}
		confirmBytes, _ := json.Marshal(confirmBody)

		confirmReq, _ := http.NewRequest("POST", apiBase+"/sync/confirm-uploads", bytes.NewReader(confirmBytes))
		confirmReq.Header.Set("Content-Type", "application/json")
		confirmReq.Header.Set("Authorization", "Bearer "+token)
		httputil.SetClientHeaders(confirmReq)

		confirmResp, err := client.Do(confirmReq)
		if err != nil {
			return uploaded, errors, reasons, fmt.Errorf("confirm uploads: %w", err)
		}

		if confirmResp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(confirmResp.Body)
			confirmResp.Body.Close()
			return uploaded, errors, reasons, fmt.Errorf("confirm failed: %d - %s", confirmResp.StatusCode, string(respBody))
		}

		// The server reports per-item outcomes inside a 200, so a batch where
		// every item was refused still arrives as a success. Decoding `error`
		// as well as `success` is what makes those refusals visible: without
		// it a migration could reject 98% of its items and say nothing.
		var confirmResult struct {
			Items []struct {
				Success bool   `json:"success"`
				Error   string `json:"error"`
			} `json:"items"`
		}
		json.NewDecoder(confirmResp.Body).Decode(&confirmResult)
		confirmResp.Body.Close()

		batchUploaded := 0
		for _, result := range confirmResult.Items {
			if result.Success {
				uploaded++
				batchUploaded++
				continue
			}
			errors++
			if result.Error != "" {
				reasons[result.Error]++
			} else {
				reasons["refused without a reason"]++
			}
		}

		// What actually landed, not what was sent. Reporting the size of the
		// request made a batch that failed entirely read as a batch that
		// succeeded entirely.
		fmt.Printf("  Batch %d/%d: %d/%d uploaded\n",
			(i/batchSize)+1, (len(observations)+batchSize-1)/batchSize,
			batchUploaded, len(confirmBodies))
	}

	return uploaded, errors, reasons, nil
}

// reportPendingAdminKeyHolders tells the operator that other admins are waiting
// for the org private key, and stops there.
//
// Sync used to seal the org private key to those admins itself, in the
// background, to whatever public key /org-key/admins-pending returned. That key
// is the org's entire escrow — it opens every vault key in the organization —
// and a server that listed a key of its own got a copy of it with nobody
// watching. The check that would catch such a substitution is a human comparing
// a fingerprint out of band with the admin it belongs to, and sync has no human:
// it runs from 'sinesync sync', from the daemon, from a shell script. There is
// no version of this that is both automatic and safe, so the distribution moved
// to 'sinesync admin provision', which prompts per recipient and seals nothing
// it cannot confirm.
//
// What is left here is a detection: the listing is a plain read, it names who is
// waiting, and it costs the operator nothing. Deliberately no private key is
// fetched or decrypted on this path and no holders record is submitted, so there
// is nothing here for a substituted key to be sealed to.
//
// Returns how many admins are waiting, for tests.
func reportPendingAdminKeyHolders(w io.Writer, token, orgID string) int {
	pendingAdmins, err := fetchAdminsPendingKeyHolders(token, orgID)
	if err != nil {
		fmt.Fprintf(w, "  Warning: failed to check pending admin holders: %v\n", err)
		return 0
	}
	if len(pendingAdmins) == 0 {
		return 0
	}

	fmt.Fprintf(w, "  ⚠ %d admin(s) are waiting for the org key and were NOT given it here.\n", len(pendingAdmins))
	fmt.Fprintln(w, "    Run 'sinesync admin provision' to distribute it. It will ask you to confirm")
	fmt.Fprintln(w, "    each admin's key fingerprint with them directly, which sync cannot do.")
	return len(pendingAdmins)
}

func runVaultSync(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	fmt.Println("Syncing vault keys...")

	// Load existing local config to preserve project mappings
	existingConfig, _ := loadLocalVaultConfig()
	existingProjects := make(map[string][]string)
	if existingConfig != nil {
		for _, v := range existingConfig.Vaults {
			existingProjects[v.VaultID] = v.Projects
		}
	}

	// Check org membership early to skip personal vaults for org users
	orgInfo, _ := fetchUserOrgInfo(token)
	isOrgUser := orgInfo != nil

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	// For each vault, get the encrypted key (projects are local-only)
	localConfig := LocalVaultConfig{Vaults: make([]LocalVault, 0)}

	// Personal vault sync (skip for org users)
	if !isOrgUser {
		// Get all vaults
		req, err := http.NewRequest("GET", apiBase+"/vaults", nil)
		if err != nil {
			return err
		}

		resp, err := doVaultRequest(client, req, &token)
		if err != nil {
			return fmt.Errorf("failed to fetch vaults: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("server error: %s", string(body))
		}

		var result struct {
			Vaults []VaultWithRole `json:"vaults"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return err
		}

		for _, v := range result.Vaults {
			// Get encrypted vault key
			keyReq, err := http.NewRequest("GET", apiBase+"/vaults/"+v.ID+"/key", nil)
			if err != nil {
				fmt.Printf("  Warning: failed to create key request for vault %s: %v\n", v.Name, err)
				continue
			}

			keyResp, err := doVaultRequest(client, keyReq, &token)
			if err != nil {
				fmt.Printf("  Warning: failed to get key for vault %s: %v\n", v.Name, err)
				continue
			}

			var keyResult struct {
				EncryptedVaultKey string `json:"encryptedVaultKey"`
			}
			if keyResp.StatusCode == http.StatusOK {
				if err := json.NewDecoder(keyResp.Body).Decode(&keyResult); err != nil {
					fmt.Printf("  Warning: failed to decode key response for vault %s: %v\n", v.Name, err)
				}
			} else {
				fmt.Printf("  Warning: key fetch returned status %d for vault %s\n", keyResp.StatusCode, v.Name)
			}
			keyResp.Body.Close()

			// Normalize the encrypted vault key to AES-GCM format
			// Vault owners already have AES-GCM keys; invited members have X25519-sealed keys
			if keyResult.EncryptedVaultKey != "" {
				normalizedKey, err := normalizeVaultKey(keyResult.EncryptedVaultKey, token)
				if err != nil {
					fmt.Printf("  Warning: failed to normalize key for vault %s: %v\n", v.Name, err)
				} else {
					keyResult.EncryptedVaultKey = normalizedKey
				}
			}

			// Preserve existing local project mappings
			projects := existingProjects[v.ID]
			if projects == nil {
				projects = []string{}
			}

			localConfig.Vaults = append(localConfig.Vaults, LocalVault{
				VaultID:           v.ID,
				Name:              v.Name,
				EncryptedVaultKey: keyResult.EncryptedVaultKey,
				Projects:          projects,
				IsDefault:         v.IsDefault,
			})

			fmt.Printf("  ✓ %s (%d local projects)\n", v.Name, len(projects))
		}
	}

	// --- Org vault sync section ---
	if isOrgUser {
		fmt.Println()
		fmt.Println("Syncing org vaults...")

		isAdmin := orgInfo.Role == "admin" || orgInfo.Role == "owner"

		// Check for pending provisions and hint admin to run provision command
		if isAdmin {
			needsProvisioning := false
			if orgInfo.OrgPublicKey == "" {
				needsProvisioning = true
			} else {
				pending, err := fetchPendingProvisions(token, orgInfo.OrgID)
				if err == nil && len(pending) > 0 {
					needsProvisioning = true
				}
				orgVaultsCheck, err := fetchOrgVaults(token, orgInfo.OrgID)
				if err == nil {
					for _, ov := range orgVaultsCheck {
						if ov.EncryptedVaultKey == "" {
							needsProvisioning = true
							break
						}
					}
				}
			}
			if needsProvisioning {
				fmt.Println("  ⚠ Pending provisions detected — run 'sinesync admin provision' to provision members")
			}
		}

		// Warn if key holder count is dangerously low
		if orgInfo.KeyHolderCount != nil && *orgInfo.KeyHolderCount < 2 {
			if *orgInfo.KeyHolderCount == 0 {
				fmt.Println("  ⚠ No key holders — run 'sinesync admin provision' to initialize org encryption")
			} else {
				fmt.Println("  ⚠ Only 1 key holder — run 'sinesync admin provision' on another admin device for redundancy")
			}
		}

		// Admins missing a key holder record are reported, never provisioned
		// from here. See reportPendingAdminKeyHolders.
		if isAdmin && orgInfo.OrgPublicKey != "" {
			reportPendingAdminKeyHolders(os.Stdout, token, orgInfo.OrgID)
		}

		// Fetch org vaults and get user's own vault keys (no admin provisioning here)
		orgVaults, err := fetchOrgVaults(token, orgInfo.OrgID)
		if err != nil {
			fmt.Printf("  Warning: failed to fetch org vaults: %v\n", err)
		} else {
			for _, ov := range orgVaults {
				encKey, err := fetchOrgVaultKey(token, orgInfo.OrgID, ov.ID)
				if err != nil {
					fmt.Printf("  Warning: failed to fetch key for org vault %s: %v\n", ov.Name, err)
					continue
				}

				if encKey == "" {
					fmt.Printf("  %s: access pending — an admin will provision your keys shortly\n", ov.Name)
					continue
				}

				// Normalize the key (X25519 -> AES-GCM)
				normalizedKey, err := normalizeVaultKey(encKey, token)
				if err != nil {
					fmt.Printf("  Warning: failed to normalize key for org vault %s: %v\n", ov.Name, err)
					continue
				}

				// Preserve existing local project mappings
				projects := existingProjects[ov.ID]
				if projects == nil {
					projects = []string{}
				}

				localConfig.Vaults = append(localConfig.Vaults, LocalVault{
					VaultID:           ov.ID,
					Name:              ov.Name,
					EncryptedVaultKey: normalizedKey,
					Projects:          projects,
					IsOrgVault:        true,
					OrgID:             orgInfo.OrgID,
				})

				fmt.Printf("  ✓ %s [org] (%d local projects)\n", ov.Name, len(projects))
			}
		}

		// Set first org vault as default if no vault is already default
		hasDefault := false
		for _, v := range localConfig.Vaults {
			if v.IsDefault {
				hasDefault = true
				break
			}
		}
		if !hasDefault && len(localConfig.Vaults) > 0 {
			localConfig.Vaults[0].IsDefault = true
		}
	}

	// Save local config
	if err := saveLocalVaultConfig(&localConfig); err != nil {
		return fmt.Errorf("failed to save vault config: %w", err)
	}

	fmt.Printf("\n✓ Synced %d vaults\n", len(localConfig.Vaults))

	// Trigger daemon sync so it picks up the new vault config immediately
	if running, info := daemon.IsRunning(); running {
		if err := triggerDaemonSync(info.Port); err != nil {
			fmt.Printf("warning: failed to trigger daemon sync: %v\n", err)
		} else {
			fmt.Println("✓ Daemon sync triggered")
		}
	}

	return nil
}

// Helper functions

// doVaultRequest performs an authenticated HTTP request with automatic token refresh on 401.
// It sets the Authorization header, executes the request, and if a 401 is returned,
// refreshes the access token and retries once. The token pointer is updated on refresh.
func doVaultRequest(client *http.Client, req *http.Request, token *string) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+*token)
	httputil.SetClientHeaders(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		fmt.Println("Token expired, refreshing...")
		newToken, refreshErr := refreshAccessToken(getAPIBase())
		if refreshErr != nil {
			return nil, fmt.Errorf("token expired and refresh failed: %w\nRun 'sinesync login' to re-authenticate", refreshErr)
		}
		*token = newToken

		// Rebuild the request for retry (original body may be consumed)
		retryReq := req.Clone(req.Context())
		retryReq.Header.Set("Authorization", "Bearer "+*token)
		if req.GetBody != nil {
			retryReq.Body, _ = req.GetBody()
		}

		time.Sleep(2 * time.Second)
		return client.Do(retryReq)
	}

	return resp, nil
}

func getAuthTokenForVault() (string, error) {
	// Check keyring
	if token, err := keychain.Get("deviceToken"); err == nil && token != "" {
		return token, nil
	}
	if token, err := keychain.Get("token"); err == nil && token != "" {
		return token, nil
	}

	// Fallback to file
	authCfg, err := loadAuthConfig()
	if err != nil {
		return "", err
	}
	if authCfg.DeviceToken != "" {
		return authCfg.DeviceToken, nil
	}
	if authCfg.Token != "" {
		return authCfg.Token, nil
	}

	return "", fmt.Errorf("no auth token found")
}

func setupVaultKey(token, vaultID, vaultName string) error {
	// Generate a new vault key (256-bit)
	vaultKey, err := crypto.GenerateKey(32)
	if err != nil {
		return fmt.Errorf("failed to generate vault key: %w", err)
	}

	// Encrypt vault key with user's derived key
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available")
	}

	encryptedVaultKey, err := encMgr.EncryptVaultKey(vaultKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault key: %w", err)
	}

	// Add self as member with encrypted key
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(map[string]string{
		"encryptedVaultKey": encryptedVaultKey,
		"role":              "owner",
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", apiBase+"/vaults/"+vaultID+"/members", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to add member: %s", string(respBody))
	}

	// Store locally with vault name
	addLocalVault(vaultID, vaultName, encryptedVaultKey, false)

	return nil
}

func runVaultSetupKey(cmd *cobra.Command, args []string) error {
	vaultID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// Get vault info to verify ownership and get name
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/vaults/"+vaultID, nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to get vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault not found or access denied")
	}

	var vault Vault
	if err := json.NewDecoder(resp.Body).Decode(&vault); err != nil {
		return fmt.Errorf("failed to decode vault: %w", err)
	}

	fmt.Printf("Setting up encryption key for vault: %s\n", vault.Name)

	if err := setupVaultKey(token, vaultID, vault.Name); err != nil {
		return fmt.Errorf("failed to setup vault key: %w", err)
	}

	fmt.Println("✓ Vault key set up successfully")
	fmt.Println("\nNote: Existing data is encrypted with your user key.")
	fmt.Println("To re-encrypt for sharing, use: sinesync vault migrate-project")
	return nil
}

func localVaultConfigPath() string {
	return filepath.Join(config.ConfigDir(), "vaults.json")
}

func loadLocalVaultConfig() (*LocalVaultConfig, error) {
	data, err := os.ReadFile(localVaultConfigPath())
	if err != nil {
		if os.IsNotExist(err) {
			return &LocalVaultConfig{Vaults: make([]LocalVault, 0)}, nil
		}
		return nil, err
	}

	var cfg LocalVaultConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func saveLocalVaultConfig(cfg *LocalVaultConfig) error {
	if err := os.MkdirAll(config.ConfigDir(), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(localVaultConfigPath(), data, 0600)
}

func addLocalVault(vaultID, name, encryptedKey string, isDefault bool) {
	cfg, _ := loadLocalVaultConfig()
	if cfg == nil {
		cfg = &LocalVaultConfig{Vaults: make([]LocalVault, 0)}
	}

	// Check if already exists
	for i, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			cfg.Vaults[i].EncryptedVaultKey = encryptedKey
			if name != "" {
				cfg.Vaults[i].Name = name
			}
			saveLocalVaultConfig(cfg)
			return
		}
	}

	cfg.Vaults = append(cfg.Vaults, LocalVault{
		VaultID:           vaultID,
		Name:              name,
		EncryptedVaultKey: encryptedKey,
		Projects:          make([]string, 0),
		IsDefault:         isDefault,
	})
	saveLocalVaultConfig(cfg)
}

func removeLocalVault(vaultID string) {
	cfg, _ := loadLocalVaultConfig()
	if cfg == nil {
		return
	}

	newVaults := make([]LocalVault, 0)
	for _, v := range cfg.Vaults {
		if v.VaultID != vaultID {
			newVaults = append(newVaults, v)
		}
	}
	cfg.Vaults = newVaults
	saveLocalVaultConfig(cfg)
}

func addProjectToLocalVault(vaultID, projectName string) {
	cfg, _ := loadLocalVaultConfig()
	if cfg == nil {
		return
	}

	for i, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			// Check if already exists
			for _, p := range v.Projects {
				if p == projectName {
					return
				}
			}
			cfg.Vaults[i].Projects = append(cfg.Vaults[i].Projects, projectName)
			saveLocalVaultConfig(cfg)
			return
		}
	}
}

func removeProjectFromLocalVault(vaultID, projectName string) {
	cfg, _ := loadLocalVaultConfig()
	if cfg == nil {
		return
	}

	for i, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			newProjects := make([]string, 0)
			for _, p := range v.Projects {
				if p != projectName {
					newProjects = append(newProjects, p)
				}
			}
			cfg.Vaults[i].Projects = newProjects
			saveLocalVaultConfig(cfg)
			return
		}
	}
}

// migrateProjectObservations re-encrypts and uploads observations for a project to a vault
func migrateProjectObservations(projectName, toVaultID, token string) error {
	// Get vault key
	vaultKey, err := GetVaultKey(toVaultID)
	if err != nil {
		return fmt.Errorf("failed to get vault key: %w\nRun 'sinesync vault setup-key %s' first", err, toVaultID)
	}

	// Get encryption manager
	encMgr := encryption.GetManager()
	if !encMgr.HasKey() {
		return fmt.Errorf("encryption key not available - please login again")
	}

	// Get local storage
	backend, err := storage.ResolveBackend()
	if err != nil {
		return fmt.Errorf("failed to open storage: %w", err)
	}
	defer backend.Close()

	// Get observations for this project
	observations, err := backend.ListObservations()
	if err != nil {
		return fmt.Errorf("failed to load observations: %w", err)
	}

	var projectObs []storage.Observation
	for _, obs := range observations {
		if obs.Core.Project == projectName {
			projectObs = append(projectObs, obs)
		}
	}

	if len(projectObs) == 0 {
		fmt.Printf("No local observations for project '%s'\n", projectName)
		return nil
	}

	fmt.Printf("Found %d observations to re-encrypt and upload\n", len(projectObs))

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 300 * time.Second}

	fmt.Println("Re-encrypting with vault key and uploading...")

	uploaded, failed, reasons, err := reencryptAndUploadObservations(projectObs, vaultKey, toVaultID, token, apiBase, client, encMgr)
	if err != nil {
		return fmt.Errorf("re-encryption failed: %w", err)
	}

	return reportMigrationOutcome(os.Stdout, uploaded, failed, reasons)
}

// GetVaultForProject returns the vault ID for a given project
func GetVaultForProject(projectName string) (string, error) {
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return "", err
	}

	// Check if project is explicitly assigned to a vault
	for _, v := range cfg.Vaults {
		for _, p := range v.Projects {
			if p == projectName {
				return v.VaultID, nil
			}
		}
	}

	// Return default vault
	for _, v := range cfg.Vaults {
		if v.IsDefault {
			return v.VaultID, nil
		}
	}

	// No default vault found
	return "", nil
}

// GetVaultKey returns the decrypted vault key for a given vault ID
func GetVaultKey(vaultID string) ([]byte, error) {
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return nil, err
	}

	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			if v.EncryptedVaultKey == "" {
				return nil, fmt.Errorf("no vault key found")
			}

			encMgr := encryption.GetManager()
			return encMgr.DecryptVaultKey(v.EncryptedVaultKey)
		}
	}

	return nil, fmt.Errorf("vault not found: %s", vaultID)
}

// GetDefaultVaultID returns the default vault ID
func GetDefaultVaultID() (string, error) {
	cfg, err := loadLocalVaultConfig()
	if err != nil {
		return "", err
	}

	for _, v := range cfg.Vaults {
		if v.IsDefault {
			return v.VaultID, nil
		}
	}

	return "", fmt.Errorf("no default vault configured")
}

// === Vault Sharing Commands ===

// runVaultShare creates an invite and sends email to the invitee.
// The invitee must accept, then the inviter confirms with the encrypted vault key.
// This async flow eliminates user enumeration - we never check if user exists upfront.
func runVaultShare(cmd *cobra.Command, args []string) error {
	vaultID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	fmt.Printf("Creating invite for %s...\n", shareEmail)

	// Create invite on server - just email, no encryption yet
	inviteBody := map[string]interface{}{
		"email": shareEmail,
	}

	bodyBytes, err := json.Marshal(inviteBody)
	if err != nil {
		return fmt.Errorf("failed to marshal invite body: %w", err)
	}

	inviteReq, err := http.NewRequest("POST", apiBase+"/vaults/"+vaultID+"/invites", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	inviteReq.Header.Set("Content-Type", "application/json")

	inviteResp, err := doVaultRequest(client, inviteReq, &token)
	if err != nil {
		return fmt.Errorf("failed to create invite: %w", err)
	}
	defer inviteResp.Body.Close()

	if inviteResp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(inviteResp.Body)
		return fmt.Errorf("server error: %s", string(respBody))
	}

	var result struct {
		ID           string `json:"id"`
		InviteeEmail string `json:"inviteeEmail"`
		Status       string `json:"status"`
		Message      string `json:"message"`
	}
	if err := json.NewDecoder(inviteResp.Body).Decode(&result); err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("✓ Invite sent to %s\n", shareEmail)
	fmt.Println()
	fmt.Println("What happens next:")
	fmt.Println("  1. They receive an email with a link to accept")
	fmt.Println("  2. They click the link and create an account (or log in)")
	fmt.Println("  3. You'll be notified to confirm the invite")
	fmt.Println("  4. Run 'sinesync vault pending-confirm' to see invites awaiting confirmation")
	fmt.Println("  5. Run 'sinesync vault confirm <invite-id>' to complete the share")

	return nil
}

// runVaultPendingConfirm lists invites that are awaiting confirmation from the inviter
func runVaultPendingConfirm(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/invites/awaiting-confirmation", nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch invites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(respBody))
	}

	var result struct {
		Invites []struct {
			ID               string `json:"id"`
			VaultID          string `json:"vaultId"`
			VaultName        string `json:"vaultName"`
			InviteeEmail     string `json:"inviteeEmail"`
			InviteePublicKey string `json:"inviteePublicKey"`
			AcceptedAt       string `json:"acceptedAt"`
		} `json:"invites"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if len(result.Invites) == 0 {
		fmt.Println("No invites awaiting confirmation.")
		return nil
	}

	fmt.Println("Invites awaiting your confirmation:")
	fmt.Println()
	for _, inv := range result.Invites {
		fmt.Printf("  Invite ID: %s\n", inv.ID)
		fmt.Printf("  Vault:     %s (%s)\n", inv.VaultName, inv.VaultID)
		fmt.Printf("  Invitee:   %s\n", inv.InviteeEmail)
		fmt.Printf("  Accepted:  %s\n", inv.AcceptedAt)
		fmt.Println()
		fmt.Printf("  To confirm: sinesync vault confirm %s\n", inv.ID)
		fmt.Println("  " + strings.Repeat("-", 50))
	}

	return nil
}

// runVaultConfirm confirms an invite by encrypting the vault key for the invitee
func runVaultConfirm(cmd *cobra.Command, args []string) error {
	inviteID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	// First, get the invite details to get the vault ID and invitee's public key
	req, err := http.NewRequest("GET", apiBase+"/invites/awaiting-confirmation", nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch invites: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Invites []struct {
			ID               string `json:"id"`
			VaultID          string `json:"vaultId"`
			VaultName        string `json:"vaultName"`
			InviteeEmail     string `json:"inviteeEmail"`
			InviteePublicKey string `json:"inviteePublicKey"`
		} `json:"invites"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// Find the invite
	var targetInvite *struct {
		ID               string `json:"id"`
		VaultID          string `json:"vaultId"`
		VaultName        string `json:"vaultName"`
		InviteeEmail     string `json:"inviteeEmail"`
		InviteePublicKey string `json:"inviteePublicKey"`
	}
	for i := range result.Invites {
		if result.Invites[i].ID == inviteID {
			targetInvite = &result.Invites[i]
			break
		}
	}

	if targetInvite == nil {
		return fmt.Errorf("invite not found or not awaiting confirmation")
	}

	fmt.Printf("Confirming invite for %s to vault %s...\n", targetInvite.InviteeEmail, targetInvite.VaultName)

	// The public key is relayed by the server, so confirming blind would let a
	// compromised server substitute its own and read the vault key. Show a
	// fingerprint the invitee can read back over any channel that is not this
	// one — the email address alone proves nothing, since the server supplies
	// that too.
	fingerprint, err := crypto.KeyFingerprint(targetInvite.InviteePublicKey)
	if err != nil {
		return fmt.Errorf("the invitee's public key is unusable (%w); refusing to seal the vault key to it", err)
	}

	// The fingerprint this machine computed is deliberately not shown before
	// the prompt: the invitee reads theirs out, the owner types it, and the
	// comparison happens here over all 60 bits. Printing it first would invite
	// the owner to type what is already on their own screen, which a
	// substituted key passes trivially.
	ok := confirmFingerprintByTyping(os.Stdout, bufio.NewReader(os.Stdin), fingerprint, fingerprintPromptText{
		intro: []string{
			fmt.Sprintf("Ask %s to run 'sinesync vault pending' and read out the fingerprint it shows.", targetInvite.InviteeEmail),
			"Use a channel that is not this one — a phone call, in person. Not the invite itself.",
			"Then type it in exactly as they read it. Case, dashes and spaces do not matter.",
		},
		label:    "Fingerprint they read out: ",
		declined: []string{"Cancelled. The vault key was not shared."},
		mismatchHint: []string{
			"A fingerprint that does not match means the public key this server relayed is not",
			"the one on their machine. Do not retry until you know why.",
		},
	})
	if !ok {
		return nil
	}

	// Get the vault key from local storage
	vaultKey, err := GetVaultKey(targetInvite.VaultID)
	if err != nil {
		return fmt.Errorf("failed to get vault key: %w", err)
	}

	// Encrypt vault key with invitee's public key
	encryptedVaultKey, err := crypto.X25519Seal(vaultKey, targetInvite.InviteePublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt vault key: %w", err)
	}

	// Confirm the invite
	confirmBody := map[string]interface{}{
		"encryptedVaultKey": encryptedVaultKey,
	}
	bodyBytes, err := json.Marshal(confirmBody)
	if err != nil {
		return fmt.Errorf("failed to marshal confirm body: %w", err)
	}

	confirmReq, err := http.NewRequest("POST", apiBase+"/invites/"+inviteID+"/confirm", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	confirmReq.Header.Set("Content-Type", "application/json")

	confirmResp, err := doVaultRequest(client, confirmReq, &token)
	if err != nil {
		return fmt.Errorf("failed to confirm invite: %w", err)
	}
	defer confirmResp.Body.Close()

	if confirmResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(confirmResp.Body)
		return fmt.Errorf("server error: %s", string(respBody))
	}

	fmt.Println()
	fmt.Printf("✓ Invite confirmed! %s now has access to %s\n", targetInvite.InviteeEmail, targetInvite.VaultName)

	return nil
}

func runVaultInvites(cmd *cobra.Command, args []string) error {
	vaultID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/vaults/"+vaultID+"/invites", nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch invites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	var result struct {
		Invites []VaultInvite `json:"invites"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if len(result.Invites) == 0 {
		fmt.Println("No pending invites.")
		return nil
	}

	fmt.Println("Pending invites:")
	fmt.Println()
	for _, inv := range result.Invites {
		inviteType := "direct"
		if inv.InviteType == "new_user" {
			inviteType = "new user (needs codes)"
		}
		fmt.Printf("  %s\n", inv.InviteeEmail)
		fmt.Printf("    ID: %s\n", inv.ID)
		fmt.Printf("    Type: %s\n", inviteType)
		fmt.Printf("    Expires: %s\n", inv.ExpiresAt)
		fmt.Println()
	}

	return nil
}

func runVaultCancelInvite(cmd *cobra.Command, args []string) error {
	inviteID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	// First, get the invite details to find the vault ID
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	// Get invite to find vault ID
	inviteReq, err := http.NewRequest("GET", apiBase+"/invites/"+inviteID, nil)
	if err != nil {
		return err
	}

	inviteResp, err := doVaultRequest(client, inviteReq, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch invite: %w", err)
	}
	defer inviteResp.Body.Close()

	if inviteResp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("invite not found")
	}

	if inviteResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(inviteResp.Body)
		return fmt.Errorf("failed to fetch invite: %s", string(body))
	}

	// We need to get vaultId from somewhere - the invite details endpoint
	// doesn't return it in the public response, so we need to search our vaults
	fmt.Println("Searching for invite in your vaults...")

	// Get all vaults
	vaultsReq, err := http.NewRequest("GET", apiBase+"/vaults", nil)
	if err != nil {
		return err
	}

	vaultsResp, err := doVaultRequest(client, vaultsReq, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch vaults: %w", err)
	}
	defer vaultsResp.Body.Close()

	var vaultsResult struct {
		Vaults []VaultWithRole `json:"vaults"`
	}
	if err := json.NewDecoder(vaultsResp.Body).Decode(&vaultsResult); err != nil {
		return err
	}

	// Search each vault for the invite
	var foundVaultID string
	for _, vault := range vaultsResult.Vaults {
		if vault.Role != "owner" {
			continue // Only owners can see invites
		}

		invitesReq, err := http.NewRequest("GET", apiBase+"/vaults/"+vault.ID+"/invites", nil)
		if err != nil {
			continue
		}

		invitesResp, err := doVaultRequest(client, invitesReq, &token)
		if err != nil || invitesResp.StatusCode != http.StatusOK {
			if invitesResp != nil {
				invitesResp.Body.Close()
			}
			continue
		}

		var invitesResult struct {
			Invites []VaultInvite `json:"invites"`
		}
		if err := json.NewDecoder(invitesResp.Body).Decode(&invitesResult); err != nil {
			invitesResp.Body.Close()
			continue
		}
		invitesResp.Body.Close()

		for _, inv := range invitesResult.Invites {
			if inv.ID == inviteID {
				foundVaultID = vault.ID
				break
			}
		}

		if foundVaultID != "" {
			break
		}
	}

	if foundVaultID == "" {
		return fmt.Errorf("invite not found in any of your owned vaults")
	}

	// Cancel the invite
	cancelReq, err := http.NewRequest("DELETE", apiBase+"/vaults/"+foundVaultID+"/invites/"+inviteID, nil)
	if err != nil {
		return err
	}

	cancelResp, err := doVaultRequest(client, cancelReq, &token)
	if err != nil {
		return fmt.Errorf("failed to cancel invite: %w", err)
	}
	defer cancelResp.Body.Close()

	if cancelResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(cancelResp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	fmt.Println("Invite cancelled successfully.")
	return nil
}

func runVaultAccept(cmd *cobra.Command, args []string) error {
	inviteID := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	// Get invite details first (to show vault name and inviter)
	fmt.Println("Fetching invite details...")
	inviteReq, err := http.NewRequest("GET", apiBase+"/invites/"+inviteID, nil)
	if err != nil {
		return err
	}

	inviteResp, err := doVaultRequest(client, inviteReq, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch invite: %w", err)
	}
	defer inviteResp.Body.Close()

	if inviteResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(inviteResp.Body)
		return fmt.Errorf("invite error: %s", string(body))
	}

	var inviteDetails struct {
		ID           string `json:"id"`
		VaultName    string `json:"vaultName"`
		InviterEmail string `json:"inviterEmail"`
		InviteeEmail string `json:"inviteeEmail"`
		Status       string `json:"status"`
	}
	if err := json.NewDecoder(inviteResp.Body).Decode(&inviteDetails); err != nil {
		return fmt.Errorf("failed to decode invite: %w", err)
	}

	fmt.Printf("Vault: %s\n", inviteDetails.VaultName)
	fmt.Printf("From: %s\n", inviteDetails.InviterEmail)
	fmt.Println()

	// Accept the invite (no body needed - server gets our public key from profile)
	acceptReq, err := http.NewRequest("POST", apiBase+"/invites/"+inviteID+"/accept", nil)
	if err != nil {
		return err
	}

	acceptResp, err := doVaultRequest(client, acceptReq, &token)
	if err != nil {
		return fmt.Errorf("failed to accept invite: %w", err)
	}
	defer acceptResp.Body.Close()

	if acceptResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(acceptResp.Body)
		return fmt.Errorf("accept failed: %s", string(body))
	}

	fmt.Println("✓ Invite accepted!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. %s will be notified that you accepted\n", inviteDetails.InviterEmail)
	fmt.Println("  2. They will confirm the share and encrypt the vault key for you")
	fmt.Println("  3. Once confirmed, run 'sinesync vault sync' to access the shared vault")

	return nil
}

func runVaultPending(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/invites/", nil)
	if err != nil {
		return err
	}

	resp, err := doVaultRequest(client, req, &token)
	if err != nil {
		return fmt.Errorf("failed to fetch pending invites: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	var result struct {
		Invites []VaultInvite `json:"invites"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	// Reported unconditionally, and before the empty-list return. The owner asks
	// the invitee to compare this AFTER they accept — by which point the invite
	// has moved to awaiting_confirmation and no longer appears below, so gating
	// it on having pending invites would hide it exactly when it is wanted.
	reportOwnKeyFingerprint(token)

	if len(result.Invites) == 0 {
		fmt.Println("No pending vault invites.")
		return nil
	}

	fmt.Println("Your pending vault invites:")
	fmt.Println()
	for _, inv := range result.Invites {
		inviteType := "direct"
		if inv.InviteType == "new_user" {
			inviteType = "requires codes"
		}
		fmt.Printf("  %s\n", inv.VaultName)
		fmt.Printf("    Invite ID: %s\n", inv.ID)
		fmt.Printf("    Type: %s\n", inviteType)
		fmt.Printf("    Expires: %s\n", inv.ExpiresAt)
		fmt.Printf("    Accept: sinesync vault accept %s\n", inv.ID)
		fmt.Println()
	}

	return nil
}

// Causes of a failed own-key derivation that the invitee has to tell apart.
var (
	// errKeypairUnavailable: the server never handed back a usable keypair
	// response — transport failure, non-200, or a body that would not parse.
	errKeypairUnavailable = errors.New("your key material could not be retrieved from the server")

	// errKeyMaterialUnusable: the private key decrypted under our own master
	// key but will not yield a fingerprint.
	errKeyMaterialUnusable = errors.New("your key material is not usable")
)

// ownPublicKey derives this user's X25519 public key from the private key they
// hold, rather than reading it back from the server.
//
// The server's copy of a public key is not evidence of anything. A malicious one
// can return an attacker's key for /users/keypair, and anything sealed to what it
// returned is readable by whoever holds the matching private key — the user would
// be encrypting to a stranger while believing they were encrypting to themselves.
// The private key arrives encrypted to this user's master key, so a substituted
// one simply does not decrypt, which makes the locally derived public key the only
// one worth sealing to.
func ownPublicKey(token string) (string, error) {
	priv, err := fetchAndDecryptPrivateKey(token)
	if err != nil {
		return "", err
	}
	pub, err := crypto.PublicKeyFromPrivate(priv)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errKeyMaterialUnusable, err)
	}
	return pub, nil
}

// ownKeyFingerprint derives this user's fingerprint from their own private key.
//
// Derived, never fetched: a malicious server would report a substituted key's
// fingerprint to both sides and the comparison would agree. The private key
// arrives encrypted to our own master key, so a substituted one simply would
// not decrypt.
func ownKeyFingerprint(token string) (string, error) {
	pub, err := ownPublicKey(token)
	if err != nil {
		return "", err
	}
	fp, err := crypto.KeyFingerprint(pub)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errKeyMaterialUnusable, err)
	}
	return fp, nil
}

// fingerprintFailure explains a failed derivation in terms the invitee can act
// on.
//
// The causes are not interchangeable. A keychain this process cannot read is
// routine, happens with no attacker anywhere near it, and is fixed locally —
// the derivation needs the master key. A server that will not return the key
// material is the adversary this control exists to stop, doing the one thing
// that suppresses the check. Key material that will not decrypt under our own
// master key is the exact shape of a substituted key. Reporting any of these as
// another either wastes the invitee's alarm or spends it in the wrong place.
func fingerprintFailure(err error) (cause string, advice []string) {
	switch {
	case errors.Is(err, encryption.ErrNoKey):
		return "this machine cannot read its own encryption key, so nothing could be decrypted locally", []string{
			"Nothing here points at an attacker: deriving the fingerprint needs your master key, and this machine does not currently have it.",
			"Unlock your login keychain, or run 'sinesync login' on this machine, then run this command again.",
			"'sinesync doctor' reports more about keychain access.",
		}
	case errors.Is(err, errKeypairUnavailable):
		return "the server did not return your key material", []string{
			"This may be an outage. It is also exactly how a compromised server would suppress this check, so it does not get the benefit of the doubt.",
			"Try again. While it keeps failing, do not confirm a vault invite and do not read a fingerprint to anyone.",
		}
	default:
		return "your key material did not decrypt to a usable key", []string{
			"Treat this as suspicious. The key material stored for you is encrypted to your master key, so it should decrypt here; a private key that does not is what a substituted one looks like.",
			"Do not accept or confirm a vault invite until this command prints a fingerprint.",
		}
	}
}

// reportOwnKeyFingerprint shows the invitee the value a vault owner will ask
// them to read back — or, failing that, says so loudly.
//
// Silence is the dangerous outcome, and it is the server that can trigger it:
// the derivation starts with an authenticated GET, so a 500 or a mangled body
// is enough. The owner's side already refuses outright to seal a vault key to a
// public key it cannot fingerprint. The invitee's side is the one that anchors
// trust locally, so it must not degrade to printing nothing — the owner would
// be reading out a fingerprint (possibly a substituted key's) while the invitee
// has nothing to compare and no reason to suspect anything.
//
// The listing still prints: this command is how an invitee finds their invites,
// and withholding them helps no one. The warning goes to stderr so that piping
// or grepping the list cannot swallow it.
func reportOwnKeyFingerprint(token string) {
	fp, err := ownKeyFingerprint(token)
	if err == nil {
		fmt.Printf("Your key fingerprint: %s\n", fp)
		fmt.Println("Anyone sharing a vault with you should see this same value before they confirm.")
		fmt.Println()
		return
	}

	cause, advice := fingerprintFailure(err)
	w := os.Stderr
	fmt.Fprintln(w, "!! Your key fingerprint could NOT be derived.")
	fmt.Fprintf(w, "   Cause:  %s.\n", cause)
	fmt.Fprintf(w, "   Detail: %v\n", err)
	fmt.Fprintln(w)
	for _, line := range advice {
		fmt.Fprintf(w, "   %s\n", line)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "   Until a fingerprint appears here there is nothing for a vault owner to")
	fmt.Fprintln(w, "   check against, and a compromised server can put its own key in place of")
	fmt.Fprintln(w, "   yours without either of you seeing it.")
	fmt.Fprintln(w)
}

// normalizeVaultKey ensures the encrypted vault key is in AES-GCM format.
// Vault owners already have AES-GCM keys. Invited members have X25519-sealed keys
// from the invite confirmation flow. This converts X25519 keys to AES-GCM so that
// vaults.json always contains a consistent format for the daemon and CLI.
func normalizeVaultKey(encryptedKey string, token string) (string, error) {
	encMgr := encryption.GetManager()

	// Try AES-GCM first (vault owner case) — if it works, key is already normalized
	if _, err := encMgr.DecryptVaultKey(encryptedKey); err == nil {
		return encryptedKey, nil
	}

	// AES-GCM failed → try X25519 (invited member case)
	privateKey, err := fetchAndDecryptPrivateKey(token)
	if err != nil {
		return "", fmt.Errorf("cannot decrypt X25519 vault key: %w", err)
	}

	vaultKeyBytes, err := crypto.X25519Open(encryptedKey, privateKey)
	if err != nil {
		return "", fmt.Errorf("X25519 decrypt failed: %w", err)
	}

	// Re-encrypt as AES-GCM so local storage always uses consistent format
	normalized, err := encMgr.EncryptVaultKey(vaultKeyBytes)
	if err != nil {
		return "", fmt.Errorf("re-encrypt vault key: %w", err)
	}

	return normalized, nil
}

// fetchAndDecryptPrivateKey retrieves the user's encrypted X25519 private key
// from the server and decrypts it with the local derived key.
func fetchAndDecryptPrivateKey(token string) (string, error) {
	apiBase := getAPIBase()
	client := &http.Client{Timeout: 10 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/users/keypair", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	httputil.SetClientHeaders(req)

	// Everything the server controls is tagged with errKeypairUnavailable, so a
	// caller can tell "the server gave us nothing to work with" apart from "we
	// have no key to decrypt with" and from "what it gave us is not ours".
	// Those three want different reactions from the user.
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errKeypairUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: keypair fetch returned status %d", errKeypairUnavailable, resp.StatusCode)
	}

	var result struct {
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("%w: keypair response did not parse: %w", errKeypairUnavailable, err)
	}

	encMgr := encryption.GetManager()
	return encMgr.DecryptUserPrivateKey(result.EncryptedPrivateKey)
}

// reportMigrationOutcome prints what happened to a migration and returns an
// error when anything was refused, so the exit code says so too.
//
// A tick and a zero exit over a 98% failure rate is exactly how a vault
// migration that moved 25 of 2,134 observations read as a success, for as long
// as it did. The per-item reasons come back inside a 200 response, so the only
// thing standing between a silent failure and a legible one is printing them.
func reportMigrationOutcome(w io.Writer, uploaded, failed int, reasons map[string]int) error {
	if failed == 0 {
		fmt.Fprintf(w, "  %d observations uploaded\n", uploaded)
		return nil
	}

	fmt.Fprintf(w, "  %d uploaded, %d refused\n", uploaded, failed)

	type reason struct {
		text string
		n    int
	}
	ordered := make([]reason, 0, len(reasons))
	for text, n := range reasons {
		ordered = append(ordered, reason{text, n})
	}
	// Commonest first, then alphabetically, so the output is stable run to run.
	sort.Slice(ordered, func(a, b int) bool {
		if ordered[a].n != ordered[b].n {
			return ordered[a].n > ordered[b].n
		}
		return ordered[a].text < ordered[b].text
	})
	for _, r := range ordered {
		fmt.Fprintf(w, "    %d x %s\n", r.n, r.text)
	}

	return fmt.Errorf("%d of %d observations were not migrated", failed, uploaded+failed)
}
