package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/crypto"
	"github.com/miclip/sinesync/internal/encryption"
	"github.com/spf13/cobra"
	kr "github.com/zalando/go-keyring"
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

type VaultProject struct {
	ID          string `json:"id"`
	VaultID     string `json:"vaultId"`
	ProjectName string `json:"projectName"`
	CreatedAt   string `json:"createdAt"`
}

type VaultMember struct {
	ID                string `json:"id"`
	VaultID           string `json:"vaultId"`
	UserID            string `json:"userId"`
	EncryptedVaultKey string `json:"encryptedVaultKey"`
	Role              string `json:"role"`
	JoinedAt          string `json:"joinedAt"`
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
	Args:  cobra.ExactArgs(2),
	RunE:  runVaultAddProject,
}

var vaultRemoveProjectCmd = &cobra.Command{
	Use:   "remove-project <vault-id> <project-name>",
	Short: "Remove a project from a vault",
	Args:  cobra.ExactArgs(2),
	RunE:  runVaultRemoveProject,
}

var vaultSyncCmd = &cobra.Command{
	Use:   "sync",
	Short: "Sync vault keys from server",
	Long:  `Fetch and store encrypted vault keys from the server.`,
	RunE:  runVaultSync,
}

func init() {
	rootCmd.AddCommand(vaultCmd)
	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultCreateCmd)
	vaultCmd.AddCommand(vaultDeleteCmd)
	vaultCmd.AddCommand(vaultProjectsCmd)
	vaultCmd.AddCommand(vaultAddProjectCmd)
	vaultCmd.AddCommand(vaultRemoveProjectCmd)
	vaultCmd.AddCommand(vaultSyncCmd)
}

func runVaultList(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/vaults", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
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

	return nil
}

func runVaultCreate(cmd *cobra.Command, args []string) error {
	name := args[0]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
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
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
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
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
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

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", apiBase+"/vaults/"+vaultID+"/projects", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch projects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	var result struct {
		Projects []VaultProject `json:"projects"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	if len(result.Projects) == 0 {
		fmt.Println("No projects in this vault.")
		return nil
	}

	fmt.Println("Projects in vault:")
	for _, p := range result.Projects {
		fmt.Printf("  - %s\n", p.ProjectName)
	}

	return nil
}

func runVaultAddProject(cmd *cobra.Command, args []string) error {
	vaultID := args[0]
	projectName := args[1]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	body, err := json.Marshal(map[string]string{"projectName": projectName})
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}
	req, err := http.NewRequest("POST", apiBase+"/vaults/"+vaultID+"/projects", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to add project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(respBody))
	}

	// Update local config
	addProjectToLocalVault(vaultID, projectName)

	fmt.Printf("✓ Added project '%s' to vault\n", projectName)
	return nil
}

func runVaultRemoveProject(cmd *cobra.Command, args []string) error {
	vaultID := args[0]
	projectName := args[1]

	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("DELETE", apiBase+"/vaults/"+vaultID+"/projects/"+url.PathEscape(projectName), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to remove project: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error: %s", string(body))
	}

	// Update local config
	removeProjectFromLocalVault(vaultID, projectName)

	fmt.Printf("✓ Removed project '%s' from vault\n", projectName)
	return nil
}

func runVaultSync(cmd *cobra.Command, args []string) error {
	token, err := getAuthTokenForVault()
	if err != nil {
		return fmt.Errorf("not logged in: %w", err)
	}

	fmt.Println("Syncing vault keys...")

	apiBase := getAPIBase()
	client := &http.Client{Timeout: 30 * time.Second}

	// Get all vaults
	req, err := http.NewRequest("GET", apiBase+"/vaults", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
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

	// For each vault, get the encrypted key and projects
	localConfig := LocalVaultConfig{Vaults: make([]LocalVault, 0)}

	for _, v := range result.Vaults {
		// Get encrypted vault key
		keyReq, err := http.NewRequest("GET", apiBase+"/vaults/"+v.ID+"/key", nil)
		if err != nil {
			fmt.Printf("  Warning: failed to create key request for vault %s: %v\n", v.Name, err)
			continue
		}
		keyReq.Header.Set("Authorization", "Bearer "+token)

		keyResp, err := client.Do(keyReq)
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

		// Get projects
		projReq, err := http.NewRequest("GET", apiBase+"/vaults/"+v.ID+"/projects", nil)
		var projects []string
		if err == nil {
			projReq.Header.Set("Authorization", "Bearer "+token)
			projResp, err := client.Do(projReq)
			if err == nil && projResp.StatusCode == http.StatusOK {
				var projResult struct {
					Projects []VaultProject `json:"projects"`
				}
				if err := json.NewDecoder(projResp.Body).Decode(&projResult); err == nil {
					for _, p := range projResult.Projects {
						projects = append(projects, p.ProjectName)
					}
				}
				projResp.Body.Close()
			} else if projResp != nil {
				projResp.Body.Close()
			}
		}

		localConfig.Vaults = append(localConfig.Vaults, LocalVault{
			VaultID:           v.ID,
			Name:              v.Name,
			EncryptedVaultKey: keyResult.EncryptedVaultKey,
			Projects:          projects,
			IsDefault:         v.IsDefault,
		})

		fmt.Printf("  ✓ %s (%d projects)\n", v.Name, len(projects))
	}

	// Save local config
	if err := saveLocalVaultConfig(&localConfig); err != nil {
		return fmt.Errorf("failed to save vault config: %w", err)
	}

	fmt.Printf("\n✓ Synced %d vaults\n", len(localConfig.Vaults))
	return nil
}

// Helper functions

func getAuthTokenForVault() (string, error) {
	// Check keyring
	if token, err := kr.Get(keyringService, "deviceToken"); err == nil && token != "" {
		return token, nil
	}
	if token, err := kr.Get(keyringService, "token"); err == nil && token != "" {
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
