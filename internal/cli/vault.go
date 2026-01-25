package cli

import (
	"fmt"
	"strings"

	"github.com/miclip/sinesync/internal/config"
	"github.com/spf13/cobra"
)

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Manage sync vaults (like 1Password vaults)",
	Long: `Vaults are encrypted storage destinations for your memories.

By default, you have a "personal" vault. You can create additional vaults
for teams or projects, each with its own encryption key and storage backend.

Examples:
  sinesync vault list                    # List all vaults
  sinesync vault create team-acme        # Create a new vault
  sinesync vault route conductor team-acme  # Route a project to vault
  sinesync vault set-backend team-acme s3   # Use S3 for storage`,
}

func init() {
	vaultCmd.AddCommand(vaultListCmd)
	vaultCmd.AddCommand(vaultCreateCmd)
	vaultCmd.AddCommand(vaultDeleteCmd)
	vaultCmd.AddCommand(vaultRouteCmd)
	vaultCmd.AddCommand(vaultUnrouteCmd)
	vaultCmd.AddCommand(vaultRoutesCmd)
	vaultCmd.AddCommand(vaultSetBackendCmd)
	vaultCmd.AddCommand(vaultInfoCmd)
}

var vaultListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all vaults",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		fmt.Println("\nVaults")
		fmt.Println("─────────────────────────────────────────────────────")

		if len(cfg.Vaults) == 0 {
			fmt.Println("\n  No vaults configured")
			fmt.Println()
			return nil
		}

		fmt.Printf("\n  %-15s %-10s %-12s %s\n", "ID", "Type", "Backend", "Routes")
		fmt.Printf("  %s %s %s %s\n",
			strings.Repeat("-", 15),
			strings.Repeat("-", 10),
			strings.Repeat("-", 12),
			strings.Repeat("-", 20))

		for _, vault := range cfg.Vaults {
			// Count routes to this vault
			routeCount := 0
			for _, v := range cfg.Routes {
				if v == vault.ID {
					routeCount++
				}
			}

			backendType := "sinesync"
			if vault.Backend != nil {
				backendType = vault.Backend.Type
			}

			defaultMark := ""
			if vault.ID == cfg.DefaultVault {
				defaultMark = " (default)"
			}

			fmt.Printf("  %-15s %-10s %-12s %d projects%s\n",
				vault.ID, vault.Type, backendType, routeCount, defaultMark)
		}

		fmt.Println()
		return nil
	},
}

var vaultCreateCmd = &cobra.Command{
	Use:   "create <vault-id>",
	Short: "Create a new vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultID := args[0]
		vaultType, _ := cmd.Flags().GetString("type")
		backendType, _ := cmd.Flags().GetString("backend")

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		// Check if vault already exists
		if cfg.GetVault(vaultID) != nil {
			return fmt.Errorf("vault %q already exists", vaultID)
		}

		vault := &config.Vault{
			ID:   vaultID,
			Name: vaultID,
			Type: vaultType,
			Backend: &config.Backend{
				Type: backendType,
			},
		}

		cfg.AddVault(vault)

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Created vault %q\n", vaultID)
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Printf("  1. Generate encryption key: sinesync vault keygen %s\n", vaultID)
		if backendType != "sinesync" {
			fmt.Printf("  2. Configure backend: sinesync vault set-backend %s %s --bucket <bucket>\n", vaultID, backendType)
		}
		fmt.Printf("  3. Route projects: sinesync vault route <project> %s\n", vaultID)

		return nil
	},
}

func init() {
	vaultCreateCmd.Flags().String("type", "personal", "Vault type: personal or shared")
	vaultCreateCmd.Flags().String("backend", "sinesync", "Backend type: sinesync, s3, azure, local")
}

var vaultDeleteCmd = &cobra.Command{
	Use:   "delete <vault-id>",
	Short: "Delete a vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultID := args[0]
		force, _ := cmd.Flags().GetBool("force")

		if vaultID == "personal" && !force {
			return fmt.Errorf("cannot delete personal vault (use --force to override)")
		}

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if cfg.GetVault(vaultID) == nil {
			return fmt.Errorf("vault %q not found", vaultID)
		}

		cfg.RemoveVault(vaultID)

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Deleted vault %q\n", vaultID)
		return nil
	},
}

func init() {
	vaultDeleteCmd.Flags().Bool("force", false, "Force deletion")
}

var vaultRouteCmd = &cobra.Command{
	Use:   "route <project> <vault-id>",
	Short: "Route a project to a specific vault",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		project := args[0]
		vaultID := args[1]

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if cfg.GetVault(vaultID) == nil {
			return fmt.Errorf("vault %q not found", vaultID)
		}

		cfg.SetRoute(project, vaultID)

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Project %q will sync to vault %q\n", project, vaultID)
		return nil
	},
}

var vaultUnrouteCmd = &cobra.Command{
	Use:   "unroute <project>",
	Short: "Remove project routing (use default vault)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		project := args[0]

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		cfg.ClearRoute(project)

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Project %q will now use default vault (%s)\n", project, cfg.DefaultVault)
		return nil
	},
}

var vaultRoutesCmd = &cobra.Command{
	Use:   "routes",
	Short: "Show all project-to-vault routes",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		fmt.Println("\nProject Routes")
		fmt.Println("─────────────────────────────────────────────────────")

		if len(cfg.Routes) == 0 {
			fmt.Printf("\n  No explicit routes. All projects → %s (default)\n", cfg.DefaultVault)
			fmt.Println()
			return nil
		}

		fmt.Printf("\n  %-30s → %s\n", "Project", "Vault")
		fmt.Printf("  %s   %s\n",
			strings.Repeat("-", 30),
			strings.Repeat("-", 15))

		for project, vault := range cfg.Routes {
			fmt.Printf("  %-30s → %s\n", project, vault)
		}

		fmt.Printf("\n  (unrouted projects → %s)\n", cfg.DefaultVault)
		fmt.Println()
		return nil
	},
}

var vaultSetBackendCmd = &cobra.Command{
	Use:   "set-backend <vault-id> <backend-type>",
	Short: "Configure storage backend for a vault",
	Long: `Configure where a vault stores its encrypted data.

Backend types:
  sinesync  - Managed sinesync cloud (default)
  s3        - S3-compatible (AWS, MinIO, Backblaze B2, R2)
  azure     - Azure Blob Storage
  local     - Local filesystem (for testing or NAS)

Examples:
  # Use AWS S3
  sinesync vault set-backend team-acme s3 \
    --bucket my-bucket \
    --region us-west-2

  # Use MinIO
  sinesync vault set-backend team-acme s3 \
    --endpoint http://minio.local:9000 \
    --bucket memories \
    --access-key mykey \
    --secret-key mysecret

  # Use local filesystem
  sinesync vault set-backend test local --path /mnt/nas/sinesync`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultID := args[0]
		backendType := args[1]

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		vault := cfg.GetVault(vaultID)
		if vault == nil {
			return fmt.Errorf("vault %q not found", vaultID)
		}

		backend := &config.Backend{Type: backendType}

		// S3 options
		if bucket, _ := cmd.Flags().GetString("bucket"); bucket != "" {
			backend.Bucket = bucket
		}
		if region, _ := cmd.Flags().GetString("region"); region != "" {
			backend.Region = region
		}
		if endpoint, _ := cmd.Flags().GetString("endpoint"); endpoint != "" {
			backend.Endpoint = endpoint
		}
		if accessKey, _ := cmd.Flags().GetString("access-key"); accessKey != "" {
			backend.AccessKey = accessKey
		}
		if secretKey, _ := cmd.Flags().GetString("secret-key"); secretKey != "" {
			backend.SecretKey = secretKey
		}

		// Azure options
		if container, _ := cmd.Flags().GetString("container"); container != "" {
			backend.Container = container
		}
		if accountName, _ := cmd.Flags().GetString("account-name"); accountName != "" {
			backend.AccountName = accountName
		}

		// Local options
		if path, _ := cmd.Flags().GetString("path"); path != "" {
			backend.Path = path
		}

		vault.Backend = backend

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Vault %q now uses %s backend\n", vaultID, backendType)
		return nil
	},
}

func init() {
	// S3 flags
	vaultSetBackendCmd.Flags().String("bucket", "", "S3 bucket name")
	vaultSetBackendCmd.Flags().String("region", "", "AWS region")
	vaultSetBackendCmd.Flags().String("endpoint", "", "Custom S3 endpoint (for MinIO, R2, etc.)")
	vaultSetBackendCmd.Flags().String("access-key", "", "Access key ID")
	vaultSetBackendCmd.Flags().String("secret-key", "", "Secret access key")

	// Azure flags
	vaultSetBackendCmd.Flags().String("container", "", "Azure container name")
	vaultSetBackendCmd.Flags().String("account-name", "", "Azure account name")

	// Local flags
	vaultSetBackendCmd.Flags().String("path", "", "Local filesystem path")
}

var vaultInfoCmd = &cobra.Command{
	Use:   "info <vault-id>",
	Short: "Show vault details",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		vaultID := args[0]

		cfg, err := config.Load()
		if err != nil {
			return err
		}

		vault := cfg.GetVault(vaultID)
		if vault == nil {
			return fmt.Errorf("vault %q not found", vaultID)
		}

		fmt.Printf("\nVault: %s\n", vault.ID)
		fmt.Println("─────────────────────────────────────────────────────")
		fmt.Printf("  Name:     %s\n", vault.Name)
		fmt.Printf("  Type:     %s\n", vault.Type)

		if vault.Backend != nil {
			fmt.Printf("\n  Backend:  %s\n", vault.Backend.Type)
			switch vault.Backend.Type {
			case "s3":
				if vault.Backend.Endpoint != "" {
					fmt.Printf("  Endpoint: %s\n", vault.Backend.Endpoint)
				}
				fmt.Printf("  Bucket:   %s\n", vault.Backend.Bucket)
				if vault.Backend.Region != "" {
					fmt.Printf("  Region:   %s\n", vault.Backend.Region)
				}
			case "azure":
				fmt.Printf("  Container: %s\n", vault.Backend.Container)
				fmt.Printf("  Account:   %s\n", vault.Backend.AccountName)
			case "local":
				fmt.Printf("  Path:     %s\n", vault.Backend.Path)
			}
		}

		if vault.TeamID != "" {
			fmt.Printf("\n  Team:     %s\n", vault.TeamName)
			if len(vault.Members) > 0 {
				fmt.Printf("  Members:  %d\n", len(vault.Members))
			}
		}

		// Show routes to this vault
		routedProjects := []string{}
		for project, v := range cfg.Routes {
			if v == vaultID {
				routedProjects = append(routedProjects, project)
			}
		}
		if len(routedProjects) > 0 {
			fmt.Printf("\n  Routed projects:\n")
			for _, p := range routedProjects {
				fmt.Printf("    • %s\n", p)
			}
		}

		fmt.Println()
		return nil
	},
}
