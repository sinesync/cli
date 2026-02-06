package cli

import (
	"context"
	"fmt"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage sync configuration",
}

func init() {
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configProjectsCmd)
	configCmd.AddCommand(configExcludeCmd)
	configCmd.AddCommand(configIncludeCmd)
	configCmd.AddCommand(configIncludeOnlyCmd)
	configCmd.AddCommand(configClearFiltersCmd)
}

var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Show current configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		fmt.Println("\nsine~sync configuration")
		fmt.Println("────────────────────────────────────────")
		mode := cfg.Mode
		if mode == "" {
			mode = "standalone"
		}
		fmt.Printf("\nMode: %s\n", mode)

		if cfg.Sync != nil {
			fmt.Println("\nSync settings:")
			if len(cfg.Sync.ExcludeProjects) > 0 {
				fmt.Printf("  Excluded projects: %v\n", cfg.Sync.ExcludeProjects)
			}
			if len(cfg.Sync.IncludeProjects) > 0 {
				fmt.Printf("  Include only: %v\n", cfg.Sync.IncludeProjects)
			}
			if len(cfg.Sync.ExcludeProjects) == 0 && len(cfg.Sync.IncludeProjects) == 0 {
				fmt.Println("  All projects synced (no filters)")
			}
		} else {
			fmt.Println("\nSync settings: all projects synced (no filters)")
		}

		fmt.Println()
		return nil
	},
}

var configProjectsCmd = &cobra.Command{
	Use:   "projects",
	Short: "List available projects from memory adapters",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, _ := config.Load()

		fmt.Println("\nAvailable projects")
		fmt.Println("────────────────────────────────────────────────────────────")

		if !adapters.IsClaudeMemInstalled() {
			fmt.Println("\n[claude-mem] Not installed")
			fmt.Println()
			return nil
		}

		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err != nil || adapter == nil {
			fmt.Println("\n[claude-mem] Could not open database")
			fmt.Println()
			return nil
		}
		defer adapter.Close()

		ctx := context.Background()
		projects, err := adapter.GetProjects(ctx)
		if err != nil {
			return err
		}

		fmt.Println("\n[claude-mem]")
		if len(projects) == 0 {
			fmt.Println("  No projects found")
		} else {
			fmt.Printf("  %-30s %8s %12s\n", "Project", "Count", "Last Activity")
			fmt.Printf("  %s %s %s\n",
				"------------------------------",
				"--------",
				"------------")

			for _, p := range projects {
				status := ""
				if cfg.Sync != nil {
					for _, ex := range cfg.Sync.ExcludeProjects {
						if ex == p.Name {
							status = " [excluded]"
							break
						}
					}
				}

				date := p.LastActivity
				if len(date) > 10 {
					date = date[:10]
				}

				name := p.Name + status
				if len(name) > 30 {
					name = name[:30]
				}

				fmt.Printf("  %-30s %8d %12s\n", name, p.Count, date)
			}
		}

		fmt.Println()
		return nil
	},
}

var configExcludeCmd = &cobra.Command{
	Use:   "exclude <project>",
	Short: "Exclude a project from sync",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		project := args[0]
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if cfg.Sync == nil {
			cfg.Sync = &config.SyncConfig{}
		}

		// Check if already excluded
		for _, p := range cfg.Sync.ExcludeProjects {
			if p == project {
				fmt.Printf("Project %q is already excluded\n", project)
				return nil
			}
		}

		cfg.Sync.ExcludeProjects = append(cfg.Sync.ExcludeProjects, project)

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Project %q will be excluded from sync\n", project)
		return nil
	},
}

var configIncludeCmd = &cobra.Command{
	Use:   "include <project>",
	Short: "Include a project in sync (remove from exclusions)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		project := args[0]
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if cfg.Sync == nil {
			fmt.Printf("Project %q is already included (no exclusions set)\n", project)
			return nil
		}

		// Remove from exclusions
		newExclusions := []string{}
		found := false
		for _, p := range cfg.Sync.ExcludeProjects {
			if p == project {
				found = true
			} else {
				newExclusions = append(newExclusions, p)
			}
		}
		cfg.Sync.ExcludeProjects = newExclusions

		if !found {
			fmt.Printf("Project %q is already included\n", project)
			return nil
		}

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Project %q will now be synced\n", project)
		return nil
	},
}

var configIncludeOnlyCmd = &cobra.Command{
	Use:   "include-only <project> [project2...]",
	Short: "Only sync specified projects (exclude all others)",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		if cfg.Sync == nil {
			cfg.Sync = &config.SyncConfig{}
		}

		cfg.Sync.IncludeProjects = args
		cfg.Sync.ExcludeProjects = nil // Clear exclusions

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Printf("✓ Only syncing: %v\n", args)
		fmt.Println("  (all other projects will be ignored)")
		return nil
	},
}

var configClearFiltersCmd = &cobra.Command{
	Use:   "clear-filters",
	Short: "Clear all project filters (sync everything)",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		cfg.Sync = nil

		if err := config.Save(cfg); err != nil {
			return err
		}

		fmt.Println("✓ All project filters cleared - all projects will sync")
		return nil
	},
}
