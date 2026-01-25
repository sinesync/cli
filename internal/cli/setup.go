package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/spf13/cobra"
)

// Claude settings structure
type ClaudeSettings struct {
	McpServers map[string]MCPServerConfig `json:"mcpServers,omitempty"`
	Hooks      *HooksConfig               `json:"hooks,omitempty"`
}

type MCPServerConfig struct {
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}

type HooksConfig struct {
	SessionEnd []HookEntry `json:"SessionEnd,omitempty"`
}

type HookEntry struct {
	Matcher string       `json:"matcher"`
	Hooks   []HookAction `json:"hooks"`
}

type HookAction struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

func runSetup(cmd *cobra.Command, args []string) error {
	fmt.Println("sine~sync setup")
	fmt.Println("─────────────────────────────────────────")

	// Get binary path
	binaryPath, err := exec.LookPath("sinesync")
	if err != nil {
		// Try current directory
		binaryPath, _ = filepath.Abs("./sinesync")
	}

	claudeMemInstalled := adapters.IsClaudeMemInstalled()

	// Step 1: Check claude-mem
	fmt.Println("\n1. Checking for claude-mem...")
	if claudeMemInstalled {
		adapter, _ := adapters.NewClaudeMemAdapter(true)
		if adapter != nil && adapter.IsAvailable() {
			count, _ := adapter.GetObservationCount()
			fmt.Printf("   ✓ claude-mem found (%d observations)\n", count)
			adapter.Close()
		}
	} else {
		fmt.Println("   ✗ claude-mem not found (will run in standalone mode)")
	}

	// Step 2: Register MCP server
	fmt.Println("\n2. Registering MCP server with Claude Code...")
	err = registerMCPServer(binaryPath)
	if err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
		fmt.Println("   You can manually add to ~/.claude/settings.json")
	} else {
		fmt.Println("   ✓ MCP server registered")
	}

	// Step 3: Configure hooks
	fmt.Println("\n3. Configuring SessionEnd hook...")
	err = configureHooks(binaryPath, claudeMemInstalled)
	if err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Println("   ✓ SessionEnd hook configured")
	}

	// Step 4: Save config
	fmt.Println("\n4. Saving configuration...")
	cfg := &config.Config{
		ClaudeMemMode: claudeMemInstalled,
	}
	if err := config.Save(cfg); err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Printf("   ✓ Config saved to %s\n", config.ConfigPath())
	}

	// Summary
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("Setup complete!")
	fmt.Println("")
	if claudeMemInstalled {
		fmt.Println("Mode: claude-mem")
		fmt.Println("  • Memory tools provided by claude-mem")
		fmt.Println("  • Sync tools provided by sinesync")
		fmt.Println("  • Observations imported every 10 minutes")
		fmt.Println("  • Full sync on session end")
	} else {
		fmt.Println("Mode: standalone")
		fmt.Println("  • Memory + sync tools provided by sinesync")
	}
	fmt.Println("")
	fmt.Println("Restart Claude Code to apply changes.")

	return nil
}

func registerMCPServer(binaryPath string) error {
	settingsPath := getClaudeSettingsPath()

	// Read existing settings
	settings := ClaudeSettings{
		McpServers: make(map[string]MCPServerConfig),
	}

	data, err := os.ReadFile(settingsPath)
	if err == nil {
		json.Unmarshal(data, &settings)
	}

	if settings.McpServers == nil {
		settings.McpServers = make(map[string]MCPServerConfig)
	}

	// Add sinesync server
	settings.McpServers["sinesync"] = MCPServerConfig{
		Command: binaryPath,
		Args:    []string{"mcp", "start"},
	}

	// Write back
	return writeClaudeSettings(settingsPath, &settings)
}

func configureHooks(binaryPath string, claudeMemMode bool) error {
	settingsPath := getClaudeSettingsPath()

	// Read existing settings
	settings := ClaudeSettings{}
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		json.Unmarshal(data, &settings)
	}

	if settings.Hooks == nil {
		settings.Hooks = &HooksConfig{}
	}

	// Check if already configured
	for _, hook := range settings.Hooks.SessionEnd {
		for _, action := range hook.Hooks {
			if action.Command == binaryPath+" sync-session" {
				return nil // Already configured
			}
		}
	}

	// Add SessionEnd hook
	settings.Hooks.SessionEnd = append(settings.Hooks.SessionEnd, HookEntry{
		Matcher: "",
		Hooks: []HookAction{
			{
				Type:    "command",
				Command: binaryPath + " sync-session",
			},
		},
	})

	return writeClaudeSettings(settingsPath, &settings)
}

func getClaudeSettingsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude", "settings.json")
}

func writeClaudeSettings(path string, settings *ClaudeSettings) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}
