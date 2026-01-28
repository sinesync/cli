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
	fmt.Println("\n1. Detecting mode...")
	if claudeMemInstalled {
		adapter, _ := adapters.NewClaudeMemAdapter(true)
		if adapter != nil && adapter.IsAvailable() {
			count, _ := adapter.GetObservationCount()
			fmt.Printf("   ✓ claude-mem found (%d observations)\n", count)
			fmt.Println("   → Using adapter mode")
			adapter.Close()
		}
	} else {
		fmt.Println("   ✗ claude-mem not found")
		fmt.Println("   → Using standalone mode")
	}

	// Step 2: Register MCP server
	fmt.Println("\n2. Registering MCP server...")
	err = registerMCPServer(binaryPath)
	if err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
		fmt.Println("   You can manually add to ~/.claude/settings.json")
	} else {
		fmt.Println("   ✓ MCP server registered")
	}

	// Step 3: Configure hooks based on mode
	fmt.Println("\n3. Configuring Claude Code hooks...")
	err = configureAllHooks(binaryPath, claudeMemInstalled)
	if err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		if claudeMemInstalled {
			fmt.Println("   ✓ PreCompact hook (import observations)")
			fmt.Println("   ✓ SessionStart hook (inject context on compact)")
		} else {
			fmt.Println("   ✓ SessionStart hook (inject context)")
			fmt.Println("   ✓ PostToolUse hook (capture observations)")
			fmt.Println("   ✓ Stop hook (session summary)")
		}
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

	// Step 5: Start daemon
	fmt.Println("\n5. Starting daemon...")
	startCmd := exec.Command(binaryPath, "daemon", "start")
	if output, err := startCmd.CombinedOutput(); err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Printf("   %s", string(output))
	}

	// Summary
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("Setup complete!")
	fmt.Println("")
	if claudeMemInstalled {
		fmt.Println("Mode: adapter (claude-mem)")
		fmt.Println("  • Memory tools: claude-mem")
		fmt.Println("  • Sync tools: sinesync MCP")
		fmt.Println("  • Auto-import from claude-mem on compact")
		fmt.Println("  • Background sync every 10 minutes")
	} else {
		fmt.Println("Mode: standalone")
		fmt.Println("  • Memory + sync: sinesync")
		fmt.Println("  • Captures observations from all tool use")
		fmt.Println("  • Background sync every 10 minutes")
	}
	fmt.Println("")
	fmt.Println("Dashboard: http://127.0.0.1:5741")
	fmt.Println("")
	fmt.Println("Restart Claude Code to apply changes.")

	return nil
}

func registerMCPServer(binaryPath string) error {
	settingsPath := getClaudeSettingsPath()

	// Read existing settings as raw JSON to preserve all fields
	var settings map[string]interface{}
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		json.Unmarshal(data, &settings)
	}
	if settings == nil {
		settings = make(map[string]interface{})
	}

	// Get or create mcpServers section
	mcpServers, ok := settings["mcpServers"].(map[string]interface{})
	if !ok {
		mcpServers = make(map[string]interface{})
	}

	// Add sinesync server
	mcpServers["sinesync"] = map[string]interface{}{
		"type":    "stdio",
		"command": binaryPath,
		"args":    []string{"mcp", "start"},
	}

	settings["mcpServers"] = mcpServers

	// Write back preserving all fields
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, output, 0644)
}

func configureAllHooks(binaryPath string, claudeMemMode bool) error {
	settingsPath := getClaudeSettingsPath()

	// Read existing settings as raw JSON to preserve other fields
	var settings map[string]interface{}
	data, err := os.ReadFile(settingsPath)
	if err == nil {
		json.Unmarshal(data, &settings)
	}
	if settings == nil {
		settings = make(map[string]interface{})
	}

	// Get or create hooks section
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		hooks = make(map[string]interface{})
	}

	if claudeMemMode {
		// Adapter mode - import from claude-mem
		hooks["PreCompact"] = []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": binaryPath + " import",
						"timeout": 120,
					},
				},
			},
		}
		hooks["SessionStart"] = []map[string]interface{}{
			{
				"matcher": "compact",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": binaryPath + " context",
						"timeout": 30,
					},
				},
			},
		}
		// Remove standalone-mode hooks that may exist from previous setup
		delete(hooks, "PostToolUse")
		delete(hooks, "Stop")
	} else {
		// Standalone mode - full capture
		hooks["SessionStart"] = []map[string]interface{}{
			{
				"matcher": "startup|clear|compact",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": binaryPath + " context",
						"timeout": 60,
					},
				},
			},
		}
		hooks["PostToolUse"] = []map[string]interface{}{
			{
				"matcher": "*",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": binaryPath + " capture",
						"timeout": 30,
					},
				},
			},
		}
		hooks["Stop"] = []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": binaryPath + " summarize",
						"timeout": 60,
					},
				},
			},
		}
		// Remove adapter-mode hook that may exist from previous setup
		delete(hooks, "PreCompact")
	}

	settings["hooks"] = hooks

	// Write back
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(settingsPath, output, 0644)
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
