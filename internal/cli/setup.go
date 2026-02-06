package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/daemon"
	"github.com/miclip/sinesync/internal/storage"
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

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Detect adapters and determine mode
	fmt.Println("\n1. Detecting mode...")

	registry := adapters.DefaultRegistry()
	available := registry.Available()
	defer registry.Close()

	mode := "standalone"

	if len(available) > 0 {
		// Show detected adapters
		fmt.Println("   Memory tools detected:")
		for _, a := range available {
			countStr := ""
			if c, ok := a.(adapters.Countable); ok {
				if count, err := c.GetObservationCount(); err == nil {
					countStr = fmt.Sprintf(" (%d observations)", count)
				}
			}
			fmt.Printf("     • %s%s\n", a.Name(), countStr)
		}

		// Prompt for mode
		fmt.Println("")
		fmt.Println("   Which mode would you like?")
		fmt.Println("     1. Standalone (recommended) — sinesync handles all memory")
		fmt.Printf("     2. Adapter (%s) — existing tool handles memory, sinesync adds sync\n", available[0].Name())
		fmt.Print("   Choice [1]: ")

		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		if choice == "2" {
			mode = "adapter"
			fmt.Println("   → Using adapter mode")
		} else {
			mode = "standalone"
			fmt.Println("   → Using standalone mode")

			// Force a final import from adapters to catch any observations since last sync
			fmt.Println("   Importing latest observations from adapters...")
			if err := runImport(nil, nil); err != nil {
				fmt.Printf("   ✗ Import failed: %v\n", err)
			} else {
				fmt.Println("   ✓ Import complete")
			}
		}
	} else {
		fmt.Println("   ✗ No memory tools found")
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
	adapterMode := mode == "adapter"
	err = configureAllHooks(binaryPath, adapterMode)
	if err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		if adapterMode {
			fmt.Println("   ✓ PreCompact hook (import observations)")
			fmt.Println("   ✓ SessionStart hook (inject context on compact)")
		} else {
			fmt.Println("   ✓ SessionStart hook (inject context)")
			fmt.Println("   ✓ PostToolUse hook (capture observations)")
			fmt.Println("   ✓ UserPromptSubmit hook (record prompts)")
			fmt.Println("   ✓ Stop hook (session summary)")
		}
	}

	// Step 4: Save config
	fmt.Println("\n4. Saving configuration...")
	cfg, _ := config.Load()
	previousMode := cfg.Mode // capture before mutation
	cfg.Mode = mode
	cfg.ClaudeMemMode = false // Clear deprecated field
	if err := config.Save(cfg); err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Printf("   ✓ Config saved to %s\n", config.ConfigPath())
	}

	// Step 5: Reset sync manifest if switching to standalone from a different mode
	if mode == "standalone" && previousMode != "standalone" {
		fmt.Println("\n5. Resetting sync manifest for new backend...")
		syncManifest := storage.GetSyncManifest()
		syncManifest.ClearSeenIDs()
		if err := syncManifest.Save(); err != nil {
			fmt.Printf("   ✗ Failed to save manifest: %v\n", err)
		} else {
			fmt.Println("   ✓ Sync manifest reset (cloud sync will re-pull all observations)")
		}
	}

	// Step 6: Restart daemon (must restart so manifest reset takes effect)
	fmt.Println("\n6. Restarting daemon...")
	stopCmd := exec.Command(binaryPath, "daemon", "stop")
	stopCmd.CombinedOutput() // ignore error if not running
	startCmd := exec.Command(binaryPath, "daemon", "start")
	if output, err := startCmd.CombinedOutput(); err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Printf("   %s", string(output))
	}

	// Step 7: Force cloud sync (pushes imported observations, pulls from other devices)
	if mode == "standalone" {
		fmt.Println("\n7. Syncing with cloud...")
		if err := triggerDaemonSync(daemon.DefaultPort); err != nil {
			fmt.Printf("   ✗ Sync trigger failed: %v\n", err)
		} else {
			fmt.Println("   ✓ Cloud sync triggered")
		}
	}

	// Summary
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("Setup complete!")
	fmt.Println("")
	if adapterMode {
		fmt.Printf("Mode: adapter (%s)\n", available[0].Name())
		fmt.Printf("  • Memory tools: %s\n", available[0].Name())
		fmt.Println("  • Sync tools: sinesync MCP")
		fmt.Println("  • Auto-import from adapter on compact")
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

// triggerDaemonSync sends a POST to the daemon's sync endpoint to force an immediate sync.
func triggerDaemonSync(port int) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(fmt.Sprintf("http://127.0.0.1:%d/api/sync", port), "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

func registerMCPServer(binaryPath string) error {
	// Remove existing entry first (idempotent - ignore errors if not found)
	rmCmd := exec.Command("claude", "mcp", "remove", "--scope", "user", "sinesync")
	rmCmd.CombinedOutput()

	// Use 'claude mcp add' CLI to register in the correct location (~/.claude.json)
	cmd := exec.Command("claude", "mcp", "add", "--transport", "stdio", "--scope", "user", "sinesync", "--", binaryPath, "mcp", "start")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}

	// Clean up stale mcpServers entry from settings.json (old setup wrote there)
	settingsPath := getClaudeSettingsPath()
	var settings map[string]interface{}
	data, readErr := os.ReadFile(settingsPath)
	if readErr == nil {
		if err := json.Unmarshal(data, &settings); err == nil {
			if mcpServers, ok := settings["mcpServers"].(map[string]interface{}); ok {
				delete(mcpServers, "sinesync")
				if len(mcpServers) == 0 {
					delete(settings, "mcpServers")
				}
				out, _ := json.MarshalIndent(settings, "", "  ")
				os.WriteFile(settingsPath, out, 0644)
			}
		}
	}

	return nil
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
		delete(hooks, "UserPromptSubmit")
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
		hooks["UserPromptSubmit"] = []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": binaryPath + " prompt",
						"timeout": 10,
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
