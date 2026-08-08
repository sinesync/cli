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

	toml "github.com/pelletier/go-toml/v2"

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

	// Resolve the binary path for hook/MCP configuration.
	// Prefer os.Executable() for the actual running binary, but detect
	// temporary paths from "go run" and fall back to PATH lookup.
	binaryPath, err := os.Executable()
	if err == nil {
		// Detect "go run" temp binaries — they won't exist after the process exits
		if strings.Contains(binaryPath, "/go-build") || strings.Contains(binaryPath, "\\go-build") {
			if lp, lpErr := exec.LookPath("sinesync"); lpErr == nil {
				binaryPath = lp
			} else {
				return fmt.Errorf("running via 'go run' and sinesync is not on PATH — please install the binary first")
			}
		}
	} else {
		// os.Executable() failed — fall back to PATH lookup
		if lp, lpErr := exec.LookPath("sinesync"); lpErr == nil {
			binaryPath = lp
		} else {
			return fmt.Errorf("unable to determine sinesync binary path: %w", err)
		}
	}
	if _, statErr := os.Stat(binaryPath); statErr != nil {
		return fmt.Errorf("sinesync binary not found at %q: %w", binaryPath, statErr)
	}

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Detect AI coding tools and adapters
	fmt.Println("\n1. Detecting AI coding tools...")

	// Detect supported coding tools
	hasClaudeCode := false
	if _, err := exec.LookPath("claude"); err == nil {
		hasClaudeCode = true
		fmt.Println("   ✓ Claude Code")
	}
	hasCodex := false
	if _, err := exec.LookPath("codex"); err == nil {
		hasCodex = true
		fmt.Println("   ✓ OpenAI Codex")
	}
	hasCursor := false
	if _, err := exec.LookPath("cursor"); err == nil {
		hasCursor = true
	} else if home, err := os.UserHomeDir(); err == nil && home != "" {
		if _, err := os.Stat(filepath.Join(home, ".cursor")); err == nil {
			hasCursor = true
		}
	}
	if hasCursor {
		fmt.Println("   ✓ Cursor")
	}
	if !hasClaudeCode && !hasCodex && !hasCursor {
		fmt.Println("   ✗ No supported AI coding tools found")
	}

	// Detect memory adapters
	registry := adapters.DefaultRegistry()
	available := registry.Available()
	defer registry.Close()

	mode := "standalone"

	if len(available) > 0 {
		fmt.Println("\n   Memory tools detected:")
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
		fmt.Println("   → Using standalone mode")
	}

	adapterMode := mode == "adapter"

	// Step 2: Claude Code integration (if installed)
	if hasClaudeCode {
		fmt.Println("\n2. Configuring Claude Code...")
		err = registerMCPServer(binaryPath)
		if err != nil {
			fmt.Printf("   ✗ MCP registration failed: %v\n", err)
			fmt.Println("   You can manually add to ~/.claude/settings.json")
		} else {
			fmt.Println("   ✓ MCP server registered")
		}
		err = configureAllHooks(binaryPath, adapterMode)
		if err != nil {
			fmt.Printf("   ✗ Hook configuration failed: %v\n", err)
		} else {
			if adapterMode {
				fmt.Println("   ✓ PreCompact hook (import observations)")
				fmt.Println("   ✓ SessionStart hook (inject context on compact)")
			} else {
				fmt.Println("   ✓ SessionStart hook (inject context)")
				fmt.Println("   ✓ PostToolUse hook (capture observations)")
				fmt.Println("   ✓ UserPromptSubmit hook (record prompts)")
				fmt.Println("   ✓ Stop hook (session summary)")
				fmt.Println("   ✓ SubagentStart/Stop hooks (capture subagent work)")
			}
		}
	} else {
		fmt.Println("\n2. Skipping Claude Code (not installed)")
	}

	// Step 3: Cursor integration (if installed)
	if hasCursor {
		fmt.Println("\n3. Configuring Cursor...")
		if err := configureCursor(binaryPath, adapterMode); err != nil {
			fmt.Printf("   ✗ Failed: %v\n", err)
		} else {
			fmt.Println("   ✓ MCP server registered in ~/.cursor/mcp.json")
			if adapterMode {
				fmt.Println("   ✓ beforeSubmitPrompt hook (inject context)")
			} else {
				fmt.Println("   ✓ beforeSubmitPrompt hook (inject context)")
				fmt.Println("   ✓ afterMCPExecution hook (capture observations)")
				fmt.Println("   ✓ afterShellExecution hook (capture observations)")
				fmt.Println("   ✓ afterFileEdit hook (capture file edits)")
				fmt.Println("   ✓ stop hook (session summary)")
			}
		}
	} else {
		fmt.Println("\n3. Skipping Cursor (not installed)")
	}

	// Step 4: Codex integration (if installed)
	if hasCodex {
		fmt.Println("\n4. Configuring Codex...")
		if err := configureCodex(binaryPath); err != nil {
			fmt.Printf("   ✗ Failed: %v\n", err)
		} else {
			fmt.Println("   ✓ MCP server registered in ~/.codex/config.toml")
			fmt.Println("   ✓ Notify hook configured for observation capture")
		}
	} else {
		fmt.Println("\n4. Skipping Codex (not installed)")
	}

	// Step 5: Save config
	fmt.Println("\n5. Saving configuration...")
	cfg, _ := config.Load()
	previousMode := cfg.Mode // capture before mutation
	cfg.Mode = mode
	cfg.ClaudeMemMode = false // Clear deprecated field
	if err := config.Save(cfg); err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Printf("   ✓ Config saved to %s\n", config.ConfigPath())
	}

	// Step 6: Reset sync manifest if switching to standalone from a different mode
	if mode == "standalone" && previousMode != "standalone" {
		fmt.Println("\n6. Resetting sync manifest for new backend...")
		syncManifest := storage.GetSyncManifest()
		syncManifest.ClearSeenIDs()
		if err := syncManifest.Save(); err != nil {
			fmt.Printf("   ✗ Failed to save manifest: %v\n", err)
		} else {
			fmt.Println("   ✓ Sync manifest reset (cloud sync will re-pull all observations)")
		}
	}

	// Step 7: Restart daemon (must restart so manifest reset takes effect)
	fmt.Println("\n7. Restarting daemon...")
	stopCmd := exec.Command(binaryPath, "daemon", "stop")
	stopCmd.CombinedOutput() // ignore error if not running
	startCmd := exec.Command(binaryPath, "daemon", "start")
	if output, err := startCmd.CombinedOutput(); err != nil {
		fmt.Printf("   ✗ Failed: %v\n", err)
	} else {
		fmt.Printf("   %s", string(output))
	}

	// Step 8: Sync vault keys (only if logged in, must run before cloud sync)
	if authCfg, err := loadAuthConfig(); err == nil && authCfg != nil &&
		(authCfg.DeviceToken != "" || authCfg.Token != "") {
		fmt.Print("\n8. ")
		if err := runVaultSync(nil, nil); err != nil {
			fmt.Printf("   ✗ Vault sync failed: %v\n", err)
		}
	}

	// Step 9: Force cloud sync (pushes imported observations, pulls from other devices)
	if mode == "standalone" {
		fmt.Println("\n9. Syncing with cloud...")
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
	fmt.Println("Dashboard: run 'sinesync dashboard' to open it (port 5741)")
	fmt.Println("")
	fmt.Println("Restart Claude Code to apply changes.")

	return nil
}

// triggerDaemonSync sends a POST to the daemon's sync endpoint to force an immediate sync.
func triggerDaemonSync(port int) error {
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := authedRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/api/sync", port), nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if hookAuthError(resp, "sync") {
		return fmt.Errorf("daemon rejected the hook secret")
	}
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
				if out, marshalErr := json.MarshalIndent(settings, "", "  "); marshalErr == nil {
					if writeErr := os.WriteFile(settingsPath, out, 0600); writeErr == nil {
						os.Chmod(settingsPath, 0600)
					}
				}
			}
		}
	}

	return nil
}

func configureAllHooks(binaryPath string, claudeMemMode bool) error {
	settingsPath := getClaudeSettingsPath()

	// On Windows, convert backslashes to forward slashes in hook commands.
	// Claude Code hooks run via bash which interprets backslashes as escapes.
	hookBinaryPath := strings.ReplaceAll(binaryPath, "\\", "/")

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
						"command": hookBinaryPath + " import",
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
						"command": hookBinaryPath + " context",
						"timeout": 30,
					},
				},
			},
		}
		// Remove standalone-mode hooks that may exist from previous setup
		delete(hooks, "PostToolUse")
		delete(hooks, "UserPromptSubmit")
		delete(hooks, "Stop")
		delete(hooks, "SubagentStart")
		delete(hooks, "SubagentStop")
	} else {
		// Standalone mode - full capture
		hooks["SessionStart"] = []map[string]interface{}{
			{
				"matcher": "startup|clear|compact",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": hookBinaryPath + " context",
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
						"command": hookBinaryPath + " capture",
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
						"command": hookBinaryPath + " prompt",
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
						"command": hookBinaryPath + " summarize",
						"timeout": 60,
					},
				},
			},
		}
		hooks["SubagentStart"] = []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": hookBinaryPath + " subagent-start",
						"timeout": 10,
					},
				},
			},
		}
		hooks["SubagentStop"] = []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": hookBinaryPath + " subagent-stop",
						"timeout": 60,
					},
				},
			},
		}
		// Remove adapter-mode hook that may exist from previous setup
		delete(hooks, "PreCompact")
	}

	settings["hooks"] = hooks

	// Write back — ensure directory exists for fresh installs
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0755); err != nil {
		return err
	}
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(settingsPath, output, 0600); err != nil {
		return err
	}
	return os.Chmod(settingsPath, 0600)
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

	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// configureCodex registers sinesync's MCP server and notify hook in Codex's config.toml.
func configureCodex(binaryPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home dir: %w", err)
	}

	codexDir := filepath.Join(home, ".codex")
	configPath := filepath.Join(codexDir, "config.toml")

	// Ensure .codex directory exists
	if err := os.MkdirAll(codexDir, 0755); err != nil {
		return fmt.Errorf("cannot create .codex dir: %w", err)
	}

	// Read existing config (or start fresh)
	var cfg map[string]interface{}
	data, err := os.ReadFile(configPath)
	if os.IsNotExist(err) {
		cfg = make(map[string]interface{})
	} else if err != nil {
		return fmt.Errorf("cannot read config.toml: %w", err)
	} else {
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("config.toml has syntax error (fix manually or remove it): %w", err)
		}
	}

	// Set notify command
	cfg["notify"] = []string{binaryPath, "codex-notify"}

	// Set MCP server
	mcpServers, ok := cfg["mcp_servers"].(map[string]interface{})
	if !ok {
		mcpServers = make(map[string]interface{})
	}
	mcpServers["sinesync"] = map[string]interface{}{
		"command": binaryPath,
		"args":    []string{"mcp", "start"},
	}
	cfg["mcp_servers"] = mcpServers

	// Write back
	output, err := toml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal TOML: %w", err)
	}

	if err := os.WriteFile(configPath, output, 0600); err != nil {
		return err
	}
	return os.Chmod(configPath, 0600)
}

// configureCursor registers sinesync's MCP server and hook entries for Cursor.
// MCP server goes in ~/.cursor/mcp.json, hooks go in ~/.cursor/hooks.json.
// In adapter mode, only the context hook is installed (claude-mem handles capture).
// In standalone mode, all capture hooks are installed.
// Existing entries from other tools are preserved (merged, not clobbered).
func configureCursor(binaryPath string, adapterMode bool) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home dir: %w", err)
	}

	cursorDir := filepath.Join(home, ".cursor")

	// Ensure .cursor directory exists
	if err := os.MkdirAll(cursorDir, 0755); err != nil {
		return fmt.Errorf("cannot create .cursor dir: %w", err)
	}

	// --- Register MCP server in ~/.cursor/mcp.json ---
	mcpPath := filepath.Join(cursorDir, "mcp.json")
	var mcpCfg map[string]interface{}
	mcpData, err := os.ReadFile(mcpPath)
	if os.IsNotExist(err) {
		mcpCfg = make(map[string]interface{})
	} else if err != nil {
		return fmt.Errorf("cannot read mcp.json: %w", err)
	} else {
		if err := json.Unmarshal(mcpData, &mcpCfg); err != nil {
			return fmt.Errorf("mcp.json has syntax error (fix manually or remove it): %w", err)
		}
	}

	mcpServers, ok := mcpCfg["mcpServers"].(map[string]interface{})
	if !ok {
		mcpServers = make(map[string]interface{})
	}
	mcpServers["sinesync"] = map[string]interface{}{
		"command": binaryPath,
		"args":    []string{"mcp", "start"},
	}
	mcpCfg["mcpServers"] = mcpServers

	mcpOutput, err := json.MarshalIndent(mcpCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal mcp.json: %w", err)
	}
	if err := os.WriteFile(mcpPath, mcpOutput, 0600); err != nil {
		return fmt.Errorf("failed to write mcp.json: %w", err)
	}
	os.Chmod(mcpPath, 0600)

	// --- Configure hooks in ~/.cursor/hooks.json ---
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	var cfg map[string]interface{}
	data, err := os.ReadFile(hooksPath)
	if os.IsNotExist(err) {
		cfg = make(map[string]interface{})
	} else if err != nil {
		return fmt.Errorf("cannot read hooks.json: %w", err)
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("hooks.json has syntax error (fix manually or remove it): %w", err)
		}
	}

	// Get or create hooks section
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		hooks = make(map[string]interface{})
	}

	// Define sinesync hook entries based on mode
	sinesyncHooks := map[string]string{
		"beforeSubmitPrompt": binaryPath + " cursor-hook context",
	}
	// Standalone-only hooks for direct observation capture
	standaloneOnlyEvents := []string{"afterMCPExecution", "afterShellExecution", "afterFileEdit", "stop"}

	if !adapterMode {
		sinesyncHooks["afterMCPExecution"] = binaryPath + " cursor-hook capture"
		sinesyncHooks["afterShellExecution"] = binaryPath + " cursor-hook capture"
		sinesyncHooks["afterFileEdit"] = binaryPath + " cursor-hook file-edit"
		sinesyncHooks["stop"] = binaryPath + " cursor-hook summarize"
	}

	for event, command := range sinesyncHooks {
		entry := map[string]interface{}{"command": command}

		// Merge into existing hook list, replacing any existing sinesync entry
		existing, _ := hooks[event].([]interface{})
		merged := make([]interface{}, 0, len(existing)+1)
		for _, e := range existing {
			if m, ok := e.(map[string]interface{}); ok {
				if cmd, _ := m["command"].(string); strings.Contains(cmd, "sinesync") {
					continue // Remove old sinesync entry
				}
			}
			merged = append(merged, e)
		}
		merged = append(merged, entry)
		hooks[event] = merged
	}

	// In adapter mode, clean up standalone-only hooks from a previous setup
	if adapterMode {
		for _, event := range standaloneOnlyEvents {
			existing, _ := hooks[event].([]interface{})
			if len(existing) == 0 {
				continue
			}
			cleaned := make([]interface{}, 0, len(existing))
			for _, e := range existing {
				if m, ok := e.(map[string]interface{}); ok {
					if cmd, _ := m["command"].(string); strings.Contains(cmd, "sinesync") {
						continue // Remove sinesync capture hooks
					}
				}
				cleaned = append(cleaned, e)
			}
			if len(cleaned) > 0 {
				hooks[event] = cleaned
			} else {
				delete(hooks, event)
			}
		}
	}

	cfg["hooks"] = hooks

	// Write back
	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hooks.json: %w", err)
	}

	if err := os.WriteFile(hooksPath, output, 0600); err != nil {
		return err
	}
	return os.Chmod(hooksPath, 0600)
}
