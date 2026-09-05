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

	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/daemon"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/spf13/cobra"
)

var teardownCmd = &cobra.Command{
	Use:   "teardown",
	Short: "Remove sine~sync hooks, MCP, and stop the daemon",
	Long: `Reverses the setup command: performs a final cloud sync, removes all
hooks and MCP server registrations from Claude Code, Cursor, and Codex,
optionally deletes the local memory database, and stops the daemon.

This does NOT delete your cloud data or account.`,
	RunE: runTeardown,
}

func init() {
	rootCmd.AddCommand(teardownCmd)
}

func runTeardown(cmd *cobra.Command, args []string) error {
	fmt.Println("sine~sync teardown")
	fmt.Println("─────────────────────────────────────────")

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Final sync (push local data to cloud) and wait for completion
	fmt.Println("\n1. Final cloud sync...")
	if err := triggerDaemonSync(daemon.DefaultPort); err != nil {
		fmt.Printf("   ⚠ Sync failed (daemon may not be running): %v\n", err)
		fmt.Println("   Your local data is preserved and can be synced later.")
	} else {
		fmt.Println("   ✓ Cloud sync triggered")
		if err := waitForSyncComplete(daemon.DefaultPort, 60*time.Second); err != nil {
			fmt.Printf("   ⚠ Timed out waiting for sync to complete: %v\n", err)
		} else {
			fmt.Println("   ✓ Cloud sync complete")
		}
	}

	// Step 2: Remove Claude Code integration
	// Always attempt to remove hooks from settings.json (file-based, no CLI needed).
	// Only gate MCP removal on the claude CLI being available.
	fmt.Println("\n2. Removing Claude Code integration...")
	if err := removeClaudeHooks(); err != nil {
		fmt.Printf("   ⚠ Hook removal failed: %v\n", err)
	} else {
		fmt.Println("   ✓ Hooks removed from ~/.claude/settings.json")
	}
	if _, err := exec.LookPath("claude"); err == nil {
		if err := removeMCPServer(); err != nil {
			fmt.Printf("   ⚠ MCP removal failed: %v\n", err)
		} else {
			fmt.Println("   ✓ MCP server removed")
		}
	} else {
		fmt.Println("   Skipped MCP removal (claude CLI not found on PATH)")
	}

	// Step 3: Remove Cursor integration
	fmt.Println("\n3. Removing Cursor integration...")
	if err := removeCursor(); err != nil {
		fmt.Printf("   ⚠ Failed: %v\n", err)
	} else {
		fmt.Println("   ✓ MCP and hooks removed from ~/.cursor/")
	}

	// Step 4: Remove Codex integration
	fmt.Println("\n4. Removing Codex integration...")
	if err := removeCodex(); err != nil {
		fmt.Printf("   ⚠ Failed: %v\n", err)
	} else {
		fmt.Println("   ✓ MCP and notify hook removed from ~/.codex/config.toml")
	}

	// Step 5: Stop daemon (before touching memory.db to avoid file lock races)
	fmt.Println("\n5. Stopping daemon...")
	if running, _ := daemon.IsRunning(); running {
		if err := daemon.Stop(); err != nil {
			fmt.Printf("   ⚠ Failed to stop: %v\n", err)
		} else {
			fmt.Println("   ✓ Daemon stopped")
		}
	} else {
		fmt.Println("   Daemon was not running")
	}

	// Step 6: Ask about memory.db deletion (after daemon is stopped)
	deletedDB := false
	memoryPath := filepath.Join(config.DataDir(), "memory.db")
	_, statErr := os.Stat(memoryPath)
	if statErr == nil {
		fmt.Printf("\n6. Delete local memory database?\n")
		fmt.Printf("   Path: %s\n", memoryPath)
		fmt.Print("   Delete? [y/N]: ")
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(strings.ToLower(answer))
		if answer == "y" || answer == "yes" {
			// Also remove WAL/SHM files that SQLite may have created
			os.Remove(memoryPath + "-wal")
			os.Remove(memoryPath + "-shm")
			if err := os.Remove(memoryPath); err != nil {
				fmt.Printf("   ⚠ Failed to delete: %v\n", err)
			} else {
				fmt.Println("   ✓ Memory database deleted")
				deletedDB = true
			}
		} else {
			fmt.Println("   Kept (you can re-sync later with 'sinesync setup')")
		}
	} else if os.IsNotExist(statErr) {
		fmt.Println("\n6. No local memory database found")
		deletedDB = true // no DB means nothing to preserve keys for
	} else {
		fmt.Printf("\n6. ⚠ Could not check memory database: %v\n", statErr)
		fmt.Println("   Proceeding as if database were deleted; related keychain entries will be cleared.")
		deletedDB = true
	}

	// Step 7: Clear keychain credentials (encryption keys, tokens, etc.)
	// Preserve local-db-key if the user kept the database, so it remains accessible.
	fmt.Println("\n7. Clearing keychain credentials...")
	var keysToKeep []string
	if !deletedDB {
		keysToKeep = append(keysToKeep, "local-db-key")
	}
	keychain.ClearExcept(keysToKeep)
	_ = keychain.Delete("token")
	_ = keychain.Delete("refreshToken")
	_ = keychain.Delete("deviceToken")
	fmt.Println("   ✓ Keychain credentials cleared")

	// Summary
	fmt.Println("\n─────────────────────────────────────────")
	fmt.Println("Teardown complete!")
	fmt.Println("")
	fmt.Println("What's preserved:")
	fmt.Println("  • Cloud data (login again to re-sync)")
	fmt.Println("  • Config (~/.sinesync/config.json)")
	fmt.Println("")
	fmt.Println("To set up again: sinesync setup")

	return nil
}

// waitForSyncComplete polls the daemon's sync status endpoint until syncing is
// false or the timeout expires.
func waitForSyncComplete(port int, timeout time.Duration) error {
	client := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		req, err := authedRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/api/sync", port), nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		if hookAuthError(resp, "sync status") {
			resp.Body.Close()
			return fmt.Errorf("daemon rejected the hook secret")
		}
		var status struct {
			Syncing bool `json:"syncing"`
		}
		json.NewDecoder(resp.Body).Decode(&status)
		resp.Body.Close()

		if !status.Syncing {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("sync still running after %s", timeout)
}

// removeMCPServer removes the sinesync MCP server from Claude Code.
func removeMCPServer() error {
	rmCmd := exec.Command("claude", "mcp", "remove", "--scope", "user", "sinesync")
	output, err := rmCmd.CombinedOutput()
	if err != nil {
		// Don't fail if it wasn't registered
		if strings.Contains(string(output), "not found") || strings.Contains(string(output), "No MCP") {
			return nil
		}
		return fmt.Errorf("%s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

// removeClaudeHooks removes all sinesync hook entries from ~/.claude/settings.json.
func removeClaudeHooks() error {
	settingsPath := getClaudeSettingsPath()

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No settings file, nothing to do
		}
		return err
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("failed to parse settings.json: %w", err)
	}

	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return nil // No hooks section
	}

	// Remove all sinesync hook events
	sinesyncEvents := []string{"SessionStart", "PostToolUse", "UserPromptSubmit", "Stop", "PreCompact"}
	changed := false
	for _, event := range sinesyncEvents {
		entries, ok := hooks[event].([]interface{})
		if !ok {
			continue
		}

		// Filter out sinesync entries, keep others
		var kept []interface{}
		for _, entry := range entries {
			m, ok := entry.(map[string]interface{})
			if !ok {
				kept = append(kept, entry)
				continue
			}
			// Check if any hook in this entry references sinesync
			hookActions, ok := m["hooks"].([]interface{})
			if !ok {
				kept = append(kept, entry)
				continue
			}
			isSinesync := false
			for _, action := range hookActions {
				if am, ok := action.(map[string]interface{}); ok {
					if cmd, ok := am["command"].(string); ok && strings.Contains(cmd, "sinesync") {
						isSinesync = true
						break
					}
				}
			}
			if !isSinesync {
				kept = append(kept, entry)
			}
		}

		if len(kept) == 0 {
			delete(hooks, event)
			changed = true
		} else if len(kept) != len(entries) {
			hooks[event] = kept
			changed = true
		}
	}

	if !changed {
		return nil
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"] = hooks
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

// removeCursor removes sinesync from Cursor's MCP and hooks config.
func removeCursor() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	cursorDir := filepath.Join(home, ".cursor")
	if _, err := os.Stat(cursorDir); os.IsNotExist(err) {
		return nil // Cursor not installed
	}

	// Remove from ~/.cursor/mcp.json
	mcpPath := filepath.Join(cursorDir, "mcp.json")
	if err := removeCursorMCP(mcpPath); err != nil {
		return fmt.Errorf("cursor MCP config: %w", err)
	}

	// Remove sinesync entries from ~/.cursor/hooks.json
	hooksPath := filepath.Join(cursorDir, "hooks.json")
	if err := removeCursorHooks(hooksPath); err != nil {
		return fmt.Errorf("cursor hooks config: %w", err)
	}

	return nil
}

// removeCursorMCP removes the sinesync entry from ~/.cursor/mcp.json.
func removeCursorMCP(mcpPath string) error {
	data, err := os.ReadFile(mcpPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %q: %w", mcpPath, err)
	}

	var mcpCfg map[string]interface{}
	if err := json.Unmarshal(data, &mcpCfg); err != nil {
		return fmt.Errorf("failed to parse %q: %w", mcpPath, err)
	}

	mcpServers, ok := mcpCfg["mcpServers"].(map[string]interface{})
	if !ok {
		return nil // No mcpServers section
	}

	if _, exists := mcpServers["sinesync"]; !exists {
		return nil // sinesync not registered
	}

	delete(mcpServers, "sinesync")
	if len(mcpServers) == 0 {
		delete(mcpCfg, "mcpServers")
	}

	output, err := json.MarshalIndent(mcpCfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}
	if err := os.WriteFile(mcpPath, output, 0600); err != nil {
		return fmt.Errorf("failed to write %q: %w", mcpPath, err)
	}
	return os.Chmod(mcpPath, 0600)
}

// removeCursorHooks removes sinesync entries from ~/.cursor/hooks.json.
func removeCursorHooks(hooksPath string) error {
	data, err := os.ReadFile(hooksPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("failed to read %q: %w", hooksPath, err)
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse %q: %w", hooksPath, err)
	}

	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return nil
	}

	changed := false
	for event, val := range hooks {
		entries, ok := val.([]interface{})
		if !ok {
			continue
		}
		var kept []interface{}
		for _, entry := range entries {
			if m, ok := entry.(map[string]interface{}); ok {
				if cmd, ok := m["command"].(string); ok && strings.Contains(cmd, "sinesync") {
					changed = true
					continue
				}
			}
			kept = append(kept, entry)
		}
		if len(kept) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = kept
		}
	}

	if !changed {
		return nil
	}

	if len(hooks) == 0 {
		delete(cfg, "hooks")
	} else {
		cfg["hooks"] = hooks
	}

	output, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal: %w", err)
	}
	if err := os.WriteFile(hooksPath, output, 0600); err != nil {
		return fmt.Errorf("failed to write %q: %w", hooksPath, err)
	}
	return os.Chmod(hooksPath, 0600)
}

// removeCodex removes sinesync from Codex's config.toml.
func removeCodex() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(home, ".codex", "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No Codex config
		}
		return err
	}

	var cfg map[string]interface{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("config.toml parse error: %w", err)
	}

	changed := false

	// Remove notify command if it references sinesync
	if notify, ok := cfg["notify"]; ok {
		if notifySlice, ok := notify.([]interface{}); ok && len(notifySlice) > 0 {
			if cmd, ok := notifySlice[0].(string); ok && strings.Contains(cmd, "sinesync") {
				delete(cfg, "notify")
				changed = true
			}
		}
	}

	// Remove sinesync from mcp_servers
	if mcpServers, ok := cfg["mcp_servers"].(map[string]interface{}); ok {
		if _, exists := mcpServers["sinesync"]; exists {
			delete(mcpServers, "sinesync")
			if len(mcpServers) == 0 {
				delete(cfg, "mcp_servers")
			}
			changed = true
		}
	}

	if !changed {
		return nil
	}

	output, err := toml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(configPath, output, 0600); err != nil {
		return err
	}
	return os.Chmod(configPath, 0600)
}
