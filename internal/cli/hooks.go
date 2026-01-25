package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/miclip/sinesync/internal/daemon"
	"github.com/spf13/cobra"
)

// Hook commands - thin CLI wrappers that call daemon API
// These are called by Claude Code hooks

var contextCmd = &cobra.Command{
	Use:   "context",
	Short: "Inject relevant context (SessionStart hook)",
	Long: `Called by SessionStart hook to inject relevant memories.

Reads hook input from stdin, outputs context for Claude.
Automatically starts daemon if not running.`,
	RunE: runContext,
}

var captureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Capture observation from tool use (PostToolUse hook)",
	Long: `Called by PostToolUse hook to capture observations.

Reads tool use data from stdin, extracts and saves observations.
Automatically starts daemon if not running.`,
	RunE: runCapture,
}

var summarizeCmd = &cobra.Command{
	Use:   "summarize",
	Short: "Summarize session (Stop hook)",
	Long: `Called by Stop hook to create session summary.

Reads session data from stdin, creates summary observation.
Automatically starts daemon if not running.`,
	RunE: runSummarize,
}

var hooksConfigCmd = &cobra.Command{
	Use:   "hooks-config",
	Short: "Generate hooks configuration for Claude Code",
	Long: `Outputs hooks.json configuration for Claude Code integration.

Copy this to your Claude Code settings or use --install to auto-install.`,
	RunE: runHooksConfig,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(summarizeCmd)
	rootCmd.AddCommand(hooksConfigCmd)

	hooksConfigCmd.Flags().Bool("install", false, "Install hooks to Claude Code settings")
	hooksConfigCmd.Flags().Bool("standalone", false, "Generate hooks for standalone mode (memory tools)")
}

// HookInput is the JSON structure received from Claude Code hooks
type HookInput struct {
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	PermissionMode string `json:"permission_mode"`
	HookEventName  string `json:"hook_event_name"`

	// SessionStart specific
	Source string `json:"source,omitempty"` // startup, resume, clear, compact
	Model  string `json:"model,omitempty"`

	// Tool use specific
	ToolName     string `json:"tool_name,omitempty"`
	ToolInput    string `json:"tool_input,omitempty"`
	ToolResponse string `json:"tool_response,omitempty"`
	ToolUseID    string `json:"tool_use_id,omitempty"`

	// UserPromptSubmit specific
	Prompt string `json:"prompt,omitempty"`
}

func runContext(cmd *cobra.Command, args []string) error {
	// Ensure daemon is running
	info, err := daemon.EnsureRunning()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Read hook input from stdin
	var input HookInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		// If no stdin, use defaults
		input.CWD, _ = os.Getwd()
	}

	// Extract project name from CWD
	project := filepath.Base(input.CWD)

	// Call daemon API
	apiURL := fmt.Sprintf("http://127.0.0.1:%d/api/context?project=%s", info.Port, url.QueryEscape(project))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return fmt.Errorf("failed to call daemon: %w", err)
	}
	defer resp.Body.Close()

	// Forward response to stdout
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func runCapture(cmd *cobra.Command, args []string) error {
	// Ensure daemon is running
	info, err := daemon.EnsureRunning()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Read hook input from stdin
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	// Call daemon API
	apiURL := fmt.Sprintf("http://127.0.0.1:%d/api/capture", info.Port)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(inputData))
	if err != nil {
		return fmt.Errorf("failed to call daemon: %w", err)
	}
	defer resp.Body.Close()

	// Forward response to stdout
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func runSummarize(cmd *cobra.Command, args []string) error {
	// Ensure daemon is running
	info, err := daemon.EnsureRunning()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	// Read hook input from stdin
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	// Call daemon API
	apiURL := fmt.Sprintf("http://127.0.0.1:%d/api/summarize", info.Port)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(inputData))
	if err != nil {
		return fmt.Errorf("failed to call daemon: %w", err)
	}
	defer resp.Body.Close()

	// Forward response to stdout
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func runHooksConfig(cmd *cobra.Command, args []string) error {
	install, _ := cmd.Flags().GetBool("install")
	standalone, _ := cmd.Flags().GetBool("standalone")

	// Get sinesync executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	var hooks map[string]interface{}

	if standalone {
		// Standalone mode - full memory tool hooks (like claude-mem)
		hooks = generateStandaloneHooks(exePath)
	} else {
		// Adapter mode - just PreCompact for import
		hooks = generateAdapterHooks(exePath)
	}

	config := map[string]interface{}{
		"hooks": hooks,
	}

	output, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	if install {
		return installHooks(config)
	}

	fmt.Println(string(output))
	return nil
}

func generateAdapterHooks(exePath string) map[string]interface{} {
	return map[string]interface{}{
		"PreCompact": []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": fmt.Sprintf("%s import", exePath),
						"timeout": 120,
					},
				},
			},
		},
		"SessionStart": []map[string]interface{}{
			{
				"matcher": "compact",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": fmt.Sprintf("%s context", exePath),
						"timeout": 30,
					},
				},
			},
		},
	}
}

func generateStandaloneHooks(exePath string) map[string]interface{} {
	return map[string]interface{}{
		"SessionStart": []map[string]interface{}{
			{
				"matcher": "startup|clear|compact",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": fmt.Sprintf("%s context", exePath),
						"timeout": 60,
					},
				},
			},
		},
		"PostToolUse": []map[string]interface{}{
			{
				"matcher": "*",
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": fmt.Sprintf("%s capture", exePath),
						"timeout": 30,
					},
				},
			},
		},
		"Stop": []map[string]interface{}{
			{
				"hooks": []map[string]interface{}{
					{
						"type":    "command",
						"command": fmt.Sprintf("%s summarize", exePath),
						"timeout": 60,
					},
				},
			},
		},
	}
}

func installHooks(config map[string]interface{}) error {
	// Find Claude Code settings file
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	settingsPath := filepath.Join(home, ".claude", "settings.json")

	// Read existing settings
	var settings map[string]interface{}
	if data, err := os.ReadFile(settingsPath); err == nil {
		if err := json.Unmarshal(data, &settings); err != nil {
			settings = make(map[string]interface{})
		}
	} else {
		settings = make(map[string]interface{})
	}

	// Merge hooks
	if existingHooks, ok := settings["hooks"].(map[string]interface{}); ok {
		newHooks := config["hooks"].(map[string]interface{})
		for k, v := range newHooks {
			existingHooks[k] = v
		}
		settings["hooks"] = existingHooks
	} else {
		settings["hooks"] = config["hooks"]
	}

	// Write back
	output, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(settingsPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write settings: %w", err)
	}

	fmt.Printf("Hooks installed to %s\n", settingsPath)
	return nil
}
