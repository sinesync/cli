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
	Use:    "context",
	Short:  "Inject relevant context (SessionStart hook)",
	Hidden: true, // Internal command called by hooks
	RunE:   runContext,
}

var captureCmd = &cobra.Command{
	Use:    "capture",
	Short:  "Capture observation from tool use (PostToolUse hook)",
	Hidden: true, // Internal command called by hooks
	RunE:   runCapture,
}

var summarizeCmd = &cobra.Command{
	Use:    "summarize",
	Short:  "Summarize session (Stop hook)",
	Hidden: true, // Internal command called by hooks
	RunE:   runSummarize,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(summarizeCmd)
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

	// Check auth status and print user-visible message
	authStatus := checkAuthStatus(info.Port)
	if authStatus != "" {
		fmt.Fprintf(os.Stderr, "\n[sine~sync] %s\n\n", authStatus)
	}

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

func checkAuthStatus(port int) string {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/api/sync", port))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var status struct {
		Authenticated bool   `json:"authenticated"`
		SyncError     string `json:"syncError"`
		Syncing       bool   `json:"syncing"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return ""
	}

	if !status.Authenticated {
		return "Cloud sync disabled. Run 'sinesync login' to enable."
	}
	if status.SyncError != "" {
		return fmt.Sprintf("Sync error: %s", status.SyncError)
	}
	return ""
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
