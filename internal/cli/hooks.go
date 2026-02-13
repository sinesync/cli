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
	"strings"
	"time"

	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/daemon"
	"github.com/spf13/cobra"
)

// Hook commands - thin CLI wrappers that call daemon API
// These are called by Claude Code hooks.
// They POST directly to the daemon's known port without checking if it's
// running — the daemon is already started by "sinesync setup".

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

var promptCmd = &cobra.Command{
	Use:    "prompt",
	Short:  "Record user prompt (UserPromptSubmit hook)",
	Hidden: true, // Internal command called by hooks
	RunE:   runPrompt,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(summarizeCmd)
	rootCmd.AddCommand(promptCmd)
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

func daemonURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", daemon.DefaultPort, path)
}

// hookClient is a shared HTTP client with a short timeout for fire-and-forget hooks.
var hookClient = &http.Client{Timeout: 3 * time.Second}

// contextClient has a longer timeout since context injection reads the full response.
var contextClient = &http.Client{Timeout: 10 * time.Second}

// readHookSecret reads the daemon hook secret from the data directory.
func readHookSecret() string {
	secretPath := filepath.Join(config.DataDir(), "hook-secret")
	data, err := os.ReadFile(secretPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// hookPost sends a POST request to the daemon with the hook secret header.
func hookPost(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	if secret := readHookSecret(); secret != "" {
		req.Header.Set("X-Hook-Secret", secret)
	}
	return hookClient.Do(req)
}

// hookGet sends a GET request to the daemon with the hook secret header.
func hookGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if secret := readHookSecret(); secret != "" {
		req.Header.Set("X-Hook-Secret", secret)
	}
	return hookClient.Do(req)
}

// contextGet sends a GET request using the longer-timeout context client with the hook secret.
func contextGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if secret := readHookSecret(); secret != "" {
		req.Header.Set("X-Hook-Secret", secret)
	}
	return contextClient.Do(req)
}

// runContext needs the response (injected into Claude Code's context via stdout),
// so it waits for the full response. Uses a longer timeout than fire-and-forget hooks.
func runContext(cmd *cobra.Command, args []string) error {
	var input HookInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		input.CWD, _ = os.Getwd()
	}

	project := filepath.Base(input.CWD)

	// Check auth status
	authStatus := checkAuthStatus()
	if authStatus != "" {
		fmt.Fprintf(os.Stderr, "\n[sine~sync] %s\n\n", authStatus)
	}

	apiURL := daemonURL(fmt.Sprintf("/api/context?project=%s&session_id=%s",
		url.QueryEscape(project), url.QueryEscape(input.SessionID)))

	resp, err := contextGet(apiURL)
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	defer resp.Body.Close()

	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func checkAuthStatus() string {
	resp, err := hookGet(daemonURL("/api/sync"))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var status struct {
		Authenticated bool   `json:"authenticated"`
		SyncError     string `json:"syncError"`
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

// Fire-and-forget hooks: POST to daemon, drain and close body for keep-alive.

func drainClose(resp *http.Response) {
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func runCapture(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/capture"), "application/json", bytes.NewReader(inputData))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}

func runSummarize(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/summarize"), "application/json", bytes.NewReader(inputData))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}

func runPrompt(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/prompt"), "application/json", bytes.NewReader(inputData))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}
