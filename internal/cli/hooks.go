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

	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/daemon"
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

var subagentStartCmd = &cobra.Command{
	Use:    "subagent-start",
	Short:  "Record subagent spawn (SubagentStart hook)",
	Hidden: true,
	RunE:   runSubagentStart,
}

var subagentStopCmd = &cobra.Command{
	Use:    "subagent-stop",
	Short:  "Process subagent transcript (SubagentStop hook)",
	Hidden: true,
	RunE:   runSubagentStop,
}

func init() {
	rootCmd.AddCommand(contextCmd)
	rootCmd.AddCommand(captureCmd)
	rootCmd.AddCommand(summarizeCmd)
	rootCmd.AddCommand(promptCmd)
	rootCmd.AddCommand(subagentStartCmd)
	rootCmd.AddCommand(subagentStopCmd)
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

// The daemon owns the secret file, so it owns the path too — defining it twice
// is how the writer and the reader end up disagreeing.
func hookSecretPath() string { return daemon.HookSecretPath() }

func readHookSecret() string { return daemon.ReadHookSecret() }

// hookAuthError reports whether resp is a 401 and, if so, explains the cause on
// stderr. The daemon rejects any request without the shared secret it writes to
// $(DataDir)/hook-secret at startup, so a bare "unauthorized" would be
// mystifying — the actionable fact is that the file is missing or unreadable.
func hookAuthError(resp *http.Response, op string) bool {
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	secretPath := filepath.Join(config.DataDir(), "hook-secret")
	if readHookSecret() == "" {
		fmt.Fprintf(os.Stderr, "[sine~sync] %s: cannot read the daemon hook secret at %s. The daemon writes it on startup; run 'sinesync restart'.\n", op, secretPath)
	} else {
		fmt.Fprintf(os.Stderr, "[sine~sync] %s: the daemon rejected the hook secret at %s — it is probably stale. Run 'sinesync restart'.\n", op, secretPath)
	}
	return true
}

// authedRequest builds a request to the daemon carrying the hook secret.
//
// Every /api/ route except health and status now requires it, so any caller
// that builds its own request — rather than going through hookGet/hookPost —
// must use this or it will silently start getting 401s. That is how `sinesync
// status`, setup's sync trigger, and teardown's sync polling broke when the
// read endpoints were protected.
func authedRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if secret := readHookSecret(); secret != "" {
		req.Header.Set("X-Hook-Secret", secret)
	}
	return req, nil
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

	// Only a 200 body is context worth injecting. Copying an error page to
	// stdout would splice "unauthorized" into the session's context block.
	if resp.StatusCode != http.StatusOK {
		if !hookAuthError(resp, "context injection failed") {
			fmt.Fprintf(os.Stderr, "[sine~sync] context injection failed: daemon returned %d\n", resp.StatusCode)
		}
		return nil
	}

	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func checkAuthStatus() string {
	resp, err := hookGet(daemonURL("/api/sync"))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		hookAuthError(resp, "sync status unavailable")
		return "Cannot authenticate to the sine~sync daemon. Run 'sinesync restart'."
	}

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

// drainClose finishes with a fire-and-forget response. These hooks stay silent
// about ordinary failures by design, but an auth failure is a misconfiguration
// that would otherwise drop every observation without a word, so it is reported.
func drainClose(resp *http.Response) {
	hookAuthError(resp, "observation not recorded")
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

func runSubagentStart(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/subagent-start"), "application/json", bytes.NewReader(inputData))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}

func runSubagentStop(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/subagent-stop"), "application/json", bytes.NewReader(inputData))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}
