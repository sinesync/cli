package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// Cursor hook commands - thin CLI wrappers that normalize Cursor hook payloads
// and forward them to the existing daemon API endpoints.
// No daemon changes needed — Cursor payloads map cleanly to existing endpoints.

var cursorHookCmd = &cobra.Command{
	Use:    "cursor-hook",
	Short:  "Cursor hook commands",
	Hidden: true,
}

var cursorContextCmd = &cobra.Command{
	Use:    "context",
	Short:  "Inject context via .cursor/rules (beforeSubmitPrompt hook)",
	Hidden: true,
	RunE:   runCursorContext,
}

var cursorCaptureCmd = &cobra.Command{
	Use:    "capture",
	Short:  "Capture observation (afterMCPExecution / afterShellExecution hook)",
	Hidden: true,
	RunE:   runCursorCapture,
}

var cursorFileEditCmd = &cobra.Command{
	Use:    "file-edit",
	Short:  "Capture file edit observation (afterFileEdit hook)",
	Hidden: true,
	RunE:   runCursorFileEdit,
}

var cursorSummarizeCmd = &cobra.Command{
	Use:    "summarize",
	Short:  "Summarize session (stop hook)",
	Hidden: true,
	RunE:   runCursorSummarize,
}

func init() {
	cursorHookCmd.AddCommand(cursorContextCmd)
	cursorHookCmd.AddCommand(cursorCaptureCmd)
	cursorHookCmd.AddCommand(cursorFileEditCmd)
	cursorHookCmd.AddCommand(cursorSummarizeCmd)
	rootCmd.AddCommand(cursorHookCmd)
}

// Cursor payload types

type CursorBeforeSubmitPrompt struct {
	ConversationID string   `json:"conversation_id"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Prompt         string   `json:"prompt"`
}

type CursorAfterMCPExecution struct {
	ConversationID string          `json:"conversation_id"`
	WorkspaceRoots []string        `json:"workspace_roots"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ResultJSON     json.RawMessage `json:"result_json"`
}

type CursorAfterShellExecution struct {
	ConversationID string   `json:"conversation_id"`
	WorkspaceRoots []string `json:"workspace_roots"`
	Command        string   `json:"command"`
	Output         string   `json:"output"`
}

type CursorFileEdit struct {
	OldText string `json:"old_text"`
	NewText string `json:"new_text"`
}

type CursorAfterFileEdit struct {
	ConversationID string           `json:"conversation_id"`
	WorkspaceRoots []string         `json:"workspace_roots"`
	FilePath       string           `json:"file_path"`
	Edits          []CursorFileEdit `json:"edits"`
}

type CursorStopEvent struct {
	ConversationID string   `json:"conversation_id"`
	WorkspaceRoots []string `json:"workspace_roots"`
}

// cursorWorkspaceRoot returns the first workspace root, falling back to os.Getwd().
func cursorWorkspaceRoot(roots []string) string {
	if len(roots) > 0 && roots[0] != "" {
		return roots[0]
	}
	cwd, _ := os.Getwd()
	return cwd
}

// writeCursorRulesFile writes context to .cursor/rules/sinesync-context.mdc
// with frontmatter so Cursor auto-includes it in every chat.
func writeCursorRulesFile(workspaceRoot, content string) error {
	rulesDir := filepath.Join(workspaceRoot, ".cursor", "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return err
	}

	mdcContent := fmt.Sprintf(`---
description: sinesync context - relevant memories for this project
alwaysApply: true
---

%s
`, content)

	path := filepath.Join(rulesDir, "sinesync-context.mdc")
	if err := os.WriteFile(path, []byte(mdcContent), 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// runCursorContext handles beforeSubmitPrompt: fetches context from daemon
// and writes it to .cursor/rules/sinesync-context.mdc.
func runCursorContext(cmd *cobra.Command, args []string) error {
	var input CursorBeforeSubmitPrompt
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		input.WorkspaceRoots = nil
	}

	root := cursorWorkspaceRoot(input.WorkspaceRoots)
	project := filepath.Base(root)

	// Check auth status
	authStatus := checkAuthStatus()
	if authStatus != "" {
		fmt.Fprintf(os.Stderr, "\n[sine~sync] %s\n\n", authStatus)
	}

	apiURL := daemonURL(fmt.Sprintf("/api/context?project=%s&session_id=%s",
		url.QueryEscape(project), url.QueryEscape(input.ConversationID)))

	resp, err := contextGet(apiURL)
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	content := strings.TrimSpace(string(body))
	if content == "" {
		return nil
	}

	// Write context to .cursor/rules/ for Cursor to pick up
	if err := writeCursorRulesFile(root, content); err != nil {
		fmt.Fprintf(os.Stderr, "[sinesync] failed to write cursor rules: %v\n", err)
	}

	return nil
}

// cursorCapturePayload matches the daemon's /api/capture expected format.
// tool_input and tool_response are json.RawMessage so the daemon can unmarshal
// them into map[string]interface{} for structured field extraction.
type cursorCapturePayload struct {
	SessionID    string          `json:"session_id"`
	ToolName     string          `json:"tool_name"`
	ToolInput    json.RawMessage `json:"tool_input"`
	ToolResponse json.RawMessage `json:"tool_response,omitempty"`
	CWD          string          `json:"cwd"`
}

// runCursorCapture handles afterMCPExecution and afterShellExecution.
// It probes for tool_name (MCP) vs command (shell) to normalize the payload.
func runCursorCapture(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	// Probe the raw JSON to determine MCP vs shell
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(inputData, &raw); err != nil {
		return nil
	}

	var payload cursorCapturePayload

	if _, hasTool := raw["tool_name"]; hasTool {
		// MCP execution — passthrough tool_input as-is (already JSON)
		var mcp CursorAfterMCPExecution
		if err := json.Unmarshal(inputData, &mcp); err != nil {
			return nil
		}
		payload = cursorCapturePayload{
			SessionID:    mcp.ConversationID,
			CWD:          cursorWorkspaceRoot(mcp.WorkspaceRoots),
			ToolName:     mcp.ToolName,
			ToolInput:    mcp.ToolInput,
			ToolResponse: mcp.ResultJSON,
		}
	} else if _, hasCmd := raw["command"]; hasCmd {
		// Shell execution — build structured Bash tool_input
		var shell CursorAfterShellExecution
		if err := json.Unmarshal(inputData, &shell); err != nil {
			return nil
		}
		toolInput, _ := json.Marshal(map[string]string{"command": shell.Command})
		toolResponse, _ := json.Marshal(shell.Output)
		payload = cursorCapturePayload{
			SessionID:    shell.ConversationID,
			CWD:          cursorWorkspaceRoot(shell.WorkspaceRoots),
			ToolName:     "Bash",
			ToolInput:    toolInput,
			ToolResponse: toolResponse,
		}
	} else {
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/capture"), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}

// runCursorFileEdit handles afterFileEdit by synthesizing Edit tool observations.
// Emits one capture per edit so the daemon gets structured file_path/old_string/new_string.
func runCursorFileEdit(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	var input CursorAfterFileEdit
	if err := json.Unmarshal(inputData, &input); err != nil {
		return nil
	}

	cwd := cursorWorkspaceRoot(input.WorkspaceRoots)

	// If no edits, send a minimal Edit observation with just the file path
	if len(input.Edits) == 0 {
		toolInput, _ := json.Marshal(map[string]string{
			"file_path": input.FilePath,
		})
		payload := cursorCapturePayload{
			SessionID: input.ConversationID,
			CWD:       cwd,
			ToolName:  "Edit",
			ToolInput: toolInput,
		}
		body, _ := json.Marshal(payload)
		if resp, err := hookPost(daemonURL("/api/capture"), "application/json", bytes.NewReader(body)); err == nil {
			drainClose(resp)
		}
		return nil
	}

	// Emit one capture per edit with structured fields
	for _, e := range input.Edits {
		toolInput, _ := json.Marshal(map[string]string{
			"file_path":  input.FilePath,
			"old_string": e.OldText,
			"new_string": e.NewText,
		})
		payload := cursorCapturePayload{
			SessionID: input.ConversationID,
			CWD:       cwd,
			ToolName:  "Edit",
			ToolInput: toolInput,
		}
		body, err := json.Marshal(payload)
		if err != nil {
			continue
		}
		if resp, err := hookPost(daemonURL("/api/capture"), "application/json", bytes.NewReader(body)); err == nil {
			drainClose(resp)
		}
	}
	return nil
}

// runCursorSummarize handles the stop event by forwarding to /api/summarize.
func runCursorSummarize(cmd *cobra.Command, args []string) error {
	inputData, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil
	}

	var input CursorStopEvent
	if err := json.Unmarshal(inputData, &input); err != nil {
		return nil
	}

	payload := map[string]string{
		"session_id": input.ConversationID,
		"cwd":        cursorWorkspaceRoot(input.WorkspaceRoots),
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/summarize"), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}

