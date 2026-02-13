package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// codexNotifyCmd handles Codex notify callbacks.
// Codex invokes: sinesync codex-notify '{"type":"agent-turn-complete",...}'
var codexNotifyCmd = &cobra.Command{
	Use:    "codex-notify",
	Short:  "Handle Codex notify callback",
	Hidden: true,
	Args:   cobra.ExactArgs(1),
	RunE:   runCodexNotify,
}

func init() {
	rootCmd.AddCommand(codexNotifyCmd)
}

// CodexNotifyPayload is the JSON structure Codex passes as a CLI argument.
type CodexNotifyPayload struct {
	Type                 string   `json:"type"`
	ThreadID             string   `json:"thread-id"`
	TurnID               string   `json:"turn-id"`
	CWD                  string   `json:"cwd"`
	InputMessages        []string `json:"input-messages"`
	LastAssistantMessage string   `json:"last-assistant-message"`
}

func runCodexNotify(cmd *cobra.Command, args []string) error {
	var payload CodexNotifyPayload
	if err := json.Unmarshal([]byte(args[0]), &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sinesync] codex-notify: invalid JSON: %v\n", err)
		return nil // silent exit, don't break Codex
	}

	// Only handle agent-turn-complete events
	if payload.Type != "agent-turn-complete" {
		return nil
	}

	// Skip if there's no content to capture
	if payload.LastAssistantMessage == "" {
		return nil
	}

	// POST to daemon's codex-capture endpoint
	body, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	resp, err := hookPost(daemonURL("/api/codex-capture"), "application/json", bytes.NewReader(body))
	if err != nil {
		return nil // Daemon not available — silently skip
	}
	drainClose(resp)
	return nil
}
