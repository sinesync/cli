package daemon

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// transcriptToolCall represents a single tool invocation extracted from a subagent transcript.
type transcriptToolCall struct {
	ToolName     string
	ToolInput    map[string]interface{}
	ToolResponse string
}

// pendingToolUse tracks an unmatched tool_use event while parsing a transcript.
type pendingToolUse struct {
	Name  string
	Input map[string]interface{}
}

// parseTranscript reads a Claude Code subagent transcript JSONL file and extracts
// tool calls with their responses. It handles two transcript formats:
//   - Message format: {"role":"assistant","content":[{"type":"tool_use",...}]}
//   - Event format:   {"type":"tool_use","name":"Bash","input":{...}}
//
// Tool results are matched to tool_use events by their id/tool_use_id fields.
// Results are returned in transcript order so capping is deterministic.
func parseTranscript(path string) ([]transcriptToolCall, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Track tool_use events keyed by id (for response matching) and in order (for output)
	pending := make(map[string]*pendingToolUse)
	var orderedIDs []string // preserves transcript order
	results := make(map[string]string)

	scanner := bufio.NewScanner(f)
	// Increase buffer for large transcript lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		var raw map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			log.Printf("[transcript] Skipping malformed line: %v", err)
			continue
		}

		// Check for message format: {"role":"assistant","content":[...]}
		if role, _ := raw["role"].(string); role == "assistant" {
			contentArr, ok := raw["content"].([]interface{})
			if !ok {
				continue
			}
			for _, item := range contentArr {
				block, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				processBlock(block, pending, &orderedIDs, results)
			}
			continue
		}

		// Check for tool_result in message format: {"role":"user","content":[{"type":"tool_result",...}]}
		if role, _ := raw["role"].(string); role == "user" {
			contentArr, ok := raw["content"].([]interface{})
			if !ok {
				continue
			}
			for _, item := range contentArr {
				block, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				processBlock(block, pending, &orderedIDs, results)
			}
			continue
		}

		// Event format: top-level {"type":"tool_use",...} or {"type":"tool_result",...}
		processBlock(raw, pending, &orderedIDs, results)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading transcript %s: %w", path, err)
	}

	// Build result slice in transcript order
	var calls []transcriptToolCall
	for _, id := range orderedIDs {
		tu := pending[id]
		calls = append(calls, transcriptToolCall{
			ToolName:     tu.Name,
			ToolInput:    tu.Input,
			ToolResponse: results[id], // empty string if no matching result
		})
	}

	return calls, nil
}

// processBlock handles a single content block, extracting tool_use or tool_result data.
func processBlock(block map[string]interface{}, pending map[string]*pendingToolUse, orderedIDs *[]string, results map[string]string) {
	blockType, _ := block["type"].(string)

	switch blockType {
	case "tool_use":
		id, _ := block["id"].(string)
		name, _ := block["name"].(string)
		if id == "" || name == "" {
			return
		}
		input, _ := block["input"].(map[string]interface{})
		if input == nil {
			input = make(map[string]interface{})
		}
		if _, exists := pending[id]; !exists {
			*orderedIDs = append(*orderedIDs, id)
		}
		pending[id] = &pendingToolUse{Name: name, Input: input}

	case "tool_result":
		toolUseID, _ := block["tool_use_id"].(string)
		if toolUseID == "" {
			return
		}
		// Extract text content from tool_result
		switch content := block["content"].(type) {
		case string:
			results[toolUseID] = content
		case []interface{}:
			// Content can be [{type:"text", text:"..."}]
			for _, item := range content {
				if m, ok := item.(map[string]interface{}); ok {
					if text, ok := m["text"].(string); ok {
						results[toolUseID] = text
						break
					}
				}
			}
		}
	}
}
