package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/daemon"
)

// JSON-RPC structures
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
}

type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]interface{} `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Capabilities struct {
	Tools map[string]interface{} `json:"tools,omitempty"`
}

type InitializeResult struct {
	ProtocolVersion string       `json:"protocolVersion"`
	Capabilities    Capabilities `json:"capabilities"`
	ServerInfo      ServerInfo   `json:"serverInfo"`
}

// Server holds MCP server state
type Server struct {
	mode       string // "standalone" or "adapter"
	daemonPort int
	httpClient *http.Client
}

// Sync tools (both modes)
var syncTools = []Tool{
	{
		Name:        "sinesync_status",
		Description: "Check sine~sync status: storage, mode, daemon status",
		InputSchema: InputSchema{Type: "object", Properties: map[string]interface{}{}},
	},
	{
		Name:        "sinesync_search",
		Description: "Search memories with semantic similarity",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"query": map[string]interface{}{"type": "string", "description": "Search query"},
				"limit": map[string]interface{}{"type": "number", "description": "Max results (default 20)"},
			},
			Required: []string{"query"},
		},
	},
	{
		Name:        "sinesync_projects",
		Description: "List projects with observation counts",
		InputSchema: InputSchema{Type: "object", Properties: map[string]interface{}{}},
	},
}

// Memory tools (standalone mode only)
var memoryTools = []Tool{
	{
		Name:        "memory_store",
		Description: "Store an observation/memory",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"type":    map[string]interface{}{"type": "string", "enum": []string{"bugfix", "feature", "decision", "discovery", "change", "refactor"}},
				"title":   map[string]interface{}{"type": "string", "description": "Short title"},
				"summary": map[string]interface{}{"type": "string", "description": "Brief summary"},
				"content": map[string]interface{}{"type": "string", "description": "Detailed content"},
				"project": map[string]interface{}{"type": "string", "description": "Project name"},
			},
			Required: []string{"type", "title", "summary"},
		},
	},
	{
		Name:        "memory_get",
		Description: "Get a specific memory by ID",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"id": map[string]interface{}{"type": "string", "description": "Observation ID"},
			},
			Required: []string{"id"},
		},
	},
}

// StartServer starts the MCP server
func StartServer() error {
	// Ensure daemon is running first
	info, err := daemon.EnsureRunning()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sine~sync: Failed to start daemon: %v\n", err)
		return err
	}

	// Detect mode
	mode := "standalone"
	if adapters.IsClaudeMemInstalled() {
		mode = "adapter"
	}

	server := &Server{
		mode:       mode,
		daemonPort: info.Port,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Select tools based on mode
	var tools []Tool
	if mode == "adapter" {
		tools = syncTools
		fmt.Fprintln(os.Stderr, "sine~sync MCP: adapter mode (claude-mem detected)")
		fmt.Fprintln(os.Stderr, "  → Memory tools: claude-mem")
		fmt.Fprintln(os.Stderr, "  → Sync/search: sinesync")
	} else {
		tools = append(memoryTools, syncTools...)
		fmt.Fprintln(os.Stderr, "sine~sync MCP: standalone mode")
		fmt.Fprintln(os.Stderr, "  → Memory + sync tools: sinesync")
	}

	fmt.Fprintf(os.Stderr, "  → Daemon: http://127.0.0.1:%d\n", info.Port)
	fmt.Fprintf(os.Stderr, "  → Dashboard: http://127.0.0.1:%d\n", info.Port)

	// Read JSON-RPC messages from stdin
	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}

		var resp Response
		resp.JSONRPC = "2.0"
		resp.ID = req.ID

		switch req.Method {
		case "initialize":
			resp.Result = InitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities:    Capabilities{Tools: map[string]interface{}{}},
				ServerInfo:      ServerInfo{Name: "sinesync", Version: "0.1.0"},
			}

		case "tools/list":
			resp.Result = map[string]interface{}{"tools": tools}

		case "tools/call":
			resp.Result = server.handleToolCall(req.Params)

		case "notifications/initialized":
			continue

		default:
			resp.Error = &Error{Code: -32601, Message: "Method not found"}
		}

		respBytes, _ := json.Marshal(resp)
		fmt.Println(string(respBytes))
	}

	return scanner.Err()
}

func (s *Server) handleToolCall(params json.RawMessage) interface{} {
	var call struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(params, &call); err != nil {
		return errorResult("Invalid params")
	}

	switch call.Name {
	case "sinesync_status":
		return s.handleStatus()
	case "sinesync_search":
		return s.handleSearch(call.Arguments)
	case "sinesync_projects":
		return s.handleProjects()
	case "memory_store":
		return s.handleMemoryStore(call.Arguments)
	case "memory_get":
		return s.handleMemoryGet(call.Arguments)
	default:
		return errorResult(fmt.Sprintf("Unknown tool: %s", call.Name))
	}
}

func (s *Server) handleStatus() interface{} {
	resp, err := s.httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/api/status", s.daemonPort))
	if err != nil {
		return errorResult(fmt.Sprintf("Daemon error: %v", err))
	}
	defer resp.Body.Close()

	var status map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return errorResult("Failed to parse status")
	}

	return textResult(status)
}

func (s *Server) handleSearch(args map[string]interface{}) interface{} {
	query, _ := args["query"].(string)
	if query == "" {
		return errorResult("Query required")
	}

	limit := 20
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	apiURL := fmt.Sprintf("http://127.0.0.1:%d/api/search?q=%s&limit=%d",
		s.daemonPort, url.QueryEscape(query), limit)

	resp, err := s.httpClient.Get(apiURL)
	if err != nil {
		return errorResult(fmt.Sprintf("Search error: %v", err))
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult("Failed to parse search results")
	}

	// Format for display
	observations, _ := result["observations"].([]interface{})
	var output []map[string]interface{}
	for _, obs := range observations {
		if o, ok := obs.(map[string]interface{}); ok {
			output = append(output, map[string]interface{}{
				"id":        o["id"],
				"type":      o["type"],
				"title":     o["title"],
				"summary":   o["summary"],
				"project":   o["project"],
				"score":     o["score"],
				"createdAt": o["createdAt"],
			})
		}
	}

	return textResult(map[string]interface{}{
		"query":        query,
		"total":        result["total"],
		"observations": output,
	})
}

func (s *Server) handleProjects() interface{} {
	resp, err := s.httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/api/projects", s.daemonPort))
	if err != nil {
		return errorResult(fmt.Sprintf("Projects error: %v", err))
	}
	defer resp.Body.Close()

	var projects []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return errorResult("Failed to parse projects")
	}

	return textResult(map[string]interface{}{"projects": projects})
}

func (s *Server) handleMemoryStore(args map[string]interface{}) interface{} {
	if s.mode == "adapter" {
		return errorResult("Use claude-mem for memory storage in adapter mode")
	}

	// Get current working directory for project
	cwd, _ := os.Getwd()
	project := filepath.Base(cwd)
	if p, ok := args["project"].(string); ok && p != "" {
		project = p
	}

	obsType, _ := args["type"].(string)
	title, _ := args["title"].(string)
	summary, _ := args["summary"].(string)
	content, _ := args["content"].(string)

	// Create capture request
	captureReq := map[string]interface{}{
		"session_id": "mcp-manual",
		"tool_name":  "ManualStore",
		"tool_input": fmt.Sprintf(`{"type":"%s","title":"%s","summary":"%s","content":"%s"}`,
			obsType, title, summary, content),
		"tool_response": "Manual observation",
		"cwd":           cwd,
	}

	body, _ := json.Marshal(captureReq)
	resp, err := s.httpClient.Post(
		fmt.Sprintf("http://127.0.0.1:%d/api/capture", s.daemonPort),
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return errorResult(fmt.Sprintf("Store error: %v", err))
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	return textResult(map[string]interface{}{
		"stored":  true,
		"id":      result["id"],
		"title":   title,
		"type":    obsType,
		"project": project,
	})
}

func (s *Server) handleMemoryGet(args map[string]interface{}) interface{} {
	id, _ := args["id"].(string)
	if id == "" {
		return errorResult("ID required")
	}

	resp, err := s.httpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/api/observations/%s", s.daemonPort, id))
	if err != nil {
		return errorResult(fmt.Sprintf("Get error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return errorResult("Observation not found")
	}

	var obs map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&obs); err != nil {
		return errorResult("Failed to parse observation")
	}

	return textResult(obs)
}

func textResult(data interface{}) interface{} {
	jsonBytes, _ := json.MarshalIndent(data, "", "  ")
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": string(jsonBytes)},
		},
	}
}

func errorResult(msg string) interface{} {
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": fmt.Sprintf(`{"error": "%s"}`, msg)},
		},
		"isError": true,
	}
}
