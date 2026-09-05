package mcp

import (
	"bufio"
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

	"github.com/sinesync/cli/internal/adapters"
	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/daemon"
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
	Tools map[string]interface{} `json:"tools"`
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

// readHookSecret loads the daemon's shared secret from its 0600 file. A missing
// or unreadable file yields an empty secret rather than an error, so the MCP
// server still starts and can answer tools/list; the daemon then rejects the
// API calls with 401 and apiError explains that the secret file is the cause.
func readHookSecret() string {
	b, err := os.ReadFile(filepath.Join(config.DataDir(), "hook-secret"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// daemonURL builds an absolute URL for a daemon API path.
func (s *Server) daemonURL(path string) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", s.daemonPort, path)
}

// do issues a request to the daemon with the hook secret attached. Every daemon
// call goes through here so no endpoint can silently skip authentication.
//
// The secret is re-read per request rather than cached at startup, matching the
// hook client in internal/cli/hooks.go: the daemon generates a fresh secret
// every time it starts, and an MCP server outlives daemon restarts, so a cached
// copy would go stale and reject every subsequent call.
func (s *Server) do(method, url string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if secret := readHookSecret(); secret != "" {
		req.Header.Set("X-Hook-Secret", secret)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return s.httpClient.Do(req)
}

func (s *Server) get(path string) (*http.Response, error) {
	return s.do(http.MethodGet, s.daemonURL(path), nil, "")
}

// Sync tools (both modes)
var syncTools = []Tool{
	{
		Name:        "sinesync_status",
		Description: "Check sine~sync daemon status including storage size, observation count, embedding model, and operating mode",
		InputSchema: InputSchema{Type: "object", Properties: map[string]interface{}{}},
	},
	{
		Name:        "sinesync_search",
		Description: "Quick semantic search across all observations. Use the 'search' tool instead for filtered queries (by project, type, or date range)",
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
		Description: "List all projects and the number of observations in each. Useful for discovering available projects before filtering searches",
		InputSchema: InputSchema{Type: "object", Properties: map[string]interface{}{}},
	},
}

// Memory tools (standalone mode only) — 3-layer workflow matching claude-mem
var memoryTools = []Tool{
	{
		Name:        "search",
		Description: "Search observations by semantic similarity. Returns matching IDs, titles, summaries, and scores. Supports filtering by project, type (discovery, decision, bugfix, feature, change, refactor), and date range. Use 'get_observations' to fetch full details for specific IDs",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"query":     map[string]interface{}{"type": "string", "description": "Search query"},
				"limit":     map[string]interface{}{"type": "number", "description": "Max results (default 20)"},
				"project":   map[string]interface{}{"type": "string", "description": "Filter by project"},
				"type":      map[string]interface{}{"type": "string", "description": "Filter by type (discovery, decision, bugfix, etc.)"},
				"dateStart": map[string]interface{}{"type": "string", "description": "Filter start date (ISO 8601)"},
				"dateEnd":   map[string]interface{}{"type": "string", "description": "Filter end date (ISO 8601)"},
			},
			Required: []string{"query"},
		},
	},
	{
		Name:        "timeline",
		Description: "View observations surrounding a specific point in time. Provide an observation ID as anchor, or a query to find one automatically. Returns neighboring observations with full details, useful for understanding what happened before and after a specific event",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"anchor":       map[string]interface{}{"type": "string", "description": "Observation ID to center timeline on"},
				"query":        map[string]interface{}{"type": "string", "description": "Search query to find anchor automatically"},
				"depth_before": map[string]interface{}{"type": "number", "description": "Observations before anchor (default 5)"},
				"depth_after":  map[string]interface{}{"type": "number", "description": "Observations after anchor (default 5)"},
			},
		},
	},
	{
		Name:        "get_observations",
		Description: "Fetch full observation details by ID. Returns complete content, facts, concepts, files, and metadata. Use after 'search' to get the full context for specific results",
		InputSchema: InputSchema{
			Type: "object",
			Properties: map[string]interface{}{
				"ids": map[string]interface{}{
					"type":        "array",
					"items":       map[string]interface{}{"type": "string"},
					"description": "Array of observation IDs to fetch (required)",
				},
			},
			Required: []string{"ids"},
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

	// Determine mode from config, fall back to auto-detect for unconfigured installs
	cfg, _ := config.Load()
	mode := cfg.Mode
	if mode == "" {
		if adapters.IsClaudeMemInstalled() {
			mode = "adapter"
		} else {
			mode = "standalone"
		}
	}

	server := &Server{
		mode:       mode,
		daemonPort: info.Port,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	if readHookSecret() == "" {
		fmt.Fprintf(os.Stderr, "sine~sync MCP: warning: no hook secret at %s; the daemon will reject every API call until it is readable\n",
			filepath.Join(config.DataDir(), "hook-secret"))
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
	fmt.Fprintf(os.Stderr, "  → Dashboard: run 'sinesync dashboard' (port %d)\n", info.Port)

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
	case "search":
		return s.handleMCPSearch(call.Arguments)
	case "timeline":
		return s.handleMCPTimeline(call.Arguments)
	case "get_observations":
		return s.handleMCPGetObservations(call.Arguments)
	default:
		return errorResult(fmt.Sprintf("Unknown tool: %s", call.Name))
	}
}

func (s *Server) handleStatus() interface{} {
	resp, err := s.get("/api/status")
	if err != nil {
		return errorResult(fmt.Sprintf("Daemon error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return apiError("Status", resp)
	}

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

	apiPath := fmt.Sprintf("/api/mcp/search?query=%s&limit=%d", url.QueryEscape(query), limit)

	resp, err := s.get(apiPath)
	if err != nil {
		return errorResult(fmt.Sprintf("Search error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return apiError("Search", resp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult("Failed to parse search results")
	}

	// Format for display — /api/mcp/search returns "results" key
	results, _ := result["results"].([]interface{})
	var output []map[string]interface{}
	for _, obs := range results {
		if o, ok := obs.(map[string]interface{}); ok {
			output = append(output, map[string]interface{}{
				"id":         o["id"],
				"type":       o["type"],
				"title":      o["title"],
				"summary":    o["summary"],
				"project":    o["project"],
				"score":      o["score"],
				"created_at": o["created_at"],
			})
		}
	}

	return textResult(map[string]interface{}{
		"query":        query,
		"total":        len(output),
		"observations": output,
	})
}

func (s *Server) handleProjects() interface{} {
	resp, err := s.get("/api/projects")
	if err != nil {
		return errorResult(fmt.Sprintf("Projects error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return apiError("Projects", resp)
	}

	var projects []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return errorResult("Failed to parse projects")
	}

	return textResult(map[string]interface{}{"projects": projects})
}

func (s *Server) handleMCPSearch(args map[string]interface{}) interface{} {
	query, _ := args["query"].(string)
	if query == "" {
		return errorResult("Query required")
	}

	limit := 20
	if l, ok := args["limit"].(float64); ok {
		limit = int(l)
	}

	// Build query params
	params := url.Values{}
	params.Set("query", query)
	params.Set("limit", fmt.Sprintf("%d", limit))
	if p, ok := args["project"].(string); ok && p != "" {
		params.Set("project", p)
	}
	if t, ok := args["type"].(string); ok && t != "" {
		params.Set("type", t)
	}
	if ds, ok := args["dateStart"].(string); ok && ds != "" {
		params.Set("dateStart", ds)
	}
	if de, ok := args["dateEnd"].(string); ok && de != "" {
		params.Set("dateEnd", de)
	}

	resp, err := s.get("/api/mcp/search?" + params.Encode())
	if err != nil {
		return errorResult(fmt.Sprintf("Search error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return apiError("Search", resp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult("Failed to parse search results")
	}

	return textResult(result)
}

func (s *Server) handleMCPTimeline(args map[string]interface{}) interface{} {
	// Build query params
	params := url.Values{}
	if anchor, ok := args["anchor"].(string); ok && anchor != "" {
		params.Set("anchor", anchor)
	}
	if query, ok := args["query"].(string); ok && query != "" {
		params.Set("query", query)
	}
	if db, ok := args["depth_before"].(float64); ok {
		params.Set("depth_before", fmt.Sprintf("%d", int(db)))
	}
	if da, ok := args["depth_after"].(float64); ok {
		params.Set("depth_after", fmt.Sprintf("%d", int(da)))
	}

	resp, err := s.get("/api/mcp/timeline?" + params.Encode())
	if err != nil {
		return errorResult(fmt.Sprintf("Timeline error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return apiError("Timeline", resp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult("Failed to parse timeline results")
	}

	return textResult(result)
}

func (s *Server) handleMCPGetObservations(args map[string]interface{}) interface{} {
	idsRaw, ok := args["ids"].([]interface{})
	if !ok || len(idsRaw) == 0 {
		return errorResult("ids array required")
	}

	ids := make([]string, 0, len(idsRaw))
	for _, id := range idsRaw {
		if s, ok := id.(string); ok {
			ids = append(ids, s)
		}
	}
	if len(ids) == 0 {
		return errorResult("ids array must contain at least one string")
	}

	reqBody, _ := json.Marshal(map[string]interface{}{"ids": ids})
	resp, err := s.do(
		http.MethodPost,
		s.daemonURL("/api/mcp/observations"),
		bytes.NewReader(reqBody),
		"application/json",
	)
	if err != nil {
		return errorResult(fmt.Sprintf("Get observations error: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return apiError("Get observations", resp)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errorResult("Failed to parse observations")
	}

	return textResult(result)
}

// apiError converts a non-200 daemon response into a tool error. A 401 gets an
// actionable message instead of the daemon's bare "unauthorized": the caller
// needs to know the secret file is the problem, not the query.
func apiError(op string, resp *http.Response) interface{} {
	if resp.StatusCode == http.StatusUnauthorized {
		secretPath := filepath.Join(config.DataDir(), "hook-secret")
		if readHookSecret() == "" {
			return errorResult(fmt.Sprintf(
				"%s failed: cannot read the daemon hook secret at %s. The daemon writes it on startup; run 'sinesync restart'.",
				op, secretPath))
		}
		return errorResult(fmt.Sprintf(
			"%s failed: the daemon rejected the hook secret at %s — it is probably stale. Run 'sinesync restart'.",
			op, secretPath))
	}
	body, _ := io.ReadAll(resp.Body)
	return errorResult(fmt.Sprintf("%s failed (%d): %s", op, resp.StatusCode, strings.TrimSpace(string(body))))
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
	// Marshalled rather than interpolated: messages now carry filesystem paths
	// and daemon response bodies, either of which can contain a quote or a
	// newline that would produce malformed JSON.
	payload, err := json.Marshal(map[string]string{"error": msg})
	if err != nil {
		payload = []byte(`{"error": "unknown error"}`)
	}
	return map[string]interface{}{
		"content": []map[string]interface{}{
			{"type": "text", "text": string(payload)},
		},
		"isError": true,
	}
}
