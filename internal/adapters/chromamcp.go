package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ChromaCollectionName = "cm__claude-mem"
	ChromaPythonVersion  = "3.13"
)

// ChromaMCPClient is a real MCP client that talks to chroma-mcp
type ChromaMCPClient struct {
	cmd       *exec.Cmd
	stdin     io.WriteCloser
	stdout    *bufio.Reader
	stderrLog *os.File
	mu        sync.Mutex
	requestID int64
	connected bool
}

// mcp request/response types
type mcpRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int64      `json:"id,omitempty"` // Pointer so notifications can omit it
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// chromaVectorDBPath returns the path to the chroma vector db
func chromaVectorDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude-mem", "vector-db")
}

// nextRequestID returns a pointer to the next request ID
func (c *ChromaMCPClient) nextRequestID() *int64 {
	id := atomic.AddInt64(&c.requestID, 1)
	return &id
}

// NewChromaMCPClient creates a new ChromaDB MCP client
func NewChromaMCPClient() *ChromaMCPClient {
	return &ChromaMCPClient{}
}

// Connect starts the chroma-mcp process and initializes the connection
func (c *ChromaMCPClient) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected {
		return nil
	}

	// Ensure vector-db directory exists
	vectorDBPath := chromaVectorDBPath()
	if err := os.MkdirAll(vectorDBPath, 0755); err != nil {
		return fmt.Errorf("create vector-db dir: %w", err)
	}

	// Find uvx - check common locations
	uvxPath, lookErr := exec.LookPath("uvx")
	if lookErr != nil {
		// Check common locations
		home, _ := os.UserHomeDir()
		candidates := []string{
			filepath.Join(home, ".local", "bin", "uvx"),
			"/usr/local/bin/uvx",
			"/opt/homebrew/bin/uvx",
		}
		for _, p := range candidates {
			if _, err := os.Stat(p); err == nil {
				uvxPath = p
				break
			}
		}
		if uvxPath == "" {
			return fmt.Errorf("uvx not found - required for ChromaDB")
		}
	}

	// Start chroma-mcp process
	c.cmd = exec.CommandContext(ctx, uvxPath, "--python", ChromaPythonVersion, "chroma-mcp",
		"--client-type", "persistent",
		"--data-dir", vectorDBPath)

	// Create process group so we can kill all child processes
	c.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	var err error
	c.stdin, err = c.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}

	stdout, err := c.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	c.stdout = bufio.NewReader(stdout)

	// Capture stderr to file for debugging (stored in struct for proper cleanup)
	home, _ := os.UserHomeDir()
	stderrPath := filepath.Join(home, ".sinesync", "chroma-stderr.log")
	c.stderrLog, _ = os.OpenFile(stderrPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if c.stderrLog != nil {
		c.cmd.Stderr = c.stderrLog
	}

	if err := c.cmd.Start(); err != nil {
		return fmt.Errorf("start chroma-mcp: %w", err)
	}

	// Give chroma-mcp time to start up
	time.Sleep(3 * time.Second)

	// Check if process is still alive by sending signal 0
	if c.cmd.Process == nil {
		return fmt.Errorf("chroma-mcp process is nil after start")
	}
	if err := c.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("chroma-mcp process died during startup: %w", err)
	}

	// Send initialize request
	initReq := mcpRequest{
		JSONRPC: "2.0",
		ID:      c.nextRequestID(),
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "sinesync",
				"version": "1.0.0",
			},
		},
	}

	if _, err := c.sendRequest(initReq); err != nil {
		c.cmd.Process.Kill()
		return fmt.Errorf("initialize: %w", err)
	}

	// Send initialized notification
	initNotif := mcpRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
	}
	if err := c.sendNotification(initNotif); err != nil {
		c.cmd.Process.Kill()
		return fmt.Errorf("initialized notification: %w", err)
	}

	c.connected = true
	return nil
}

// Close shuts down the chroma-mcp process
func (c *ChromaMCPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return nil
	}

	c.connected = false
	if c.stdin != nil {
		c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		// Kill the entire process group (negative PID) to ensure child processes are cleaned up
		syscall.Kill(-c.cmd.Process.Pid, syscall.SIGKILL)
		c.cmd.Wait()
	}
	if c.stderrLog != nil {
		c.stderrLog.Close()
		c.stderrLog = nil
	}
	return nil
}

// sendRequest sends a request and waits for response
func (c *ChromaMCPClient) sendRequest(req mcpRequest) (*mcpResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	expectedID := int64(0)
	if req.ID != nil {
		expectedID = *req.ID
	}

	// Write request
	if _, err := c.stdin.Write(append(data, '\n')); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	// Read response, skipping non-JSON lines (startup messages, logs, etc.)
	// and responses that don't match our request ID
	timeout := time.After(30 * time.Second)
	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("timeout waiting for response to request %d", expectedID)
		default:
		}

		line, err := c.stdout.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}

		// Skip empty lines and non-JSON lines
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] != '{' {
			continue
		}

		var resp mcpResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			// Not valid JSON, skip it
			continue
		}

		// Match response ID to request ID
		if resp.ID != expectedID {
			// This response is for a different request, keep reading
			continue
		}

		if resp.Error != nil {
			return nil, fmt.Errorf("MCP error %d: %s", resp.Error.Code, resp.Error.Message)
		}

		return &resp, nil
	}
}

// sendNotification sends a notification (no response expected)
func (c *ChromaMCPClient) sendNotification(req mcpRequest) error {
	data, err := json.Marshal(req)
	if err != nil {
		return err
	}

	if _, err := c.stdin.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("write notification: %w", err)
	}
	return nil
}

// EnsureCollection ensures the collection exists
func (c *ChromaMCPClient) EnsureCollection(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("not connected")
	}

	// Try to get collection info first
	getReq := mcpRequest{
		JSONRPC: "2.0",
		ID:      c.nextRequestID(),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "chroma_list_collections",
			"arguments": map[string]interface{}{},
		},
	}

	resp, err := c.sendRequest(getReq)
	if err != nil {
		// Try to create collection
		createReq := mcpRequest{
			JSONRPC: "2.0",
			ID:      c.nextRequestID(),
			Method:  "tools/call",
			Params: map[string]interface{}{
				"name": "chroma_create_collection",
				"arguments": map[string]interface{}{
					"collection_name": ChromaCollectionName,
				},
			},
		}
		_, err = c.sendRequest(createReq)
		return err
	}

	// Check if our collection exists in the list
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &result); err == nil {
		for _, c := range result.Content {
			if c.Text == ChromaCollectionName {
				return nil // Collection exists
			}
		}
	}

	// Create collection if not found
	createReq := mcpRequest{
		JSONRPC: "2.0",
		ID:      c.nextRequestID(),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "chroma_create_collection",
			"arguments": map[string]interface{}{
				"collection_name": ChromaCollectionName,
			},
		},
	}
	_, err = c.sendRequest(createReq)
	return err
}

// AddDocuments adds documents to the collection synchronously
// This blocks until the operation completes - providing natural backpressure
func (c *ChromaMCPClient) AddDocuments(ctx context.Context, ids []string, documents []string, metadatas []map[string]interface{}) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected {
		return fmt.Errorf("not connected")
	}

	req := mcpRequest{
		JSONRPC: "2.0",
		ID:      c.nextRequestID(),
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "chroma_add_documents",
			"arguments": map[string]interface{}{
				"collection_name": ChromaCollectionName,
				"ids":             ids,
				"documents":       documents,
				"metadatas":       metadatas,
			},
		},
	}

	resp, err := c.sendRequest(req)
	if err != nil {
		return err
	}

	// Check response content for errors
	if resp.Result != nil {
		var result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			IsError bool `json:"isError"`
		}
		if err := json.Unmarshal(resp.Result, &result); err == nil {
			if result.IsError {
				if len(result.Content) > 0 {
					errText := result.Content[0].Text
					// If documents already exist, that's fine - they're already embedded
					if strings.Contains(errText, "already exist") {
						return nil // Not an error for our purposes
					}
					return fmt.Errorf("chroma error: %s", errText)
				}
				return fmt.Errorf("chroma returned isError=true")
			}
		}
	}

	return nil
}

// FormatObservationDocs formats an observation into ChromaDB documents
// matching claude-mem's format
func FormatObservationDocs(obsID int64, memorySessionID, project, obsType, title, subtitle, narrative string,
	facts, concepts, filesRead, filesModified []string, createdAtEpoch int64) ([]string, []string, []map[string]interface{}) {

	var ids []string
	var documents []string
	var metadatas []map[string]interface{}

	baseMeta := map[string]interface{}{
		"sqlite_id":         obsID,
		"doc_type":          "observation",
		"memory_session_id": memorySessionID,
		"project":           project,
		"created_at_epoch":  createdAtEpoch,
		"type":              obsType,
		"title":             title,
	}

	if subtitle != "" {
		baseMeta["subtitle"] = subtitle
	}
	if len(concepts) > 0 {
		baseMeta["concepts"] = joinStrings(concepts, ",")
	}
	if len(filesRead) > 0 {
		baseMeta["files_read"] = joinStrings(filesRead, ",")
	}
	if len(filesModified) > 0 {
		baseMeta["files_modified"] = joinStrings(filesModified, ",")
	}

	// Add narrative document
	if narrative != "" {
		ids = append(ids, fmt.Sprintf("obs_%d_narrative", obsID))
		documents = append(documents, narrative)
		meta := copyMeta(baseMeta)
		meta["field_type"] = "narrative"
		metadatas = append(metadatas, meta)
	}

	// Add fact documents
	for i, fact := range facts {
		ids = append(ids, fmt.Sprintf("obs_%d_fact_%d", obsID, i))
		documents = append(documents, fact)
		meta := copyMeta(baseMeta)
		meta["field_type"] = "fact"
		meta["fact_index"] = i
		metadatas = append(metadatas, meta)
	}

	return ids, documents, metadatas
}

func joinStrings(s []string, sep string) string {
	if len(s) == 0 {
		return ""
	}
	result := s[0]
	for i := 1; i < len(s); i++ {
		result += sep + s[i]
	}
	return result
}

func copyMeta(m map[string]interface{}) map[string]interface{} {
	copy := make(map[string]interface{})
	for k, v := range m {
		copy[k] = v
	}
	return copy
}

// Legacy type alias for backward compatibility
type ChromaSyncClient = ChromaMCPClient
