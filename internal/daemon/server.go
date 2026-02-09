package daemon

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/embeddings"
	"github.com/miclip/sinesync/internal/keychain"
	"github.com/miclip/sinesync/internal/storage"
	"github.com/zalando/go-keyring"
)

//go:embed static/*
var staticFiles embed.FS

// Server is the unified daemon server (dashboard + hook API)
type Server struct {
	port     int
	backend  storage.StorageBackend
	config   *config.Config
	embedder *embeddings.Provider
	httpServer *http.Server
	mode       string // "standalone" or "adapter"
	syncManager *SyncManager

	// Observation cache
	obsCache      []storage.Observation
	obsCacheTime  time.Time
	obsCacheTTL   time.Duration
	obsCacheMu    sync.Mutex

	// Async hook processing queue
	hookQueue    chan func()
	hookDone     chan struct{}
	hookShutdown atomic.Bool
}

// NewServer creates a new daemon server
func NewServer(port int) *Server {
	if port == 0 {
		port = DefaultPort
	}

	cfg, _ := config.Load()

	// Determine mode from config, fall back to auto-detect for unconfigured installs
	mode := cfg.Mode
	if mode == "" {
		if adapters.IsClaudeMemInstalled() {
			mode = "adapter"
		} else {
			mode = "standalone"
		}
	}

	embedder, _ := embeddings.NewProvider()

	// Try SQLCipher backend first, fall back to LocalStorage
	var backend storage.StorageBackend
	sqlBackend := initSQLCipherBackend()
	if sqlBackend != nil {
		backend = sqlBackend

		// Auto-migrate legacy JSON observations if they exist
		if storage.HasLegacyObservations(config.DataDir()) {
			localSource := storage.NewLocalStorage()
			migrated, err := storage.MigrateLocalToSQLCipher(localSource, sqlBackend)
			if err != nil {
				log.Printf("[daemon] Migration error: %v", err)
			} else if migrated > 0 {
				log.Printf("[daemon] Migrated %d observations from JSON to SQLCipher", migrated)
				if err := storage.RenameLegacyDir(config.DataDir()); err != nil {
					log.Printf("[daemon] Failed to rename legacy dir: %v", err)
				}

				// Backfill embeddings for migrated observations in background
				if embedder != nil {
					go backfillEmbeddings(sqlBackend, embedder)
				}
			}
		}
	} else {
		log.Printf("[daemon] Falling back to JSON file storage")
		backend = storage.NewLocalStorage()
	}

	return &Server{
		port:        port,
		backend:     backend,
		config:      cfg,
		embedder:    embedder,
		mode:        mode,
		syncManager: NewSyncManager(backend, mode),
		obsCacheTTL: 30 * time.Second, // Cache for 30 seconds
	}
}

// initSQLCipherBackend attempts to create a SQLCipher storage backend.
// Returns nil if key is unavailable or database creation fails.
func initSQLCipherBackend() *storage.SQLCipherStorage {
	dbPath := filepath.Join(config.DataDir(), "memory.db")

	key, err := keychain.GetOrCreateDBKey()
	if err != nil {
		log.Printf("[daemon] Failed to resolve DB key: %v", err)
		return nil
	}

	db, err := storage.NewSQLCipherStorage(dbPath, key)
	if err != nil {
		log.Printf("[daemon] SQLCipher init failed: %v", err)
		return nil
	}

	log.Printf("[daemon] Using SQLCipher encrypted storage")
	return db
}

// backfillEmbeddings generates embeddings for observations that lack them.
func backfillEmbeddings(backend *storage.SQLCipherStorage, embedder *embeddings.Provider) {
	if !embedder.IsReady() {
		return
	}

	observations, err := backend.ListObservations()
	if err != nil {
		log.Printf("[migrate] Failed to list observations for embedding backfill: %v", err)
		return
	}

	backfilled := 0
	failed := 0
	for _, obs := range observations {
		if obs.Embedding.IsCompatibleWith(embeddings.ModelName, embeddings.TokenizerType, embeddings.Dimensions) {
			continue
		}
		obsCopy := obs
		text := obsCopy.TextForEmbedding()
		vec, err := embedder.Embed(text)
		if err != nil {
			failed++
			if failed <= 3 {
				log.Printf("[migrate] WARNING: embedding failed for %s: %v", obsCopy.ID, err)
			}
			continue
		}
		obsCopy.Embedding.Vector = vec
		obsCopy.Embedding.Model = embeddings.ModelName
		obsCopy.Embedding.Tokenizer = embedder.TokenizerType()
		obsCopy.Embedding.Dims = embeddings.Dimensions
		if err := backend.SaveObservation(&obsCopy); err == nil {
			backfilled++
		}
	}

	if backfilled > 0 || failed > 0 {
		log.Printf("[migrate] Backfill complete: %d embedded, %d failed", backfilled, failed)
	}
}

// getObservations returns cached observations, refreshing if stale
func (s *Server) getObservations() []storage.Observation {
	s.obsCacheMu.Lock()
	defer s.obsCacheMu.Unlock()

	if time.Since(s.obsCacheTime) > s.obsCacheTTL || s.obsCache == nil {
		log.Printf("[cache] Loading observations into cache...")
		start := time.Now()
		s.obsCache, _ = s.backend.ListObservations()
		s.obsCacheTime = time.Now()
		log.Printf("[cache] Cached %d observations in %v", len(s.obsCache), time.Since(start))
	}
	return s.obsCache
}

// invalidateCache forces a cache refresh on next access
func (s *Server) invalidateCache() {
	s.obsCacheMu.Lock()
	s.obsCacheTime = time.Time{}
	s.obsCacheMu.Unlock()
}

// processHookQueue drains the async work queue with panic recovery.
func (s *Server) processHookQueue() {
	defer close(s.hookDone)
	for work := range s.hookQueue {
		s.safeExec(work)
	}
}

func (s *Server) safeExec(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[hook] Panic in queued work: %v", r)
		}
	}()
	fn()
}

// enqueueHook submits work to the async queue. Drops if shutting down or full.
func (s *Server) enqueueHook(fn func()) {
	if s.hookShutdown.Load() {
		return
	}
	select {
	case s.hookQueue <- fn:
	default:
		log.Printf("[hook] Queue full, dropping work item")
	}
}

// Run starts the server and blocks until shutdown
func (s *Server) Run() error {
	mux := http.NewServeMux()

	// Health/status endpoints
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/status", s.handleStatus)

	// Hook API endpoints
	mux.HandleFunc("/api/context", s.handleContext)
	mux.HandleFunc("/api/capture", s.handleCapture)
	mux.HandleFunc("/api/summarize", s.handleSummarize)
	mux.HandleFunc("/api/prompt", s.handlePrompt)

	// Dashboard API endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/observations", s.handleObservations)
	mux.HandleFunc("/api/observations/", s.handleObservation)
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/tags", s.handleTags)
	mux.HandleFunc("/api/search", s.handleSearch)
	mux.HandleFunc("/api/sync", s.handleSync)
	mux.HandleFunc("/api/vaults", s.handleVaults)

	// MCP API endpoints (3-layer workflow)
	mux.HandleFunc("/api/mcp/search", s.handleMCPSearch)
	mux.HandleFunc("/api/mcp/timeline", s.handleMCPTimeline)
	mux.HandleFunc("/api/mcp/observations", s.handleMCPGetObservations)

	// Static files for dashboard
	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Write PID file
	if err := WritePIDInfo(&PIDInfo{
		PID:       os.Getpid(),
		Port:      s.port,
		StartedAt: time.Now(),
		Version:   "0.1.0",
	}); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Start async hook processing queue
	s.hookQueue = make(chan func(), 256)
	s.hookDone = make(chan struct{})
	go s.processHookQueue()

	// Start background sync
	s.syncManager.Start()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[daemon] Shutting down...")
		s.syncManager.Stop()
		s.hookShutdown.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx) // stop accepting, wait for in-flight handlers
		close(s.hookQueue)
		<-s.hookDone // drain queued work
		if err := s.backend.Close(); err != nil {
			log.Printf("[daemon] Error closing storage backend: %v", err)
		}
		RemovePIDFile()
	}()

	log.Printf("[daemon] sine~sync starting on http://%s", addr)
	log.Printf("[daemon]   Mode: %s", s.mode)
	log.Printf("[daemon]   Dashboard: http://%s", addr)
	log.Printf("[daemon]   Hook API: http://%s/api/", addr)
	log.Printf("[daemon]   Cloud sync: every %v", SyncInterval)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// === Health endpoints ===

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status": "ok",
		"mode":   s.mode,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	itemCount, storageBytes, _ := s.backend.GetStatus()

	status := map[string]interface{}{
		"mode":    s.mode,
		"port":    s.port,
		"storage": map[string]interface{}{
			"observations": itemCount,
			"bytes":        storageBytes,
		},
		"embeddings": map[string]interface{}{
			"ready": s.embedder != nil && s.embedder.IsReady(),
			"model": embeddings.ModelName,
		},
	}

	if s.mode == "adapter" && adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			defer adapter.Close()
			count, _ := adapter.GetObservationCount()
			status["adapter"] = map[string]interface{}{
				"name":         "claude-mem",
				"observations": count,
			}
		}
	}

	writeJSON(w, status)
}

// === Hook API endpoints ===

func (s *Server) handleContext(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	sessionID := r.URL.Query().Get("session_id")
	limit := 20

	// Ensure session exists in SQLCipher
	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			_ = sqlBackend.EnsureSession(sessionID, project, time.Now().Unix())
		}
	}

	observations := s.getObservations()

	// Filter by project if specified
	if project != "" {
		var filtered []storage.Observation
		for _, obs := range observations {
			if obs.Core.Project == project {
				filtered = append(filtered, obs)
			}
		}
		observations = filtered
	}

	// Sort by relevance (for now, just by date)
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Core.CreatedAt.After(observations[j].Core.CreatedAt)
	})

	// Limit
	if len(observations) > limit {
		observations = observations[:limit]
	}

	// Format context output
	var sb strings.Builder
	sb.WriteString("# [sinesync] Recent context\n\n")

	// Check auth status and add sync info
	syncing, lastSync, syncErr := s.syncManager.Status()
	authenticated := s.isAuthenticated()

	if !authenticated {
		sb.WriteString("**Cloud sync disabled** - Run `sinesync login` to enable cross-device sync\n\n")
	} else if syncErr != "" {
		sb.WriteString(fmt.Sprintf("**Sync error**: %s\n\n", syncErr))
	} else if syncing {
		sb.WriteString("**Syncing** to cloud...\n\n")
	} else if !lastSync.IsZero() {
		sb.WriteString(fmt.Sprintf("**Last sync**: %s\n\n", formatRelativeTime(lastSync)))
	}

	for _, obs := range observations {
		sb.WriteString(fmt.Sprintf("**%s** (%s)\n", obs.Core.Title, obs.Core.Type))
		if obs.Core.Summary != "" {
			sb.WriteString(fmt.Sprintf("%s\n", obs.Core.Summary))
		}
		sb.WriteString("\n")
	}

	// Return as hook output format
	writeJSON(w, map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":     "SessionStart",
			"additionalContext": sb.String(),
		},
	})
}

// isAuthenticated checks if user has valid auth tokens
func (s *Server) isAuthenticated() bool {
	const keyringService = "sinesync"

	// Check keyring first (preferred secure storage)
	if token, err := keyring.Get(keyringService, "token"); err == nil && token != "" {
		return true
	}
	if deviceToken, err := keyring.Get(keyringService, "deviceToken"); err == nil && deviceToken != "" {
		return true
	}

	// Fallback to JSON file
	authPath := filepath.Join(config.ConfigDir(), "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return false
	}

	var auth struct {
		DeviceToken string `json:"deviceToken"`
		Token       string `json:"token"`
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		return false
	}

	return auth.DeviceToken != "" || auth.Token != ""
}

func formatRelativeTime(t time.Time) string {
	diff := time.Since(t)
	if diff < time.Minute {
		return "just now"
	}
	if diff < time.Hour {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(diff.Hours()/24))
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID    string          `json:"session_id"`
		ToolName     string          `json:"tool_name"`
		ToolInput    json.RawMessage `json:"tool_input"`
		ToolResponse json.RawMessage `json:"tool_response"`
		CWD          string          `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Skip tools that don't produce meaningful observations
	skipTools := map[string]bool{
		"Read": true, "Glob": true, "Grep": true,
		"ListMcpResourcesTool": true, "SlashCommand": true,
		"Skill": true, "TodoWrite": true, "AskUserQuestion": true,
		"TaskList": true, "TaskGet": true,
	}

	if skipTools[hookInput.ToolName] {
		writeJSON(w, map[string]interface{}{"status": "skipped"})
		return
	}

	// Ack immediately — do heavy work (extraction, embedding, save) async
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	s.enqueueHook(func() {
		s.processCapture(hookInput.SessionID, hookInput.ToolName, hookInput.ToolInput, hookInput.ToolResponse, hookInput.CWD)
	})
}

// processCapture does the actual observation extraction, embedding, and save.
func (s *Server) processCapture(sessionID, toolName string, toolInput, toolResponse json.RawMessage, cwd string) {
	project := filepath.Base(cwd)
	log.Printf("[capture] Processing: tool=%s session=%s project=%s", toolName, sessionID, project)

	var toolInputData map[string]interface{}
	json.Unmarshal(toolInput, &toolInputData)

	var toolResponseStr string
	if err := json.Unmarshal(toolResponse, &toolResponseStr); err != nil {
		toolResponseStr = string(toolResponse)
	}

	obs := s.extractObservation(toolName, toolInputData, toolResponseStr, project)
	if obs == nil {
		return
	}

	textForEmbedding := obs.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			obs.Embedding.Vector = embedding
			obs.Embedding.Model = embeddings.ModelName
			obs.Embedding.Tokenizer = s.embedder.TokenizerType()
			obs.Embedding.Dims = embeddings.Dimensions
		} else {
			log.Printf("[capture] WARNING: embedding failed for %s: %v", obs.ID, err)
		}
	} else {
		log.Printf("[capture] WARNING: embedder not available, observation %s will have no embedding", obs.ID)
	}

	obs.Core.SessionID = sessionID

	if err := s.backend.SaveObservation(obs); err != nil {
		log.Printf("[capture] Failed to save observation: %v", err)
		return
	}
	s.invalidateCache()

	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			_ = sqlBackend.IncrementSessionObservationCount(sessionID)
		}
	}

	log.Printf("[capture] Saved: id=%s title=%s type=%s", obs.ID, obs.Core.Title, obs.Core.Type)
}

func (s *Server) extractObservation(toolName string, toolInput map[string]interface{}, toolResponse, project string) *storage.Observation {
	now := time.Now()
	obs := &storage.Observation{
		ID: generateID(),
		Core: storage.Core{
			Project:   project,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Source: storage.Source{
			Adapter: "sinesync",
			Epoch:   now.Unix(),
		},
	}

	switch toolName {
	case "Write":
		filePath, _ := toolInput["file_path"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Created file: %s", filepath.Base(filePath))
		obs.Core.Summary = fmt.Sprintf("Created new file at %s", filePath)
		obs.Core.Content = truncate(toolResponse, 500)
		obs.Structured.Files.Modified = []string{filePath}
		obs.Structured.CodeRefs = []string{filePath}
		obs.Structured.Concepts = extractConceptsFromPath(filePath)

	case "Edit":
		filePath, _ := toolInput["file_path"].(string)
		oldString, _ := toolInput["old_string"].(string)
		newString, _ := toolInput["new_string"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Modified file: %s", filepath.Base(filePath))
		oldSnippet := truncate(oldString, 50)
		newSnippet := truncate(newString, 50)
		obs.Core.Summary = fmt.Sprintf("Changed '%s' to '%s'", oldSnippet, newSnippet)
		obs.Core.Content = truncate(toolResponse, 500)
		obs.Structured.Files.Modified = []string{filePath}
		obs.Structured.CodeRefs = []string{filePath}
		obs.Structured.Concepts = extractConceptsFromPath(filePath)

	case "Bash":
		command, _ := toolInput["command"].(string)
		description, _ := toolInput["description"].(string)

		obs.Core.Type = "change"
		if strings.Contains(command, "test") || strings.Contains(command, "pytest") || strings.Contains(command, "jest") {
			obs.Core.Type = "discovery"
		} else if strings.Contains(command, "git commit") {
			obs.Core.Type = "change"
		} else if strings.Contains(command, "build") || strings.Contains(command, "compile") {
			obs.Core.Type = "change"
		}

		if description != "" {
			obs.Core.Title = description
		} else {
			obs.Core.Title = fmt.Sprintf("Ran command: %s", truncate(command, 40))
		}
		obs.Core.Summary = truncate(command, 100)
		obs.Core.Content = truncate(toolResponse, 500)

		// Check if command failed
		if strings.Contains(toolResponse, "error") || strings.Contains(toolResponse, "Error") {
			obs.Core.Type = "bugfix"
			obs.Structured.Facts = append(obs.Structured.Facts, "Command encountered errors")
		}

		// Extract concepts from command
		obs.Structured.Concepts = extractConceptsFromCommand(command)

	case "Task":
		prompt, _ := toolInput["prompt"].(string)
		obs.Core.Type = "discovery"
		obs.Core.Title = "Delegated task"
		obs.Core.Summary = truncate(prompt, 100)
		obs.Core.Content = truncate(toolResponse, 500)

	case "WebFetch", "WebSearch":
		obs.Core.Type = "discovery"
		if urlStr, ok := toolInput["url"].(string); ok {
			obs.Core.Title = fmt.Sprintf("Fetched: %s", truncate(urlStr, 50))
		} else if query, ok := toolInput["query"].(string); ok {
			obs.Core.Title = fmt.Sprintf("Searched: %s", truncate(query, 50))
		}
		obs.Core.Summary = truncate(toolResponse, 100)
		obs.Core.Content = truncate(toolResponse, 500)

	case "NotebookEdit":
		notebookPath, _ := toolInput["notebook_path"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Edited notebook: %s", filepath.Base(notebookPath))
		obs.Core.Summary = truncate(toolResponse, 100)
		obs.Structured.Files.Modified = []string{notebookPath}
		obs.Structured.Concepts = []string{"jupyter", "notebook"}

	default:
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Used tool: %s", toolName)
		obs.Core.Summary = truncate(toolResponse, 100)
		obs.Core.Content = truncate(toolResponse, 500)
	}

	// Skip if we couldn't generate a meaningful title
	if obs.Core.Title == "" {
		return nil
	}

	return obs
}

// extractConceptsFromPath extracts language/framework concepts from a file path.
func extractConceptsFromPath(filePath string) []string {
	var concepts []string
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		concepts = append(concepts, "go")
	case ".ts", ".tsx":
		concepts = append(concepts, "typescript")
	case ".js", ".jsx":
		concepts = append(concepts, "javascript")
	case ".py":
		concepts = append(concepts, "python")
	case ".rs":
		concepts = append(concepts, "rust")
	case ".svelte":
		concepts = append(concepts, "svelte")
	case ".sql":
		concepts = append(concepts, "sql")
	case ".tf":
		concepts = append(concepts, "terraform")
	case ".yaml", ".yml":
		concepts = append(concepts, "yaml")
	case ".json":
		concepts = append(concepts, "json")
	}

	// Extract directory-based concepts
	dir := strings.ToLower(filePath)
	if strings.Contains(dir, "test") || strings.Contains(dir, "_test.") {
		concepts = append(concepts, "testing")
	}
	if strings.Contains(dir, "api") || strings.Contains(dir, "routes") {
		concepts = append(concepts, "api")
	}
	if strings.Contains(dir, "config") {
		concepts = append(concepts, "configuration")
	}
	if strings.Contains(dir, "migration") {
		concepts = append(concepts, "migration")
	}

	return concepts
}

// extractConceptsFromCommand extracts concepts from a shell command.
func extractConceptsFromCommand(command string) []string {
	var concepts []string
	cmd := strings.ToLower(command)

	if strings.Contains(cmd, "go ") {
		concepts = append(concepts, "go")
	}
	if strings.Contains(cmd, "npm ") || strings.Contains(cmd, "yarn ") || strings.Contains(cmd, "pnpm ") {
		concepts = append(concepts, "nodejs")
	}
	if strings.Contains(cmd, "docker") {
		concepts = append(concepts, "docker")
	}
	if strings.Contains(cmd, "git ") {
		concepts = append(concepts, "git")
	}
	if strings.Contains(cmd, "terraform") || strings.Contains(cmd, "tf ") {
		concepts = append(concepts, "terraform")
	}
	if strings.Contains(cmd, "test") || strings.Contains(cmd, "pytest") || strings.Contains(cmd, "jest") {
		concepts = append(concepts, "testing")
	}
	if strings.Contains(cmd, "build") || strings.Contains(cmd, "compile") {
		concepts = append(concepts, "build")
	}

	return concepts
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func generateID() string {
	// Simple UUID-like ID
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *Server) handleSummarize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID      string `json:"session_id"`
		CWD            string `json:"cwd"`
		TranscriptPath string `json:"transcript_path"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		hookInput.CWD, _ = os.Getwd()
	}

	// Ack immediately — queue summary generation
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	sessionID := hookInput.SessionID
	project := filepath.Base(hookInput.CWD)

	s.enqueueHook(func() {
		s.processSummarize(sessionID, project)
	})
}

// processSummarize generates and saves a session summary observation.
func (s *Server) processSummarize(sessionID, project string) {
	observations := s.getObservations()
	hourAgo := time.Now().Add(-1 * time.Hour)

	var sessionObs []storage.Observation
	for _, obs := range observations {
		if obs.Core.Project == project && obs.Core.CreatedAt.After(hourAgo) {
			sessionObs = append(sessionObs, obs)
		}
	}

	if len(sessionObs) == 0 {
		log.Printf("[summarize] No observations for session=%s project=%s", sessionID, project)
		return
	}

	now := time.Now()
	typeCount := make(map[string]int)
	var files []string
	var titles []string
	filesMap := make(map[string]bool)

	for _, obs := range sessionObs {
		typeCount[obs.Core.Type]++
		titles = append(titles, obs.Core.Title)
		for _, f := range obs.Structured.AllFiles() {
			if !filesMap[f] {
				filesMap[f] = true
				files = append(files, f)
			}
		}
	}

	var summaryParts []string
	for t, c := range typeCount {
		summaryParts = append(summaryParts, fmt.Sprintf("%d %s", c, t))
	}

	summary := &storage.Observation{
		ID: generateID(),
		Core: storage.Core{
			Type:      "decision",
			Title:     fmt.Sprintf("Session summary: %s", project),
			Summary:   fmt.Sprintf("Session included %s across %d files", strings.Join(summaryParts, ", "), len(files)),
			Project:   project,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Structured: storage.Structured{
			Facts: titles,
			Files: storage.Files{
				Modified: files,
			},
		},
		Source: storage.Source{
			Adapter: "sinesync",
			ID:      sessionID,
			Epoch:   now.Unix(),
		},
	}

	textForEmbedding := summary.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			summary.Embedding.Vector = embedding
			summary.Embedding.Model = embeddings.ModelName
			summary.Embedding.Tokenizer = s.embedder.TokenizerType()
			summary.Embedding.Dims = embeddings.Dimensions
		} else {
			log.Printf("[summarize] WARNING: embedding failed for summary %s: %v", summary.ID, err)
		}
	}

	if err := s.backend.SaveObservation(summary); err != nil {
		log.Printf("[summarize] Failed to save summary: %v", err)
		return
	}
	s.invalidateCache()

	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			summaryText := fmt.Sprintf("Session included %s across %d files", strings.Join(summaryParts, ", "), len(files))
			_ = sqlBackend.CompleteSession(sessionID, time.Now(), summaryText, len(sessionObs))
			_ = sqlBackend.InsertSessionSummary(sessionID, project, summaryText, len(sessionObs), files, time.Now().Unix())
		}
	}

	log.Printf("[summarize] Saved summary for session=%s project=%s (%d observations, %d files)",
		sessionID, project, len(sessionObs), len(files))
}

func (s *Server) handlePrompt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID string `json:"session_id"`
		Prompt    string `json:"prompt"`
		CWD       string `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if hookInput.Prompt == "" {
		writeJSON(w, map[string]interface{}{"status": "skipped"})
		return
	}

	// Ack immediately — queue DB writes
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	sessionID := hookInput.SessionID
	prompt := hookInput.Prompt
	project := filepath.Base(hookInput.CWD)

	s.enqueueHook(func() {
		if sessionID == "" {
			return
		}
		sqlBackend, ok := s.backend.(*storage.SQLCipherStorage)
		if !ok {
			return
		}

		_ = sqlBackend.EnsureSession(sessionID, project, time.Now().Unix())

		promptNumber := 1
		if err := sqlBackend.DB().QueryRow(
			"SELECT COALESCE(MAX(prompt_number), 0) + 1 FROM user_prompts WHERE session_id = ?",
			sessionID,
		).Scan(&promptNumber); err != nil {
			log.Printf("[prompt] Failed to get prompt number for session=%s: %v", sessionID, err)
		}

		_ = sqlBackend.InsertUserPrompt(sessionID, prompt, project, promptNumber, time.Now().Unix())
		log.Printf("[prompt] Recorded prompt for session=%s project=%s", sessionID, project)
	})
}

// === Dashboard API endpoints ===

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	stats := map[string]interface{}{
		"totalObservations": len(observations),
		"byType":            countByField(observations, func(o storage.Observation) string { return o.Core.Type }),
		"byProject":         countByField(observations, func(o storage.Observation) string { return o.Core.Project }),
		"byClassification":  countByField(observations, func(o storage.Observation) string { return o.Meta.Classification }),
		"starred":           countIf(observations, func(o storage.Observation) bool { return o.Meta.Starred }),
		"archived":          countIf(observations, func(o storage.Observation) bool { return o.Meta.Archived }),
		"tagged":            countIf(observations, func(o storage.Observation) bool { return len(o.Meta.Tags) > 0 }),
	}

	itemCount, storageBytes, _ := s.backend.GetStatus()
	stats["storageItems"] = itemCount
	stats["storageBytes"] = storageBytes

	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			count, _ := adapter.GetObservationCount()
			stats["claudeMemObservations"] = count
			adapter.Close()
		}
	}

	weekAgo := time.Now().AddDate(0, 0, -7)
	recentCount := 0
	for _, obs := range observations {
		if obs.Core.CreatedAt.After(weekAgo) {
			recentCount++
		}
	}
	stats["recentWeek"] = recentCount

	// Sync status
	syncing, lastSync, lastError := s.syncManager.Status()
	syncManifest := storage.GetSyncManifest()
	stats["syncedCount"] = syncManifest.GetSyncedCount()
	stats["syncing"] = syncing
	if !lastSync.IsZero() {
		stats["lastSync"] = lastSync.Format(time.RFC3339)
	}
	if lastError != "" {
		stats["syncError"] = lastError
	}

	// Vault breakdown
	vaultCfg, _ := loadLocalVaultConfig()
	if vaultCfg != nil && len(vaultCfg.Vaults) > 0 {
		byVault := make(map[string]int)
		vaultNames := make(map[string]string)

		// Build project-to-vault mapping
		projectVault := make(map[string]string)
		var defaultVaultID string
		for _, v := range vaultCfg.Vaults {
			vaultNames[v.VaultID] = v.Name
			if v.IsDefault {
				defaultVaultID = v.VaultID
			}
			for _, p := range v.Projects {
				projectVault[p] = v.VaultID
			}
		}

		// Count observations per vault
		for _, obs := range observations {
			vaultID := projectVault[obs.Core.Project]
			if vaultID == "" {
				vaultID = defaultVaultID
			}
			if vaultID != "" {
				byVault[vaultID]++
			}
		}

		stats["byVault"] = byVault
		stats["vaultNames"] = vaultNames
	}

	writeJSON(w, stats)
}

func (s *Server) handleVaults(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()
	syncManifest := storage.GetSyncManifest()

	vaultCfg, err := loadLocalVaultConfig()
	if err != nil || vaultCfg == nil || len(vaultCfg.Vaults) == 0 {
		writeJSON(w, map[string]interface{}{
			"vaults":      []interface{}{},
			"totalItems":  len(observations),
			"totalSynced": syncManifest.GetSyncedCount(),
		})
		return
	}

	// Build project-to-vault mapping
	projectVault := make(map[string]string)
	var defaultVaultID string
	for _, v := range vaultCfg.Vaults {
		if v.IsDefault {
			defaultVaultID = v.VaultID
		}
		for _, p := range v.Projects {
			projectVault[p] = v.VaultID
		}
	}

	// Count observations per vault
	vaultCounts := make(map[string]int)
	for _, obs := range observations {
		vaultID := projectVault[obs.Core.Project]
		if vaultID == "" {
			vaultID = defaultVaultID
		}
		if vaultID != "" {
			vaultCounts[vaultID]++
		}
	}

	// Build vault response
	type vaultInfo struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		IsDefault   bool     `json:"isDefault"`
		Projects    []string `json:"projects"`
		ItemCount   int      `json:"itemCount"`
		SyncedCount int      `json:"syncedCount"`
	}

	vaults := make([]vaultInfo, 0, len(vaultCfg.Vaults))
	for _, v := range vaultCfg.Vaults {
		vaults = append(vaults, vaultInfo{
			ID:          v.VaultID,
			Name:        v.Name,
			IsDefault:   v.IsDefault,
			Projects:    v.Projects,
			ItemCount:   vaultCounts[v.VaultID],
			SyncedCount: vaultCounts[v.VaultID], // Approximation - synced items are tracked globally
		})
	}

	writeJSON(w, map[string]interface{}{
		"vaults":      vaults,
		"totalItems":  len(observations),
		"totalSynced": syncManifest.GetSyncedCount(),
	})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Trigger immediate sync
		s.syncManager.TriggerSync()
		writeJSON(w, map[string]interface{}{"status": "triggered"})
		return
	}

	// GET - return sync status
	syncing, lastSync, lastError := s.syncManager.Status()
	syncManifest := storage.GetSyncManifest()
	authenticated := s.isAuthenticated()

	// Get local observation count
	localCount, _, _ := s.backend.GetStatus()

	status := map[string]interface{}{
		"syncing":       syncing,
		"syncedCount":   syncManifest.GetSyncedCount(),
		"localCount":    localCount,
		"authenticated": authenticated,
	}
	if !lastSync.IsZero() {
		status["lastSync"] = lastSync.Format(time.RFC3339)
	}
	if lastError != "" {
		status["syncError"] = lastError
	}

	// Add backfill status
	backfillRunning, backfillProgress, backfillTotal, backfillElapsed := s.syncManager.BackfillStatus()
	if backfillRunning {
		status["backfill"] = map[string]interface{}{
			"running":  true,
			"progress": backfillProgress,
			"total":    backfillTotal,
			"elapsed":  backfillElapsed.Round(time.Second).String(),
		}
	}

	// Add claude-mem status if in adapter mode
	if s.mode == "adapter" && adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			defer adapter.Close()
			claudeMemCount, _ := adapter.GetObservationCount()
			backlog := adapter.GetEmbeddingBacklog()
			status["claudeMem"] = map[string]interface{}{
				"observations":     claudeMemCount,
				"embeddingBacklog": backlog,
			}
		}
	}

	writeJSON(w, status)
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()
	query := r.URL.Query()

	// Apply filters
	if project := query.Get("project"); project != "" {
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return o.Core.Project == project
		})
	}

	if obsType := query.Get("type"); obsType != "" {
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return o.Core.Type == obsType
		})
	}

	if query.Get("archived") != "true" {
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return !o.Meta.Archived
		})
	}

	if search := query.Get("search"); search != "" {
		searchLower := strings.ToLower(search)
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return strings.Contains(strings.ToLower(o.Core.Title), searchLower) ||
				strings.Contains(strings.ToLower(o.Core.Summary), searchLower)
		})
	}

	// Sort by date
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Core.CreatedAt.After(observations[j].Core.CreatedAt)
	})

	totalFiltered := len(observations)

	// Pagination
	page, limit := 1, 50
	fmt.Sscanf(query.Get("page"), "%d", &page)
	fmt.Sscanf(query.Get("limit"), "%d", &limit)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	offset := (page - 1) * limit
	if offset >= len(observations) {
		observations = []storage.Observation{}
	} else {
		end := offset + limit
		if end > len(observations) {
			end = len(observations)
		}
		observations = observations[offset:end]
	}

	totalPages := (totalFiltered + limit - 1) / limit

	result := make([]map[string]interface{}, len(observations))
	for i, obs := range observations {
		result[i] = observationToMap(obs)
	}

	writeJSON(w, map[string]interface{}{
		"observations": result,
		"total":        totalFiltered,
		"page":         page,
		"limit":        limit,
		"totalPages":   totalPages,
		"hasNext":      page < totalPages,
		"hasPrev":      page > 1,
	})
}

func (s *Server) handleObservation(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/observations/")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		obs, err := s.backend.GetObservation(id)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		writeJSON(w, observationToMap(*obs))

	case http.MethodDelete:
		s.handleDeleteObservation(w, r, id)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDeleteObservation(w http.ResponseWriter, r *http.Request, id string) {
	// Get observation first to get project/title for claude-mem deletion
	obs, err := s.backend.GetObservation(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Delete from local sinesync storage
	if err := s.backend.DeleteObservation(id); err != nil {
		http.Error(w, "Failed to delete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete from claude-mem if it exists there
	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(false)
		if err == nil && adapter != nil {
			defer adapter.Close()
			ctx := context.Background()

			// Try deleting by source ID first (if it came from claude-mem)
			if obs.Source.Adapter == adapters.ClaudeMemAdapterName && obs.Source.ID != "" {
				adapter.DeleteBySourceID(ctx, obs.Source.ID)
			} else {
				// Fall back to project+title match
				adapter.DeleteByProjectAndTitle(ctx, obs.Core.Project, obs.Core.Title)
			}
		}
	}

	// Mark for cloud deletion on next sync (explicit delete, safe to propagate)
	syncManifest := storage.GetSyncManifest()
	syncManifest.MarkPendingDelete(id)
	syncManifest.Save()

	// Clear observation cache to force refresh
	s.obsCache = nil

	log.Printf("[server] Deleted observation %s (project: %s, title: %s)", id, obs.Core.Project, obs.Core.Title)
	writeJSON(w, map[string]bool{"success": true})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	projects := make(map[string]int)
	for _, obs := range observations {
		if obs.Core.Project != "" {
			projects[obs.Core.Project]++
		}
	}

	// Build project-to-vault mapping
	projectVault := make(map[string]string)
	vaultCfg, _ := loadLocalVaultConfig()
	if vaultCfg != nil {
		for _, v := range vaultCfg.Vaults {
			for _, p := range v.Projects {
				projectVault[p] = v.Name
			}
		}
	}

	type projectInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
		Vault string `json:"vault,omitempty"`
	}

	result := make([]projectInfo, 0, len(projects))
	for name, count := range projects {
		result = append(result, projectInfo{
			Name:  name,
			Count: count,
			Vault: projectVault[name],
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	writeJSON(w, result)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	tags := make(map[string]int)
	for _, obs := range observations {
		for _, tag := range obs.Meta.Tags {
			tags[tag]++
		}
	}

	type tagInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	result := make([]tagInfo, 0, len(tags))
	for name, count := range tags {
		result = append(result, tagInfo{Name: name, Count: count})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	writeJSON(w, result)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSON(w, map[string]interface{}{"observations": []interface{}{}, "total": 0})
		return
	}

	observations := s.getObservations()

	var queryEmbedding []float32
	if s.embedder != nil && s.embedder.IsReady() {
		if vec, err := s.embedder.Embed(query); err == nil {
			queryEmbedding = vec
		} else {
			queryEmbedding = embeddings.FallbackEmbed(query)
		}
	} else {
		queryEmbedding = embeddings.FallbackEmbed(query)
	}

	type scoredObs struct {
		obs   storage.Observation
		score float32
	}

	var results []scoredObs
	for _, obs := range observations {
		if len(obs.Embedding.Vector) > 0 {
			score := embeddings.CosineSimilarity(queryEmbedding, obs.Embedding.Vector)
			results = append(results, scoredObs{obs: obs, score: score})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	// Pagination
	params := r.URL.Query()
	page, limit := 1, 50
	fmt.Sscanf(params.Get("page"), "%d", &page)
	fmt.Sscanf(params.Get("limit"), "%d", &limit)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	totalResults := len(results)
	totalPages := (totalResults + limit - 1) / limit

	offset := (page - 1) * limit
	if offset >= len(results) {
		results = []scoredObs{}
	} else {
		end := offset + limit
		if end > len(results) {
			end = len(results)
		}
		results = results[offset:end]
	}

	output := make([]map[string]interface{}, len(results))
	for i, r := range results {
		m := observationToMap(r.obs)
		m["score"] = r.score
		output[i] = m
	}

	writeJSON(w, map[string]interface{}{
		"observations": output,
		"total":        totalResults,
		"page":         page,
		"limit":        limit,
		"totalPages":   totalPages,
		"hasNext":      page < totalPages,
		"hasPrev":      page > 1,
		"query":        query,
	})
}

// === MCP API endpoints (3-layer workflow) ===

func (s *Server) handleMCPSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		writeJSON(w, map[string]interface{}{"results": []interface{}{}, "total": 0})
		return
	}

	limit := 20
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	if limit < 1 || limit > 200 {
		limit = 20
	}

	// Build filters
	filters := storage.SearchFilters{
		Project: r.URL.Query().Get("project"),
		Type:    r.URL.Query().Get("type"),
	}
	if ds := r.URL.Query().Get("dateStart"); ds != "" {
		if t, err := time.Parse(time.RFC3339, ds); err == nil {
			filters.DateStart = &t
		}
	}
	if de := r.URL.Query().Get("dateEnd"); de != "" {
		if t, err := time.Parse(time.RFC3339, de); err == nil {
			filters.DateEnd = &t
		}
	}

	// Try SQLCipher hybrid search first
	if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
		var queryVec []float32
		if s.embedder != nil && s.embedder.IsReady() {
			queryVec, _ = s.embedder.Embed(query)
		}

		results, err := sqlBackend.HybridSearch(query, queryVec, limit, filters)
		if err == nil {
			writeJSON(w, map[string]interface{}{
				"results": results,
				"total":   len(results),
				"query":   query,
			})
			return
		}
	}

	// Fallback: brute-force search for LocalStorage backend
	observations := s.getObservations()
	var queryEmbedding []float32
	if s.embedder != nil && s.embedder.IsReady() {
		if vec, err := s.embedder.Embed(query); err == nil {
			queryEmbedding = vec
		} else {
			queryEmbedding = embeddings.FallbackEmbed(query)
		}
	} else {
		queryEmbedding = embeddings.FallbackEmbed(query)
	}

	type scoredResult struct {
		obs   storage.Observation
		score float32
	}
	var scored []scoredResult
	for _, obs := range observations {
		if filters.Project != "" && obs.Core.Project != filters.Project {
			continue
		}
		if filters.Type != "" && obs.Core.Type != filters.Type {
			continue
		}
		if filters.DateStart != nil && obs.Core.CreatedAt.Before(*filters.DateStart) {
			continue
		}
		if filters.DateEnd != nil && obs.Core.CreatedAt.After(*filters.DateEnd) {
			continue
		}
		if len(obs.Embedding.Vector) > 0 {
			score := embeddings.CosineSimilarity(queryEmbedding, obs.Embedding.Vector)
			scored = append(scored, scoredResult{obs: obs, score: score})
		} else if strings.Contains(strings.ToLower(obs.Core.Title+" "+obs.Core.Summary+" "+obs.Core.Content), strings.ToLower(query)) {
			// Text match fallback for observations without embeddings
			scored = append(scored, scoredResult{obs: obs, score: 0.1})
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}

	results := make([]storage.SearchResult, len(scored))
	for i, sr := range scored {
		results[i] = storage.SearchResult{
			ID:        sr.obs.ID,
			Title:     sr.obs.Core.Title,
			Summary:   sr.obs.Core.Summary,
			Type:      sr.obs.Core.Type,
			Project:   sr.obs.Core.Project,
			CreatedAt: sr.obs.Core.CreatedAt.Format(time.RFC3339),
			Score:     float64(sr.score),
		}
	}

	writeJSON(w, map[string]interface{}{
		"results": results,
		"total":   len(results),
		"query":   query,
	})
}

func (s *Server) handleMCPTimeline(w http.ResponseWriter, r *http.Request) {
	anchorID := r.URL.Query().Get("anchor")
	query := r.URL.Query().Get("query")

	depthBefore := 5
	depthAfter := 5
	fmt.Sscanf(r.URL.Query().Get("depth_before"), "%d", &depthBefore)
	fmt.Sscanf(r.URL.Query().Get("depth_after"), "%d", &depthAfter)
	if depthBefore < 0 {
		depthBefore = 0
	} else if depthBefore > 50 {
		depthBefore = 50
	}
	if depthAfter < 0 {
		depthAfter = 0
	} else if depthAfter > 50 {
		depthAfter = 50
	}

	sqlBackend, ok := s.backend.(*storage.SQLCipherStorage)
	if !ok {
		// Fallback for LocalStorage: just return recent observations
		observations := s.getObservations()
		total := depthBefore + depthAfter + 1
		if total > len(observations) {
			total = len(observations)
		}
		result := make([]map[string]interface{}, total)
		for i := 0; i < total; i++ {
			result[i] = observationToMap(observations[i])
		}
		writeJSON(w, map[string]interface{}{"observations": result})
		return
	}

	var observations []storage.Observation
	var err error

	if anchorID != "" {
		observations, err = sqlBackend.TimelineSearch(anchorID, depthBefore, depthAfter)
	} else if query != "" {
		var queryVec []float32
		if s.embedder != nil && s.embedder.IsReady() {
			queryVec, _ = s.embedder.Embed(query)
		}
		observations, err = sqlBackend.TimelineSearchByQuery(query, queryVec, depthBefore, depthAfter)
	} else {
		writeJSON(w, map[string]interface{}{"error": "anchor or query required"})
		return
	}

	if err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}

	result := make([]map[string]interface{}, len(observations))
	for i, obs := range observations {
		result[i] = observationToMap(obs)
	}
	writeJSON(w, map[string]interface{}{"observations": result})
}

func (s *Server) handleMCPGetObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	observations := make([]map[string]interface{}, 0, len(req.IDs))
	for _, id := range req.IDs {
		obs, err := s.backend.GetObservation(id)
		if err != nil {
			continue
		}
		observations = append(observations, observationToMap(*obs))
	}

	writeJSON(w, map[string]interface{}{"observations": observations})
}

// === Helpers ===

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func observationToMap(obs storage.Observation) map[string]interface{} {
	return map[string]interface{}{
		"id":             obs.ID,
		"type":           obs.Core.Type,
		"title":          obs.Core.Title,
		"summary":        obs.Core.Summary,
		"content":        obs.Core.Content,
		"project":        obs.Core.Project,
		"facts":          obs.Structured.Facts,
		"concepts":       obs.Structured.Concepts,
		"files":          obs.Structured.AllFiles(),
		"source":         obs.Source.Adapter,
		"tags":           obs.Meta.Tags,
		"classification": obs.Meta.Classification,
		"starred":        obs.Meta.Starred,
		"archived":       obs.Meta.Archived,
		"createdAt":      obs.Core.CreatedAt.Format(time.RFC3339),
		"updatedAt":      obs.Core.UpdatedAt.Format(time.RFC3339),
	}
}

func countByField(observations []storage.Observation, getter func(storage.Observation) string) map[string]int {
	counts := make(map[string]int)
	for _, obs := range observations {
		val := getter(obs)
		if val != "" {
			counts[val]++
		}
	}
	return counts
}

func countIf(observations []storage.Observation, predicate func(storage.Observation) bool) int {
	count := 0
	for _, obs := range observations {
		if predicate(obs) {
			count++
		}
	}
	return count
}

func filterObservations(observations []storage.Observation, predicate func(storage.Observation) bool) []storage.Observation {
	result := make([]storage.Observation, 0)
	for _, obs := range observations {
		if predicate(obs) {
			result = append(result, obs)
		}
	}
	return result
}
