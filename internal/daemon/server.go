package daemon

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/embeddings"
	"github.com/miclip/sinesync/internal/storage"
)

//go:embed static/*
var staticFiles embed.FS

// Server is the unified daemon server (dashboard + hook API)
type Server struct {
	port         int
	localStorage *storage.LocalStorage
	config       *config.Config
	embedder     *embeddings.Provider
	httpServer   *http.Server
	mode         string // "standalone" or "adapter"

	// Observation cache
	obsCache      []storage.Observation
	obsCacheTime  time.Time
	obsCacheTTL   time.Duration
}

// NewServer creates a new daemon server
func NewServer(port int) *Server {
	if port == 0 {
		port = DefaultPort
	}

	cfg, _ := config.Load()

	// Detect mode
	mode := "standalone"
	if adapters.IsClaudeMemInstalled() {
		mode = "adapter"
	}

	embedder, _ := embeddings.NewProvider()

	return &Server{
		port:         port,
		localStorage: storage.NewLocalStorage(),
		config:       cfg,
		embedder:     embedder,
		mode:         mode,
		obsCacheTTL:  30 * time.Second, // Cache for 30 seconds
	}
}

// getObservations returns cached observations, refreshing if stale
func (s *Server) getObservations() []storage.Observation {
	if time.Since(s.obsCacheTime) > s.obsCacheTTL || s.obsCache == nil {
		fmt.Fprintf(os.Stderr, "Loading observations into cache...\n")
		start := time.Now()
		s.obsCache, _ = s.localStorage.ListObservations()
		s.obsCacheTime = time.Now()
		fmt.Fprintf(os.Stderr, "Cached %d observations in %v\n", len(s.obsCache), time.Since(start))
	}
	return s.obsCache
}

// invalidateCache forces a cache refresh on next access
func (s *Server) invalidateCache() {
	s.obsCacheTime = time.Time{}
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

	// Dashboard API endpoints
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/observations", s.handleObservations)
	mux.HandleFunc("/api/observations/", s.handleObservation)
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/tags", s.handleTags)
	mux.HandleFunc("/api/search", s.handleSearch)

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

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nsine~sync daemon shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
		RemovePIDFile()
	}()

	fmt.Fprintf(os.Stderr, "sine~sync daemon starting on http://%s\n", addr)
	fmt.Fprintf(os.Stderr, "  Mode: %s\n", s.mode)
	fmt.Fprintf(os.Stderr, "  Dashboard: http://%s\n", addr)
	fmt.Fprintf(os.Stderr, "  Hook API: http://%s/api/\n", addr)

	return s.httpServer.ListenAndServe()
}

// === Health endpoints ===

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status": "ok",
		"mode":   s.mode,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	itemCount, storageBytes, _ := s.localStorage.GetStatus()

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
	limit := 20

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

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read hook input
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID    string `json:"session_id"`
		ToolName     string `json:"tool_name"`
		ToolInput    string `json:"tool_input"`
		ToolResponse string `json:"tool_response"`
		CWD          string `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Skip tools that don't produce meaningful observations
	skipTools := map[string]bool{
		"Read": true, "Glob": true, "Grep": true, // Read-only tools
		"ListMcpResourcesTool": true, "SlashCommand": true,
		"Skill": true, "TodoWrite": true, "AskUserQuestion": true,
		"TaskList": true, "TaskGet": true,
	}

	if skipTools[hookInput.ToolName] {
		writeJSON(w, map[string]interface{}{"status": "skipped", "reason": "read-only tool"})
		return
	}

	// Extract project from CWD
	project := filepath.Base(hookInput.CWD)

	// Parse tool input for context
	var toolInputData map[string]interface{}
	json.Unmarshal([]byte(hookInput.ToolInput), &toolInputData)

	// Determine observation type and extract details
	obs := s.extractObservation(hookInput.ToolName, toolInputData, hookInput.ToolResponse, project)
	if obs == nil {
		writeJSON(w, map[string]interface{}{"status": "skipped", "reason": "no observation extracted"})
		return
	}

	// Generate embedding
	textForEmbedding := obs.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			obs.Embedding.Vector = embedding
			obs.Embedding.Model = embeddings.ModelName
		}
	} else {
		obs.Embedding.Vector = embeddings.FallbackEmbed(textForEmbedding)
		obs.Embedding.Model = "fallback"
	}

	// Save observation
	if err := s.localStorage.SaveObservation(obs); err != nil {
		http.Error(w, "Failed to save observation", http.StatusInternalServerError)
		return
	}
	s.invalidateCache()

	writeJSON(w, map[string]interface{}{
		"status": "captured",
		"id":     obs.ID,
		"title":  obs.Core.Title,
		"type":   obs.Core.Type,
	})
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
		obs.Structured.Files.Modified = []string{filePath}

	case "Edit":
		filePath, _ := toolInput["file_path"].(string)
		oldString, _ := toolInput["old_string"].(string)
		newString, _ := toolInput["new_string"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Modified file: %s", filepath.Base(filePath))
		// Truncate for summary
		oldSnippet := truncate(oldString, 50)
		newSnippet := truncate(newString, 50)
		obs.Core.Summary = fmt.Sprintf("Changed '%s' to '%s'", oldSnippet, newSnippet)
		obs.Structured.Files.Modified = []string{filePath}

	case "Bash":
		command, _ := toolInput["command"].(string)
		description, _ := toolInput["description"].(string)

		// Determine type based on command
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

		// Check if command failed
		if strings.Contains(toolResponse, "error") || strings.Contains(toolResponse, "Error") {
			obs.Core.Type = "bugfix"
			obs.Structured.Facts = append(obs.Structured.Facts, "Command encountered errors")
		}

	case "Task":
		prompt, _ := toolInput["prompt"].(string)
		obs.Core.Type = "discovery"
		obs.Core.Title = fmt.Sprintf("Delegated task")
		obs.Core.Summary = truncate(prompt, 100)

	case "WebFetch", "WebSearch":
		obs.Core.Type = "discovery"
		if url, ok := toolInput["url"].(string); ok {
			obs.Core.Title = fmt.Sprintf("Fetched: %s", truncate(url, 50))
		} else if query, ok := toolInput["query"].(string); ok {
			obs.Core.Title = fmt.Sprintf("Searched: %s", truncate(query, 50))
		}
		obs.Core.Summary = truncate(toolResponse, 100)

	default:
		// Generic handling for other tools
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Used tool: %s", toolName)
		obs.Core.Summary = truncate(toolResponse, 100)
	}

	// Skip if we couldn't generate a meaningful title
	if obs.Core.Title == "" {
		return nil
	}

	return obs
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

	// Read hook input
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
		// Use defaults if parsing fails
		hookInput.CWD, _ = os.Getwd()
	}

	project := filepath.Base(hookInput.CWD)

	// Get recent observations from this session (last hour as proxy)
	observations := s.getObservations()
	hourAgo := time.Now().Add(-1 * time.Hour)

	var sessionObs []storage.Observation
	for _, obs := range observations {
		if obs.Core.Project == project && obs.Core.CreatedAt.After(hourAgo) {
			sessionObs = append(sessionObs, obs)
		}
	}

	if len(sessionObs) == 0 {
		writeJSON(w, map[string]interface{}{
			"status":  "skipped",
			"reason":  "no observations in session",
			"project": project,
		})
		return
	}

	// Create session summary observation
	now := time.Now()

	// Collect stats
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

	// Build summary text
	var summaryParts []string
	for t, c := range typeCount {
		summaryParts = append(summaryParts, fmt.Sprintf("%d %s", c, t))
	}

	summary := &storage.Observation{
		ID: generateID(),
		Core: storage.Core{
			Type:      "decision", // Session summaries are like decisions/milestones
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
			ID:      hookInput.SessionID,
			Epoch:   now.Unix(),
		},
	}

	// Generate embedding
	textForEmbedding := summary.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			summary.Embedding.Vector = embedding
			summary.Embedding.Model = embeddings.ModelName
		}
	} else {
		summary.Embedding.Vector = embeddings.FallbackEmbed(textForEmbedding)
		summary.Embedding.Model = "fallback"
	}

	// Save
	if err := s.localStorage.SaveObservation(summary); err != nil {
		http.Error(w, "Failed to save summary", http.StatusInternalServerError)
		return
	}
	s.invalidateCache()

	writeJSON(w, map[string]interface{}{
		"status":           "summarized",
		"id":               summary.ID,
		"observationCount": len(sessionObs),
		"fileCount":        len(files),
		"project":          project,
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

	itemCount, storageBytes, _ := s.localStorage.GetStatus()
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
	syncManifest := storage.GetSyncManifest()
	stats["syncedCount"] = syncManifest.GetSyncedCount()
	lastSync := syncManifest.GetLastSync()
	if !lastSync.IsZero() {
		stats["lastSync"] = lastSync.Format(time.RFC3339)
	}

	writeJSON(w, stats)
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

	obs, err := s.localStorage.GetObservation(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	writeJSON(w, observationToMap(*obs))
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	projects := make(map[string]int)
	for _, obs := range observations {
		if obs.Core.Project != "" {
			projects[obs.Core.Project]++
		}
	}

	type projectInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	result := make([]projectInfo, 0, len(projects))
	for name, count := range projects {
		result = append(result, projectInfo{Name: name, Count: count})
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
		queryEmbedding, _ = s.embedder.Embed(query)
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
