package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/config"
	"github.com/miclip/sinesync/internal/embeddings"
	"github.com/miclip/sinesync/internal/storage"
)

//go:embed static/*
var staticFiles embed.FS

const (
	// Port 5741 - looks like "SINE" if you squint at it
	DefaultPort = 5741
)

// Server is the dashboard HTTP server
type Server struct {
	port         int
	localStorage *storage.LocalStorage
	config       *config.Config
	httpServer   *http.Server
}

// NewServer creates a new dashboard server
func NewServer(port int) *Server {
	if port == 0 {
		port = DefaultPort
	}

	cfg, _ := config.Load()

	return &Server{
		port:         port,
		localStorage: storage.NewLocalStorage(),
		config:       cfg,
	}
}

// Start starts the dashboard server
func (s *Server) Start(openBrowser bool) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/observations", s.handleObservations)
	mux.HandleFunc("/api/observations/", s.handleObservation)
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/tags", s.handleTags)
	mux.HandleFunc("/api/vaults", s.handleVaults)
	mux.HandleFunc("/api/search", s.handleSearch)

	// Static files
	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	url := fmt.Sprintf("http://%s", addr)
	fmt.Printf("sine~sync dashboard starting on %s\n", url)
	fmt.Printf("  Port 5741 = \"SINE\" (if you squint)\n")
	fmt.Println()

	if openBrowser {
		go func() {
			time.Sleep(500 * time.Millisecond)
			openURL(url)
		}()
	}

	return s.httpServer.ListenAndServe()
}

// Stop stops the server
func (s *Server) Stop() error {
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// API Handlers

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	observations, _ := s.localStorage.ListObservations()

	// Calculate stats
	stats := map[string]interface{}{
		"totalObservations": len(observations),
		"byType":            countByField(observations, func(o storage.Observation) string { return o.Core.Type }),
		"byProject":         countByField(observations, func(o storage.Observation) string { return o.Core.Project }),
		"byClassification":  countByField(observations, func(o storage.Observation) string { return o.Meta.Classification }),
		"starred":           countIf(observations, func(o storage.Observation) bool { return o.Meta.Starred }),
		"archived":          countIf(observations, func(o storage.Observation) bool { return o.Meta.Archived }),
		"tagged":            countIf(observations, func(o storage.Observation) bool { return len(o.Meta.Tags) > 0 }),
	}

	// Storage stats
	itemCount, storageBytes, _ := s.localStorage.GetStatus()
	stats["storageItems"] = itemCount
	stats["storageBytes"] = storageBytes

	// Claude-mem stats
	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			count, _ := adapter.GetObservationCount()
			stats["claudeMemObservations"] = count
			adapter.Close()
		}
	}

	// Vault stats
	if s.config != nil {
		stats["vaultCount"] = len(s.config.Vaults)
		stats["routeCount"] = len(s.config.Routes)
	}

	// Recent activity (last 7 days)
	weekAgo := time.Now().AddDate(0, 0, -7)
	recentCount := 0
	for _, obs := range observations {
		if obs.Core.CreatedAt.After(weekAgo) {
			recentCount++
		}
	}
	stats["recentWeek"] = recentCount

	writeJSON(w, stats)
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		observations, _ := s.localStorage.ListObservations()

		// Apply filters from query params
		query := r.URL.Query()

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

		if tag := query.Get("tag"); tag != "" {
			observations = filterObservations(observations, func(o storage.Observation) bool {
				return o.HasTag(tag)
			})
		}

		if classification := query.Get("classification"); classification != "" {
			observations = filterObservations(observations, func(o storage.Observation) bool {
				return o.Meta.Classification == classification
			})
		}

		if query.Get("starred") == "true" {
			observations = filterObservations(observations, func(o storage.Observation) bool {
				return o.Meta.Starred
			})
		}

		if query.Get("archived") != "true" {
			// By default, hide archived
			observations = filterObservations(observations, func(o storage.Observation) bool {
				return !o.Meta.Archived
			})
		}

		// Text search filter
		if search := query.Get("search"); search != "" {
			searchLower := strings.ToLower(search)
			observations = filterObservations(observations, func(o storage.Observation) bool {
				return strings.Contains(strings.ToLower(o.Core.Title), searchLower) ||
					strings.Contains(strings.ToLower(o.Core.Summary), searchLower)
			})
		}

		// Sort by date descending
		sort.Slice(observations, func(i, j int) bool {
			return observations[i].Core.CreatedAt.After(observations[j].Core.CreatedAt)
		})

		// Total count after filtering (before pagination)
		totalFiltered := len(observations)

		// Pagination
		page := 1
		limit := 50
		if p := query.Get("page"); p != "" {
			fmt.Sscanf(p, "%d", &page)
			if page < 1 {
				page = 1
			}
		}
		if l := query.Get("limit"); l != "" {
			fmt.Sscanf(l, "%d", &limit)
			if limit < 1 {
				limit = 50
			}
			if limit > 200 {
				limit = 200
			}
		}

		// Calculate offset
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

		// Return without embeddings (too large)
		result := make([]map[string]interface{}, len(observations))
		for i, obs := range observations {
			result[i] = observationToMap(obs, false)
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
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleObservation(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path: /api/observations/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/observations/")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case "GET":
		obs, err := s.localStorage.GetObservation(id)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		writeJSON(w, observationToMap(*obs, true))

	case "PATCH":
		// Update observation metadata
		obs, err := s.localStorage.GetObservation(id)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}

		var update struct {
			Tags           *[]string `json:"tags"`
			Classification *string   `json:"classification"`
			Starred        *bool     `json:"starred"`
			Archived       *bool     `json:"archived"`
			Notes          *string   `json:"notes"`
		}

		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if update.Tags != nil {
			obs.Meta.Tags = *update.Tags
		}
		if update.Classification != nil {
			obs.Meta.Classification = *update.Classification
		}
		if update.Starred != nil {
			obs.Meta.Starred = *update.Starred
		}
		if update.Archived != nil {
			obs.Meta.Archived = *update.Archived
		}
		if update.Notes != nil {
			obs.Meta.Notes = *update.Notes
		}

		obs.Core.UpdatedAt = time.Now()

		if err := s.localStorage.SaveObservation(obs); err != nil {
			http.Error(w, "Failed to save", http.StatusInternalServerError)
			return
		}

		writeJSON(w, observationToMap(*obs, false))

	case "DELETE":
		if err := s.localStorage.Delete("observation", id); err != nil {
			http.Error(w, "Failed to delete", http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{"status": "deleted"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	observations, _ := s.localStorage.ListObservations()

	projects := make(map[string]int)
	for _, obs := range observations {
		if obs.Core.Project != "" {
			projects[obs.Core.Project]++
		}
	}

	// Convert to sorted list
	type projectInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
		Vault string `json:"vault,omitempty"`
	}

	result := make([]projectInfo, 0, len(projects))
	for name, count := range projects {
		vault := ""
		if s.config != nil {
			vault = s.config.GetVaultForProject(name)
		}
		result = append(result, projectInfo{Name: name, Count: count, Vault: vault})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	writeJSON(w, result)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	observations, _ := s.localStorage.ListObservations()

	tags := make(map[string]int)
	for _, obs := range observations {
		for _, tag := range obs.Meta.Tags {
			tags[tag]++
		}
	}

	// Convert to sorted list
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

func (s *Server) handleVaults(w http.ResponseWriter, r *http.Request) {
	if s.config == nil {
		writeJSON(w, []interface{}{})
		return
	}

	writeJSON(w, s.config.ListVaults())
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSON(w, map[string]interface{}{"observations": []interface{}{}, "total": 0})
		return
	}

	observations, _ := s.localStorage.ListObservations()

	// Generate query embedding using ONNX if available
	embedder, _ := embeddings.NewProvider()
	var queryEmbedding []float32
	if embedder != nil && embedder.IsReady() {
		queryEmbedding, _ = embedder.Embed(query)
		defer embedder.Close()
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

	// Sort by score descending
	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	// Pagination for search results
	params := r.URL.Query()
	page := 1
	limit := 50
	if p := params.Get("page"); p != "" {
		fmt.Sscanf(p, "%d", &page)
		if page < 1 {
			page = 1
		}
	}
	if l := params.Get("limit"); l != "" {
		fmt.Sscanf(l, "%d", &limit)
		if limit < 1 || limit > 200 {
			limit = 50
		}
	}

	totalResults := len(results)
	totalPages := (totalResults + limit - 1) / limit

	// Apply pagination
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
		m := observationToMap(r.obs, false)
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

// Helpers

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func observationToMap(obs storage.Observation, includeEmbedding bool) map[string]interface{} {
	m := map[string]interface{}{
		"id":             obs.ID,
		"type":           obs.Core.Type,
		"title":          obs.Core.Title,
		"summary":        obs.Core.Summary,
		"content":        obs.Core.Content,
		"facts":          obs.Structured.Facts,
		"concepts":       obs.Structured.Concepts,
		"files":          obs.Structured.AllFiles(),
		"filesRead":      obs.Structured.Files.Read,
		"filesModified":  obs.Structured.Files.Modified,
		"codeRefs":       obs.Structured.CodeRefs,
		"project":        obs.Core.Project,
		"source":         obs.Source.Adapter,
		"sourceId":       obs.Source.ID,
		"tags":           obs.Meta.Tags,
		"classification": obs.Meta.Classification,
		"starred":        obs.Meta.Starred,
		"archived":       obs.Meta.Archived,
		"notes":          obs.Meta.Notes,
		"vaultId":        obs.Meta.VaultID,
		"createdAt":      obs.Core.CreatedAt.Format(time.RFC3339),
		"updatedAt":      obs.Core.UpdatedAt.Format(time.RFC3339),
	}

	if includeEmbedding && len(obs.Embedding.Vector) > 0 {
		m["embedding"] = obs.Embedding.Vector
		m["embeddingModel"] = obs.Embedding.Model
	}

	return m
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

func openURL(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		return
	}

	cmd.Start()
}
