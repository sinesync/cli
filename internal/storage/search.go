// ABOUTME: FTS5 full-text, sqlite-vec vector, and hybrid RRF search for observations.
// ABOUTME: Provides timeline queries and search filter helpers for the MCP 3-layer workflow.
package storage

import (
	"fmt"
	"log"
	"sort"
	"time"
)

// SearchResult represents a compact search result (for the MCP index layer).
type SearchResult struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	Summary   string  `json:"summary"`
	Type      string  `json:"type"`
	Project   string  `json:"project"`
	CreatedAt string  `json:"created_at"`
	Score     float64 `json:"score"`
}

// SearchFilters constrains search results.
type SearchFilters struct {
	Project   string
	Type      string
	DateStart *time.Time
	DateEnd   *time.Time
}

// FTS5Search performs full-text search using the FTS5 index.
func (s *SQLCipherStorage) FTS5Search(query string, limit int, filters SearchFilters) ([]SearchResult, error) {
	where, args := buildFilterClauses(filters)

	q := fmt.Sprintf(`
		SELECT o.id, o.title, o.summary, o.type, o.project, o.created_at,
			observations_fts.rank
		FROM observations_fts
		JOIN observations o ON o.rowid = observations_fts.rowid
		WHERE observations_fts MATCH ?
		%s
		ORDER BY observations_fts.rank
		LIMIT ?
	`, where)

	allArgs := append([]interface{}{query}, args...)
	allArgs = append(allArgs, limit)

	rows, err := s.db.Query(q, allArgs...)
	if err != nil {
		return nil, fmt.Errorf("fts5 search: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var rank float64
		if err := rows.Scan(&r.ID, &r.Title, &r.Summary, &r.Type, &r.Project, &r.CreatedAt, &rank); err != nil {
			log.Printf("[search] FTS5 scan error: %v", err)
			continue
		}
		r.Score = -rank // FTS5 rank is negative (lower = better), flip it
		results = append(results, r)
	}
	return results, rows.Err()
}

// VectorSearch performs semantic similarity search using sqlite-vec.
func (s *SQLCipherStorage) VectorSearch(queryVec []float32, limit int, filters SearchFilters) ([]SearchResult, error) {
	vecBytes := serializeFloat32(queryVec)
	where, args := buildFilterClauses(filters)

	q := fmt.Sprintf(`
		SELECT o.id, o.title, o.summary, o.type, o.project, o.created_at,
			v.distance
		FROM observations_vec v
		JOIN observations o ON o.rowid = v.rowid
		WHERE v.embedding MATCH ?
		AND k = ?
		%s
		ORDER BY v.distance
	`, where)

	allArgs := append([]interface{}{vecBytes, limit}, args...)

	rows, err := s.db.Query(q, allArgs...)
	if err != nil {
		return nil, fmt.Errorf("vector search: %w", err)
	}
	defer rows.Close()

	var results []SearchResult
	for rows.Next() {
		var r SearchResult
		var distance float64
		if err := rows.Scan(&r.ID, &r.Title, &r.Summary, &r.Type, &r.Project, &r.CreatedAt, &distance); err != nil {
			log.Printf("[search] Vector scan error: %v", err)
			continue
		}
		r.Score = 1.0 / (1.0 + distance) // Convert distance to similarity
		results = append(results, r)
	}
	return results, rows.Err()
}

// HybridSearch combines FTS5 and vector search using reciprocal rank fusion.
func (s *SQLCipherStorage) HybridSearch(query string, queryVec []float32, limit int, filters SearchFilters) ([]SearchResult, error) {
	// RRF (Reciprocal Rank Fusion) smoothing constant. 60 is the standard default
	// from Cormack et al. that balances precision and recall when fusing ranked lists.
	const k = 60

	// Fetch more candidates than needed for fusion
	candidateLimit := limit * 3
	if candidateLimit < 50 {
		candidateLimit = 50
	}

	// Run both searches in parallel (but sqlite isn't thread-safe per connection, so sequential)
	ftsResults, ftsErr := s.FTS5Search(query, candidateLimit, filters)
	var vecResults []SearchResult
	var vecErr error
	if len(queryVec) > 0 {
		vecResults, vecErr = s.VectorSearch(queryVec, candidateLimit, filters)
	}

	// If both fail, return error
	if ftsErr != nil && vecErr != nil {
		return nil, fmt.Errorf("both searches failed: fts=%v, vec=%v", ftsErr, vecErr)
	}

	// Build rank maps
	type fusedResult struct {
		result SearchResult
		score  float64
	}

	resultMap := make(map[string]*fusedResult)

	// Add FTS results
	for rank, r := range ftsResults {
		resultMap[r.ID] = &fusedResult{
			result: r,
			score:  1.0 / float64(k+rank+1),
		}
	}

	// Add/merge vector results
	for rank, r := range vecResults {
		vecScore := 1.0 / float64(k+rank+1)
		if existing, ok := resultMap[r.ID]; ok {
			existing.score += vecScore
		} else {
			resultMap[r.ID] = &fusedResult{
				result: r,
				score:  vecScore,
			}
		}
	}

	// Sort by fused score
	fused := make([]fusedResult, 0, len(resultMap))
	for _, fr := range resultMap {
		fused = append(fused, *fr)
	}
	sort.Slice(fused, func(i, j int) bool {
		return fused[i].score > fused[j].score
	})

	// Limit and return
	if len(fused) > limit {
		fused = fused[:limit]
	}

	results := make([]SearchResult, len(fused))
	for i, fr := range fused {
		results[i] = fr.result
		results[i].Score = fr.score
	}
	return results, nil
}

// TimelineSearch returns observations around an anchor observation, ordered chronologically.
func (s *SQLCipherStorage) TimelineSearch(anchorID string, depthBefore, depthAfter int) ([]Observation, error) {
	// Get the anchor's epoch
	var anchorEpoch int64
	err := s.db.QueryRow("SELECT created_at_epoch FROM observations WHERE id = ?", anchorID).Scan(&anchorEpoch)
	if err != nil {
		return nil, fmt.Errorf("anchor not found: %w", err)
	}

	// Get observations before (including anchor)
	beforeRows, err := s.db.Query(`
		SELECT id, session_id, title, summary, content, type, project,
			created_at, updated_at,
			facts, concepts, files_read, files_modified, code_refs,
			tags, notes, classification, starred, archived,
			vault_id, source_adapter, source_id, source_machine,
			source_epoch, source_checksum,
			embedding_model, embedding_tokenizer, embedding_dims,
			extensions
		FROM observations
		WHERE created_at_epoch <= ?
		ORDER BY created_at_epoch DESC
		LIMIT ?
	`, anchorEpoch, depthBefore+1)
	if err != nil {
		return nil, fmt.Errorf("timeline before: %w", err)
	}
	defer beforeRows.Close()

	var before []Observation
	for beforeRows.Next() {
		obs, err := s.scanObservationRow(beforeRows)
		if err != nil {
			log.Printf("[search] Timeline scan error (before): %v", err)
			continue
		}
		before = append(before, *obs)
	}

	// Get observations after anchor
	afterRows, err := s.db.Query(`
		SELECT id, session_id, title, summary, content, type, project,
			created_at, updated_at,
			facts, concepts, files_read, files_modified, code_refs,
			tags, notes, classification, starred, archived,
			vault_id, source_adapter, source_id, source_machine,
			source_epoch, source_checksum,
			embedding_model, embedding_tokenizer, embedding_dims,
			extensions
		FROM observations
		WHERE created_at_epoch > ?
		ORDER BY created_at_epoch ASC
		LIMIT ?
	`, anchorEpoch, depthAfter)
	if err != nil {
		return nil, fmt.Errorf("timeline after: %w", err)
	}
	defer afterRows.Close()

	var after []Observation
	for afterRows.Next() {
		obs, err := s.scanObservationRow(afterRows)
		if err != nil {
			log.Printf("[search] Timeline scan error (after): %v", err)
			continue
		}
		after = append(after, *obs)
	}

	// Combine: reverse before (so chronological), then after
	result := make([]Observation, 0, len(before)+len(after))
	for i := len(before) - 1; i >= 0; i-- {
		result = append(result, before[i])
	}
	result = append(result, after...)

	return result, nil
}

// TimelineSearchByQuery finds the best matching observation and returns timeline around it.
func (s *SQLCipherStorage) TimelineSearchByQuery(query string, queryVec []float32, depthBefore, depthAfter int) ([]Observation, error) {
	// Find the anchor via hybrid search
	results, err := s.HybridSearch(query, queryVec, 1, SearchFilters{})
	if err != nil || len(results) == 0 {
		return nil, fmt.Errorf("no matching anchor found")
	}
	return s.TimelineSearch(results[0].ID, depthBefore, depthAfter)
}

// buildFilterClauses builds SQL WHERE clauses from filters.
func buildFilterClauses(filters SearchFilters) (string, []interface{}) {
	var clauses []string
	var args []interface{}

	if filters.Project != "" {
		clauses = append(clauses, "AND o.project = ?")
		args = append(args, filters.Project)
	}
	if filters.Type != "" {
		clauses = append(clauses, "AND o.type = ?")
		args = append(args, filters.Type)
	}
	if filters.DateStart != nil {
		clauses = append(clauses, "AND o.created_at_epoch >= ?")
		args = append(args, filters.DateStart.Unix())
	}
	if filters.DateEnd != nil {
		clauses = append(clauses, "AND o.created_at_epoch <= ?")
		args = append(args, filters.DateEnd.Unix())
	}

	where := ""
	for _, c := range clauses {
		where += " " + c
	}
	return where, args
}

