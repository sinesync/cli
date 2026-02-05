package adapters

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/miclip/sinesync/internal/doctor"
	"github.com/miclip/sinesync/internal/storage"
	_ "modernc.org/sqlite"
)

const ClaudeMemAdapterName = "claude-mem"

// hostname returns the machine hostname for cross-device dedup
func hostname() string {
	h, _ := os.Hostname()
	return h
}

// ClaudeMemDB path
func claudeMemDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude-mem", "claude-mem.db")
}

// IsClaudeMemInstalled checks if claude-mem is installed
func IsClaudeMemInstalled() bool {
	// Check for database
	if _, err := os.Stat(claudeMemDBPath()); err == nil {
		return true
	}
	// Check for settings file (database may not exist yet)
	home, _ := os.UserHomeDir()
	settingsPath := filepath.Join(home, ".claude-mem", "settings.json")
	_, err := os.Stat(settingsPath)
	return err == nil
}

// ClaudeMemExtension holds claude-mem specific data for round-trip sync
type ClaudeMemExtension struct {
	Narrative    string `json:"narrative,omitempty"`
	SDKSessionID string `json:"sdkSessionId,omitempty"`
	Subtitle     string `json:"subtitle,omitempty"`
}

// ClaudeMemAdapter implements Adapter for claude-mem
type ClaudeMemAdapter struct {
	db             *sql.DB
	readonly       bool
	lastInsertedID int64
}

// GetLastInsertedID returns the ID of the last inserted observation
func (a *ClaudeMemAdapter) GetLastInsertedID() int64 {
	return a.lastInsertedID
}

// NewClaudeMemAdapter creates a new adapter
func NewClaudeMemAdapter(readonly bool) (*ClaudeMemAdapter, error) {
	if !IsClaudeMemInstalled() {
		return nil, nil
	}

	mode := "?mode=ro"
	if !readonly {
		mode = ""
	}

	db, err := sql.Open("sqlite", claudeMemDBPath()+mode)
	if err != nil {
		return nil, err
	}

	return &ClaudeMemAdapter{db: db, readonly: readonly}, nil
}

// Name returns the adapter name
func (a *ClaudeMemAdapter) Name() string {
	return ClaudeMemAdapterName
}

// IsAvailable checks if the adapter is ready
func (a *ClaudeMemAdapter) IsAvailable() bool {
	return a.db != nil
}

// hasColumn checks if a column exists in a table
func (a *ClaudeMemAdapter) hasColumn(table, column string) bool {
	rows, err := a.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			continue
		}
		if name == column {
			return true
		}
	}
	return false
}

// Import reads observations from claude-mem and converts to sinesync format
func (a *ClaudeMemAdapter) Import(ctx context.Context, sinceEpoch int64) ([]storage.Observation, error) {
	// Check which session ID column exists
	hasMemorySessionID := a.hasColumn("observations", "memory_session_id")
	hasSDKSessionID := a.hasColumn("observations", "sdk_session_id")

	var query string
	if hasMemorySessionID {
		// Newer schema - filter out sinesync-exported observations to prevent re-import loops
		query = `
			SELECT
				id, memory_session_id, project, type, title, subtitle, narrative,
				facts, concepts, files_read, files_modified,
				created_at, created_at_epoch
			FROM observations
			WHERE created_at_epoch > ?
			  AND (memory_session_id IS NULL OR memory_session_id NOT LIKE 'sinesync-%')
			ORDER BY created_at_epoch ASC
		`
	} else if hasSDKSessionID {
		query = `
			SELECT
				id, sdk_session_id, project, type, title, subtitle, narrative,
				facts, concepts, files_read, files_modified,
				created_at, created_at_epoch
			FROM observations
			WHERE created_at_epoch > ?
			  AND (sdk_session_id IS NULL OR sdk_session_id NOT LIKE 'sinesync-%')
			ORDER BY created_at_epoch ASC
		`
	} else {
		query = `
			SELECT
				id, '' as sdk_session_id, project, type, title, subtitle, narrative,
				facts, concepts, files_read, files_modified,
				created_at, created_at_epoch
			FROM observations
			WHERE created_at_epoch > ?
			ORDER BY created_at_epoch ASC
		`
	}

	rows, err := a.db.QueryContext(ctx, query, sinceEpoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var observations []storage.Observation

	for rows.Next() {
		var (
			id                                               int64
			sdkSessionID                                     sql.NullString
			project, obsType                                 sql.NullString
			title, subtitle, narrative                       sql.NullString
			factsJSON, conceptsJSON                          sql.NullString
			filesReadJSON, filesModifiedJSON                 sql.NullString
			createdAt                                        string
			createdAtEpoch                                   int64
		)

		err := rows.Scan(
			&id, &sdkSessionID, &project, &obsType,
			&title, &subtitle, &narrative,
			&factsJSON, &conceptsJSON, &filesReadJSON, &filesModifiedJSON,
			&createdAt, &createdAtEpoch,
		)
		if err != nil {
			continue
		}

		// Skip observations with no title (can't be meaningfully indexed)
		if !title.Valid || title.String == "" {
			continue
		}

		// Parse JSON arrays
		var facts, concepts, filesRead, filesModified []string
		if factsJSON.Valid {
			json.Unmarshal([]byte(factsJSON.String), &facts)
		}
		if conceptsJSON.Valid {
			json.Unmarshal([]byte(conceptsJSON.String), &concepts)
		}
		if filesReadJSON.Valid {
			json.Unmarshal([]byte(filesReadJSON.String), &filesRead)
		}
		if filesModifiedJSON.Valid {
			json.Unmarshal([]byte(filesModifiedJSON.String), &filesModified)
		}

		parsedTime, _ := time.Parse(time.RFC3339, createdAt)

		// Build sinesync observation
		obs := storage.Observation{
			ID: uuid.New().String(),
			Core: storage.Core{
				Title:     title.String,
				Summary:   subtitle.String,
				Content:   narrative.String,
				Type:      obsType.String,
				Project:   project.String,
				CreatedAt: parsedTime,
				UpdatedAt: time.Now(),
			},
			Structured: storage.Structured{
				Facts:    facts,
				Concepts: concepts,
				Files: storage.Files{
					Read:     filesRead,
					Modified: filesModified,
				},
			},
			Source: storage.Source{
				Adapter: ClaudeMemAdapterName,
				ID:      fmt.Sprintf("%d", id),
				Machine: hostname(),
				Epoch:   createdAtEpoch,
			},
		}

		// Preserve claude-mem specific data for round-trip
		obs.SetExtension(ClaudeMemAdapterName, ClaudeMemExtension{
			Narrative:    narrative.String,
			SDKSessionID: sdkSessionID.String,
			Subtitle:     subtitle.String,
		})

		observations = append(observations, obs)
	}

	return observations, nil
}

// Export writes an observation to claude-mem
func (a *ClaudeMemAdapter) Export(ctx context.Context, obs *storage.Observation) error {
	if a.readonly {
		return fmt.Errorf("adapter is read-only")
	}

	// Check if already exists
	exists, err := a.Exists(ctx, obs)
	if err != nil {
		return err
	}
	if exists {
		return nil // Already exists, skip
	}

	// Try to get claude-mem extension for lossless round-trip
	var narrative, subtitle string

	if ext, ok := obs.GetExtension(ClaudeMemAdapterName); ok {
		if extMap, ok := ext.(map[string]interface{}); ok {
			if v, ok := extMap["narrative"].(string); ok {
				narrative = v
			}
			if v, ok := extMap["subtitle"].(string); ok {
				subtitle = v
			}
		}
	}

	// Fall back to core fields if extension not present
	if narrative == "" {
		narrative = obs.Core.Content
	}
	if subtitle == "" {
		subtitle = obs.Core.Summary
	}

	// Always use sinesync prefix - identifies exports and prevents re-import loops
	memorySessionID := "sinesync-" + obs.ID[:8]

	project := obs.Core.Project
	if project == "" {
		project = "unknown"
	}

	createdAt := obs.Core.CreatedAt.Format(time.RFC3339)
	epoch := obs.Source.Epoch
	if epoch == 0 {
		epoch = obs.Core.CreatedAt.Unix()
	}

	// Ensure session exists (required for foreign key constraint)
	contentSessionID := "sinesync-content-" + obs.ID[:8]
	_, err = a.db.ExecContext(ctx, `
		INSERT OR IGNORE INTO sdk_sessions (
			content_session_id, memory_session_id, project,
			started_at, started_at_epoch, status
		) VALUES (?, ?, ?, ?, ?, 'completed')
	`, contentSessionID, memorySessionID, project, createdAt, epoch)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}

	// Serialize JSON arrays
	factsJSON, _ := json.Marshal(obs.Structured.Facts)
	conceptsJSON, _ := json.Marshal(obs.Structured.Concepts)
	filesReadJSON, _ := json.Marshal(obs.Structured.Files.Read)
	filesModifiedJSON, _ := json.Marshal(obs.Structured.Files.Modified)

	// Map type to valid claude-mem types
	obsType := obs.Core.Type
	validTypes := map[string]bool{
		"decision": true, "bugfix": true, "feature": true,
		"refactor": true, "discovery": true, "change": true,
	}
	if !validTypes[obsType] {
		obsType = "discovery" // Default fallback
	}

	result, err := a.db.ExecContext(ctx, `
		INSERT INTO observations (
			memory_session_id, project, type, title, subtitle, narrative,
			facts, concepts, files_read, files_modified,
			created_at, created_at_epoch
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		memorySessionID, project, obsType, obs.Core.Title, subtitle, narrative,
		string(factsJSON), string(conceptsJSON), string(filesReadJSON), string(filesModifiedJSON),
		createdAt, epoch,
	)
	if err != nil {
		return err
	}

	// Capture the inserted ID for ChromaDB embedding
	if id, err := result.LastInsertId(); err == nil {
		a.lastInsertedID = id
	}

	return nil
}

// Exists checks if an observation already exists in claude-mem
func (a *ClaudeMemAdapter) Exists(ctx context.Context, obs *storage.Observation) (bool, error) {
	// First check by source ID if this came from claude-mem originally
	if obs.Source.Adapter == ClaudeMemAdapterName && obs.Source.ID != "" {
		var count int
		err := a.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM observations WHERE id = ?
		`, obs.Source.ID).Scan(&count)
		if err == nil && count > 0 {
			return true, nil
		}
	}

	// Check if this specific sinesync observation was already exported
	// Look for the memory_session_id that would be created during export
	if obs.ID != "" && len(obs.ID) >= 8 {
		expectedSessionID := "sinesync-" + obs.ID[:8]
		var count int
		err := a.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM observations
			WHERE memory_session_id = ?
		`, expectedSessionID).Scan(&count)
		if err == nil && count > 0 {
			return true, nil
		}
	}

	// Don't fall back to project + title - that causes false positives
	// where native claude-mem observations block sinesync exports
	return false, nil
}

// GetObservationID returns the sqlite ID for an observation, or 0 if not found
func (a *ClaudeMemAdapter) GetObservationID(ctx context.Context, obs *storage.Observation) int64 {
	// First try by source ID if this came from claude-mem
	if obs.Source.Adapter == ClaudeMemAdapterName && obs.Source.ID != "" {
		var id int64
		err := a.db.QueryRowContext(ctx, `
			SELECT id FROM observations WHERE id = ?
		`, obs.Source.ID).Scan(&id)
		if err == nil {
			return id
		}
	}

	// Look up by sinesync session ID (consistent with Export())
	if obs.ID != "" && len(obs.ID) >= 8 {
		var id int64
		expectedSessionID := "sinesync-" + obs.ID[:8]
		err := a.db.QueryRowContext(ctx, `
			SELECT id FROM observations
			WHERE memory_session_id = ?
			LIMIT 1
		`, expectedSessionID).Scan(&id)
		if err == nil {
			return id
		}
	}
	return 0
}

// GetProjects returns a list of projects with stats
func (a *ClaudeMemAdapter) GetProjects(ctx context.Context) ([]ProjectInfo, error) {
	rows, err := a.db.QueryContext(ctx, `
		SELECT
			COALESCE(project, '(none)') as name,
			COUNT(*) as count,
			MAX(created_at) as last_activity
		FROM observations
		GROUP BY project
		ORDER BY count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []ProjectInfo
	for rows.Next() {
		var p ProjectInfo
		if err := rows.Scan(&p.Name, &p.Count, &p.LastActivity); err != nil {
			continue
		}
		projects = append(projects, p)
	}

	return projects, nil
}

// Close closes the database connection
func (a *ClaudeMemAdapter) Close() error {
	if a.db != nil {
		return a.db.Close()
	}
	return nil
}

// GetObservationCount returns the total number of observations
func (a *ClaudeMemAdapter) GetObservationCount() (int, error) {
	var count int
	err := a.db.QueryRow("SELECT COUNT(*) FROM observations").Scan(&count)
	return count, err
}

// DeleteByProjectAndTitle deletes an observation from claude-mem by project and title
func (a *ClaudeMemAdapter) DeleteByProjectAndTitle(ctx context.Context, project, title string) error {
	if a.readonly {
		return fmt.Errorf("adapter is read-only")
	}

	_, err := a.db.ExecContext(ctx, `
		DELETE FROM observations WHERE project = ? AND title = ?
	`, project, title)
	return err
}

// DeleteBySourceID deletes an observation from claude-mem by its source ID
func (a *ClaudeMemAdapter) DeleteBySourceID(ctx context.Context, sourceID string) error {
	if a.readonly {
		return fmt.Errorf("adapter is read-only")
	}

	_, err := a.db.ExecContext(ctx, `
		DELETE FROM observations WHERE id = ?
	`, sourceID)
	return err
}

// AdapterSyncStats holds sync statistics between sinesync and claude-mem
type AdapterSyncStats struct {
	// Observations in claude-mem that came from sinesync (exported)
	ExportedToClaudeMem int
	// Observations in claude-mem that are native (not from sinesync)
	NativeInClaudeMem int
	// ChromaDB total embedding documents (each observation has multiple docs)
	ChromaEmbeddings int
	// ChromaDB unique observation IDs (for accurate backlog calculation)
	ChromaUniqueObservations int
	// Whether ChromaDB stats are available
	ChromaAvailable bool
}

// GetSyncStats returns sync statistics between sinesync and claude-mem
func (a *ClaudeMemAdapter) GetSyncStats() (*AdapterSyncStats, error) {
	stats := &AdapterSyncStats{}

	// Check which session ID column exists
	hasMemorySessionID := a.hasColumn("observations", "memory_session_id")

	var sessionIDCol string
	if hasMemorySessionID {
		sessionIDCol = "memory_session_id"
	} else {
		sessionIDCol = "sdk_session_id"
	}

	// Count sinesync-exported observations (have sinesync- prefix in session ID)
	err := a.db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM observations
		WHERE %s LIKE 'sinesync-%%'
	`, sessionIDCol)).Scan(&stats.ExportedToClaudeMem)
	if err != nil {
		return nil, err
	}

	// Count native claude-mem observations
	err = a.db.QueryRow(fmt.Sprintf(`
		SELECT COUNT(*) FROM observations
		WHERE %s IS NULL OR %s NOT LIKE 'sinesync-%%'
	`, sessionIDCol, sessionIDCol)).Scan(&stats.NativeInClaudeMem)
	if err != nil {
		return nil, err
	}

	// Try to get ChromaDB embedding count
	stats.ChromaEmbeddings, stats.ChromaUniqueObservations, stats.ChromaAvailable = a.getChromaEmbeddingCount()

	return stats, nil
}

// getChromaEmbeddingCount returns total embeddings, unique observation count, and availability
// Includes both processed embeddings and items in the queue
func (a *ClaudeMemAdapter) getChromaEmbeddingCount() (int, int, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, 0, false
	}

	chromaDBPath := filepath.Join(home, ".claude-mem", "vector-db", "chroma.sqlite3")
	if _, err := os.Stat(chromaDBPath); err != nil {
		return 0, 0, false
	}

	chromaDB, err := sql.Open("sqlite", chromaDBPath+"?mode=ro")
	if err != nil {
		return 0, 0, false
	}
	defer chromaDB.Close()

	// Total embedding documents (processed)
	var totalCount int
	chromaDB.QueryRow("SELECT COUNT(*) FROM embeddings").Scan(&totalCount)

	// Unique observation IDs from processed embeddings
	var uniqueProcessed int
	chromaDB.QueryRow(`
		SELECT COUNT(DISTINCT
			CAST(SUBSTR(embedding_id, 5, INSTR(SUBSTR(embedding_id, 5), '_') - 1) AS INTEGER)
		) FROM embeddings
		WHERE embedding_id LIKE 'obs_%'
	`).Scan(&uniqueProcessed)

	// Also count queue items (pending processing by claude-mem compact)
	var uniqueQueued int
	chromaDB.QueryRow(`
		SELECT COUNT(DISTINCT
			CAST(SUBSTR(id, 5, INSTR(SUBSTR(id, 5), '_') - 1) AS INTEGER)
		) FROM embeddings_queue
		WHERE id LIKE 'obs_%'
	`).Scan(&uniqueQueued)

	// Combine processed and queued (subtract overlap if any)
	uniqueTotal := uniqueProcessed + uniqueQueued

	return totalCount, uniqueTotal, true
}

// GetEmbeddingConfig returns the embedding configuration claude-mem expects
// Claude-mem uses sentence-transformers all-MiniLM-L6-v2 with proper WordPiece tokenization
func (a *ClaudeMemAdapter) GetEmbeddingConfig() *EmbeddingConfig {
	return &EmbeddingConfig{
		Model:     "all-MiniLM-L6-v2",
		Tokenizer: "wordpiece-hf",
		Dims:      384,
	}
}

// ExportWithEmbedding exports an observation to claude-mem SQLite AND inserts embedding into ChromaDB queue
func (a *ClaudeMemAdapter) ExportWithEmbedding(ctx context.Context, obs *storage.Observation) error {
	// First export to SQLite
	if err := a.Export(ctx, obs); err != nil {
		return err
	}

	// Get the SQLite ID we just inserted
	obsID := a.lastInsertedID
	if obsID == 0 {
		// Try to look it up
		obsID = a.GetObservationID(ctx, obs)
		if obsID == 0 {
			return fmt.Errorf("could not determine observation ID for ChromaDB")
		}
	}

	// Check if embedding is compatible
	cfg := a.GetEmbeddingConfig()
	if !obs.Embedding.IsCompatibleWith(cfg.Model, cfg.Tokenizer, cfg.Dims) {
		// Embedding is incompatible or missing - caller should have re-embedded
		return fmt.Errorf("embedding not compatible with adapter config")
	}

	// Insert into ChromaDB queue
	return a.insertChromaEmbedding(obsID, obs)
}

// insertChromaEmbedding inserts the observation's embedding directly into ChromaDB's embeddings_queue
func (a *ClaudeMemAdapter) insertChromaEmbedding(obsID int64, obs *storage.Observation) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	chromaDBPath := filepath.Join(home, ".claude-mem", "vector-db", "chroma.sqlite3")
	if _, err := os.Stat(chromaDBPath); err != nil {
		// ChromaDB not initialized yet - skip silently, embeddings can be backfilled later
		return nil
	}

	chromaDB, err := sql.Open("sqlite", chromaDBPath)
	if err != nil {
		return fmt.Errorf("open ChromaDB: %w", err)
	}
	defer chromaDB.Close()

	// Get collection topic from collections table
	var collectionID string
	err = chromaDB.QueryRow(`
		SELECT id FROM collections WHERE name = 'cm__claude-mem' LIMIT 1
	`).Scan(&collectionID)
	if err != nil {
		// Collection doesn't exist yet - claude-mem creates it on first use
		// Skip ChromaDB insertion, embeddings can be backfilled once collection exists
		return nil
	}
	topic := fmt.Sprintf("persistent://default/default/%s", collectionID)

	// Convert float32 slice to bytes (FLOAT32 encoding)
	vectorBytes := float32SliceToBytes(obs.Embedding.Vector)

	// Build metadata JSON
	metadata := buildChromaMetadata(obsID, obs)

	// Insert narrative document
	docID := fmt.Sprintf("obs_%d_narrative", obsID)
	_, err = chromaDB.Exec(`
		INSERT INTO embeddings_queue (operation, topic, id, vector, encoding, metadata)
		VALUES (0, ?, ?, ?, 'FLOAT32', ?)
	`, topic, docID, vectorBytes, metadata)
	if err != nil {
		return fmt.Errorf("insert embedding: %w", err)
	}

	// Also insert facts as separate documents if present
	for i, fact := range obs.Structured.Facts {
		factDocID := fmt.Sprintf("obs_%d_fact_%d", obsID, i)
		factMeta := buildChromaFactMetadata(obsID, obs, i, fact)
		_, err = chromaDB.Exec(`
			INSERT INTO embeddings_queue (operation, topic, id, vector, encoding, metadata)
			VALUES (0, ?, ?, ?, 'FLOAT32', ?)
		`, topic, factDocID, vectorBytes, factMeta)
		if err != nil {
			// Don't fail on fact insertion errors
			continue
		}
	}

	return nil
}

// float32SliceToBytes converts a float32 slice to raw bytes (little-endian)
func float32SliceToBytes(floats []float32) []byte {
	buf := make([]byte, len(floats)*4)
	for i, f := range floats {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return buf
}

// buildChromaMetadata builds the metadata JSON for ChromaDB
func buildChromaMetadata(obsID int64, obs *storage.Observation) string {
	// Always use sinesync prefix - consistent with Export() to identify sinesync exports
	memorySessionID := "sinesync-" + obs.ID[:8]

	meta := map[string]interface{}{
		"sqlite_id":         obsID,
		"doc_type":          "observation",
		"memory_session_id": memorySessionID,
		"project":           obs.Core.Project,
		"type":              obs.Core.Type,
		"title":             obs.Core.Title,
		"field_type":        "narrative",
		"created_at_epoch":  obs.Source.Epoch,
		"chroma:document":   obs.Core.Content,
	}
	if obs.Core.Summary != "" {
		meta["subtitle"] = obs.Core.Summary
	}
	if len(obs.Structured.Concepts) > 0 {
		meta["concepts"] = joinStrings(obs.Structured.Concepts, ",")
	}

	jsonBytes, _ := json.Marshal(meta)
	return string(jsonBytes)
}

// buildChromaFactMetadata builds metadata for a fact document
func buildChromaFactMetadata(obsID int64, obs *storage.Observation, factIndex int, fact string) string {
	// Always use sinesync prefix - consistent with Export() to identify sinesync exports
	memorySessionID := "sinesync-" + obs.ID[:8]

	meta := map[string]interface{}{
		"sqlite_id":         obsID,
		"doc_type":          "observation",
		"memory_session_id": memorySessionID,
		"project":           obs.Core.Project,
		"type":              obs.Core.Type,
		"title":             obs.Core.Title,
		"field_type":        "fact",
		"fact_index":        factIndex,
		"created_at_epoch":  obs.Source.Epoch,
		"chroma:document":   fact,
	}

	jsonBytes, _ := json.Marshal(meta)
	return string(jsonBytes)
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// GetEmbeddingBacklog returns count of observations without ChromaDB embeddings
func (a *ClaudeMemAdapter) GetEmbeddingBacklog() int {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0
	}

	chromaDBPath := filepath.Join(home, ".claude-mem", "vector-db", "chroma.sqlite3")
	if _, err := os.Stat(chromaDBPath); err != nil {
		return 0
	}

	chromaDB, err := sql.Open("sqlite", chromaDBPath+"?mode=ro")
	if err != nil {
		return 0
	}
	defer chromaDB.Close()

	// Get observation IDs that already have embeddings (in embeddings table or queue)
	existingIDs := make(map[int64]bool)

	rows, _ := chromaDB.Query(`
		SELECT DISTINCT CAST(SUBSTR(embedding_id, 5, INSTR(SUBSTR(embedding_id, 5), '_') - 1) AS INTEGER)
		FROM embeddings WHERE embedding_id LIKE 'obs_%'
	`)
	if rows != nil {
		for rows.Next() {
			var id int64
			rows.Scan(&id)
			existingIDs[id] = true
		}
		rows.Close()
	}

	rows, _ = chromaDB.Query(`
		SELECT DISTINCT CAST(SUBSTR(id, 5, INSTR(SUBSTR(id, 5), '_') - 1) AS INTEGER)
		FROM embeddings_queue WHERE id LIKE 'obs_%'
	`)
	if rows != nil {
		for rows.Next() {
			var id int64
			rows.Scan(&id)
			existingIDs[id] = true
		}
		rows.Close()
	}

	// Count observations without embeddings
	var totalObs int
	a.db.QueryRow("SELECT COUNT(*) FROM observations").Scan(&totalObs)

	return totalObs - len(existingIDs)
}

// BackfillEmbeddings generates embeddings for observations missing from ChromaDB
// Returns number of observations processed
func (a *ClaudeMemAdapter) BackfillEmbeddings(limit int) (int, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}

	chromaDBPath := filepath.Join(home, ".claude-mem", "vector-db", "chroma.sqlite3")
	if _, err := os.Stat(chromaDBPath); err != nil {
		// ChromaDB not initialized yet
		return 0, nil
	}

	chromaDB, err := sql.Open("sqlite", chromaDBPath)
	if err != nil {
		return 0, err
	}
	defer chromaDB.Close()

	// Get collection topic
	var collectionID string
	err = chromaDB.QueryRow(`SELECT id FROM collections WHERE name = 'cm__claude-mem' LIMIT 1`).Scan(&collectionID)
	if err != nil {
		// Collection doesn't exist yet - claude-mem creates it on first use
		return 0, nil
	}
	topic := fmt.Sprintf("persistent://default/default/%s", collectionID)

	// Get existing observation IDs
	existingIDs := make(map[int64]bool)
	rows, _ := chromaDB.Query(`
		SELECT DISTINCT CAST(SUBSTR(embedding_id, 5, INSTR(SUBSTR(embedding_id, 5), '_') - 1) AS INTEGER)
		FROM embeddings WHERE embedding_id LIKE 'obs_%'
		UNION
		SELECT DISTINCT CAST(SUBSTR(id, 5, INSTR(SUBSTR(id, 5), '_') - 1) AS INTEGER)
		FROM embeddings_queue WHERE id LIKE 'obs_%'
	`)
	if rows != nil {
		for rows.Next() {
			var id int64
			rows.Scan(&id)
			existingIDs[id] = true
		}
		rows.Close()
	}

	// Get observations needing embeddings
	rows, err = a.db.Query(`
		SELECT id, project, type, title, subtitle, narrative, created_at_epoch, memory_session_id
		FROM observations
		ORDER BY id ASC
	`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	type obsData struct {
		ID               int64
		Project          string
		Type             string
		Title            string
		Subtitle         string
		Narrative        string
		Epoch            int64
		MemorySessionID  string
	}

	var toProcess []obsData
	for rows.Next() {
		var o obsData
		var project, obsType, title, subtitle, narrative, memSessionID sql.NullString
		err := rows.Scan(&o.ID, &project, &obsType, &title, &subtitle, &narrative, &o.Epoch, &memSessionID)
		if err != nil {
			continue
		}
		o.Project = project.String
		o.Type = obsType.String
		o.Title = title.String
		o.Subtitle = subtitle.String
		o.Narrative = narrative.String
		o.MemorySessionID = memSessionID.String

		if existingIDs[o.ID] {
			continue
		}
		if o.Title == "" && o.Narrative == "" {
			continue
		}
		toProcess = append(toProcess, o)
		if len(toProcess) >= limit {
			break
		}
	}

	if len(toProcess) == 0 {
		return 0, nil
	}

	// Initialize embedder (import cycle avoided by using package directly)
	embedder, err := getEmbedder()
	if err != nil {
		return 0, err
	}
	// Don't close - it's a singleton that may be reused

	if !embedder.IsReady() {
		return 0, fmt.Errorf("embedder not ready")
	}

	// Process observations
	processed := 0
	for _, o := range toProcess {
		text := o.Title
		if o.Narrative != "" {
			text += "\n" + o.Narrative
		}

		vector, err := embedder.Embed(text)
		if err != nil {
			continue
		}

		vectorBytes := float32SliceToBytes(vector)

		meta := map[string]interface{}{
			"sqlite_id":        o.ID,
			"doc_type":         "observation",
			"project":          o.Project,
			"type":             o.Type,
			"title":            o.Title,
			"field_type":       "narrative",
			"created_at_epoch": o.Epoch,
			"chroma:document":  text,
		}
		if o.MemorySessionID != "" {
			meta["memory_session_id"] = o.MemorySessionID
		}
		if o.Subtitle != "" {
			meta["subtitle"] = o.Subtitle
		}
		metaJSON, _ := json.Marshal(meta)

		docID := fmt.Sprintf("obs_%d_narrative", o.ID)
		_, err = chromaDB.Exec(`
			INSERT INTO embeddings_queue (operation, topic, id, vector, encoding, metadata)
			VALUES (0, ?, ?, ?, 'FLOAT32', ?)
		`, topic, docID, vectorBytes, string(metaJSON))
		if err != nil {
			continue
		}
		processed++
	}

	return processed, nil
}

// EmbedderInterface to avoid import cycle
type EmbedderInterface interface {
	IsReady() bool
	Embed(text string) ([]float32, error)
	Close() error
}

// getEmbedder is set by RegisterEmbedder to avoid import cycle
var getEmbedder func() (EmbedderInterface, error)

// RegisterEmbedder sets the embedder factory function
func RegisterEmbedder(factory func() (EmbedderInterface, error)) {
	getEmbedder = factory
}

// DoctorChecks returns diagnostic checks for the claude-mem adapter
func (a *ClaudeMemAdapter) DoctorChecks() []doctor.Check {
	return []doctor.Check{
		{
			Name:     "Stuck SDK sessions",
			Category: "claude-mem",
			Severity: doctor.SeverityError,
			Run:      a.checkStuckSessions,
		},
		{
			Name:     "Orphaned pending messages",
			Category: "claude-mem",
			Severity: doctor.SeverityWarning,
			Run:      a.checkOrphanedMessages,
		},
		{
			Name:     "Embedding backlog",
			Category: "claude-mem",
			Severity: doctor.SeverityWarning,
			Run:      a.checkEmbeddingBacklog,
		},
		{
			Name:     "ChromaDB health",
			Category: "claude-mem",
			Severity: doctor.SeverityInfo,
			Run:      a.checkChromaHealth,
		},
		{
			Name:     "Observations with empty project",
			Category: "claude-mem",
			Severity: doctor.SeverityWarning,
			Run:      a.checkEmptyProjects,
		},
	}
}

// checkStuckSessions finds active sessions with no recent activity
func (a *ClaudeMemAdapter) checkStuckSessions(ctx context.Context, fix bool) doctor.CheckResult {
	result := doctor.CheckResult{
		Name:     "Stuck SDK sessions",
		Category: "claude-mem",
		Severity: doctor.SeverityError,
		CanFix:   true,
	}

	// Find sessions active for >2 hours with pending messages piling up
	rows, err := a.db.QueryContext(ctx, `
		SELECT s.id, s.content_session_id,
			COALESCE(s.started_at_epoch, 0),
			(SELECT COUNT(*) FROM pending_messages WHERE session_db_id = s.id AND status = 'pending') as pending
		FROM sdk_sessions s
		WHERE s.status = 'active'
		AND s.started_at_epoch < ?
	`, time.Now().Add(-2*time.Hour).UnixMilli())
	if err != nil {
		result.Status = doctor.StatusFail
		result.Message = fmt.Sprintf("Query error: %v", err)
		return result
	}
	defer rows.Close()

	type stuckSession struct {
		id        int64
		sessionID string
		age       time.Duration
		pending   int
	}
	var stuck []stuckSession

	for rows.Next() {
		var s stuckSession
		var epoch int64
		if err := rows.Scan(&s.id, &s.sessionID, &epoch, &s.pending); err != nil {
			continue
		}
		s.age = time.Since(time.UnixMilli(epoch))
		stuck = append(stuck, s)
	}

	if len(stuck) == 0 {
		result.Status = doctor.StatusPass
		result.Message = "No stuck sessions"
		return result
	}

	for _, s := range stuck {
		displayID := s.sessionID
		if len(displayID) > 8 {
			displayID = displayID[:8]
		}
		detail := fmt.Sprintf("session %d (%s) active for %s, %d pending messages",
			s.id, displayID, s.age.Round(time.Minute), s.pending)
		result.Details = append(result.Details, detail)
	}

	if fix {
		fixed := 0
		for _, s := range stuck {
			_, err := a.db.ExecContext(ctx, `UPDATE sdk_sessions SET status = 'completed' WHERE id = ?`, s.id)
			if err == nil {
				// Clear pending messages for completed session
				a.db.ExecContext(ctx, `UPDATE pending_messages SET status = 'completed' WHERE session_db_id = ? AND status = 'pending'`, s.id)
				fixed++
			}
		}
		result.Status = doctor.StatusFixed
		result.FixApplied = true
		result.Message = fmt.Sprintf("Completed %d/%d stuck sessions", fixed, len(stuck))
		return result
	}

	result.Status = doctor.StatusFail
	result.Message = fmt.Sprintf("%d stuck sessions", len(stuck))
	return result
}

// checkOrphanedMessages finds pending messages for non-existent or completed sessions
func (a *ClaudeMemAdapter) checkOrphanedMessages(ctx context.Context, fix bool) doctor.CheckResult {
	result := doctor.CheckResult{
		Name:     "Orphaned pending messages",
		Category: "claude-mem",
		Severity: doctor.SeverityWarning,
		CanFix:   true,
	}

	var orphanedCount int
	err := a.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM pending_messages pm
		LEFT JOIN sdk_sessions s ON pm.session_db_id = s.id
		WHERE pm.status = 'pending'
		AND (s.id IS NULL OR s.status = 'completed')
	`).Scan(&orphanedCount)
	if err != nil {
		result.Status = doctor.StatusFail
		result.Message = fmt.Sprintf("Query error: %v", err)
		return result
	}

	if orphanedCount == 0 {
		result.Status = doctor.StatusPass
		result.Message = "No orphaned messages"
		return result
	}

	if fix {
		res, err := a.db.ExecContext(ctx, `
			UPDATE pending_messages SET status = 'completed'
			WHERE status = 'pending'
			AND session_db_id IN (
				SELECT pm.session_db_id FROM pending_messages pm
				LEFT JOIN sdk_sessions s ON pm.session_db_id = s.id
				WHERE pm.status = 'pending'
				AND (s.id IS NULL OR s.status = 'completed')
			)
		`)
		if err == nil {
			affected, _ := res.RowsAffected()
			result.Status = doctor.StatusFixed
			result.FixApplied = true
			result.Message = fmt.Sprintf("Cleared %d orphaned messages", affected)
			return result
		}
		result.Status = doctor.StatusFail
		result.Message = fmt.Sprintf("Fix failed: %v", err)
		return result
	}

	result.Status = doctor.StatusWarn
	result.Message = fmt.Sprintf("%d orphaned pending messages", orphanedCount)
	return result
}

// checkEmbeddingBacklog reports observations missing ChromaDB embeddings
func (a *ClaudeMemAdapter) checkEmbeddingBacklog(ctx context.Context, fix bool) doctor.CheckResult {
	result := doctor.CheckResult{
		Name:     "Embedding backlog",
		Category: "claude-mem",
		Severity: doctor.SeverityWarning,
		CanFix:   true,
	}

	backlog := a.GetEmbeddingBacklog()

	if backlog == 0 {
		result.Status = doctor.StatusPass
		result.Message = "All observations have embeddings"
		return result
	}

	if fix {
		if getEmbedder == nil {
			result.Status = doctor.StatusWarn
			result.Message = fmt.Sprintf("%d observations without embeddings (embedder not available for fix)", backlog)
			return result
		}
		processed, err := a.BackfillEmbeddings(100)
		if err != nil {
			result.Status = doctor.StatusWarn
			result.Message = fmt.Sprintf("%d observations without embeddings, fix error: %v", backlog, err)
			return result
		}
		result.Status = doctor.StatusFixed
		result.FixApplied = true
		result.Message = fmt.Sprintf("Embedded %d observations", processed)
		return result
	}

	result.Status = doctor.StatusWarn
	result.Message = fmt.Sprintf("%d observations without embeddings", backlog)
	return result
}

// checkChromaHealth verifies ChromaDB is accessible and has data
func (a *ClaudeMemAdapter) checkChromaHealth(ctx context.Context, fix bool) doctor.CheckResult {
	result := doctor.CheckResult{
		Name:     "ChromaDB health",
		Category: "claude-mem",
		Severity: doctor.SeverityInfo,
		CanFix:   false,
	}

	totalEmbeddings, uniqueObs, available := a.getChromaEmbeddingCount()
	if !available {
		result.Status = doctor.StatusSkip
		result.Message = "ChromaDB not available"
		return result
	}

	// Get total observation count for comparison
	var totalObs int
	if err := a.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM observations").Scan(&totalObs); err != nil {
		result.Status = doctor.StatusSkip
		result.Message = fmt.Sprintf("Cannot query observations: %v", err)
		return result
	}

	coverage := 0
	if totalObs > 0 {
		coverage = uniqueObs * 100 / totalObs
	}

	result.Status = doctor.StatusPass
	result.Message = fmt.Sprintf("%d embeddings, %d/%d observations covered (%d%%)",
		totalEmbeddings, uniqueObs, totalObs, coverage)

	if coverage < 50 && totalObs > 10 {
		result.Status = doctor.StatusWarn
		result.Message = fmt.Sprintf("Low coverage: %d embeddings, %d/%d observations (%d%%)",
			totalEmbeddings, uniqueObs, totalObs, coverage)
	}

	return result
}

// checkEmptyProjects reports observations with no project set
func (a *ClaudeMemAdapter) checkEmptyProjects(ctx context.Context, fix bool) doctor.CheckResult {
	result := doctor.CheckResult{
		Name:     "Observations with empty project",
		Category: "claude-mem",
		Severity: doctor.SeverityWarning,
		CanFix:   false,
	}

	var emptyCount, totalCount int
	if err := a.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM observations").Scan(&totalCount); err != nil {
		result.Status = doctor.StatusSkip
		result.Message = fmt.Sprintf("Cannot query observations: %v", err)
		return result
	}
	if err := a.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM observations
		WHERE project IS NULL OR project = ''
	`).Scan(&emptyCount); err != nil {
		result.Status = doctor.StatusSkip
		result.Message = fmt.Sprintf("Cannot query observations: %v", err)
		return result
	}

	if emptyCount == 0 {
		result.Status = doctor.StatusPass
		result.Message = fmt.Sprintf("All %d observations have a project", totalCount)
		return result
	}

	result.Status = doctor.StatusWarn
	result.Message = fmt.Sprintf("%d/%d observations have no project", emptyCount, totalCount)
	return result
}
