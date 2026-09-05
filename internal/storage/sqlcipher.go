// ABOUTME: Encrypted SQLite storage backend using SQLCipher with FTS5 and sqlite-vec.
// ABOUTME: Handles schema init, CRUD, session tracking, and vector embedding storage.
package storage

import (
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"time"

	sqlite_vec "github.com/asg017/sqlite-vec-go-bindings/cgo"
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

func init() {
	sqlite_vec.Auto()
}

// SQLCipherStorage implements StorageBackend using an encrypted SQLite database.
type SQLCipherStorage struct {
	db     *sql.DB
	dbPath string
}

// NewSQLCipherStorage opens (or creates) an encrypted SQLCipher database.
// key must be exactly 32 bytes. The encryption key is passed via the DSN
// (_pragma_key) so the driver applies it on every connection, making the
// database/sql connection pool safe.
func NewSQLCipherStorage(dbPath string, key []byte) (*SQLCipherStorage, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("create db directory: %w", err)
	}

	// Pass encryption key via DSN so the driver applies PRAGMA key on every
	// new connection. This avoids the problem where database/sql reopens a
	// connection that lacks the encryption key.
	hexKey := hex.EncodeToString(key)
	dsn := fmt.Sprintf("%s?_pragma_key=%s&_pragma_cipher_plaintext_header_size=0&_foreign_keys=1&_pragma_journal_mode=WAL&_pragma_busy_timeout=5000",
		dbPath, url.QueryEscape("x'"+hexKey+"'"))

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Verify the key works by reading from the database
	var cnt int
	if err := db.QueryRow("SELECT count(*) FROM sqlite_master").Scan(&cnt); err != nil {
		db.Close()
		return nil, fmt.Errorf("key verification failed (wrong key?): %w", err)
	}

	s := &SQLCipherStorage{db: db, dbPath: dbPath}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	log.Printf("[sqlcipher] Opened encrypted database: %s", dbPath)
	return s, nil
}

func (s *SQLCipherStorage) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		project TEXT,
		started_at_epoch INTEGER NOT NULL,
		ended_at TEXT,
		status TEXT DEFAULT 'active',
		observation_count INTEGER DEFAULT 0,
		summary TEXT
	);

	CREATE TABLE IF NOT EXISTS observations (
		id TEXT PRIMARY KEY,
		session_id TEXT,
		title TEXT NOT NULL,
		summary TEXT,
		content TEXT,
		type TEXT NOT NULL,
		project TEXT,
		created_at TEXT NOT NULL,
		created_at_epoch INTEGER NOT NULL,
		updated_at TEXT NOT NULL,
		facts TEXT,
		concepts TEXT,
		files_read TEXT,
		files_modified TEXT,
		code_refs TEXT,
		tags TEXT,
		notes TEXT,
		classification TEXT DEFAULT 'private',
		starred INTEGER DEFAULT 0,
		archived INTEGER DEFAULT 0,
		vault_id TEXT,
		source_adapter TEXT DEFAULT 'sinesync',
		source_id TEXT,
		source_machine TEXT,
		source_epoch INTEGER,
		source_checksum TEXT,
		embedding_model TEXT,
		embedding_tokenizer TEXT,
		embedding_dims INTEGER,
		extensions TEXT,
		prompt_number INTEGER,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id)
	);

	CREATE INDEX IF NOT EXISTS idx_observations_session_id ON observations(session_id);
	CREATE INDEX IF NOT EXISTS idx_observations_project ON observations(project);
	CREATE INDEX IF NOT EXISTS idx_observations_type ON observations(type);
	CREATE INDEX IF NOT EXISTS idx_observations_created_at_epoch ON observations(created_at_epoch);
	CREATE INDEX IF NOT EXISTS idx_observations_vault_id ON observations(vault_id);

	CREATE TABLE IF NOT EXISTS user_prompts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		prompt TEXT NOT NULL,
		prompt_number INTEGER,
		project TEXT,
		created_at_epoch INTEGER NOT NULL,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id)
	);

	CREATE TABLE IF NOT EXISTS session_summaries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		project TEXT,
		summary TEXT NOT NULL,
		observation_count INTEGER,
		files TEXT,
		created_at_epoch INTEGER NOT NULL,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id)
	);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("create tables: %w", err)
	}

	// FTS5 virtual table — only create if not exists
	// We check because CREATE VIRTUAL TABLE IF NOT EXISTS is supported in newer SQLite
	var ftsCount int
	s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='observations_fts'").Scan(&ftsCount)
	if ftsCount == 0 {
		_, err := s.db.Exec(`
			CREATE VIRTUAL TABLE observations_fts USING fts5(
				title, summary, content, facts, concepts,
				content='observations', content_rowid='rowid'
			)
		`)
		if err != nil {
			return fmt.Errorf("create FTS5 table: %w", err)
		}

		// Populate the FTS index with any existing observations rows
		if _, err := s.db.Exec(`INSERT INTO observations_fts(observations_fts) VALUES('rebuild')`); err != nil {
			return fmt.Errorf("rebuild FTS5 index: %w", err)
		}
	}

	// sqlite-vec virtual table
	var vecCount int
	s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='observations_vec'").Scan(&vecCount)
	if vecCount == 0 {
		_, err := s.db.Exec(`
			CREATE VIRTUAL TABLE observations_vec USING vec0(
				embedding float[384]
			)
		`)
		if err != nil {
			return fmt.Errorf("create vec0 table: %w", err)
		}
	}

	// FTS5 sync triggers
	if _, err := s.db.Exec(`
		CREATE TRIGGER IF NOT EXISTS obs_fts_insert AFTER INSERT ON observations BEGIN
			INSERT INTO observations_fts(rowid, title, summary, content, facts, concepts)
			VALUES (NEW.rowid, NEW.title, NEW.summary, NEW.content, NEW.facts, NEW.concepts);
		END
	`); err != nil {
		return fmt.Errorf("create FTS insert trigger: %w", err)
	}
	if _, err := s.db.Exec(`
		CREATE TRIGGER IF NOT EXISTS obs_fts_delete AFTER DELETE ON observations BEGIN
			INSERT INTO observations_fts(observations_fts, rowid, title, summary, content, facts, concepts)
			VALUES ('delete', OLD.rowid, OLD.title, OLD.summary, OLD.content, OLD.facts, OLD.concepts);
		END
	`); err != nil {
		return fmt.Errorf("create FTS delete trigger: %w", err)
	}
	if _, err := s.db.Exec(`
		CREATE TRIGGER IF NOT EXISTS obs_fts_update AFTER UPDATE ON observations BEGIN
			INSERT INTO observations_fts(observations_fts, rowid, title, summary, content, facts, concepts)
			VALUES ('delete', OLD.rowid, OLD.title, OLD.summary, OLD.content, OLD.facts, OLD.concepts);
			INSERT INTO observations_fts(rowid, title, summary, content, facts, concepts)
			VALUES (NEW.rowid, NEW.title, NEW.summary, NEW.content, NEW.facts, NEW.concepts);
		END
	`); err != nil {
		return fmt.Errorf("create FTS update trigger: %w", err)
	}

	return nil
}

// SaveObservation inserts or replaces an observation.
func (s *SQLCipherStorage) SaveObservation(obs *Observation) error {
	factsJSON, err := json.Marshal(obs.Structured.Facts)
	if err != nil {
		return fmt.Errorf("marshal facts: %w", err)
	}
	conceptsJSON, err := json.Marshal(obs.Structured.Concepts)
	if err != nil {
		return fmt.Errorf("marshal concepts: %w", err)
	}
	filesReadJSON, err := json.Marshal(obs.Structured.Files.Read)
	if err != nil {
		return fmt.Errorf("marshal files_read: %w", err)
	}
	filesModifiedJSON, err := json.Marshal(obs.Structured.Files.Modified)
	if err != nil {
		return fmt.Errorf("marshal files_modified: %w", err)
	}
	codeRefsJSON, err := json.Marshal(obs.Structured.CodeRefs)
	if err != nil {
		return fmt.Errorf("marshal code_refs: %w", err)
	}
	tagsJSON, err := json.Marshal(obs.Meta.Tags)
	if err != nil {
		return fmt.Errorf("marshal tags: %w", err)
	}
	extensionsJSON, err := json.Marshal(obs.Extensions)
	if err != nil {
		return fmt.Errorf("marshal extensions: %w", err)
	}

	// RFC3339Nano, not RFC3339. RFC3339 has no fractional part, so every
	// timestamp written through it was silently truncated to the second — which
	// meant a plaintext observation could never be proved to have round-tripped
	// intact, and the legacy migration could not honestly delete anything.
	//
	// Backward compatible in both directions: time.Parse with the RFC3339
	// layout accepts a fractional seconds field even though the layout does not
	// contain one, so an old reader handles a new value, and rows already
	// stored without a fraction keep parsing exactly as before. Existing rows
	// are deliberately NOT rewritten — migrating data at rest is a separate
	// change with its own risks.
	createdAt := obs.Core.CreatedAt.Format(time.RFC3339Nano)
	updatedAt := obs.Core.UpdatedAt.Format(time.RFC3339Nano)
	createdAtEpoch := obs.Core.CreatedAt.Unix()

	starred := 0
	if obs.Meta.Starred {
		starred = 1
	}
	archived := 0
	if obs.Meta.Archived {
		archived = 1
	}

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Delete existing FTS/vec entries if this is a replace (trigger handles FTS, vec is manual)
	var existingRowid int64
	err = tx.QueryRow("SELECT rowid FROM observations WHERE id = ?", obs.ID).Scan(&existingRowid)
	isUpdate := err == nil

	if isUpdate {
		// Delete old vec entry
		if _, err := tx.Exec("DELETE FROM observations_vec WHERE rowid = ?", existingRowid); err != nil {
			return fmt.Errorf("delete old vec entry: %w", err)
		}
	}

	result, err := tx.Exec(`
		INSERT OR REPLACE INTO observations (
			id, session_id, title, summary, content, type, project,
			created_at, created_at_epoch, updated_at,
			facts, concepts, files_read, files_modified, code_refs,
			tags, notes, classification, starred, archived,
			vault_id, source_adapter, source_id, source_machine,
			source_epoch, source_checksum,
			embedding_model, embedding_tokenizer, embedding_dims,
			extensions
		) VALUES (
			?, ?, ?, ?, ?, ?, ?,
			?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?,
			?, ?, ?, ?,
			?, ?,
			?, ?, ?,
			?
		)
	`,
		obs.ID, nilIfEmpty(obs.Core.SessionID), obs.Core.Title, obs.Core.Summary, obs.Core.Content, obs.Core.Type, obs.Core.Project,
		createdAt, createdAtEpoch, updatedAt,
		string(factsJSON), string(conceptsJSON), string(filesReadJSON), string(filesModifiedJSON), string(codeRefsJSON),
		string(tagsJSON), obs.Meta.Notes, obs.Meta.Classification, starred, archived,
		obs.Meta.VaultID, obs.Source.Adapter, obs.Source.ID, obs.Source.Machine,
		obs.Source.Epoch, obs.Source.Checksum,
		obs.Embedding.Model, obs.Embedding.Tokenizer, obs.Embedding.Dims,
		string(extensionsJSON),
	)
	if err != nil {
		return fmt.Errorf("insert observation: %w", err)
	}

	// Get the rowid for vec insertion
	rowid, err := result.LastInsertId()
	if err != nil {
		// If INSERT OR REPLACE didn't change rowid, look it up
		tx.QueryRow("SELECT rowid FROM observations WHERE id = ?", obs.ID).Scan(&rowid)
	}

	// Insert embedding into vec table if available.
	// Vector insert failure is non-fatal: the observation is already persisted,
	// and search will fall back to FTS5-only. Log for debugging but don't fail the transaction.
	if len(obs.Embedding.Vector) > 0 && rowid > 0 {
		vecBytes := serializeFloat32(obs.Embedding.Vector)
		_, err = tx.Exec("INSERT INTO observations_vec(rowid, embedding) VALUES (?, ?)", rowid, vecBytes)
		if err != nil {
			log.Printf("[sqlcipher] Warning: failed to insert vector for %s: %v", obs.ID, err)
		}
	}

	return tx.Commit()
}

// GetObservation retrieves a single observation by ID.
func (s *SQLCipherStorage) GetObservation(id string) (*Observation, error) {
	row := s.db.QueryRow(`
		SELECT id, session_id, title, summary, content, type, project,
			created_at, updated_at,
			facts, concepts, files_read, files_modified, code_refs,
			tags, notes, classification, starred, archived,
			vault_id, source_adapter, source_id, source_machine,
			source_epoch, source_checksum,
			embedding_model, embedding_tokenizer, embedding_dims,
			extensions
		FROM observations WHERE id = ?
	`, id)

	return s.scanObservation(row)
}

// ListObservations returns all observations ordered by created_at_epoch DESC.
func (s *SQLCipherStorage) ListObservations() ([]Observation, error) {
	rows, err := s.db.Query(`
		SELECT id, session_id, title, summary, content, type, project,
			created_at, updated_at,
			facts, concepts, files_read, files_modified, code_refs,
			tags, notes, classification, starred, archived,
			vault_id, source_adapter, source_id, source_machine,
			source_epoch, source_checksum,
			embedding_model, embedding_tokenizer, embedding_dims,
			extensions
		FROM observations ORDER BY created_at_epoch DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("list observations: %w", err)
	}
	defer rows.Close()

	var observations []Observation
	for rows.Next() {
		obs, err := s.scanObservationRow(rows)
		if err != nil {
			log.Printf("[sqlcipher] Warning: failed to scan observation: %v", err)
			continue
		}
		observations = append(observations, *obs)
	}
	return observations, rows.Err()
}

// DeleteObservation removes an observation by ID.
func (s *SQLCipherStorage) DeleteObservation(id string) error {
	// Get rowid for vec deletion
	var rowid int64
	err := s.db.QueryRow("SELECT rowid FROM observations WHERE id = ?", id).Scan(&rowid)
	if err != nil {
		return fmt.Errorf("observation not found: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Delete vec entry explicitly (FTS handled by trigger)
	if _, err := tx.Exec("DELETE FROM observations_vec WHERE rowid = ?", rowid); err != nil {
		return fmt.Errorf("delete observation vec: %w", err)
	}

	// Delete observation (triggers handle FTS)
	if _, err := tx.Exec("DELETE FROM observations WHERE id = ?", id); err != nil {
		return fmt.Errorf("delete observation: %w", err)
	}

	return tx.Commit()
}

// ObservationExists checks if an observation exists by its source fields.
func (s *SQLCipherStorage) ObservationExists(obs *Observation) (bool, error) {
	if obs.Source.Adapter != "" && obs.Source.ID != "" {
		return s.ExistsBySource(obs.Source.Adapter, obs.Source.Machine, obs.Source.ID)
	}
	return false, nil
}

// ExistsBySource checks for duplicate observations by source adapter, machine, and ID.
func (s *SQLCipherStorage) ExistsBySource(adapter, machine, sourceID string) (bool, error) {
	var count int
	err := s.db.QueryRow(
		"SELECT COUNT(*) FROM observations WHERE source_adapter = ? AND source_machine = ? AND source_id = ?",
		adapter, machine, sourceID,
	).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// GetStatus returns storage statistics.
func (s *SQLCipherStorage) GetStatus() (itemCount int, storageBytes int64, err error) {
	err = s.db.QueryRow("SELECT COUNT(*) FROM observations").Scan(&itemCount)
	if err != nil {
		return 0, 0, err
	}

	info, statErr := os.Stat(s.dbPath)
	if statErr == nil {
		storageBytes = info.Size()
	}
	return itemCount, storageBytes, nil
}

// Close closes the database connection.
func (s *SQLCipherStorage) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// DB returns the underlying database connection (for search and session queries).
func (s *SQLCipherStorage) DB() *sql.DB {
	return s.db
}

// Rekey re-encrypts the database with a new key (e.g., transitioning from local key to derived key).
func (s *SQLCipherStorage) Rekey(newKey []byte) error {
	if len(newKey) != 32 {
		return fmt.Errorf("new key must be 32 bytes, got %d", len(newKey))
	}
	hexKey := hex.EncodeToString(newKey)
	_, err := s.db.Exec(fmt.Sprintf(`PRAGMA rekey = "x'%s'"`, hexKey))
	if err != nil {
		return fmt.Errorf("database rekey failed: %w", err)
	}
	return nil
}

// --- Session/Prompt helpers (used by daemon) ---

// EnsureSession creates a session row if it doesn't exist.
func (s *SQLCipherStorage) EnsureSession(sessionID, project string, startedAtEpoch int64) error {
	_, err := s.db.Exec(`
		INSERT OR IGNORE INTO sessions (session_id, project, started_at_epoch, status)
		VALUES (?, ?, ?, 'active')
	`, sessionID, project, startedAtEpoch)
	return err
}

// CompleteSession marks a session as completed.
func (s *SQLCipherStorage) CompleteSession(sessionID string, endedAt time.Time, summary string, obsCount int) error {
	_, err := s.db.Exec(`
		UPDATE sessions SET status = 'completed', ended_at = ?, summary = ?, observation_count = ?
		WHERE session_id = ?
	`, endedAt.Format(time.RFC3339), summary, obsCount, sessionID)
	return err
}

// InsertUserPrompt records a user prompt.
func (s *SQLCipherStorage) InsertUserPrompt(sessionID, prompt, project string, promptNumber int, epochSec int64) error {
	_, err := s.db.Exec(`
		INSERT INTO user_prompts (session_id, prompt, prompt_number, project, created_at_epoch)
		VALUES (?, ?, ?, ?, ?)
	`, sessionID, prompt, promptNumber, project, epochSec)
	return err
}

// InsertSessionSummary records a session summary.
func (s *SQLCipherStorage) InsertSessionSummary(sessionID, project, summary string, obsCount int, files []string, epochSec int64) error {
	filesJSON, _ := json.Marshal(files)
	_, err := s.db.Exec(`
		INSERT INTO session_summaries (session_id, project, summary, observation_count, files, created_at_epoch)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sessionID, project, summary, obsCount, string(filesJSON), epochSec)
	return err
}

// IncrementSessionObservationCount increments the observation count for a session.
func (s *SQLCipherStorage) IncrementSessionObservationCount(sessionID string) error {
	_, err := s.db.Exec(`
		UPDATE sessions SET observation_count = observation_count + 1
		WHERE session_id = ?
	`, sessionID)
	return err
}

// --- Internal helpers ---

// scanObservation scans a single row into an Observation.
func (s *SQLCipherStorage) scanObservation(row *sql.Row) (*Observation, error) {
	var obs Observation
	var (
		sessionID                                                  sql.NullString
		createdAt, updatedAt                                       string
		factsJSON, conceptsJSON, filesReadJSON, filesModifiedJSON  sql.NullString
		codeRefsJSON, tagsJSON, extensionsJSON                     sql.NullString
		notes, classification, vaultID                             sql.NullString
		sourceAdapter, sourceID, sourceMachine, sourceChecksum     sql.NullString
		embeddingModel, embeddingTokenizer                         sql.NullString
		starred, archived                                          int
		sourceEpoch                                                sql.NullInt64
		embeddingDims                                              sql.NullInt64
	)

	err := row.Scan(
		&obs.ID, &sessionID, &obs.Core.Title, &obs.Core.Summary, &obs.Core.Content,
		&obs.Core.Type, &obs.Core.Project,
		&createdAt, &updatedAt,
		&factsJSON, &conceptsJSON, &filesReadJSON, &filesModifiedJSON, &codeRefsJSON,
		&tagsJSON, &notes, &classification, &starred, &archived,
		&vaultID, &sourceAdapter, &sourceID, &sourceMachine,
		&sourceEpoch, &sourceChecksum,
		&embeddingModel, &embeddingTokenizer, &embeddingDims,
		&extensionsJSON,
	)
	if err != nil {
		return nil, err
	}

	s.deserializeObservation(&obs, sessionID, createdAt, updatedAt,
		factsJSON, conceptsJSON, filesReadJSON, filesModifiedJSON, codeRefsJSON,
		tagsJSON, notes, classification, vaultID,
		sourceAdapter, sourceID, sourceMachine, sourceChecksum,
		sourceEpoch, embeddingModel, embeddingTokenizer, embeddingDims,
		extensionsJSON, starred, archived)

	return &obs, nil
}

// scanObservationRow scans from rows.Scan (multiple rows).
func (s *SQLCipherStorage) scanObservationRow(rows *sql.Rows) (*Observation, error) {
	var obs Observation
	var (
		sessionID                                                  sql.NullString
		createdAt, updatedAt                                       string
		factsJSON, conceptsJSON, filesReadJSON, filesModifiedJSON  sql.NullString
		codeRefsJSON, tagsJSON, extensionsJSON                     sql.NullString
		notes, classification, vaultID                             sql.NullString
		sourceAdapter, sourceID, sourceMachine, sourceChecksum     sql.NullString
		embeddingModel, embeddingTokenizer                         sql.NullString
		starred, archived                                          int
		sourceEpoch                                                sql.NullInt64
		embeddingDims                                              sql.NullInt64
	)

	err := rows.Scan(
		&obs.ID, &sessionID, &obs.Core.Title, &obs.Core.Summary, &obs.Core.Content,
		&obs.Core.Type, &obs.Core.Project,
		&createdAt, &updatedAt,
		&factsJSON, &conceptsJSON, &filesReadJSON, &filesModifiedJSON, &codeRefsJSON,
		&tagsJSON, &notes, &classification, &starred, &archived,
		&vaultID, &sourceAdapter, &sourceID, &sourceMachine,
		&sourceEpoch, &sourceChecksum,
		&embeddingModel, &embeddingTokenizer, &embeddingDims,
		&extensionsJSON,
	)
	if err != nil {
		return nil, err
	}

	s.deserializeObservation(&obs, sessionID, createdAt, updatedAt,
		factsJSON, conceptsJSON, filesReadJSON, filesModifiedJSON, codeRefsJSON,
		tagsJSON, notes, classification, vaultID,
		sourceAdapter, sourceID, sourceMachine, sourceChecksum,
		sourceEpoch, embeddingModel, embeddingTokenizer, embeddingDims,
		extensionsJSON, starred, archived)

	return &obs, nil
}

func (s *SQLCipherStorage) deserializeObservation(obs *Observation,
	sessionID sql.NullString,
	createdAt, updatedAt string,
	factsJSON, conceptsJSON, filesReadJSON, filesModifiedJSON, codeRefsJSON sql.NullString,
	tagsJSON, notes, classification, vaultID sql.NullString,
	sourceAdapter, sourceID, sourceMachine, sourceChecksum sql.NullString,
	sourceEpoch sql.NullInt64,
	embeddingModel, embeddingTokenizer sql.NullString,
	embeddingDims sql.NullInt64,
	extensionsJSON sql.NullString,
	starred, archived int,
) {
	if sessionID.Valid {
		obs.Core.SessionID = sessionID.String
	}
	obs.Core.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	obs.Core.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAt)

	if factsJSON.Valid {
		json.Unmarshal([]byte(factsJSON.String), &obs.Structured.Facts)
	}
	if conceptsJSON.Valid {
		json.Unmarshal([]byte(conceptsJSON.String), &obs.Structured.Concepts)
	}
	if filesReadJSON.Valid {
		json.Unmarshal([]byte(filesReadJSON.String), &obs.Structured.Files.Read)
	}
	if filesModifiedJSON.Valid {
		json.Unmarshal([]byte(filesModifiedJSON.String), &obs.Structured.Files.Modified)
	}
	if codeRefsJSON.Valid {
		json.Unmarshal([]byte(codeRefsJSON.String), &obs.Structured.CodeRefs)
	}
	if tagsJSON.Valid {
		json.Unmarshal([]byte(tagsJSON.String), &obs.Meta.Tags)
	}
	if notes.Valid {
		obs.Meta.Notes = notes.String
	}
	if classification.Valid {
		obs.Meta.Classification = classification.String
	}
	obs.Meta.Starred = starred != 0
	obs.Meta.Archived = archived != 0
	if vaultID.Valid {
		obs.Meta.VaultID = vaultID.String
	}

	if sourceAdapter.Valid {
		obs.Source.Adapter = sourceAdapter.String
	}
	if sourceID.Valid {
		obs.Source.ID = sourceID.String
	}
	if sourceMachine.Valid {
		obs.Source.Machine = sourceMachine.String
	}
	if sourceEpoch.Valid {
		obs.Source.Epoch = sourceEpoch.Int64
	}
	if sourceChecksum.Valid {
		obs.Source.Checksum = sourceChecksum.String
	}

	if embeddingModel.Valid {
		obs.Embedding.Model = embeddingModel.String
	}
	if embeddingTokenizer.Valid {
		obs.Embedding.Tokenizer = embeddingTokenizer.String
	}
	if embeddingDims.Valid {
		obs.Embedding.Dims = int(embeddingDims.Int64)
	}

	if extensionsJSON.Valid && extensionsJSON.String != "null" {
		json.Unmarshal([]byte(extensionsJSON.String), &obs.Extensions)
	}
}

// nilIfEmpty returns nil for empty strings (to store NULL in SQLite instead of empty string).
func nilIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// serializeFloat32 converts a float32 slice to little-endian bytes for sqlite-vec.
// GetObservationVector returns the embedding actually stored in the sqlite-vec
// table for an observation, or nil when there is no vector row for it.
//
// It exists because SaveObservation treats a failed vector insert as non-fatal:
// the observation is persisted and search silently degrades to FTS-only. That
// is a reasonable trade for a live capture, and an unacceptable one for
// deciding whether a plaintext file is safe to delete — "the vector probably
// made it" is not a basis for removing the only other copy.
func (s *SQLCipherStorage) GetObservationVector(id string) ([]float32, error) {
	var rowid int64
	if err := s.db.QueryRow("SELECT rowid FROM observations WHERE id = ?", id).Scan(&rowid); err != nil {
		return nil, err
	}

	var blob []byte
	err := s.db.QueryRow("SELECT embedding FROM observations_vec WHERE rowid = ?", rowid).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return deserializeFloat32(blob), nil
}

// deserializeFloat32 is the inverse of serializeFloat32.
func deserializeFloat32(buf []byte) []float32 {
	vec := make([]float32, len(buf)/4)
	for i := range vec {
		vec[i] = math.Float32frombits(binary.LittleEndian.Uint32(buf[i*4:]))
	}
	return vec
}

func serializeFloat32(vec []float32) []byte {
	buf := make([]byte, len(vec)*4)
	for i, v := range vec {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(v))
	}
	return buf
}
