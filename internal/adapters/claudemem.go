package adapters

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/miclip/sinesync/internal/storage"
	_ "modernc.org/sqlite"
)

const ClaudeMemAdapterName = "claude-mem"

// ClaudeMemDB path
func claudeMemDBPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".claude-mem", "claude-mem.db")
}

// IsClaudeMemInstalled checks if claude-mem database exists
func IsClaudeMemInstalled() bool {
	_, err := os.Stat(claudeMemDBPath())
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
	db       *sql.DB
	readonly bool
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
	// Check if sdk_session_id column exists (newer claude-mem versions have it)
	hasSDKSessionID := a.hasColumn("observations", "sdk_session_id")

	var query string
	if hasSDKSessionID {
		query = `
			SELECT
				id, sdk_session_id, project, type, title, subtitle, narrative,
				facts, concepts, files_read, files_modified,
				created_at, created_at_epoch
			FROM observations
			WHERE created_at_epoch > ?
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
			sdkSessionID                                     string
			project, obsType, title                          string
			subtitle, narrative                              sql.NullString
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
				Title:     title,
				Summary:   subtitle.String,
				Content:   narrative.String,
				Type:      obsType,
				Project:   project,
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
				Epoch:   createdAtEpoch,
			},
		}

		// Preserve claude-mem specific data for round-trip
		obs.SetExtension(ClaudeMemAdapterName, ClaudeMemExtension{
			Narrative:    narrative.String,
			SDKSessionID: sdkSessionID,
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
	var narrative, sdkSessionID, subtitle string

	if ext, ok := obs.GetExtension(ClaudeMemAdapterName); ok {
		if extMap, ok := ext.(map[string]interface{}); ok {
			if v, ok := extMap["narrative"].(string); ok {
				narrative = v
			}
			if v, ok := extMap["sdkSessionId"].(string); ok {
				sdkSessionID = v
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
	if sdkSessionID == "" {
		sdkSessionID = "sinesync-" + obs.ID[:8]
	}

	// Serialize JSON arrays
	factsJSON, _ := json.Marshal(obs.Structured.Facts)
	conceptsJSON, _ := json.Marshal(obs.Structured.Concepts)
	filesReadJSON, _ := json.Marshal(obs.Structured.Files.Read)
	filesModifiedJSON, _ := json.Marshal(obs.Structured.Files.Modified)

	createdAt := obs.Core.CreatedAt.Format(time.RFC3339)
	epoch := obs.Source.Epoch
	if epoch == 0 {
		epoch = obs.Core.CreatedAt.Unix()
	}

	_, err = a.db.ExecContext(ctx, `
		INSERT INTO observations (
			sdk_session_id, project, type, title, subtitle, narrative,
			facts, concepts, files_read, files_modified,
			created_at, created_at_epoch
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		sdkSessionID, obs.Core.Project, obs.Core.Type, obs.Core.Title, subtitle, narrative,
		string(factsJSON), string(conceptsJSON), string(filesReadJSON), string(filesModifiedJSON),
		createdAt, epoch,
	)

	return err
}

// Exists checks if an observation already exists in claude-mem
func (a *ClaudeMemAdapter) Exists(ctx context.Context, obs *storage.Observation) (bool, error) {
	// First check by source ID if this came from claude-mem
	if obs.Source.Adapter == ClaudeMemAdapterName && obs.Source.ID != "" {
		var count int
		err := a.db.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM observations WHERE id = ?
		`, obs.Source.ID).Scan(&count)
		if err == nil && count > 0 {
			return true, nil
		}
	}

	// Fall back to project + title check
	var count int
	err := a.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM observations
		WHERE project = ? AND title = ?
	`, obs.Core.Project, obs.Core.Title).Scan(&count)

	return count > 0, err
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
