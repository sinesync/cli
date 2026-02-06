// ABOUTME: Migration utilities for moving observations between storage backends.
// ABOUTME: Supports legacy JSON-to-SQLCipher migration on daemon startup.
package storage

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
)

// MigrateLocalToSQLCipher migrates observations from JSON file storage to SQLCipher.
// Returns the number of migrated observations.
func MigrateLocalToSQLCipher(source *LocalStorage, dest *SQLCipherStorage) (int, error) {
	observations, err := source.ListObservations()
	if err != nil {
		return 0, err
	}

	if len(observations) == 0 {
		return 0, nil
	}

	migrated := 0
	for _, obs := range observations {
		obsCopy := obs

		// Check if already exists (dedup by ID)
		existing, err := dest.GetObservation(obsCopy.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			// Real DB error — skip this observation
			log.Printf("[migrate] Failed to check existing observation %s: %v", obsCopy.ID, err)
			continue
		}
		if existing != nil {
			continue
		}

		if err := dest.SaveObservation(&obsCopy); err != nil {
			log.Printf("[migrate] Failed to migrate observation %s: %v", obsCopy.ID, err)
			continue
		}
		migrated++
	}

	return migrated, nil
}

// HasLegacyObservations checks if the legacy JSON observation directory has files.
func HasLegacyObservations(dataDir string) bool {
	obsDir := filepath.Join(dataDir, "observation")
	entries, err := os.ReadDir(obsDir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			return true
		}
	}
	return false
}

// RenameLegacyDir renames the observation directory to observation.migrated.
func RenameLegacyDir(dataDir string) error {
	obsDir := filepath.Join(dataDir, "observation")
	migratedDir := filepath.Join(dataDir, "observation.migrated")

	// Don't rename if .migrated already exists
	if _, err := os.Stat(migratedDir); err == nil {
		return nil
	}

	return os.Rename(obsDir, migratedDir)
}
