// ABOUTME: Provides ResolveBackend() for CLI commands to open the unified SQLCipher storage.
// ABOUTME: Handles keychain key resolution and legacy JSON-to-SQLCipher migration.
package storage

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/keychain"
)

// ResolveBackend opens the SQLCipher storage backend for CLI use.
// It resolves the DB key from the keychain, opens the encrypted database,
// and runs the legacy JSON → SQLCipher migration if needed.
// Returns an error if the key or database cannot be initialized — CLI
// commands must not silently fall back to unencrypted JSON storage.
func ResolveBackend() (StorageBackend, error) {
	key, err := keychain.GetOrCreateDBKey()
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DB key: %w", err)
	}

	dbPath := filepath.Join(config.DataDir(), "memory.db")
	db, err := NewSQLCipherStorage(dbPath, key)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLCipher storage: %w", err)
	}

	// Auto-migrate legacy JSON observations if they exist
	if HasLegacyObservations(config.DataDir()) {
		localSource := NewLocalStorage()
		migrated, err := MigrateLocalToSQLCipher(localSource, db)
		if err != nil {
			log.Printf("[resolve] Migration error: %v", err)
		} else if migrated > 0 {
			log.Printf("[resolve] Migrated %d observations from JSON to SQLCipher", migrated)
			if err := RenameLegacyDir(config.DataDir()); err != nil {
				log.Printf("[resolve] Failed to rename legacy dir: %v", err)
			}
		}
	}

	return db, nil
}
