// ABOUTME: Provides ResolveBackend() for CLI commands to open the unified SQLCipher storage.
// ABOUTME: Handles keychain key resolution and legacy JSON-to-SQLCipher migration.
package storage

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/sinesync/cli/internal/config"
)

// ResolveBackend opens the SQLCipher storage backend for CLI use.
//
// It hardens any legacy plaintext, resolves the DB key from the keychain, opens
// the encrypted database, and migrates and removes the legacy plaintext store.
// Every step fails closed: CLI commands must not silently fall back to
// unencrypted JSON storage, and must not silently leave plaintext behind that
// nothing reads any more.
func ResolveBackend() (StorageBackend, error) {
	// Before the keychain lookup, not after: if the key cannot be resolved this
	// function returns without opening anything, and any plaintext an older
	// build left behind would stay world-readable for the rest of the session.
	// The daemon runs the same preflight for the same reason.
	if err := HardenLegacyPlaintext(config.DataDir()); err != nil {
		var lp *LegacyPlaintextError
		if errors.As(err, &lp) {
			return nil, fmt.Errorf("%w\n\n%s", err, lp.Remedy())
		}
		return nil, err
	}

	// Through the shared resolver, the same one the daemon uses. A CLI command
	// and the daemon disagreeing about which key opens the database is how a
	// user ends up with one of them working and the other reporting that their
	// memories cannot be decrypted.
	dbPath := filepath.Join(config.DataDir(), "memory.db")
	key, source, err := ResolveDBKey(dbPath)
	if err != nil {
		var mm *DBKeyMismatchError
		if errors.As(err, &mm) {
			return nil, fmt.Errorf("%w\n\n%s", err, mm.Remedy())
		}
		return nil, fmt.Errorf("failed to resolve DB key: %w", err)
	}

	db, err := NewSQLCipherStorage(dbPath, key)
	if err != nil {
		// ResolveDBKey verified this key against this file moments ago, so a
		// failure here is not a wrong key — say so, rather than sending the
		// user after their keychain.
		return nil, fmt.Errorf("failed to open SQLCipher storage with the %s (the key was verified against %s first, so this is not a key mismatch): %w", source, dbPath, err)
	}

	// Migrate the legacy plaintext store into the encrypted one and delete it.
	// Either every plaintext observation ends up verified inside SQLCipher and
	// the directory is gone, or the directory is untouched and this fails —
	// there is no outcome where data stops being readable without anyone being
	// told.
	// Quarantined entries are already logged, one line each, with the exact
	// path they were moved to and why. A CLI command's log output goes to
	// stderr, so the user sees them.
	if _, err := CleanupLegacyPlaintext(db, config.DataDir()); err != nil {
		db.Close()
		var lc *LegacyCleanupError
		if errors.As(err, &lc) {
			return nil, fmt.Errorf("%w\n\n%s", err, lc.Remedy())
		}
		return nil, err
	}

	return db, nil
}
