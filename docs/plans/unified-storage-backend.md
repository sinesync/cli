# RFD: Unified SQLCipher Storage for Adapter Mode

**Status:** Draft
**Authors:** miclip
**Branch:** `rfd/unified-storage-backend`

## Goal

Use the SQLCipher `memory.db` as the local storage backend in both standalone and adapter modes. Today, adapter mode stores observations as JSON files while standalone mode uses SQLCipher. This RFD unifies them — adapter mode imports into SQLCipher instead of JSON, syncs to cloud from SQLCipher, and continues bridging to claude-mem's databases as it does today.

## Problem

The daemon already prefers SQLCipher and falls back to JSON only when `initSQLCipherBackend()` returns nil (keyring errors, DB open failure, etc.). However, the CLI commands bypass this entirely and hardcode `storage.NewLocalStorage()` (JSON files) in multiple places. This means:

1. **CLI always uses JSON** — even when the daemon is running on SQLCipher, the CLI reads/writes JSON files in `~/.sinesync/data/observation/`.
2. **No encryption at rest for CLI path** — JSON files are plaintext on disk. We took the CGO hit for SQLCipher; we should use it everywhere.
3. **Two storage paths to maintain** — the daemon uses SQLCipher but the CLI uses JSON. Both must be supported, tested, and kept in sync.
4. **Blocks visual layer** — a CLI dashboard, browser extension, or 1Password-like memory manager needs a queryable local store. JSON files don't support this.

## What Changes

**One thing:** the storage backend across the entire CLI switches from JSON files to SQLCipher.

**What stays the same:**
- Claude-mem adapter — still imports from claude-mem's DB, still exports back to claude-mem's DB + ChromaDB
- Cloud sync — still reads observations from local storage, encrypts, uploads
- Backfill jobs — still run in adapter mode (export to claude-mem, chroma embeddings)
- MCP tools — adapter mode still exposes only sync tools (claude-mem handles memory tools)

## Architecture

### Today

```
Daemon:  claude-mem DB ──import──→ SQLCipher memory.db ──sync──→ Cloud (GCS)
                                          │
                                          └──export──→ claude-mem DB + ChromaDB

CLI:     JSON files ──sync──→ Cloud (GCS)   ← bypasses SQLCipher entirely
```

### After

```
Daemon + CLI:  claude-mem DB ──import──→ SQLCipher memory.db ──sync──→ Cloud (GCS)
                                                │
                                                └──export──→ claude-mem DB + ChromaDB
```

The daemon path is already correct. The change is making all CLI commands use the same SQLCipher backend instead of hardcoding JSON.

## Implementation

### 1. Remove mode-conditional storage init

**File:** `internal/daemon/server.go` (lines 70-97)

The daemon already does this correctly — `initSQLCipherBackend()` first, JSON fallback only on failure (keyring errors, DB open/creation failure, etc.). No daemon changes needed.

### 2. Adapter import writes to SQLCipher

**File:** `internal/daemon/server.go` — observation capture endpoint

The capture/import path already calls `backend.SaveObservation()`. Since `backend` is now always SQLCipher (when key is available), imported observations go directly into `memory.db`. No changes needed to the import code itself — the `StorageBackend` interface abstracts this.

### 3. Sync reads from SQLCipher

**File:** `internal/daemon/sync.go`

The sync manager already calls `m.backend.ListObservations()` and `m.backend.SaveObservation()`. Since the backend is now SQLCipher, sync automatically reads from and writes to `memory.db`. No changes needed.

### 4. Migration of existing JSON data

**File:** `internal/daemon/server.go` (lines 82-96)

The auto-migration from JSON → SQLCipher already exists and runs on startup when legacy JSON files are detected. Adapter mode users who upgrade will get their existing JSON observations migrated into SQLCipher on first start.

### 5. Shared backend resolution

**File:** `internal/storage/resolve.go` (**New**)

Extract the backend resolution logic from the daemon into a shared helper so both daemon and CLI use the same storage.

```go
// ResolveBackend returns SQLCipher if available, otherwise returns an error.
// Unlike the daemon (which can fall back to JSON), CLI commands should not
// silently degrade to unencrypted storage.
func ResolveBackend() (StorageBackend, error) {
    backend := initSQLCipherBackend()
    if backend != nil {
        return backend, nil
    }
    return nil, fmt.Errorf("SQLCipher unavailable (keyring error or DB failure) — cannot proceed without encrypted storage")
}
```

The daemon keeps its existing fallback-to-JSON behavior for resilience. CLI commands get a hard error instead — silently falling back to plaintext JSON would defeat the purpose of encryption at rest.

### 6. Replace all NewLocalStorage() call sites

All CLI code paths that hardcode `storage.NewLocalStorage()` must switch to `storage.ResolveBackend()`:

| File | Lines | Usage |
|------|-------|-------|
| `internal/cli/sync.go` | 79, 381, 472 | sync, push, pull commands |
| `internal/cli/root.go` | 65, 270, 362, 471 | Various CLI commands |
| `internal/cli/vault.go` | 611, 718, 1303 | Vault commands |
| `internal/dashboard/server.go` | 48 | Dashboard server |
| `internal/doctor/core.go` | 139 | Health checks |

### 7. Concurrent access: CLI vs daemon

Both the CLI and daemon may open `memory.db` simultaneously. SQLCipher (via SQLite) supports concurrent access under WAL mode:

- **Multiple readers** — safe, no contention.
- **Single writer at a time** — SQLite serializes writes with a busy timeout.

The daemon already opens with WAL mode. `ResolveBackend()` must also open with WAL and set a reasonable busy timeout (e.g., 5 seconds) so CLI writes don't fail immediately if the daemon holds a write lock.

If contention becomes a problem in practice, the CLI could instead proxy through the daemon's HTTP API rather than opening the DB directly. That's out of scope for this RFD but noted as a future option.

### 8. Sync manifest

The sync manifest (`~/.sinesync/sync-manifest.json`) tracks cloud sync state and is currently a standalone JSON file. It stays as-is for now — it contains no observation content, only IDs and checksums, so the encryption-at-rest concern doesn't apply. Moving it into SQLCipher is a future cleanup, not a blocker.

## What This Enables

With a single queryable SQLCipher database in both modes:

1. **CLI dashboard** — `sinesync dashboard` can query `memory.db` directly for stats, recent activity, project breakdown. No need to load all JSON files into memory.

2. **Browser extension** — a 1Password-like memory manager that connects to the daemon's HTTP API. Search, tag, star, archive, delete memories. The daemon already has the endpoints; they just need a queryable backend.

3. **Reports** — session summaries, project activity, memory growth over time. SQL queries against a single DB instead of filesystem walks.

4. **Unified search in adapter mode** — today, adapter mode has no local search (claude-mem handles it). With SQLCipher + FTS5 + sqlite-vec, adapter mode could optionally offer sinesync's search tools alongside claude-mem's. Not proposed here, but enabled by this change.

## Files to Modify

| File | Change |
|------|--------|
| `internal/storage/resolve.go` | **New** — shared `ResolveBackend()` helper for daemon and CLI |
| `internal/cli/sync.go` | Use `ResolveBackend()` instead of `NewLocalStorage()` (3 call sites) |
| `internal/cli/root.go` | Use `ResolveBackend()` instead of `NewLocalStorage()` (4 call sites) |
| `internal/cli/vault.go` | Use `ResolveBackend()` instead of `NewLocalStorage()` (3 call sites) |
| `internal/dashboard/server.go` | Use `ResolveBackend()` instead of `NewLocalStorage()` (1 call site) |
| `internal/doctor/core.go` | Use `ResolveBackend()` instead of `NewLocalStorage()` (1 call site) |
| `internal/daemon/server.go` | Confirm SQLCipher-first init applies to both modes (minimal change) |

## Migration

- Existing adapter mode users with JSON files: auto-migrated on first startup (existing logic)
- Existing standalone users: no change (already on SQLCipher)
- Cloud sync state: preserved — migrated observations maintain checksums, no re-upload
- Sync manifest: stays as JSON file (no sensitive content, future cleanup)

## Verification

1. `go build ./...` succeeds
2. Adapter mode daemon starts → creates/opens `memory.db`
3. Claude-mem import → observations in SQLCipher, not JSON
4. Cloud sync push/pull reads from SQLCipher
5. Backfill export to claude-mem still works from SQLCipher
6. CLI `sinesync sync` uses SQLCipher backend
7. CLI commands error clearly when SQLCipher is unavailable (no silent JSON fallback)
8. Legacy JSON observations auto-migrate on upgrade
9. No JSON files created in `~/.sinesync/data/observation/` after upgrade
10. Concurrent CLI + daemon access works under WAL mode (e.g., `sinesync sync push` while daemon is running)
