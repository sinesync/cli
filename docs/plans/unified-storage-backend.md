# RFD: Unified SQLCipher Storage for Adapter Mode

**Status:** Draft
**Authors:** miclip
**Branch:** `rfd/unified-storage-backend`

## Goal

Use the SQLCipher `memory.db` as the local storage backend in both standalone and adapter modes. Today, adapter mode stores observations as JSON files while standalone mode uses SQLCipher. This RFD unifies them — adapter mode imports into SQLCipher instead of JSON, syncs to cloud from SQLCipher, and continues bridging to claude-mem's databases as it does today.

## Problem

The daemon already prefers SQLCipher and falls back to JSON only when `initSQLCipherBackend()` returns nil (keyring errors, DB open failure, etc.). However, the CLI sync commands (`sinesync sync push/pull`) bypass this entirely and hardcode `storage.NewLocalStorage()` (JSON files). This means:

1. **CLI sync always uses JSON** — even when the daemon is running on SQLCipher, the CLI reads/writes JSON files in `~/.sinesync/data/observation/`.
2. **No encryption at rest for CLI path** — JSON files are plaintext on disk. We took the CGO hit for SQLCipher; we should use it everywhere.
3. **Two storage paths to maintain** — the daemon uses SQLCipher but the CLI uses JSON. Both must be supported, tested, and kept in sync.
4. **Blocks visual layer** — a CLI dashboard, browser extension, or 1Password-like memory manager needs a queryable local store. JSON files don't support this.

## What Changes

**One thing:** the storage backend in adapter mode switches from JSON files to SQLCipher.

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

The daemon path is already correct. The change is making the CLI sync commands use the same SQLCipher backend instead of hardcoding JSON.

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

### 5. Remove LocalStorage from sync path

**File:** `internal/cli/sync.go`

The CLI `sync` commands (`push`, `pull`, `status`) currently create a `storage.NewLocalStorage()` directly. These need to use the same SQLCipher backend resolution as the daemon.

```go
// Before
localStorage := storage.NewLocalStorage()

// After
backend := resolveStorageBackend() // SQLCipher if key available, else LocalStorage
```

Extract the backend resolution logic from the daemon into a shared helper (e.g., `storage.ResolveBackend()`) so both daemon and CLI use the same storage.

## What This Enables

With a single queryable SQLCipher database in both modes:

1. **CLI dashboard** — `sinesync dashboard` can query `memory.db` directly for stats, recent activity, project breakdown. No need to load all JSON files into memory.

2. **Browser extension** — a 1Password-like memory manager that connects to the daemon's HTTP API. Search, tag, star, archive, delete memories. The daemon already has the endpoints; they just need a queryable backend.

3. **Reports** — session summaries, project activity, memory growth over time. SQL queries against a single DB instead of filesystem walks.

4. **Unified search in adapter mode** — today, adapter mode has no local search (claude-mem handles it). With SQLCipher + FTS5 + sqlite-vec, adapter mode could optionally offer sinesync's search tools alongside claude-mem's. Not proposed here, but enabled by this change.

## Files to Modify

| File | Change |
|------|--------|
| `internal/daemon/server.go` | Confirm SQLCipher-first init applies to both modes (minimal change) |
| `internal/cli/sync.go` | Use shared backend resolution instead of `NewLocalStorage()` |
| `internal/storage/resolve.go` | **New** — shared `ResolveBackend()` helper for daemon and CLI |

## Migration

- Existing adapter mode users with JSON files: auto-migrated on first startup (existing logic)
- Existing standalone users: no change (already on SQLCipher)
- Cloud sync state: preserved — migrated observations maintain checksums, no re-upload

## Verification

1. `go build ./...` succeeds
2. Adapter mode daemon starts → creates/opens `memory.db`
3. Claude-mem import → observations in SQLCipher, not JSON
4. Cloud sync push/pull reads from SQLCipher
5. Backfill export to claude-mem still works from SQLCipher
6. CLI `sinesync sync` uses SQLCipher backend
7. Legacy JSON observations auto-migrate on upgrade
8. No JSON files created in `~/.sinesync/data/observation/` after upgrade
