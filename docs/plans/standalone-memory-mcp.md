# RFD: Standalone Memory MCP

**Status:** Draft
**Authors:** miclip
**Branch:** `rfd/standalone-memory-mcp`

## Goal

Upgrade sinesync's standalone mode into a secure, zero-knowledge alternative to claude-mem. Local observations stored in an encrypted SQLite database (SQLCipher) with built-in vector search (sqlite-vec), exposed to Claude Code via MCP tools and hooks, synced to the cloud using the existing sinesync sync protocol.

## Principles

1. **Zero-knowledge** — all data encrypted at rest locally (SQLCipher) and in transit/cloud (AES-256-GCM)
2. **Interop** — observations sync bidirectionally between standalone users and claude-mem users via shared vaults
3. **Same schema** — uses the existing `storage.Observation` canonical JSON format for storage and sync
4. **claude-mem parity** — same 3-layer MCP workflow (search → timeline → get_observations)
5. **Adapter mode preserved** — claude-mem adapter still works. `sinesync setup` auto-detects claude-mem and wires adapter mode

## Architecture Overview

```
Claude Code Hooks (settings.json)
    ├── SessionStart  ──→ GET  /api/context     ──→ inject recent context
    ├── UserPromptSubmit → POST /api/prompt     ──→ record user prompt
    ├── PostToolUse   ──→ POST /api/capture     ──→ extract + store observation
    └── Stop          ──→ POST /api/summarize   ──→ session summary

Daemon (Go, HTTP on 127.0.0.1:PORT)
    ├── SQLCipher DB (encrypted at rest)
    │   ├── observations table + FTS5 virtual table
    │   ├── observations_vec (sqlite-vec, vector search)
    │   ├── sessions table
    │   ├── user_prompts table
    │   └── session_summaries table
    ├── ONNX embeddings (all-MiniLM-L6-v2, 384d)
    └── SyncManager → encrypt → GCS (existing protocol)

MCP Server (stdio JSON-RPC)
    ├── Standalone: search, timeline, get_observations + sync tools
    └── Adapter:    sync tools only (claude-mem handles memory)
```

## Key Management

Reuse the existing sinesync derived key for SQLCipher. Same key used for cloud sync encryption.

```
password + secretKey → Argon2id → derivedKey (32 bytes)
                                    ├── SQLCipher DB encryption (local)
                                    ├── AES-256-GCM blob encryption (cloud)
                                    └── Vault key wrapping
```

- Key already lives in OS keychain via `keychain.SetDerivedKey()`
- **Unauthenticated users** (pre-login): generate random 32-byte local key, store in keychain as `"local-db-key"`. On login, `PRAGMA rekey` to switch to the real derived key.

### SQLCipher key format

The raw 32-byte derived key is passed directly to SQLCipher, bypassing its internal PBKDF2 derivation:

```sql
PRAGMA key = "x'<hex-encoded-32-bytes>'";
PRAGMA cipher_plaintext_header_size = 0;
```

The `x'...'` hex prefix tells SQLCipher to use the raw key directly. This avoids double-derivation (Argon2id + PBKDF2) and ensures the SQLCipher key matches the cloud encryption key. Same format used for `PRAGMA rekey` during the unauthenticated → authenticated transition.

## CGO Transition

Both SQLCipher and sqlite-vec require CGO. This is the biggest build system change in this RFD — switching from pure-Go `modernc.org/sqlite` to CGO-based drivers.

### What changes

| Library | Purpose | Package |
|---------|---------|---------|
| SQLCipher | Encrypted SQLite | `github.com/miclip/go-sqlcipher/v4` ([fork](https://github.com/miclip/go-sqlcipher) of mutecomm/go-sqlcipher with SQLCipher v4.13.0 / SQLite 3.51.2) |
| sqlite-vec | Vector search | `github.com/asg017/sqlite-vec-go-bindings/cgo` |

- `CGO_ENABLED=1` required for all builds
- Driver registration changes from `"sqlite"` (`modernc.org/sqlite`) to `"sqlite3"` (`go-sqlcipher/v4`)
- All `sql.Open("sqlite", ...)` calls become `sql.Open("sqlite3", ...)` — a thin `openSQLite(dbPath)` helper can ease the transition
- `go-sqlcipher/v4` handles both encrypted and unencrypted databases — skip `PRAGMA key` for unencrypted access (e.g. claude-mem adapter reading claude-mem's DB)
- CI/CD and goreleaser configs need updates for cross-compilation
- **Note:** existing `.github/workflows/release.yml` sets `CGO_ENABLED=0` — must be updated

### Build impact

- **SQLCipher driver**: `go-sqlcipher/v4` bundles SQLCipher source and compiles it statically via CGO — no system `libsqlcipher` required for release builds
- **macOS (dev)**: CGO works out of the box with Xcode command line tools. Homebrew `sqlcipher` available for quick dynamic-link dev setup.
- **Linux (CI/prod)**: Prefer static SQLCipher builds. Multi-stage Docker: Stage 1 builds SQLCipher from source + Go binary with `CGO_ENABLED=1`; Stage 2 copies binary into minimal runtime image.
- **Windows**: Needs mingw-w64 or MSYS2. Prefer static SQLCipher to avoid distributing extra DLLs.
- **goreleaser**: Must set `CGO_ENABLED=1` and configure cross-compile toolchains per target OS/arch. Static SQLCipher preferred for all cross-compiled targets. Build tags and CGO LDFLAGS/CFLAGS to be finalized during Phase 1.

### sqlite-vec + SQLCipher compatibility — Verified

**Status: Confirmed working.** All three components (SQLCipher, sqlite-vec, FTS5) operate together in a single encrypted database.

The upstream `mutecomm/go-sqlcipher/v4` bundles SQLite 3.33.0, which lacks the `sqlite3_vtab_in` APIs (added in SQLite 3.38.0) required by sqlite-vec. Our [fork](https://github.com/miclip/go-sqlcipher) updates the amalgamation to SQLCipher v4.13.0 (SQLite 3.51.2), resolving this. Key fork changes:

- SQLCipher v4.13.0 amalgamation (sqlite3.c/sqlite3.h/sqlite3ext.h)
- Platform-native crypto: CommonCrypto on macOS, OpenSSL on Linux/Windows (libtomcrypt removed in SQLCipher v4.6+)
- FTS5 enabled, `SQLITE_EXTRA_INIT`/`SHUTDOWN` flags added
- All upstream go-sqlcipher tests pass

Test results with the fork:
```
SQLCipher version: 4.13.0 community
sqlite-vec version: v0.1.6
FTS5: PASS
Database is encrypted (no plaintext SQLite header)
```

No fallback or separate DB needed — everything lives in one encrypted file (`memory.db`).

### Questions for reviewers

- **Q1:** Are we comfortable taking on CGO for all platforms? The main tradeoff is build complexity + larger binaries in exchange for encrypted local storage and vector search.
- **Q2:** Should we support a pure-Go fallback for platforms where CGO is problematic? (e.g. `modernc.org/sqlite` without encryption, feature-flagged)
- **Q3:** Cross-compilation strategy — do we want goreleaser to handle all targets, or should we use platform-specific CI runners?

## SQLite Schema

**Database path:** `~/.sinesync/data/memory.db`

Connection setup: `PRAGMA foreign_keys = ON` on every connection open.

```sql
-- Observations (mirrors storage.Observation)
-- Note: id TEXT PRIMARY KEY still creates an implicit rowid (not WITHOUT ROWID),
-- which is used by FTS5 content_rowid and sqlite-vec rowid linkage.
CREATE TABLE observations (
    id TEXT PRIMARY KEY,                     -- UUID
    session_id TEXT,                          -- FK to sessions
    title TEXT NOT NULL,
    summary TEXT,
    content TEXT,                             -- narrative
    type TEXT NOT NULL,                       -- discovery|decision|bugfix|feature|refactor|change
    project TEXT,
    created_at TEXT NOT NULL,                 -- ISO 8601
    created_at_epoch INTEGER NOT NULL,        -- unix seconds
    updated_at TEXT NOT NULL,
    facts TEXT,                               -- JSON array
    concepts TEXT,                            -- JSON array
    files_read TEXT,                          -- JSON array
    files_modified TEXT,                      -- JSON array
    code_refs TEXT,                           -- JSON array (Structured.CodeRefs)
    tags TEXT,                                -- JSON array
    notes TEXT,                               -- Meta.Notes
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
    extensions TEXT,                          -- JSON (adapter-specific)
    prompt_number INTEGER,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE INDEX idx_observations_session_id ON observations(session_id);
CREATE INDEX idx_observations_project ON observations(project);
CREATE INDEX idx_observations_type ON observations(type);
CREATE INDEX idx_observations_created_at_epoch ON observations(created_at_epoch);
CREATE INDEX idx_observations_vault_id ON observations(vault_id);

-- FTS5 for full-text search
CREATE VIRTUAL TABLE observations_fts USING fts5(
    title, summary, content, facts, concepts,
    content='observations', content_rowid='rowid'
);
-- + INSERT/UPDATE/DELETE triggers to keep FTS in sync

-- sqlite-vec for vector similarity (384 dims)
CREATE VIRTUAL TABLE observations_vec USING vec0(
    embedding float[384]
);
-- Linked via rowid: observations.rowid = observations_vec.rowid
-- Rowids managed explicitly on insert to keep in sync

-- Sessions (for timeline queries)
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY,
    project TEXT,
    started_at_epoch INTEGER NOT NULL,
    ended_at TEXT,
    status TEXT DEFAULT 'active',
    observation_count INTEGER DEFAULT 0,
    summary TEXT
);

-- User prompts (for timeline context)
CREATE TABLE user_prompts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    prompt TEXT NOT NULL,
    prompt_number INTEGER,
    project TEXT,
    created_at_epoch INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

-- Session summaries
CREATE TABLE session_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    project TEXT,
    summary TEXT NOT NULL,
    observation_count INTEGER,
    files TEXT,                               -- JSON array
    created_at_epoch INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);
```

## MCP Tools (Standalone Mode)

Replace current `memory_store`/`memory_get` with claude-mem 3-layer workflow:

| Tool | Description | Daemon Endpoint |
|------|-------------|----------------|
| `search` | Search memory, returns compact index with IDs | `GET /api/mcp/search` |
| `timeline` | Get chronological context around an anchor observation | `GET /api/mcp/timeline` |
| `get_observations` | Fetch full details for specific IDs | `POST /api/mcp/observations` |

Plus existing sync tools (`sinesync_status`, `sinesync_search`, `sinesync_projects`) in both modes.

### Search Strategy (Hybrid)

1. **Vector search** via `observations_vec MATCH ?` — semantic similarity
2. **FTS5 search** via `observations_fts MATCH ?` — keyword matching
3. **Reciprocal rank fusion** to merge results: `score = 1/(k+rank_vec) + 1/(k+rank_fts)`
4. Filter by project, type, date range

## Hook Integration

Both layers: Claude Code native hooks → daemon HTTP API.

### Hook Events

| Hook | CLI Command | Daemon Endpoint | Action |
|------|------------|----------------|--------|
| `SessionStart` | `sinesync context` | `GET /api/context` | Inject recent observations as context |
| `UserPromptSubmit` | `sinesync prompt` | `POST /api/prompt` | Record user prompt + ensure session |
| `PostToolUse` | `sinesync capture` | `POST /api/capture` | Extract observation → embed → store in SQLCipher |
| `Stop` | `sinesync summarize` | `POST /api/summarize` | Generate session summary |

### Observation Extraction (Enhanced)

Current `extractObservation()` is basic. Enhance with:
- **Richer facts**: structured extraction from tool inputs/outputs
- **Concept extraction**: derive from file paths, extensions, directory names
- **More content**: store truncated tool output as narrative
- No LLM calls in hook path (latency constraint)

## Cloud Sync Interop

**No protocol changes.** The sync path changes only at the local storage layer:

```
Before: JSON files → serialize → gzip → AES-256-GCM → upload
After:  SQLCipher → read Observation → serialize → gzip → AES-256-GCM → upload
```

The cloud side still stores opaque per-observation encrypted blobs — not a database file. The `SyncManager` reads observations from the SQLCipher DB (plaintext in process memory, encrypted at rest on disk), serializes to canonical JSON, encrypts, and uploads. On pull, the reverse: download, decrypt, deserialize, INSERT into SQLCipher.

The `storage.Observation` canonical JSON schema is the interop format. Observations from claude-mem users (via shared vault) arrive as the same schema with `source.adapter = "claude-mem"`. Standalone observations arrive with `source.adapter = "sinesync"`. Both are stored and searchable.

## Migration (JSON → SQLCipher)

On daemon startup, detect `~/.sinesync/data/observation/` directory:
1. Read all JSON files via legacy `LocalStorage`
2. Insert into SQLCipher DB in single transaction, deduplicating by observation ID
3. Generate embeddings for any observations missing them
4. **Secure delete** legacy JSON files (best-effort overwrite + unlink) — default behavior to maintain encryption-at-rest guarantees
5. Optional `--keep-legacy-backup` flag renames old directory to `observation.migrated` instead, with a warning that it contains unencrypted data

## Files to Create/Modify

| File | Change |
|------|--------|
| `internal/storage/backend.go` | **New** — `StorageBackend` interface |
| `internal/storage/sqlcipher.go` | **New** — SQLCipher storage (CRUD, search, timeline) |
| `internal/storage/search.go` | **New** — Hybrid search (vector + FTS5 fusion) |
| `internal/daemon/server.go` | Switch to `StorageBackend` interface, add `/api/prompt`, `/api/mcp/*` endpoints, enhance `extractObservation` |
| `internal/daemon/sync.go` | Accept `StorageBackend` instead of `*LocalStorage` |
| `internal/mcp/server.go` | Replace `memory_store`/`memory_get` with search/timeline/get_observations |
| `internal/cli/setup.go` | Add `UserPromptSubmit` hook config for standalone mode |
| `internal/cli/hooks.go` | Add `runPrompt` command |
| `internal/adapters/claudemem.go` | Change import from `modernc.org/sqlite` to `go-sqlcipher/v4` (opens unencrypted claude-mem DB without `PRAGMA key`) |
| `go.mod` | Add `miclip/go-sqlcipher/v4` (with replace for `mutecomm/go-sqlcipher/v4`), `sqlite-vec-go-bindings/cgo`; remove `modernc.org/sqlite` |
| `.goreleaser.yaml` | Add `CGO_ENABLED=1`, cross-compile config |
| `.github/workflows/release.yml` | Change `CGO_ENABLED=0` to `CGO_ENABLED=1`, add build dependencies |

## Implementation Phases

### Phase 1: CGO Transition + SQLCipher Storage
- `StorageBackend` interface
- SQLCipher storage implementation (schema, CRUD, open/close)
- Key management (reuse derived key, local-only fallback)
- Swap daemon to use new storage

### Phase 2: FTS5 + sqlite-vec
- FTS5 triggers and full-text search
- sqlite-vec initialization and vector insert/query
- Hybrid search implementation (vector + FTS fusion)

### Phase 3: MCP 3-Layer Workflow
- New MCP tools: search, timeline, get_observations
- New daemon endpoints: `/api/mcp/search`, `/api/mcp/timeline`, `/api/mcp/observations`
- Response formatting (compact index, timeline, full details)

### Phase 4: Enhanced Hooks + Sessions
- `UserPromptSubmit` hook + `POST /api/prompt` endpoint
- Session tracking (create on SessionStart, complete on Stop)
- Enhanced `extractObservation` (richer facts, concepts, content)
- Session summary generation

### Phase 5: Migration + Polish
- JSON-to-SQLCipher migration on startup (with secure deletion of legacy files)
- Embedding backfill for migrated observations
- Build/CI updates for CGO

## Verification

1. `go build ./...` succeeds with `CGO_ENABLED=1`
2. Daemon starts, creates encrypted `memory.db` using derived key
3. PostToolUse hook captures observation → stored in SQLCipher → embedding generated
4. MCP `search` returns results from both vector and FTS
5. MCP `timeline` returns chronological context around anchor
6. MCP `get_observations` returns full details for IDs
7. Cloud sync pushes/pulls observations between SQLCipher and GCS
8. Shared vault: standalone user's observations readable by claude-mem user and vice versa
9. Migration: existing JSON observations imported on first startup
10. Adapter mode: claude-mem still works when detected, standalone tools hidden
11. Migration preserves sync state: migrated observations maintain cloud sync checksums and are not re-uploaded as duplicates
