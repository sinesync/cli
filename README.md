# sine~sync

End-to-end encrypted cross-device sync for AI memories.

## Overview

sine~sync provides secure cloud synchronization with zero-knowledge encryption. Your data is encrypted on-device before syncing - we never see your content.

## Components

| Directory | Description |
|-----------|-------------|
| `cmd/` | CLI entrypoint |
| `internal/` | CLI, daemon, and MCP server |
| `tools/` | Release signing utilities |
| `docs/` | Design notes and plans |

The hosted sync service and the sinesync.ai site live in separate repositories;
this repository is the client.

## Quick Start

### Build from source

```bash
# Build CLI
go build -o sinesync ./cmd/sinesync

# Or install to $GOPATH/bin
go install ./cmd/sinesync
```

### Setup

```bash
# Create account
sinesync signup

# Configure with Claude Code (auto-detects claude-mem)
sinesync setup

# Check status
sinesync status
```

### Claude Code Integration

The setup command automatically configures:
- MCP server for memory tools
- Session hooks for context injection and observation capture
- Background daemon for cloud sync and claude-mem integration

Or manually add to Claude Code:
```bash
claude mcp add sinesync -- sinesync mcp start
```

## Features

- **Cloud sync**: Push/pull memories across devices
- **Vault support**: Organize memories by project, share with teams
- **claude-mem integration**: Works alongside claude-mem for memory capture
- **Local embeddings**: Semantic search with ONNX model
- **Background daemon**: Auto-sync with `sinesync daemon start`

## Security Model

- **Master Password**: Required for new devices
- **Secret Key**: Generated at signup, save securely (Emergency Kit)
- **Encryption**: Argon2id key derivation + AES-256-GCM
- **Zero-Knowledge**: We cannot decrypt your data

## Development

```bash
# CLI (Go)
go build -o sinesync ./cmd/sinesync
./sinesync --help

# Backend (TypeScript)
cd backend && npm install && npm run dev

# Web
cd web && npm install && npm run dev
```

## CLI Commands

```
sinesync setup          # Configure with Claude Code
sinesync status         # Show sync status
sinesync doctor         # Run diagnostic health checks
sinesync doctor --fix   # Auto-fix issues
sinesync login          # Authenticate
sinesync sync           # Push and pull observations
sinesync import         # Import from claude-mem
sinesync export         # Export to claude-mem
sinesync vault list     # List vaults
sinesync vault create   # Create a new vault
sinesync daemon start   # Start background sync
sinesync mcp start      # Start MCP server
```

## License

MIT
