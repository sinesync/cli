# sine~sync

End-to-end encrypted cross-device sync for AI conversations, memories, and files.

## Overview

sine~sync provides secure cloud synchronization with zero-knowledge encryption. Your data is encrypted on-device before syncing - we never see your content.

## Components

| Directory | Description |
|-----------|-------------|
| `cli/` | Command-line tool and MCP server |
| `backend/` | GCP Cloud Run API |
| `web/` | sinesync.ai website |
| `shared/` | Common types and crypto utilities |
| `infra/` | Infrastructure as code (Terraform) |

## Quick Start

```bash
# Install CLI
npm install -g @sine/sync

# Create account and set up encryption
sinesync signup
sinesync init

# Add to Claude Code
claude mcp add sinesync -- sinesync mcp start
```

## Security Model

- **Master Password**: You memorize this, required for new devices
- **Secret Key**: Generated at setup (A3-XXXXX-...), save securely
- **Encryption**: Argon2id key derivation + AES-256-GCM
- **Zero-Knowledge**: We cannot decrypt your data

## Development

```bash
# Install dependencies
npm install

# Run CLI locally
cd cli && npm run dev

# Run backend locally
cd backend && npm run dev

# Run web locally
cd web && npm run dev
```

## License

MIT
