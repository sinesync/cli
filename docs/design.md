# sine~sync Standalone Service Design

## Overview

sine~sync is a standalone cross-device sync service for AI conversations, memories, and files. Launched independently before native sine~ integration to:

1. Validate demand before deep app integration
2. Iterate on backend without app store review cycles
3. Avoid 15-30% app store fees (web subscriptions via Stripe)
4. Provide immediate value to Claude Code users via MCP
5. De-risk the sync feature development

## Branding & Domain

- **Product name**: sine~sync
- **Domain candidates**: sinesync.ai, sinesync.io, getsinesync.com
- **CLI package**: `@sine/sync` or `sinesync`
- **MCP server name**: `sinesync`

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              User Devices                                │
├─────────────────┬─────────────────┬─────────────────┬───────────────────┤
│   Claude Code   │   Claude Code   │    sine~ iOS    │  sine~ Android    │
│   + MCP Server  │   + MCP Server  │   (Phase 2)     │   (Phase 2)       │
│   (macOS)       │   (Windows)     │                 │                   │
└────────┬────────┴────────┬────────┴────────┬────────┴─────────┬─────────┘
         │                 │                 │                   │
         └─────────────────┴────────┬────────┴───────────────────┘
                                    │
                              HTTPS/TLS
                                    │
                    ┌───────────────┴───────────────┐
                    │         GCP Backend           │
                    ├───────────────────────────────┤
                    │  Cloud Run (API)              │
                    │  Cloud Storage (Encrypted)    │
                    │  Firestore (Metadata)         │
                    │  Firebase Auth                │
                    └───────────────────────────────┘
                                    │
                    ┌───────────────┴───────────────┐
                    │      sinesync.ai (Web)        │
                    ├───────────────────────────────┤
                    │  Account management           │
                    │  Subscription (Stripe)        │
                    │  Device management            │
                    │  Secret key recovery          │
                    └───────────────────────────────┘
```

## CLI Design

### Installation

```bash
# npm
npm install -g @sine/sync

# homebrew (macOS)
brew install sinesync

# winget (Windows)
winget install sinesync
```

### Commands

```bash
# Account setup
sinesync signup              # Create account via browser OAuth
sinesync login               # Login to existing account
sinesync logout              # Clear local credentials

# Sync configuration (after account exists)
sinesync init                # Set up encryption (master password + secret key)
sinesync status              # Show sync status, last sync time, device list

# Daily operations
sinesync unlock              # Authenticate for 24 hours
sinesync lock                # Clear cached credentials
sinesync sync                # Manual sync trigger

# MCP server (called by Claude Code)
sinesync mcp start           # Start MCP server (checks auth, syncs, serves tools)

# Device management
sinesync devices             # List authorized devices
sinesync devices revoke <id> # Revoke a device

# Recovery
sinesync show-secret-key     # Display secret key (requires password)
sinesync export              # Export all data (encrypted backup)
```

### Configuration Flow

```bash
$ sinesync signup
  → Opening browser for signup...
  → ✓ Account created: user@example.com

$ sinesync init
  → Create a master password (12+ characters recommended)
  → Password: ************
  → Confirm: ************

  → Your secret key (SAVE THIS SECURELY):
  ┌────────────────────────────────────────────┐
  │  A3-KXMW9-R4PDQ-7NHVT-2JLFC-8BGYS-WDZE6   │
  └────────────────────────────────────────────┘
  → This key is required to set up new devices.
  → Store it in a password manager or write it down.

  → Confirm by entering the first 5 characters: A3-KX
  → ✓ Encryption configured
  → ✓ Credentials stored in system keychain

$ claude mcp add sinesync -- sinesync mcp start
  → ✓ MCP server registered with Claude Code
```

### Daily Authentication Flow

```bash
$ claude
  # Claude Code spawns: sinesync mcp start

  # If >24 hours since last auth:
  → sine~sync: Daily authentication required
  → Enter master password: ************
  → ✓ Unlocked for 24 hours

  # MCP server starts normally
```

## MCP Server Tools

The MCP server exposes these tools to Claude Code:

### `sync_backup`
Create an encrypted backup of specified data.

```json
{
  "name": "sync_backup",
  "description": "Backup conversations or memories to sine~sync",
  "inputSchema": {
    "type": "object",
    "properties": {
      "type": {
        "type": "string",
        "enum": ["conversation", "memory", "file", "all"],
        "description": "What to backup"
      },
      "id": {
        "type": "string",
        "description": "Specific item ID (optional, backs up all if omitted)"
      }
    },
    "required": ["type"]
  }
}
```

### `sync_restore`
Restore data from sine~sync.

```json
{
  "name": "sync_restore",
  "description": "Restore conversations or memories from sine~sync",
  "inputSchema": {
    "type": "object",
    "properties": {
      "type": {
        "type": "string",
        "enum": ["conversation", "memory", "file", "all"]
      },
      "id": {
        "type": "string",
        "description": "Specific item ID (optional)"
      },
      "since": {
        "type": "string",
        "description": "ISO timestamp - only restore items modified after this"
      }
    },
    "required": ["type"]
  }
}
```

### `sync_status`
Check sync status and last sync time.

```json
{
  "name": "sync_status",
  "description": "Check sine~sync status",
  "inputSchema": {
    "type": "object",
    "properties": {}
  }
}
```

### `sync_list`
List available items to restore.

```json
{
  "name": "sync_list",
  "description": "List items available in sine~sync",
  "inputSchema": {
    "type": "object",
    "properties": {
      "type": {
        "type": "string",
        "enum": ["conversations", "memories", "files"]
      }
    },
    "required": ["type"]
  }
}
```

## GCP Backend Design

### Services

| Service | Purpose | Notes |
|---------|---------|-------|
| **Cloud Run** | API endpoints | Auto-scaling, pay-per-request |
| **Cloud Storage** | Encrypted blobs | Lifecycle policies for old versions |
| **Firestore** | Metadata | User records, device registry, sync state |
| **Firebase Auth** | Authentication | OAuth (Google, Apple, email) |
| **Cloud KMS** | Server-side keys | For metadata encryption (not user data) |

### API Endpoints

```
POST   /api/v1/auth/signup          # Create account
POST   /api/v1/auth/login           # Get session token
POST   /api/v1/auth/refresh         # Refresh session token

GET    /api/v1/sync/status          # Get sync status for device
POST   /api/v1/sync/push            # Upload encrypted blob
GET    /api/v1/sync/pull/:id        # Download encrypted blob
GET    /api/v1/sync/manifest        # Get list of all items with timestamps
DELETE /api/v1/sync/item/:id        # Delete item

GET    /api/v1/devices              # List devices
POST   /api/v1/devices              # Register device
DELETE /api/v1/devices/:id          # Revoke device

POST   /api/v1/subscription/create  # Create Stripe checkout session
POST   /api/v1/subscription/webhook # Stripe webhook
GET    /api/v1/subscription/status  # Get subscription status
```

### Data Model (Firestore)

```
users/{userId}
  - email: string
  - createdAt: timestamp
  - subscriptionStatus: 'trial' | 'active' | 'cancelled' | 'expired'
  - subscriptionId: string (Stripe)
  - storageUsedBytes: number

users/{userId}/devices/{deviceId}
  - name: string
  - platform: 'macos' | 'windows' | 'linux' | 'ios' | 'android'
  - lastSeen: timestamp
  - createdAt: timestamp

users/{userId}/items/{itemId}
  - type: 'conversation' | 'memory' | 'file'
  - createdAt: timestamp
  - updatedAt: timestamp
  - sizeBytes: number
  - blobPath: string (GCS path)
  - checksum: string (for conflict detection)
```

### Storage Structure (Cloud Storage)

```
gs://sinesync-data/
  users/{userId}/
    items/{itemId}/
      data.enc          # Encrypted blob (AES-256-GCM)
      metadata.json     # Encrypted metadata
```

### Zero-Knowledge Design

The server stores:
- User account info (email, subscription)
- Device registry
- Encrypted blobs (cannot decrypt)
- Item metadata: type, timestamps, size (NOT content)

The server NEVER receives:
- Master password
- Secret key
- Derived encryption key
- Unencrypted content

## Security Model

### Key Derivation

```
user_salt = random(32 bytes)  // Generated at setup, stored on server
combined_salt = secret_key || user_salt

encryption_key = Argon2id(
  password: master_password,
  salt: combined_salt,
  memory: 64 MB,
  iterations: 3,
  parallelism: 4,
  hash_length: 32  // 256 bits
)
```

### Encryption

All data encrypted client-side before upload:

```
nonce = random(12 bytes)
ciphertext = AES-256-GCM(
  key: encryption_key,
  nonce: nonce,
  plaintext: JSON.stringify(data),
  aad: item_id  // Additional authenticated data
)
blob = nonce || ciphertext || auth_tag
```

### Local Credential Storage

| Platform | Storage | API |
|----------|---------|-----|
| macOS | Keychain | `keytar` / Security.framework |
| Windows | Credential Manager | `keytar` / DPAPI |
| Linux | Secret Service | `keytar` / libsecret |

Stored in keychain:
- `sinesync:derived-key` - Encrypted derived key (encrypted with session key)
- `sinesync:user-salt` - User salt (needed for re-derivation)
- `sinesync:last-auth` - Timestamp of last password entry
- `sinesync:session-token` - API session token

### Authentication Flow

```
1. User enters master password
2. CLI retrieves user_salt from keychain (or server if new device)
3. Derive encryption_key using Argon2id
4. Decrypt test blob to verify correct password
5. Cache derived_key in keychain (encrypted)
6. Store last_auth timestamp
7. Clear master_password from memory
```

### Daily Re-authentication

```
1. MCP server starts
2. Check last_auth timestamp from keychain
3. If > 24 hours:
   a. Prompt for master password
   b. Re-derive key, verify against test blob
   c. Update last_auth timestamp
4. If <= 24 hours:
   a. Use cached derived_key
5. Start serving MCP tools
```

## Web App (sinesync.ai)

### Pages

- `/` - Landing page, features, pricing
- `/signup` - Account creation
- `/login` - Login
- `/dashboard` - Account overview, usage stats
- `/devices` - Device management
- `/subscription` - Plan management, billing
- `/security` - Show secret key, change password
- `/docs` - Setup guide, FAQ

### Subscription Tiers

| Tier | Price | Storage | Devices | Notes |
|------|-------|---------|---------|-------|
| **Free Trial** | $0 | 100 MB | 2 | 14 days |
| **Personal** | $3/mo | 1 GB | 5 | Core features |
| **Pro** | $8/mo | 10 GB | Unlimited | Priority support |

### Stripe Integration

- Checkout Sessions for signup
- Customer Portal for management
- Webhooks for subscription events
- Usage-based billing consideration for storage overages

## Data Types & Sync Format

### Conversation

```json
{
  "type": "conversation",
  "id": "uuid",
  "title": "string",
  "createdAt": "ISO8601",
  "updatedAt": "ISO8601",
  "messages": [
    {
      "id": "uuid",
      "role": "user | assistant",
      "content": "string",
      "timestamp": "ISO8601",
      "modelId": "string",
      "attachments": []
    }
  ],
  "threadSummary": []
}
```

### Memory

```json
{
  "type": "memory",
  "id": "uuid",
  "content": "string",
  "category": "string",
  "importance": "number",
  "createdAt": "ISO8601",
  "lastAccessed": "ISO8601",
  "sourceConversationId": "string"
}
```

### File

```json
{
  "type": "file",
  "id": "uuid",
  "filename": "string",
  "mimeType": "string",
  "sizeBytes": "number",
  "data": "base64",  // or separate blob reference for large files
  "createdAt": "ISO8601"
}
```

## Conflict Resolution

Simple last-write-wins with conflict detection:

1. Each item has `updatedAt` timestamp and `checksum`
2. On push: if server `checksum` differs and `updatedAt` is newer, reject
3. Client can force-push or pull-then-merge
4. Conversations: merge messages by ID (append-only)
5. Memories: last-write-wins (user can restore from history)
6. Files: last-write-wins

## Future sine~ Integration Path

Phase 2 adds native sync to sine~ iOS/Android:

1. **Shared encryption code**: Port Argon2id + AES-GCM to Kotlin Multiplatform
2. **Same API**: sine~ app uses identical `/api/v1/sync/*` endpoints
3. **RevenueCat**: Add in-app purchase option (in addition to web)
4. **Biometric unlock**: Use existing BiometricGate, store derived key in Keystore/Keychain
5. **Background sync**: Periodic sync when app is open
6. **Selective sync**: Choose what to sync (conversations, memories, files)

The standalone MCP approach validates the backend and encryption before committing to native integration.

## Implementation Phases

### Phase 1: Core CLI + Backend (4-6 weeks)
- [ ] GCP project setup (Cloud Run, Storage, Firestore)
- [ ] Firebase Auth integration
- [ ] Core API endpoints (auth, push, pull, manifest)
- [ ] CLI: signup, login, init, unlock, lock
- [ ] CLI: MCP server with basic sync tools
- [ ] Encryption/decryption with Argon2id + AES-GCM
- [ ] Cross-platform keychain integration

### Phase 2: Web + Subscriptions (2-3 weeks)
- [ ] Landing page (sinesync.ai)
- [ ] Dashboard UI
- [ ] Stripe integration
- [ ] Device management UI
- [ ] Documentation

### Phase 3: Polish + Launch (2 weeks)
- [ ] Beta testing with select users
- [ ] Error handling and edge cases
- [ ] Rate limiting and abuse prevention
- [ ] Monitoring and alerting
- [ ] Public launch

### Phase 4: sine~ Native Integration (TBD)
- [ ] Port encryption to Kotlin Multiplatform
- [ ] Add sync UI to sine~ settings
- [ ] RevenueCat integration
- [ ] Background sync
- [ ] Migration path from MCP to native

## Open Questions

1. **Domain**: sinesync.ai available? Alternatives?
2. **Pricing**: $3/$8 appropriate? Need market research
3. **Free tier**: Permanent free tier or trial only?
4. **Data retention**: How long to keep deleted items?
5. **GDPR/Privacy**: Data processing agreement needed?
6. **Support**: Email only or chat?
