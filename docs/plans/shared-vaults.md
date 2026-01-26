# Vaults Plan

## Overview

**Core principle: Everything is a vault.**

Every user's data lives in vaults from day one. A vault is simply an encrypted container with one or more members. "Personal" storage is just a vault with one member. This architecture means:

- Sharing later = add member to existing vault (no re-encryption needed)
- Consistent encryption model throughout
- Users can organize projects across multiple vaults
- Corporate/team tiers are the same model, just different provisioning

Shared vaults enable teams to sync AI memories (context, decisions, bugs, learnings) for collaborative projects. Data remains end-to-end encrypted using a vault key that's securely shared via a two-channel invitation system.

## Pricing Tiers (Internal - Not Public)

> **Note:** This is internal pricing strategy. Website shows "Contact us" for team/enterprise.

| Tier | Vaults | Sharing | Members | SAML |
|------|--------|---------|---------|------|
| Free | 2 | No | 1 | No |
| Pro | Unlimited | No | 1 | No |
| Team S | Unlimited | Yes | Up to 5 | No |
| Team M | Unlimited | Yes | Up to 20 | No |
| Team L | Unlimited | Yes | Up to 100 | No |
| Corp S | Unlimited | Yes | Up to 1,000 | Yes |
| Corp L | Unlimited | Yes | Up to 10,000 | Yes |

- Vaults are cheap (just a GUID + metadata)
- Value is in sharing/collaboration features
- SAML is enterprise-only (common B2B SaaS pattern)
- Corporate tier required for IdP integration

## Security Model

### Key Hierarchy

```
User's Derived Key (password + secret key + salt → Argon2id)
    ├── encrypts → User's Private Key (X25519)
    └── encrypts → Vault Keys (one per vault user has access to)

Vault Key (random 256-bit, per vault)
    └── encrypts → All observations in that vault
```

### Two-Channel Invitation

To prevent single-point-of-failure attacks, vault access requires codes from two separate channels:

1. **Email Code** - Sent to invitee's email (proves recipient identity)
2. **Invite Code** - Given by inviter via different channel (proves inviter trust)

```
Private Key encrypted with: Argon2id(emailCode || inviteCode, salt)
```

**UI Guidance:** The dashboard/CLI must encourage inviter to share the invite code via a DIFFERENT transport (text, Slack, in-person) - NOT email. This ensures:
- Email compromise alone cannot grant vault access
- Inviter has direct verification moment with invitee
- Attack requires compromising two separate channels

## Data Model

### Firestore Collections

```typescript
// vaults collection
interface Vault {
  id: string;
  name: string;
  ownerId: string;               // creator's userId
  isDefault: boolean;            // true for user's initial vault
  createdAt: string;
  updatedAt: string;
}

// vaultProjects collection - which projects belong to which vault
interface VaultProject {
  id: string;
  vaultId: string;
  projectName: string;           // e.g., "rapidink", "sinesync"
  createdAt: string;
}

// vaultMembers collection
interface VaultMember {
  id: string;                    // odcid
  vaultId: string;
  userId: string;
  encryptedVaultKey: string;     // vault key encrypted with user's derived key
  role: 'owner' | 'editor';      // 'viewer' deferred
  joinedAt: string;
}

// vaultInvites collection
interface VaultInvite {
  id: string;
  vaultId: string;
  inviterUserId: string;
  inviteeEmail: string;
  encryptedPrivateKey: string;   // encrypted with hash(emailCode + inviteCode)
  publicKey: string;             // generated for invitee
  encryptedVaultKey: string;     // vault key encrypted with generated public key
  emailCode: string;             // hashed, sent via email
  inviteCodeHash: string;        // hashed, given to inviter to share
  salt: string;                  // for key derivation
  status: 'pending' | 'accepted' | 'expired';
  expiresAt: string;             // 7 days
  createdAt: string;
}

// users collection (additions)
interface User {
  // ... existing fields
  publicKey: string;             // X25519 public key
  encryptedPrivateKey: string;   // encrypted with derived key
  privateKeySalt: string;        // salt for private key encryption
}

// Local storage (CLI)
interface VaultMapping {
  vaultId: string;
  localProjectPath: string;      // e.g., "/workspace/rapidink"
  vaultProjectName: string;      // e.g., "rapidink"
}
```

## Invitation Flow

### Creating an Invite (Inviter)

```
1. Inviter: "Invite friend@example.com to vault 'rapidink'"

2. Server generates:
   - X25519 key pair for invitee
   - emailCode (32 bytes, base32 encoded)
   - inviteCode (32 bytes, base32 encoded) → returned to inviter only
   - salt (16 bytes)

3. Server encrypts invitee's private key:
   derivedKey = Argon2id(emailCode || inviteCode, salt)
   encryptedPrivateKey = AES-GCM(privateKey, derivedKey)

4. Inviter's client encrypts vault key with generated public key:
   encryptedVaultKey = X25519-seal(vaultKey, inviteePublicKey)

5. Server stores VaultInvite record

6. Server sends email to invitee with:
   - Invitation link
   - emailCode (displayed prominently)
   - Instructions to get inviteCode from inviter

7. Dashboard/CLI shows inviter:
   - inviteCode
   - Warning: "Share this code with friend@example.com via text, Slack,
     or in-person. DO NOT email it - that defeats the security!"
```

### Accepting an Invite (Invitee)

```
1. Invitee clicks invite link, creates account (or logs in)

2. Invitee enters:
   - emailCode (from email)
   - inviteCode (from inviter via text/Slack/etc)

3. Server validates codes match invite

4. Client derives key and decrypts private key:
   derivedKey = Argon2id(emailCode || inviteCode, salt)
   privateKey = AES-GCM-decrypt(encryptedPrivateKey, derivedKey)

5. Client decrypts vault key using private key:
   vaultKey = X25519-open(encryptedVaultKey, privateKey)

6. Client re-encrypts both for permanent storage:
   - Private key → encrypted with user's derived key
   - Vault key → encrypted with user's derived key

7. Server updates:
   - User record with publicKey, encryptedPrivateKey
   - VaultMember record created
   - VaultInvite marked as accepted

8. Invitee maps vault project to local path:
   "Map 'rapidink' to local project: /workspace/rapidink"
```

### Inviting Existing Users

If invitee already has an account (has public key):

```
1. Server returns invitee's public key to inviter
2. Inviter's client encrypts vault key directly with public key
3. No codes needed - just notification email
4. Invitee accepts, decrypts vault key with their private key
```

## API Endpoints

### Vault Management

```
POST   /v1/vaults                    Create vault
GET    /v1/vaults                    List user's vaults
GET    /v1/vaults/:id                Get vault details
DELETE /v1/vaults/:id                Delete vault (owner only)
```

### Invitations

```
POST   /v1/vaults/:id/invites        Create invitation
       Request:  { email: string }
       Response: { inviteId, inviteCode, publicKey } (inviteCode only to inviter)

GET    /v1/invites/:id               Get invite details (for accept flow)
       Response: { vaultName, inviterEmail, encryptedPrivateKey,
                   encryptedVaultKey, salt, publicKey }

POST   /v1/invites/:id/accept        Accept invitation
       Request:  { emailCode, inviteCode, encryptedPrivateKey,
                   encryptedVaultKey, publicKey }

GET    /v1/vaults/:id/members        List vault members
DELETE /v1/vaults/:id/members/:uid   Remove member (owner only)
```

### User Keys

```
GET    /v1/users/by-email/:email/public-key   Lookup public key for invite
POST   /v1/users/me/keys                       Store key pair after first invite
```

### Vault Sync

```
GET    /v1/vaults/:id/sync/manifest           Vault-specific manifest
POST   /v1/vaults/:id/sync/upload-urls        Get upload URLs for vault
POST   /v1/vaults/:id/sync/confirm-uploads    Confirm vault uploads
GET    /v1/vaults/:id/sync/download-url/:itemId  Download from vault
DELETE /v1/vaults/:id/sync/item/:itemId       Delete from vault
```

## CLI Commands

```bash
# Vault management
sinesync vault create <name> --project <project-name>
sinesync vault list
sinesync vault delete <vault-id>

# Invitations
sinesync vault invite <vault-id> <email>
# Outputs: "Share this invite code with them: XXXX-XXXX-XXXX-XXXX"

sinesync vault accept
# Interactive: prompts for invite link, email code, invite code

# Mapping
sinesync vault map <vault-id> <local-project-path>
sinesync vault unmap <vault-id>

# Status
sinesync vault status
# Shows: vault name, members, sync status, local mapping
```

## Sync Logic Changes

### Project → Vault Resolution

```go
func (m *SyncManager) getVaultForProject(project string) (*Vault, error) {
    // Check local vault mappings
    mapping := m.getVaultMapping(project)
    if mapping != nil {
        return m.getVault(mapping.VaultId)
    }
    // Default to personal vault (nil)
    return nil, nil
}
```

### Modified Sync Flow

```go
func (m *SyncManager) sync(token string) error {
    // Group observations by vault
    personalObs, vaultObs := m.groupByVault(observations)

    // Sync personal vault (existing flow)
    m.syncPersonal(token, personalObs)

    // Sync each shared vault
    for vaultId, obs := range vaultObs {
        vaultKey := m.getVaultKey(vaultId)
        m.syncVault(token, vaultId, vaultKey, obs)
    }
}
```

### Encryption per Vault

```go
func (m *SyncManager) encryptForVault(obs *Observation, vaultId string) ([]byte, error) {
    var key []byte
    if vaultId == "" {
        // Personal vault - use user's derived key
        key = m.encMgr.GetKey()
    } else {
        // Shared vault - use vault key
        key = m.getDecryptedVaultKey(vaultId)
    }
    return crypto.Encrypt(obs, key)
}
```

## Referral Tracking

The invitation system naturally supports referral tracking:

```typescript
interface VaultInvite {
  // ... existing fields
  inviterUserId: string;  // Track who invited whom
}

// Analytics/billing can query:
// - How many users did X invite?
// - Successful conversions (accepted invites)
// - Referral chains
```

**Potential promotions:**
- "Invite 3 friends → 1 month free"
- "Team discount: 20% off when 3+ members"
- "Founder's referral: both get 1 month free"

## Signup Flow Changes

### New User Signup

```
1. User signs up (existing 2SKD flow)
2. Generate X25519 key pair, encrypt with derived key
3. Create default vault "Personal"
4. Generate vault key, encrypt with user's derived key
5. User is sole member of default vault
6. All observations go to default vault unless assigned elsewhere
```

### Observation Storage

Observations now belong to vaults, not users directly:

```typescript
// GCS path changes from:
//   users/{userId}/observations/{obsId}.enc
// to:
//   vaults/{vaultId}/observations/{obsId}.enc

// Manifest changes from user-level to vault-level:
//   vaults/{vaultId}/manifest.json.gz
```

### Project Assignment

- User assigns projects to vaults (CLI or dashboard)
- Unassigned projects go to default vault
- One project → one vault (no overlap)
- Moving project to different vault = re-encrypt + re-upload

## Migration Path

### For Existing Users

1. On next login, generate X25519 key pair
2. Encrypt private key with existing derived key
3. Store in keychain + server backup
4. No disruption to existing personal vault sync

### For New Features

1. Phase 1: Key pair generation at signup
2. Phase 2: Vault creation and invitation
3. Phase 3: Vault sync with project mapping
4. Phase 4: Dashboard UI for vault management

## Security Considerations

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Server compromise | Vault keys encrypted with user keys; server never sees plaintext |
| Email compromise only | Invite code required from separate channel |
| Invite code intercepted only | Email code + email access required |
| Both channels compromised | Attacker wins (acceptable risk for invite flow) |
| Malicious inviter | User must explicitly accept and map vault |
| Key loss | Users must save secret key (existing 2SKD model) |

### Invite Code Best Practices (UI Copy)

```
Your invite code: XXXX-XXXX-XXXX-XXXX

Share this with friend@example.com using a DIFFERENT method than email:
  ✓ Text message
  ✓ Slack/Discord DM
  ✓ In person
  ✗ Do NOT email it (defeats two-channel security)

They'll need both this code AND the code in their invite email.
```

## Open Questions

1. **Vault deletion** - What happens to observations? Archive? Transfer to personal?
2. **Member removal** - Re-encrypt vault with new key? Or just revoke access?
3. **Offline invites** - How long before invite expires? (proposed: 7 days)
4. **Key rotation** - When/how to rotate vault keys?

## Implementation Order

1. Key pair generation at signup/login
2. Backend: Vault CRUD, invite endpoints
3. CLI: vault commands
4. Daemon: multi-vault sync logic
5. Dashboard: vault management UI
6. Referral tracking and promotions
