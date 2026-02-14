# Enterprise SAML Authentication & Organization Access Control

**Status**: IN PROGRESS (Phase 1 complete)
**Date**: 2026-02-14

---

## Overview

Individual users authenticate via SRP-6a (zero-knowledge). The CLI uses Bearer tokens, web uses httpOnly cookies. Vaults have members with roles (owner, editor). All observation data is E2E encrypted.

Enterprise customers need to authenticate developers via their own IdP (Okta, Azure AD) using SAML. This introduces organizations, group-based vault access, a viewer role, and per-seat billing. **All changes are additive** — existing SRP auth, individual subscriptions, and vault mechanics continue unchanged.

The enterprise dashboard is a self-hosted sinesync daemon in the customer's infra with an export adapter to their own database. It decrypts locally, preserving zero-knowledge. That's out of scope here — this plan focuses on the auth and access control foundation.

---

## 1. Data Model

### 1.1 New Firestore Collections

**`organizations`**
```
id, name, slug (unique), domains[], createdAt, updatedAt
settings: { defaultGroupId?, requireSaml, autoProvision, sessionDurationHours,
            ownerMode: 'individual'|'group', ownerGroupName?: string }
billing:  { stripeCustomerId, stripeSubscriptionId, seatCount, seatsFilled, plan, billingInterval }
saml:     { enabled, entityId, ssoUrl, certificate, signedRequests, nameIdFormat,
            spPrivateKeyRef?, spCertificate?, attributeMapping: { email, firstName?, lastName?, groups? } }
```

**`orgSlugs`** — slug reservation (doc ID = slug, same pattern as `userEmails`)

**`orgMembers`** — doc ID: `${orgId}_${userId}`
```
organizationId, userId, role: 'owner'|'admin'|'member', seatAssigned, joinedAt, samlNameId?, lastSamlLogin?
```

Note: The `owner` role can be assigned to individuals (small orgs) or mapped from a SAML group (large orgs). See `organizations.settings.ownerMode`.

**`orgGroups`**
```
id (UUID), organizationId, name, description?, createdAt, updatedAt
```

**`orgGroupMembers`** — doc ID: `${groupId}_${userId}`
```
groupId, organizationId, userId, addedAt, addedBy
```

**`orgDomains`** — doc ID = domain (e.g., "acme.com"), for fast domain->org lookup
```
organizationId, verified, verificationToken?, createdAt
```

**`vaultGroupAccess`** — doc ID: `${vaultId}_${groupId}`
```
vaultId, groupId, organizationId, role: VaultRole, encryptedVaultKey, grantedAt, grantedBy
```

**`samlSessions`** — temporary in-flight SAML handshakes (like `srpSessions`, 5-min TTL)
```
id (AuthnRequest ID), organizationId, relayState, createdAt, expiresAt,
clientType: 'web'|'cli', cliCallbackPort?, cliCodeChallenge?
```

**`samlAuthCodes`** — one-time auth codes for CLI token exchange (60s TTL)
```
code (UUID, doc ID), organizationId, userId, codeChallenge, createdAt, expiresAt
```

### 1.2 Modified Existing Types

| File | Change |
|------|--------|
| `shared/src/types/user.ts` | Added optional `organizationId?: string`, `authMethod?: 'srp'/'saml'` to User |
| `shared/src/types/vault.ts` | Added `'viewer'` to VaultRole union |
| `backend/src/config/firebase.ts` | Added new org/SAML collection names to COLLECTIONS |
| `backend/src/middleware/auth.ts` | Added optional `organizationId`, `orgRole` to AuthenticatedRequest |

All additive — no existing data migration needed.

### 1.3 Secret Management

**SAML SP private keys must NOT be stored in Firestore.** The `spPrivateKeyRef` field stores a GCP Secret Manager resource name (e.g., `projects/sinesync/secrets/saml-sp-key-{orgId}/versions/latest`). At runtime, `samlService` fetches the key via the Secret Manager API.

Requirements:
- SP private keys stored in GCP Secret Manager with automatic rotation support
- Cloud Run service account granted `roles/secretmanager.secretAccessor` (already scoped per-service)
- Org owners upload SP private key via API; backend writes to Secret Manager, stores only the ref
- Audit logging via Secret Manager's built-in Cloud Audit Logs
- Key rotation: new version in Secret Manager, update ref, old version disabled after grace period

---

## 2. SAML Authentication

### 2.1 Library

`@node-saml/node-saml` — maintained fork of passport-saml core, works standalone, TypeScript.

### 2.2 Web SP-Initiated Flow

**Step 1 — Domain Discovery**: `POST /v1/auth/saml/discover { email }` -> extract domain -> look up `orgDomains` -> return `{ samlEnabled, orgSlug }` or `{ samlEnabled: false }` (proceed with SRP).

**Step 2 — Initiate**: `GET /v1/auth/saml/login?org=acme-corp&returnTo=/dashboard` -> load org SAML config -> generate AuthnRequest -> store `samlSessions` doc -> 302 redirect to IdP SSO URL.

**Step 3 — IdP authenticates** (outside our control).

**Step 4 — ACS**: `POST /v1/auth/saml/acs` (form-encoded SAMLResponse from IdP):
1. Validate Response (signature, expiry, audience)
2. Extract NameID + attributes, recover context from `samlSessions`
3. **JIT Provisioning** if user doesn't exist: inside a Firestore transaction, atomically check `seatsFilled < seatCount`, increment `seatsFilled`, and create user (with `status: 'provisioning'`) + `orgMembers` doc (same pattern as the atomic vault member limit check in #76). Then **outside the transaction**, create default vault, auto-assign to default group if configured, sync IdP groups if attribute present, and finally set `status: 'active'`. If any post-transaction step fails: the user remains in `provisioning` state with seat assigned. A retry-safe provisioning job (or the next SAML login) detects `status: 'provisioning'` and re-runs the incomplete steps idempotently. This avoids rolling back the seat/member (which would create its own race conditions) while ensuring onboarding eventually completes
4. If user exists: verify org matches, update `lastSamlLogin`
5. Generate tokens via existing `generateAccessToken()` / `generateRefreshToken()`
6. Set cookies via existing `setAuthCookies()` (web) — `isBrowserRequest()` works unchanged
7. Clean up `samlSessions`, redirect to `returnTo`

**Step 5 — SP Metadata**: `GET /v1/auth/saml/metadata/:orgSlug` -> returns XML for IdP configuration.

### 2.3 CLI SAML Flow (auth code exchange, same pattern as `gh auth login --web`)

**Security**: Tokens are never passed in URLs. The CLI uses a one-time auth code exchanged server-side, similar to OAuth authorization code flow with PKCE.

1. CLI calls domain discovery
2. If SAML: generate `code_verifier` (random 43-128 chars), derive `code_challenge` (SHA256, base64url), generate `state` nonce
3. Start localhost HTTP server on random port
4. Open browser to `GET /v1/auth/saml/login?org=...&cli=true&callback=http://localhost:PORT/callback&state=STATE&code_challenge=CHALLENGE`
5. ACS handler detects `clientType: 'cli'`, generates a one-time `auth_code` (random UUID, stored in Firestore with 60s TTL + `code_challenge`), redirects to `localhost:PORT/callback?code=AUTH_CODE&state=STATE`
6. CLI receives the code, verifies `state`, exchanges code + `code_verifier` via `POST /v1/auth/saml/token { code, code_verifier }`
7. Backend **atomically** consumes the auth code inside a Firestore transaction: read code doc, verify `expiresAt > now` and not already consumed, verify `SHA256(code_verifier) == stored code_challenge`, delete the doc, then return tokens. The transaction ensures concurrent exchange attempts fail (only the first succeeds)
8. CLI saves tokens, shuts down HTTP server

This ensures:
- No tokens in browser history, URL logs, or crash reports
- Auth code is single-use and expires in 60 seconds
- PKCE prevents interception (code alone is useless without verifier)

Go changes in `internal/cli/auth.go`: add `runSAMLLogin()`, modify `runLogin()` to call discovery first.

### 2.4 Web Login Page

`web/src/routes/login/+page.svelte`: on email blur/submit, call discover. If SAML -> show "Sign in with SSO" button, hide password. If not -> show password, proceed with SRP.

`web/src/lib/stores/auth.ts`: add `discoverAuth(email)` and `samlLogin(orgSlug)`.

### 2.5 Why Auth Middleware Doesn't Change

SAML produces the same tokens via `generateAccessToken()`. `extractAccessToken()` already handles cookies + Bearer. `authenticate()` only verifies the token + checks user. **No changes to token verification.** Only addition: populate `organizationId`/`orgRole` on the request from the user doc.

---

## 3. Organization Management

### 3.1 Routes — `backend/src/routes/organizations.ts`

| Method | Path | Auth |
|--------|------|------|
| POST | `/v1/organizations` | authenticated user |
| GET/PATCH | `/v1/organizations/:id` | org member / org admin |
| GET/POST/DELETE/PATCH | `/v1/organizations/:id/members(/:userId)` | org admin |
| GET/POST/DELETE/PATCH | `/v1/organizations/:id/groups(/:groupId)` | org admin |
| GET/POST/DELETE | `/v1/organizations/:id/groups/:groupId/members(/:userId)` | org admin |
| GET | `/v1/organizations/:id/seats` | org admin |
| GET/POST | `/v1/organizations/:id/saml` | org owner |
| POST/DELETE | `/v1/organizations/:id/domains(/:domain)` | org admin |
| POST | `/v1/organizations/:id/domains/:domain/verify` | org admin |

### 3.2 Services

- **`organizationService.ts`** — CRUD, slug reservation, seat management, domain lookup
- **`groupService.ts`** — group CRUD, membership management, vault group access
- **`samlService.ts`** — AuthnRequest, assertion validation, JIT provisioning, SP metadata, discovery (Phase 2)

### 3.3 Authorization Middleware — `backend/src/middleware/orgAuth.ts`

`requireOrgMembership`, `requireOrgAdmin`, `requireOrgOwner` — composable with existing `authenticate`.

---

## 4. Group-Based Vault Access

### 4.1 Extending `checkVaultAccess()` — `backend/src/services/vaultService.ts`

Current checks: (1) direct membership, (2) vault ownership. Added: (3) if user has `organizationId`, get their groups -> check `vaultGroupAccess` for any match.

### 4.2 `getEffectiveVaultRole(vaultId, userId)`

Priority: direct membership role -> vault ownership ('owner') -> highest group-based role. Returns `null` if no access.

### 4.3 Viewer Role

Added `'viewer'` to VaultRole. Can pull/list/view. Cannot push/delete/manage. Enforcement: role check on write endpoints in `backend/src/routes/sync.ts`.

### 4.4 Vault Group Access Routes

Added to `backend/src/routes/vaults.ts`:
- `POST /v1/vaults/:id/groups` — grant group access
- `DELETE /v1/vaults/:id/groups/:groupId` — revoke
- `GET /v1/vaults/:id/groups` — list groups with access

---

## 5. Per-Seat Billing

- Enterprise tier: `visible: true`, self-service signup on pricing page, unlimited vaults/members, 50 GB/seat, 10 devices/user
- Stripe quantity-based subscription; prorate on seat changes
- `getUserLimits()` in `subscriptionTierService.ts`: if user has `organizationId` -> limits from org's tier. `-1` = unlimited; enforcement points skip check.

---

## 6. Files Summary

### New Files
| File | Purpose |
|------|---------|
| `shared/src/types/organization.ts` | Organization, OrgMember, OrgGroup, VaultGroupAccess types |
| `backend/src/routes/organizations.ts` | Org CRUD, member, group, SAML config routes |
| `backend/src/routes/saml.ts` | SAML auth routes (discover, login, acs, metadata) — Phase 2 |
| `backend/src/services/organizationService.ts` | Org management, seats |
| `backend/src/services/groupService.ts` | Group CRUD + membership |
| `backend/src/services/samlService.ts` | SAML protocol handling, JIT provisioning — Phase 2 |
| `backend/src/middleware/orgAuth.ts` | Org authorization middleware |
| `web/src/routes/enterprise/{members,groups,settings}/+page.svelte` | Enterprise admin UI — Phase 4 |
| `web/src/lib/stores/organization.ts` | Org state store — Phase 4 |
| `docker-compose.simplesamlphp.yml` | Local IdP for testing — Phase 2 |

### Modified Files
| File | Change |
|------|--------|
| `shared/src/types/user.ts` | Add optional `organizationId`, `authMethod` |
| `shared/src/types/vault.ts` | Add `'viewer'` to VaultRole |
| `shared/src/constants/index.ts` | Add routes, error codes |
| `backend/src/config/firebase.ts` | Add collection names |
| `backend/src/middleware/auth.ts` | Add org fields to AuthenticatedRequest |
| `backend/src/services/vaultService.ts` | Extend `checkVaultAccess()`, add `getEffectiveVaultRole()` |
| `backend/src/services/subscriptionTierService.ts` | Extend `getUserLimits()` for org users |
| `backend/src/routes/sync.ts` | Add viewer role check on writes |
| `backend/src/routes/vaults.ts` | Add group access routes |
| `backend/src/index.ts` | Mount new route modules |
| `web/src/routes/login/+page.svelte` | SAML discovery on email input — Phase 2 |
| `web/src/lib/stores/auth.ts` | Add `discoverAuth()`, `samlLogin()` — Phase 2 |
| `internal/cli/auth.go` | SAML detection + browser login flow — Phase 3 |
| `infra/modules/firestore/main.tf` | Composite indexes for new collections |

---

## 7. Implementation Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 1. Org Foundation | Org types, collections, indexes, CRUD service+routes, member management, org auth middleware, `getUserLimits()` org branch, viewer role, group service, vault group access | **Done** |
| 2. SAML Auth | `@node-saml/node-saml`, SAML service, discover/login/acs/metadata routes, JIT provisioning, web login integration, SimpleSAMLphp test setup | Planned |
| 3. CLI + SCIM | CLI browser SAML flow, SCIM auto-sync users/groups from IdP | Planned |
| 4. Enterprise UI | `/enterprise/{members,groups,settings}` pages, org Svelte store | Planned |
| 5. Dashboard Foundation (future) | Service account auth, export adapter in Go daemon, PG/Aurora adapter | Future |

---

## 8. Testing Strategy

**Local IdP**: Docker Compose SimpleSAMLphp with test users (member, admin, new user for JIT).

**Unit**: SAML assertion parsing, JIT provisioning, domain discovery, group vault access resolution, seat enforcement.

**Integration**: Full SAML flow with SimpleSAMLphp, CLI browser auth, mixed SRP+SAML in same vault, group access grant->verify, seat limits.

**Regression** (must not break): SRP signup/login (web+CLI), token refresh, vault CRUD+invites, individual subscriptions, sync push/pull, device registration.

---

## 9. Resolved Decisions

1. **No SRP Fallback**: Enterprise users authenticate via SAML only. No password fallback — too messy to maintain both auth methods per user.
2. **SCIM**: Implement in Phase 3 alongside CLI. Auto-sync users/groups from IdP.
3. **Single IdP per Org**: For v1. Multi-IdP if customers request later.
4. **IdP Group Sync**: Yes, Phase 3. Map IdP group attribute to sinesync groups on SAML login.
5. **Org Ownership Model**: Configurable via `ownerMode`. Small orgs: individual owner. Large orgs: map owner role from a SAML group (e.g., "sinesync-admins" in Okta). Set in `organizations.settings`.
6. **Self-Service**: Enterprise tier visible on pricing page. Customers sign up, configure SAML, and manage seats themselves.

## 10. Open Questions & Phase Blockers

### Blockers (must resolve before implementing the dependent phase)

1. **[Blocks Phase 3] Org-Level Encryption Keys**: The `vaultGroupAccess.encryptedVaultKey` field requires a key that all group members can decrypt. This needs a detailed crypto design document covering:
   - Org-level key pair lifecycle (generation, distribution, rotation)
   - How group members receive access to the group's vault key (re-encryption per member? shared group key?)
   - Key escrow/recovery if org owner leaves
   - Impact on zero-knowledge guarantee

   **Phase 1 and 2 are unaffected** — they only set up the data model and auth flow. Phase 3 (group vault access grant flow) cannot be implemented until this is resolved. The `vaultGroupAccess` collection schema is defined but the `encryptedVaultKey` population path is blocked.

### Open Questions

2. **Seat Auto-Scaling**: Should seats auto-expand when new SAML users JIT-provision, or require manual seat purchase first? Recommendation: auto-expand with billing notification.
