# Self-hosted export

Run a daemon inside your own infrastructure that pulls your organization's
observations from sine~sync, decrypts them locally, and writes plaintext to a
database you control.

Nothing decrypted goes back to sine~sync. The organization key never leaves your
machines, which is what keeps the zero-knowledge guarantee intact while your
admins get full visibility inside your own environment.

`sinesync-export` is a separate binary from the `sinesync` CLI, distributed
directly rather than published with the public releases. Ask us for it.

## What you need

Two credentials, deliberately separate, so that neither is sufficient alone:

| | what it is | what it grants |
|---|---|---|
| **service account** | a key id and secret | API access, scoped to named vaults, read-only, revocable |
| **credentials file** | your org private key, passphrase-encrypted | the ability to decrypt what you pull |

Revoking the service account cuts the daemon off immediately, without rotating
your organization key. That is the lever to pull if a daemon is retired or a host
is suspected.

## 1. Create a service account

As the organization **owner**:

```
POST /v1/organizations/<org-id>/service-accounts
{ "label": "warehouse exporter", "vaultIds": ["<vault-id>", "..."] }
```

The response contains the `keyId` and the `secret`. **The secret is shown once
and cannot be retrieved again.**

The vault list is fixed when the account is created. A vault added to your
organization later is *not* included, which is deliberate: a compromised daemon
reaches exactly the vaults you named and no others.

## 2. Export the organization key

As the organization **owner**, on a machine where you are logged in:

```
sinesync admin export-key --out sinesync-org.key
```

It asks for a passphrase twice. The key is unwrapped locally and never sent
anywhere, so nobody — including us — can recover this file or its passphrase for
you.

Keep the file and the passphrase apart. Give the daemon the file on disk and the
passphrase through your own secret store.

## 3. Write a config file

`/etc/sinesync/export.json`, readable only by the daemon's user:

```json
{
  "apiBase": "https://api.sinesync.ai",
  "keyId": "sa_1a2b3c4d",
  "secretEnv": "SINESYNC_SA_SECRET",
  "credentialsFile": "/etc/sinesync/sinesync-org.key",
  "passphraseEnv": "SINESYNC_ORG_PASSPHRASE",
  "vaultIds": ["<vault-id>"],
  "targetDsnEnv": "SINESYNC_TARGET_DSN",
  "pollSeconds": 60,
  "batchSize": 500
}
```

Secrets are named, not embedded: config files get copied, reviewed and backed up
in ways secret stores do not. A key the daemon does not recognise is an error
rather than an ignored line, so a typo fails at startup instead of silently
disabling a setting.

## 4. Run it

```
SINESYNC_SA_SECRET=...        \
SINESYNC_ORG_PASSPHRASE=...   \
SINESYNC_TARGET_DSN=postgres://user:pass@host/db \
  sinesync-export --config /etc/sinesync/export.json --once
```

`--once` runs a single pass and exits, so you can verify a new deployment before
leaving anything running. Drop it to run continuously.

## The export schema

Created and kept current on startup. Migrations are additive and safe to re-run.

```sql
CREATE TABLE observations (
    id          TEXT PRIMARY KEY,
    vault_id    TEXT NOT NULL,
    type        TEXT NOT NULL,
    content     JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL,
    synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

`id` and `vault_id` are `TEXT` rather than `UUID` because observation ids are
opaque strings and not all of them are UUIDs. `content` holds the whole
observation, so a new field in the format appears in your export without a
schema change.

PostgreSQL and Aurora in PostgreSQL-compatible mode are both supported; nothing
here uses an extension or a version-specific feature.

## How resuming works

The daemon has no state of its own. Each pass reads the high-water mark from
**your** database — the greatest `(updated_at, id)` already exported — and asks
for what comes after it.

That has two consequences worth knowing:

- Restarting the daemon, or moving it to another host, resumes correctly with no
  bookkeeping to carry across.
- Restoring your database from an older backup causes the daemon to re-export
  everything it lost, rather than skipping it. Rows are written by upsert, so
  re-exporting is harmless.

## Operating it

Each pass logs one line: how many observations were written, how long it took,
and the cursor it reached. A pass that fails is retried a few times and then
left for the next one — the daemon does not spin against an API that is down,
and the next pass resumes from the same place regardless.

An observation that cannot be decrypted is skipped rather than retried forever,
which would otherwise block every later observation behind it.
