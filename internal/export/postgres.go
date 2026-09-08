package export

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	// Registers the "postgres" driver for OpenPostgres. Blank, because nothing
	// here touches the driver's own API: everything goes through database/sql
	// and plain SQL, which is what keeps Aurora working too.
	_ "github.com/lib/pq"
)

// Postgres writes decrypted observations to a PostgreSQL database, which also
// covers Aurora in PostgreSQL-compatible mode: nothing here uses an extension or
// a version-specific feature.
//
// The schema is deliberately close to the one in #104, with two deviations,
// both because the issue's types would reject real data:
//
//   - id and vault_id are TEXT, not UUID. Observation.ID is a string, and only
//     some adapters happen to fill it with a UUID; a UUID column would refuse
//     every row from the others at insert time.
//   - type is TEXT, not VARCHAR(50), because a capped column turns a longer
//     observation type into a failed export rather than a longer string.
type Postgres struct {
	db *sql.DB
}

// NewPostgres wraps an already-open database. Taking a *sql.DB rather than a DSN
// keeps this testable without a server and lets the caller own pooling.
func NewPostgres(db *sql.DB) *Postgres { return &Postgres{db: db} }

// OpenPostgres connects using a libpq-style DSN or URL.
//
// The connection is verified before returning, so a daemon started with a wrong
// DSN fails at startup with the reason rather than at the first export pass.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening export target: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("connecting to export target: %w", err)
	}
	return &Postgres{db: db}, nil
}

// migrations are applied in order and each must be safe to re-run: the daemon
// migrates on every start, and an operator may be starting it against a target
// that is already current. Additive only — a new observation type is a new row,
// and a new field is a new nullable column, so nothing here ever needs to drop
// or rewrite what is already exported.
var migrations = []string{
	`CREATE TABLE IF NOT EXISTS observations (
		id          TEXT PRIMARY KEY,
		vault_id    TEXT NOT NULL,
		type        TEXT NOT NULL,
		content     JSONB NOT NULL,
		created_at  TIMESTAMPTZ NOT NULL,
		updated_at  TIMESTAMPTZ NOT NULL,
		synced_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
	)`,
	`CREATE INDEX IF NOT EXISTS idx_observations_vault ON observations (vault_id)`,
	`CREATE INDEX IF NOT EXISTS idx_observations_type ON observations (type)`,
	// (updated_at, id) rather than updated_at alone, because that is the order
	// the cursor is defined in: it makes reading the high-water mark an index
	// scan of one row instead of a sort of the table.
	`CREATE INDEX IF NOT EXISTS idx_observations_cursor ON observations (updated_at, id)`,
}

func (p *Postgres) Migrate(ctx context.Context) error {
	for i, stmt := range migrations {
		if _, err := p.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return nil
}

// Cursor reads the high-water mark from the exported data itself, so there is no
// separate position to fall out of step with it.
func (p *Postgres) Cursor(ctx context.Context) (Cursor, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT updated_at, id FROM observations ORDER BY updated_at DESC, id DESC LIMIT 1`)

	var c Cursor
	switch err := row.Scan(&c.UpdatedAt, &c.ID); {
	case err == sql.ErrNoRows:
		// An empty target exports from the beginning rather than from now.
		return Cursor{}, nil
	case err != nil:
		return Cursor{}, fmt.Errorf("reading cursor: %w", err)
	}
	return c, nil
}

// Write upserts a batch in one transaction.
//
// One statement with all rows rather than one per row: a batch of 500 is 500
// round trips otherwise, and on a link between the customer's daemon and their
// database that dominates everything else the loop does.
//
// synced_at is left to the default on insert and refreshed on update, so it
// answers "when did we last see this" rather than "when did we first".
func (p *Postgres) Write(ctx context.Context, batch []Observation) error {
	if len(batch) == 0 {
		return nil
	}

	const cols = 6
	values := make([]string, 0, len(batch))
	args := make([]any, 0, len(batch)*cols)

	for i, o := range batch {
		n := i * cols
		values = append(values, fmt.Sprintf("($%d,$%d,$%d,$%d,$%d,$%d)",
			n+1, n+2, n+3, n+4, n+5, n+6))
		args = append(args, o.ID, o.VaultID, o.Type, []byte(o.Content), o.CreatedAt, o.UpdatedAt)
	}

	stmt := `INSERT INTO observations (id, vault_id, type, content, created_at, updated_at) VALUES ` +
		strings.Join(values, ",") +
		` ON CONFLICT (id) DO UPDATE SET
			vault_id   = EXCLUDED.vault_id,
			type       = EXCLUDED.type,
			content    = EXCLUDED.content,
			created_at = EXCLUDED.created_at,
			updated_at = EXCLUDED.updated_at,
			synced_at  = NOW()`

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	// A batch lands whole or not at all, so an interrupted write cannot leave
	// the cursor pointing past rows that were never stored.
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, stmt, args...); err != nil {
		return fmt.Errorf("writing %d observations: %w", len(batch), err)
	}
	return tx.Commit()
}

func (p *Postgres) Close() error { return p.db.Close() }
