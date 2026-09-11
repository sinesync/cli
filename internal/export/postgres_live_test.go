//go:build postgres

// #104: the adapter's other tests use a recording driver and say outright that
// they do not prove PostgreSQL accepts the SQL. Nothing in this repo had ever
// run it against a server, so the export chain was built end to end without one
// row reaching a database.
//
// These do. They need a real server and are behind the `postgres` build tag, so
// the default `go test ./...` is unchanged:
//
//	docker run -d --name pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=sinesync_export \
//	  -p 55432:5432 postgres:16-alpine
//	SINESYNC_TEST_POSTGRES='postgres://postgres:test@localhost:55432/sinesync_export?sslmode=disable' \
//	  go test -tags postgres ./internal/export/ -run Live -v
//
// Without the DSN they skip rather than fail: a developer without Docker should
// not see a red suite for a dependency they were never asked to have.

package export

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

func liveDB(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("SINESYNC_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("SINESYNC_TEST_POSTGRES not set")
	}

	ctx := context.Background()
	pg, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	t.Cleanup(func() { pg.Close() })

	// Each test gets the table empty. Dropping rather than truncating also means
	// Migrate is exercised from nothing on every run, not just the first.
	if _, err := pg.db.ExecContext(ctx, `DROP TABLE IF EXISTS observations`); err != nil {
		t.Fatalf("dropping: %v", err)
	}
	if err := pg.Migrate(ctx); err != nil {
		t.Fatalf("migrating: %v", err)
	}
	return pg
}

func liveAt(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return ts
}

func liveObs(id, vault, typ, content, updated string) Observation {
	return Observation{
		ID: id, VaultID: vault, Type: typ,
		Content:   json.RawMessage(content),
		CreatedAt: liveAt("2026-01-01T00:00:00Z"),
		UpdatedAt: liveAt(updated),
	}
}

func TestLiveMigrateIsRerunnable(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	// The daemon migrates on every start, so the second run against a current
	// target must be a no-op rather than an error.
	for i := 0; i < 3; i++ {
		if err := pg.Migrate(ctx); err != nil {
			t.Fatalf("migrate run %d: %v", i+2, err)
		}
	}

	var n int
	if err := pg.db.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_indexes WHERE tablename = 'observations'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	// Three explicit indexes plus the primary key's.
	if n != 4 {
		t.Fatalf("indexes = %d, want 4", n)
	}
}

func TestLiveWriteAndReadBack(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	in := liveObs("o1", "v1", "memory", `{"title":"hello","n":1}`, "2026-02-01T10:00:00Z")
	if err := pg.Write(ctx, []Observation{in}); err != nil {
		t.Fatalf("write: %v", err)
	}

	var (
		id, vaultID, typ string
		content          []byte
		created, updated time.Time
		synced           time.Time
	)
	err := pg.db.QueryRowContext(ctx,
		`SELECT id, vault_id, type, content, created_at, updated_at, synced_at FROM observations`).
		Scan(&id, &vaultID, &typ, &content, &created, &updated, &synced)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}

	if id != "o1" || vaultID != "v1" || typ != "memory" {
		t.Fatalf("got %q/%q/%q", id, vaultID, typ)
	}
	// JSONB normalises, so compare parsed rather than byte-for-byte.
	var got, want map[string]any
	json.Unmarshal(content, &got)
	json.Unmarshal([]byte(`{"title":"hello","n":1}`), &want)
	if got["title"] != want["title"] || got["n"] != want["n"] {
		t.Fatalf("content = %v, want %v", got, want)
	}
	if !updated.Equal(liveAt("2026-02-01T10:00:00Z")) {
		t.Fatalf("updated_at = %v", updated)
	}
	if synced.IsZero() {
		t.Fatal("synced_at was not defaulted")
	}
}

func TestLiveWriteIsIdempotentOnID(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	// The contract the cursor depends on: replaying a batch must not duplicate.
	first := liveObs("o1", "v1", "memory", `{"v":1}`, "2026-02-01T10:00:00Z")
	if err := pg.Write(ctx, []Observation{first}); err != nil {
		t.Fatal(err)
	}
	var syncedFirst time.Time
	pg.db.QueryRowContext(ctx, `SELECT synced_at FROM observations WHERE id='o1'`).Scan(&syncedFirst)

	second := liveObs("o1", "v2", "decision", `{"v":2}`, "2026-02-02T10:00:00Z")
	if err := pg.Write(ctx, []Observation{second}); err != nil {
		t.Fatal(err)
	}

	var n int
	pg.db.QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows = %d, want 1 — ON CONFLICT did not take", n)
	}

	var vaultID, typ string
	var content []byte
	var syncedSecond time.Time
	pg.db.QueryRowContext(ctx,
		`SELECT vault_id, type, content, synced_at FROM observations WHERE id='o1'`).
		Scan(&vaultID, &typ, &content, &syncedSecond)

	if vaultID != "v2" || typ != "decision" {
		t.Fatalf("update did not overwrite: %q/%q", vaultID, typ)
	}
	var parsed map[string]any
	json.Unmarshal(content, &parsed)
	if parsed["v"] != float64(2) {
		t.Fatalf("content = %v, want v=2", parsed)
	}
	// synced_at answers "when did we last see this", so the update must move it.
	if !syncedSecond.After(syncedFirst) {
		t.Fatalf("synced_at did not advance: %v -> %v", syncedFirst, syncedSecond)
	}
}

func TestLiveCursorIsTheHighWaterMark(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	empty, err := pg.Cursor(ctx)
	if err != nil {
		t.Fatalf("cursor on empty: %v", err)
	}
	if !empty.UpdatedAt.IsZero() || empty.ID != "" {
		t.Fatalf("empty target gave %v, want zero so export starts from the beginning", empty)
	}

	// Deliberately inserted out of order, and with a tie on updated_at that only
	// id breaks — that pair is the whole ordering contract with the API side.
	if err := pg.Write(ctx, []Observation{
		liveObs("b", "v1", "memory", `{}`, "2026-02-02T10:00:00Z"),
		liveObs("a", "v1", "memory", `{}`, "2026-02-03T10:00:00Z"),
		liveObs("z", "v1", "memory", `{}`, "2026-02-02T10:00:00Z"),
	}); err != nil {
		t.Fatal(err)
	}

	c, err := pg.Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !c.UpdatedAt.Equal(liveAt("2026-02-03T10:00:00Z")) || c.ID != "a" {
		t.Fatalf("cursor = %v/%q, want 2026-02-03T10:00:00Z/a", c.UpdatedAt, c.ID)
	}
}

func TestLiveCursorBreaksTiesByID(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	// Same instant, different ids: the cursor must be the highest id, or a
	// resume re-reads or skips the rest of the tie.
	same := "2026-02-02T10:00:00Z"
	if err := pg.Write(ctx, []Observation{
		liveObs("a", "v1", "memory", `{}`, same),
		liveObs("c", "v1", "memory", `{}`, same),
		liveObs("b", "v1", "memory", `{}`, same),
	}); err != nil {
		t.Fatal(err)
	}

	c, err := pg.Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "c" {
		t.Fatalf("cursor id = %q, want c", c.ID)
	}
}

// The cursor's ORDER BY carries a `, id DESC` tiebreak. With the (updated_at, id)
// index in place a backwards index scan supplies that order anyway, so removing
// the clause changes nothing and a test against a populated table cannot tell.
// Drop the index and the mask goes with it: the planner sorts on updated_at
// alone, ties come back in whatever order the sort produced, and the wrong row
// is returned. Measured on this server — 2000 tied rows gave id-2000 with the
// index and id-0001 without it.
//
// So this is the test that holds the SQL responsible rather than the physical
// plan, which matters because the index is not a correctness guarantee: it is a
// CREATE INDEX IF NOT EXISTS that an operator could drop.
func TestLiveCursorTiebreakSurvivesWithoutTheIndex(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	if _, err := pg.db.ExecContext(ctx, `DROP INDEX idx_observations_cursor`); err != nil {
		t.Fatalf("dropping cursor index: %v", err)
	}

	// Enough rows that the planner sorts rather than reading them in any
	// incidentally-correct order.
	const n = 2000
	same := "2026-02-02T10:00:00Z"
	batch := make([]Observation, 0, n)
	for i := 1; i <= n; i++ {
		batch = append(batch, liveObs(fmt.Sprintf("id-%04d", i), "v1", "memory", `{}`, same))
	}
	// 2000 rows is 12000 placeholders, inside the 65535 bind limit but written in
	// chunks anyway so this test does not also depend on that ceiling.
	for i := 0; i < len(batch); i += 500 {
		end := i + 500
		if end > len(batch) {
			end = len(batch)
		}
		if err := pg.Write(ctx, batch[i:end]); err != nil {
			t.Fatalf("write chunk at %d: %v", i, err)
		}
	}

	c, err := pg.Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != fmt.Sprintf("id-%04d", n) {
		t.Fatalf("cursor id = %q, want id-%04d — with no index to supply the order, "+
			"the ORDER BY must break the tie itself or a resume skips or repeats rows",
			c.ID, n)
	}
}

// What this proves is narrower than its name suggests, and the difference is
// worth stating: a batch is ONE statement, and PostgreSQL makes a single
// statement atomic on its own. Running it outside the explicit transaction in
// Write passes this test too — verified by mutation. So this covers the
// guarantee the loop depends on (a failed batch stores nothing, so the cursor
// cannot advance past rows that were never written) without covering the
// transaction, which is redundant while the batch stays one statement and
// becomes load-bearing the moment it does not.
func TestLiveBatchIsAtomic(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	good := liveObs("ok", "v1", "memory", `{}`, "2026-02-01T10:00:00Z")
	// Invalid JSON reaches the server as a JSONB cast failure, which is the
	// realistic way a batch fails: one bad row among good ones.
	bad := liveObs("bad", "v1", "memory", `{not json`, "2026-02-01T11:00:00Z")

	if err := pg.Write(ctx, []Observation{good, bad}); err == nil {
		t.Fatal("expected the batch to fail")
	}

	var n int
	pg.db.QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&n)
	if n != 0 {
		t.Fatalf("rows = %d, want 0 — a failed batch must not leave the good row behind, "+
			"or the cursor advances past rows that were never stored", n)
	}
}

func TestLiveWriteEmptyBatchIsANoOp(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()
	if err := pg.Write(ctx, nil); err != nil {
		t.Fatalf("empty batch: %v", err)
	}
}

func TestLiveLargeBatchInOneStatement(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	// 500 rows is 3000 placeholders. PostgreSQL's bind limit is 65535, so this
	// is the size at which the single-statement design stays legal — worth
	// pinning, because exceeding it fails only against a real server.
	batch := make([]Observation, 500)
	for i := range batch {
		batch[i] = liveObs(
			fmt.Sprintf("id-%03d", i),
			"v1", "memory", fmt.Sprintf(`{"i":%d}`, i),
			liveAt("2026-02-01T10:00:00Z").Add(time.Duration(i)*time.Second).Format(time.RFC3339),
		)
	}
	if err := pg.Write(ctx, batch); err != nil {
		t.Fatalf("500-row batch: %v", err)
	}

	var n int
	pg.db.QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&n)
	if n != 500 {
		t.Fatalf("rows = %d, want 500", n)
	}
}

var _ = sql.ErrNoRows
