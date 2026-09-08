package export

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// #104: the adapter cannot be exercised against a real PostgreSQL here, so these
// verify what is verifiable without one — the statements issued, the batching,
// the parameters bound, and the transaction boundary. They do not prove
// PostgreSQL accepts the SQL.

type recDriver struct{ conn *recConn }

func (d *recDriver) Open(string) (driver.Conn, error) { return d.conn, nil }

type recConn struct {
	mu       sync.Mutex
	stmts    []string
	args     [][]driver.NamedValue
	inTx     bool
	txDepth  int
	commits  int
	rollback int
	rows     [][]driver.Value // what a query returns
}

func (c *recConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (c *recConn) Close() error                        { return nil }

func (c *recConn) Begin() (driver.Tx, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.inTx = true
	c.txDepth++
	return &recTx{c: c}, nil
}

func (c *recConn) ExecContext(_ context.Context, q string, a []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stmts = append(c.stmts, q)
	c.args = append(c.args, a)
	return driver.RowsAffected(len(a)), nil
}

func (c *recConn) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stmts = append(c.stmts, q)
	c.args = append(c.args, a)
	return &recRows{rows: c.rows}, nil
}

type recTx struct{ c *recConn }

func (t *recTx) Commit() error {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	t.c.commits++
	t.c.inTx = false
	return nil
}

func (t *recTx) Rollback() error {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	t.c.rollback++
	t.c.inTx = false
	return nil
}

type recRows struct {
	rows [][]driver.Value
	i    int
}

func (r *recRows) Columns() []string { return []string{"updated_at", "id"} }
func (r *recRows) Close() error      { return nil }
func (r *recRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}

func newRecordingDB(t *testing.T, rows [][]driver.Value) (*sql.DB, *recConn) {
	t.Helper()
	// OpenDB with a per-test connector, rather than sql.Register with a name:
	// each test needs its own recording connection, and database/sql panics on
	// a duplicate driver name.
	conn := &recConn{rows: rows}
	return sql.OpenDB(connectorFor(conn)), conn
}

type fixedConnector struct{ c *recConn }

func (f fixedConnector) Connect(context.Context) (driver.Conn, error) { return f.c, nil }
func (f fixedConnector) Driver() driver.Driver                        { return &recDriver{conn: f.c} }

func connectorFor(c *recConn) driver.Connector { return fixedConnector{c: c} }

func (c *recConn) statements() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.stmts...)
}

func TestMigrateIsIdempotentByConstruction(t *testing.T) {
	// Every statement must be re-runnable, because the daemon migrates on each
	// start and may be pointed at a target that is already current.
	for i, stmt := range migrations {
		if !strings.Contains(stmt, "IF NOT EXISTS") {
			t.Errorf("migration %d is not safe to re-run: %s", i+1, stmt)
		}
	}
}

func TestMigrateIndexesTheCursorOrder(t *testing.T) {
	// Reading the high-water mark must be an index scan, not a sort of the
	// table; an index on updated_at alone would not serve the tiebreak.
	var found bool
	for _, stmt := range migrations {
		if strings.Contains(stmt, "(updated_at, id)") {
			found = true
		}
	}
	if !found {
		t.Fatal("no index matches the (updated_at, id) cursor order")
	}
}

func TestMigrateRunsEveryStatement(t *testing.T) {
	db, conn := newRecordingDB(t, nil)
	defer db.Close()

	if err := (&Postgres{db: db}).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := len(conn.statements()); got != len(migrations) {
		t.Fatalf("issued %d statements, want %d", got, len(migrations))
	}
}

func TestCursorOfAnEmptyTargetExportsFromTheBeginning(t *testing.T) {
	// Not from now: a fresh target must receive the history, not just what
	// happens next.
	db, _ := newRecordingDB(t, nil)
	defer db.Close()

	c, err := (&Postgres{db: db}).Cursor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !c.UpdatedAt.IsZero() || c.ID != "" {
		t.Fatalf("empty target reported cursor %+v, want the zero value", c)
	}
}

func TestCursorReadsBothHalvesOfThePair(t *testing.T) {
	when := time.Unix(1700, 0).UTC()
	db, conn := newRecordingDB(t, [][]driver.Value{{when, "obs-9"}})
	defer db.Close()

	c, err := (&Postgres{db: db}).Cursor(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !c.UpdatedAt.Equal(when) || c.ID != "obs-9" {
		t.Fatalf("cursor %+v, want (%v, obs-9)", c, when)
	}
	if q := conn.statements()[0]; !strings.Contains(q, "ORDER BY updated_at DESC, id DESC") {
		t.Fatalf("cursor query does not order by the pair: %s", q)
	}
}

func TestWriteUpsertsSoARepeatedBatchIsHarmless(t *testing.T) {
	// The cursor comes from the target, so an interrupted run re-sends rows it
	// already wrote. Without ON CONFLICT that is a primary key violation and the
	// export wedges permanently.
	db, conn := newRecordingDB(t, nil)
	defer db.Close()

	err := (&Postgres{db: db}).Write(context.Background(), []Observation{
		{ID: "a", VaultID: "v", Type: "discovery", Content: json.RawMessage(`{}`),
			CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(2, 0)},
	})
	if err != nil {
		t.Fatal(err)
	}

	stmt := conn.statements()[0]
	if !strings.Contains(stmt, "ON CONFLICT (id) DO UPDATE") {
		t.Fatalf("write is not an upsert: %s", stmt)
	}
}

func TestWriteSendsOneStatementForTheWholeBatch(t *testing.T) {
	// One statement, not one per row: a batch of 500 would otherwise be 500
	// round trips over the customer's link to their own database.
	db, conn := newRecordingDB(t, nil)
	defer db.Close()

	var batch []Observation
	for _, id := range []string{"a", "b", "c"} {
		batch = append(batch, Observation{ID: id, Content: json.RawMessage(`{}`)})
	}
	if err := (&Postgres{db: db}).Write(context.Background(), batch); err != nil {
		t.Fatal(err)
	}

	var inserts int
	for _, s := range conn.statements() {
		if strings.HasPrefix(s, "INSERT INTO observations") {
			inserts++
		}
	}
	if inserts != 1 {
		t.Fatalf("issued %d INSERT statements for 3 rows, want 1", inserts)
	}
}

func TestWriteBindsEveryColumnOfEveryRow(t *testing.T) {
	db, conn := newRecordingDB(t, nil)
	defer db.Close()

	batch := []Observation{
		{ID: "a", VaultID: "v", Type: "t", Content: json.RawMessage(`{"n":1}`), CreatedAt: time.Unix(1, 0), UpdatedAt: time.Unix(2, 0)},
		{ID: "b", VaultID: "v", Type: "t", Content: json.RawMessage(`{"n":2}`), CreatedAt: time.Unix(3, 0), UpdatedAt: time.Unix(4, 0)},
	}
	if err := (&Postgres{db: db}).Write(context.Background(), batch); err != nil {
		t.Fatal(err)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	// 2 rows x 6 columns. A mismatch here is a silently shifted row, which is
	// worse than an error.
	if n := len(conn.args[0]); n != 12 {
		t.Fatalf("bound %d parameters for 2 rows, want 12", n)
	}
}

func TestWriteCommitsAsOneTransaction(t *testing.T) {
	// A partial batch would leave the cursor past rows that were never stored.
	db, conn := newRecordingDB(t, nil)
	defer db.Close()

	if err := (&Postgres{db: db}).Write(context.Background(),
		[]Observation{{ID: "a", Content: json.RawMessage(`{}`)}}); err != nil {
		t.Fatal(err)
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.commits != 1 {
		t.Fatalf("committed %d times, want 1", conn.commits)
	}
}

func TestWriteOfNothingTouchesTheDatabase(t *testing.T) {
	db, conn := newRecordingDB(t, nil)
	defer db.Close()

	if err := (&Postgres{db: db}).Write(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if got := len(conn.statements()); got != 0 {
		t.Fatalf("an empty batch issued %d statements, want 0", got)
	}
}

// Postgres must satisfy the interface the loop drives.
var _ Adapter = (*Postgres)(nil)
