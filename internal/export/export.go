// Package export runs a self-hosted export daemon (#104).
//
// It pulls encrypted observations from the sinesync API using a service account
// token, decrypts them locally with the organization key from a credentials
// file, and writes plaintext to a database the customer runs. Nothing decrypted
// ever returns to our infrastructure, which is the whole point: enterprise
// admins get full visibility inside their own environment without us holding
// plaintext.
package export

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Cursor is a position in the export, ordered by (UpdatedAt, ID).
type Cursor struct {
	UpdatedAt time.Time
	ID        string
}

// After reports whether o sorts strictly after c.
func (c Cursor) After(o Cursor) bool {
	if !c.UpdatedAt.Equal(o.UpdatedAt) {
		return c.UpdatedAt.After(o.UpdatedAt)
	}
	return c.ID > o.ID
}

// Observation is one decrypted record, as written to the export target.
type Observation struct {
	ID        string
	VaultID   string
	Type      string
	Content   json.RawMessage
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Adapter is a place decrypted observations are written.
//
// Write must be idempotent on ID. The cursor is derived from what the target
// already holds rather than tracked separately, so a batch that is written twice
// after an interrupted run has to be harmless.
type Adapter interface {
	// Migrate brings the target's schema up to date. Called once at startup and
	// expected to be safe to call against an already-current target.
	Migrate(ctx context.Context) error

	// Cursor is the high-water mark already exported: the greatest
	// (UpdatedAt, ID) pair in the target, or the zero value if it holds
	// nothing.
	//
	// A pair rather than a timestamp. Two observations can share an UpdatedAt,
	// which makes a timestamp alone unusable in both directions: a strict >
	// loses the second one permanently, and a >= re-fetches every row at the
	// newest timestamp on every pass, so the daemon never reports being caught
	// up. Ordering by (UpdatedAt, ID) is total, so "strictly after" is exact.
	Cursor(ctx context.Context) (Cursor, error)

	// Write upserts a batch by ID.
	Write(ctx context.Context, batch []Observation) error

	Close() error
}

// Source is where observations come from. An interface so the loop can be
// tested without a server, and so a future source (a local store, a replay of a
// backup) does not require changing the loop.
type Source interface {
	// Fetch returns observations strictly after the cursor in (UpdatedAt, ID)
	// order, oldest first, and reports whether more remain beyond what it
	// returned.
	Fetch(ctx context.Context, after Cursor, limit int) (batch []Observation, more bool, err error)
}

// Metrics is one pass of the loop, logged so an operator can see the daemon is
// doing something without reading the database.
type Metrics struct {
	Fetched  int
	Written  int
	Attempts int
	Duration time.Duration
	Cursor   Cursor
	Err      error
}

// Options configure a run.
type Options struct {
	// BatchSize bounds one fetch. A pull of everything would hold the whole
	// export in memory on first run, when there is the most to move.
	BatchSize int

	// Interval between passes once caught up. Ignored while a pass reports more
	// data waiting, so a first sync drains rather than trickling.
	Interval time.Duration

	// MaxAttempts per pass before giving up and waiting for the next one. A
	// failing pass must not spin: the API being down is not a reason to hammer
	// it, and the next pass will pick up from the same cursor regardless.
	MaxAttempts int

	// Backoff between attempts within a pass.
	Backoff time.Duration

	// Report receives one Metrics per pass, including failed ones.
	Report func(Metrics)

	// now is injectable so tests need not sleep.
	now func() time.Time
}

func (o *Options) withDefaults() {
	if o.BatchSize <= 0 {
		o.BatchSize = 500
	}
	if o.Interval <= 0 {
		o.Interval = time.Minute
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = 5
	}
	if o.Backoff <= 0 {
		o.Backoff = 2 * time.Second
	}
	if o.now == nil {
		o.now = time.Now
	}
}

// ErrNoAdapter is returned rather than panicking on a misconfigured run.
var ErrNoAdapter = errors.New("export: no adapter configured")

// Run exports until ctx is cancelled.
//
// Each pass reads the cursor from the target rather than from memory, so a
// restart resumes where the data actually is and a target restored from backup
// re-exports what it lost instead of skipping it.
func Run(ctx context.Context, src Source, dst Adapter, opts Options) error {
	if dst == nil {
		return ErrNoAdapter
	}
	if src == nil {
		return errors.New("export: no source configured")
	}
	opts.withDefaults()

	if err := dst.Migrate(ctx); err != nil {
		return fmt.Errorf("migrating export target: %w", err)
	}

	for {
		more, m := onePass(ctx, src, dst, &opts)
		if opts.Report != nil {
			opts.Report(m)
		}

		// Drain without pausing while the source says there is more, so a first
		// sync of a large vault does not take BatchSize per Interval forever.
		wait := opts.Interval
		if more && m.Err == nil {
			wait = 0
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// onePass fetches once and writes once, retrying the pair together.
//
// Together rather than separately, because a write that fails after a successful
// fetch has to re-fetch anyway: the cursor lives in the target, so nothing
// records that those rows were seen.
func onePass(ctx context.Context, src Source, dst Adapter, opts *Options) (bool, Metrics) {
	start := opts.now()
	m := Metrics{}

	for attempt := 1; attempt <= opts.MaxAttempts; attempt++ {
		m.Attempts = attempt

		cursor, err := dst.Cursor(ctx)
		if err != nil {
			m.Err = fmt.Errorf("reading cursor: %w", err)
		} else {
			m.Cursor = cursor

			batch, more, err := src.Fetch(ctx, cursor, opts.BatchSize)
			switch {
			case err != nil:
				m.Err = fmt.Errorf("fetching: %w", err)
			case len(batch) == 0:
				m.Err = nil
				m.Duration = opts.now().Sub(start)
				return false, m
			default:
				m.Fetched = len(batch)
				if err := dst.Write(ctx, batch); err != nil {
					m.Err = fmt.Errorf("writing: %w", err)
				} else {
					m.Written = len(batch)
					m.Err = nil
					m.Duration = opts.now().Sub(start)
					return more, m
				}
			}
		}

		if attempt == opts.MaxAttempts {
			break
		}
		select {
		case <-ctx.Done():
			m.Err = ctx.Err()
			m.Duration = opts.now().Sub(start)
			return false, m
		case <-time.After(opts.Backoff * time.Duration(attempt)):
		}
	}

	m.Duration = opts.now().Sub(start)
	return false, m
}
