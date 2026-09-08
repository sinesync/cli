package export

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

// #104: an export daemon that silently skips records is worse than one that
// fails, because the gap is only visible by comparing two systems nobody
// compares. These pin the cursor semantics, the retry behaviour, and the
// draining that stops a first sync trickling.

type fakeAdapter struct {
	mu         sync.Mutex
	rows       map[string]Observation
	migrated   int
	writes     [][]Observation
	cursorErr  error
	writeErr   error
	failWrites int
}

func newAdapter() *fakeAdapter { return &fakeAdapter{rows: map[string]Observation{}} }

func (f *fakeAdapter) Migrate(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.migrated++
	return nil
}

func (f *fakeAdapter) Cursor(context.Context) (Cursor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cursorErr != nil {
		return Cursor{}, f.cursorErr
	}
	var newest Cursor
	for _, o := range f.rows {
		c := Cursor{UpdatedAt: o.UpdatedAt, ID: o.ID}
		if c.After(newest) {
			newest = c
		}
	}
	return newest, nil
}

func (f *fakeAdapter) Write(_ context.Context, batch []Observation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failWrites > 0 {
		f.failWrites--
		return errors.New("write refused")
	}
	if f.writeErr != nil {
		return f.writeErr
	}
	f.writes = append(f.writes, batch)
	for _, o := range batch {
		f.rows[o.ID] = o // upsert by id, as a real adapter must
	}
	return nil
}

func (f *fakeAdapter) Close() error { return nil }

func (f *fakeAdapter) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.rows)
}

type fakeSource struct {
	mu    sync.Mutex
	all   []Observation
	calls []Cursor
	err   error
	fail  int
}

func (s *fakeSource) Fetch(_ context.Context, after Cursor, limit int) ([]Observation, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, after)
	if s.fail > 0 {
		s.fail--
		return nil, false, errors.New("source unavailable")
	}
	if s.err != nil {
		return nil, false, s.err
	}

	// Strictly after, in the same total order the adapter reports.
	var out []Observation
	for _, o := range s.all {
		if (Cursor{UpdatedAt: o.UpdatedAt, ID: o.ID}).After(after) {
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return (Cursor{UpdatedAt: out[j].UpdatedAt, ID: out[j].ID}).After(
			Cursor{UpdatedAt: out[i].UpdatedAt, ID: out[i].ID})
	})
	more := false
	if len(out) > limit {
		out, more = out[:limit], true
	}
	return out, more, nil
}

func at(sec int) time.Time { return time.Unix(int64(sec), 0).UTC() }

func obs(id string, sec int) Observation {
	return Observation{
		ID: id, VaultID: "v1", Type: "discovery",
		Content:   json.RawMessage(`{"x":1}`),
		CreatedAt: at(sec), UpdatedAt: at(sec),
	}
}

// runPasses drives the loop until n reports have arrived, then cancels.
func runPasses(t *testing.T, src Source, dst Adapter, opts Options, n int) []Metrics {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	var got []Metrics
	done := make(chan struct{})

	// Only defaulted, never overridden: a test that sets Interval is usually
	// testing what happens when the loop is supposed to ignore it, and
	// overwriting it here would quietly defeat exactly that.
	if opts.Interval == 0 {
		opts.Interval = time.Millisecond
	}
	opts.Backoff = time.Millisecond
	opts.Report = func(m Metrics) {
		mu.Lock()
		got = append(got, m)
		full := len(got) >= n
		mu.Unlock()
		if full {
			select {
			case <-done:
			default:
				close(done)
			}
			cancel()
		}
	}

	errc := make(chan error, 1)
	go func() { errc <- Run(ctx, src, dst, opts) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("loop did not report often enough")
	}
	<-errc

	mu.Lock()
	defer mu.Unlock()
	return append([]Metrics(nil), got...)
}

func TestExportsEverythingThenGoesQuiet(t *testing.T) {
	src := &fakeSource{all: []Observation{obs("a", 10), obs("b", 20)}}
	dst := newAdapter()

	runPasses(t, src, dst, Options{BatchSize: 10}, 2)

	if dst.count() != 2 {
		t.Fatalf("exported %d observations, want 2", dst.count())
	}
}

func TestMigratesOnceBeforeExporting(t *testing.T) {
	src := &fakeSource{all: []Observation{obs("a", 10)}}
	dst := newAdapter()

	runPasses(t, src, dst, Options{BatchSize: 10}, 3)

	if dst.migrated != 1 {
		t.Fatalf("migrated %d times, want exactly 1", dst.migrated)
	}
}

func TestResumesFromWhatTheTargetHolds(t *testing.T) {
	// The cursor is read from the target, not remembered, so a restart resumes
	// where the data actually is.
	src := &fakeSource{all: []Observation{obs("a", 10), obs("b", 20), obs("c", 30)}}
	dst := newAdapter()
	dst.rows["a"] = obs("a", 10)
	dst.rows["b"] = obs("b", 20)

	runPasses(t, src, dst, Options{BatchSize: 10}, 2)

	if len(src.calls) == 0 || !src.calls[0].UpdatedAt.Equal(at(20)) || src.calls[0].ID != "b" {
		t.Fatalf("first fetch asked from %v, want the target's newest row (20,b)", src.calls)
	}
	if dst.count() != 3 {
		t.Fatalf("holds %d rows, want 3", dst.count())
	}
}

func TestReExportsWhatARestoredTargetLost(t *testing.T) {
	// A target restored from an older backup must catch up rather than skip
	// everything newer, which a cursor kept beside the daemon would do.
	src := &fakeSource{all: []Observation{obs("a", 10), obs("b", 20), obs("c", 30)}}
	dst := newAdapter()
	dst.rows["a"] = obs("a", 10)

	runPasses(t, src, dst, Options{BatchSize: 10}, 2)

	if dst.count() != 3 {
		t.Fatalf("holds %d rows after restore, want 3", dst.count())
	}
}

func TestATiedTimestampIsNeitherSkippedNorRepeated(t *testing.T) {
	// Two observations sharing a timestamp is ordinary. Ordering by timestamp
	// alone cannot handle it: > loses one permanently, >= re-fetches both on
	// every pass. The (UpdatedAt, ID) pair does both correctly.
	src := &fakeSource{all: []Observation{obs("a", 10), obs("b", 10)}}
	dst := newAdapter()
	dst.rows["a"] = obs("a", 10)

	runPasses(t, src, dst, Options{BatchSize: 10}, 2)

	if _, ok := dst.rows["b"]; !ok {
		t.Fatal("an observation sharing the cursor timestamp was never exported")
	}
}

func TestDrainsWithoutWaitingWhileMoreRemains(t *testing.T) {
	// A first sync must not move BatchSize per Interval; with 5 rows and a
	// batch of 2 the loop should reach the end in consecutive passes.
	src := &fakeSource{all: []Observation{obs("a", 10), obs("b", 20), obs("c", 30), obs("d", 40), obs("e", 50)}}
	dst := newAdapter()

	opts := Options{BatchSize: 2, Interval: time.Hour} // an Interval it must ignore
	runPasses(t, src, dst, opts, 3)

	if dst.count() < 4 {
		t.Fatalf("drained only %d rows across three passes; the Interval was not skipped", dst.count())
	}
}

func TestRetriesAFailingFetchWithinAPass(t *testing.T) {
	src := &fakeSource{all: []Observation{obs("a", 10)}, fail: 2}
	dst := newAdapter()

	got := runPasses(t, src, dst, Options{BatchSize: 10, MaxAttempts: 4}, 1)

	if got[0].Err != nil {
		t.Fatalf("pass failed despite retries: %v", got[0].Err)
	}
	if got[0].Attempts != 3 {
		t.Fatalf("took %d attempts, want 3", got[0].Attempts)
	}
}

func TestGivesUpAPassRatherThanSpinning(t *testing.T) {
	// The API being down is not a reason to hammer it; the next pass resumes
	// from the same cursor anyway.
	src := &fakeSource{err: errors.New("down")}
	dst := newAdapter()

	got := runPasses(t, src, dst, Options{BatchSize: 10, MaxAttempts: 2}, 1)

	if got[0].Err == nil {
		t.Fatal("a pass that never succeeded reported no error")
	}
	if got[0].Attempts != 2 {
		t.Fatalf("made %d attempts, want the configured 2", got[0].Attempts)
	}
}

func TestAFailedWriteIsRetriedAndTheDataStillLands(t *testing.T) {
	src := &fakeSource{all: []Observation{obs("a", 10)}}
	dst := newAdapter()
	dst.failWrites = 1

	runPasses(t, src, dst, Options{BatchSize: 10, MaxAttempts: 3}, 1)

	if dst.count() != 1 {
		t.Fatal("the observation was lost when the first write failed")
	}
}

func TestReportsMetricsForEveryPass(t *testing.T) {
	src := &fakeSource{all: []Observation{obs("a", 10)}}
	dst := newAdapter()

	got := runPasses(t, src, dst, Options{BatchSize: 10}, 2)

	if got[0].Fetched != 1 || got[0].Written != 1 {
		t.Fatalf("first pass reported fetched=%d written=%d, want 1/1", got[0].Fetched, got[0].Written)
	}
	if got[1].Fetched != 0 {
		t.Fatalf("second pass reported fetched=%d, want 0 once caught up", got[1].Fetched)
	}
}

func TestRefusesToRunWithoutAnAdapter(t *testing.T) {
	if err := Run(context.Background(), &fakeSource{}, nil, Options{}); !errors.Is(err, ErrNoAdapter) {
		t.Fatalf("error %v, want ErrNoAdapter", err)
	}
}

func TestStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := Run(ctx, &fakeSource{}, newAdapter(), Options{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want context.Canceled", err)
	}
}
