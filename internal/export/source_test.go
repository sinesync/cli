package export

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// #104: the request the source builds is where the cursor either survives or
// quietly stops working. A dropped afterId would break ties in exactly the way
// the pair exists to prevent, and nothing downstream would notice.

type fakeAPI struct {
	mu      sync.Mutex
	queries []url.Values
	auths   []string
	tokens  int
	items   []encryptedObservation
	more    bool
	status  int
	srv     *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{status: http.StatusOK}
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/service-accounts/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tokens++
		n := f.tokens
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{
			"token": "tok-" + string(rune('0'+n)), "expiresIn": 3600,
		})
	})

	mux.HandleFunc("/v1/sync/export", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries = append(f.queries, r.URL.Query())
		f.auths = append(f.auths, r.Header.Get("Authorization"))
		status, items, more := f.status, f.items, f.more
		f.mu.Unlock()

		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": items, "more": more})
	})

	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPI) lastQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.queries[len(f.queries)-1]
}

// sourceFor builds a source whose decryptor is a stub, so these tests are about
// the request and not the crypto.
func sourceFor(f *fakeAPI, vaults ...string) *APISource {
	s := NewAPISource(f.srv.URL, "sa_k", "secret", vaults, nil)
	s.decryptFn = func(_, _ []byte) (json.RawMessage, string, error) {
		return json.RawMessage(`{"core":{"type":"discovery"}}`), "discovery", nil
	}
	// Vault keys are irrelevant to these; short-circuit the lookup.
	s.vaultKeys["v1"] = []byte("k")
	s.vaultKeys["v2"] = []byte("k")
	return s
}

func TestFetchSendsBothHalvesOfTheCursor(t *testing.T) {
	// The id half is what breaks a tie. Dropping it reintroduces exactly the
	// bug the pair exists to prevent, and silently.
	api := newFakeAPI(t)
	src := sourceFor(api, "v1")

	when := time.Unix(1700, 0).UTC()
	if _, _, err := src.Fetch(context.Background(), Cursor{UpdatedAt: when, ID: "obs-7"}, 100); err != nil {
		t.Fatal(err)
	}

	q := api.lastQuery()
	if got := q.Get("afterId"); got != "obs-7" {
		t.Fatalf("afterId = %q, want obs-7", got)
	}
	if q.Get("afterUpdatedAt") == "" {
		t.Fatal("afterUpdatedAt was not sent")
	}
}

func TestFetchOfAnEmptyCursorAsksForEverything(t *testing.T) {
	// A fresh target must receive history, not just what happens next.
	api := newFakeAPI(t)
	src := sourceFor(api, "v1")

	if _, _, err := src.Fetch(context.Background(), Cursor{}, 100); err != nil {
		t.Fatal(err)
	}
	if q := api.lastQuery(); q.Get("afterUpdatedAt") != "" || q.Get("afterId") != "" {
		t.Fatalf("a zero cursor still sent a lower bound: %v", q)
	}
}

func TestFetchScopesToTheConfiguredVaults(t *testing.T) {
	api := newFakeAPI(t)
	src := sourceFor(api, "v1", "v2")

	if _, _, err := src.Fetch(context.Background(), Cursor{}, 100); err != nil {
		t.Fatal(err)
	}
	if got := api.lastQuery()["vaultId"]; len(got) != 2 {
		t.Fatalf("sent vaultId=%v, want both configured vaults", got)
	}
}

func TestFetchAuthenticatesWithAnExchangedToken(t *testing.T) {
	api := newFakeAPI(t)
	src := sourceFor(api, "v1")

	if _, _, err := src.Fetch(context.Background(), Cursor{}, 100); err != nil {
		t.Fatal(err)
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if api.auths[0] == "" || api.auths[0][:7] != "Bearer " {
		t.Fatalf("Authorization = %q, want a bearer token", api.auths[0])
	}
	if api.tokens != 1 {
		t.Fatalf("exchanged %d tokens for one fetch, want 1", api.tokens)
	}
}

func TestTheTokenIsReusedRatherThanExchangedEveryPass(t *testing.T) {
	api := newFakeAPI(t)
	src := sourceFor(api, "v1")

	for i := 0; i < 3; i++ {
		if _, _, err := src.Fetch(context.Background(), Cursor{}, 100); err != nil {
			t.Fatal(err)
		}
	}

	api.mu.Lock()
	defer api.mu.Unlock()
	if api.tokens != 1 {
		t.Fatalf("exchanged %d tokens across 3 passes, want 1", api.tokens)
	}
}

func TestARejectedTokenIsDiscardedSoTheNextTryExchangesAFreshOne(t *testing.T) {
	// Otherwise the daemon retries with a dead credential until it gives up,
	// every pass, forever.
	api := newFakeAPI(t)
	src := sourceFor(api, "v1")

	api.mu.Lock()
	api.status = http.StatusUnauthorized
	api.mu.Unlock()

	if _, _, err := src.Fetch(context.Background(), Cursor{}, 100); err == nil {
		t.Fatal("a 401 was reported as success")
	}

	api.mu.Lock()
	api.status = http.StatusOK
	api.mu.Unlock()

	if _, _, err := src.Fetch(context.Background(), Cursor{}, 100); err != nil {
		t.Fatalf("the next fetch failed instead of re-exchanging: %v", err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.tokens != 2 {
		t.Fatalf("exchanged %d tokens, want a fresh one after the 401", api.tokens)
	}
}

func TestAnUndecryptableRecordIsSkippedNotFatal(t *testing.T) {
	// One bad record must not block every later observation behind it: the
	// cursor would never advance past it.
	api := newFakeAPI(t)
	api.items = []encryptedObservation{
		{ID: "a", VaultID: "v1", Payload: "AAAA", CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-01-01T00:00:00Z"},
		{ID: "b", VaultID: "v1", Payload: "AAAA", CreatedAt: "2026-01-02T00:00:00Z", UpdatedAt: "2026-01-02T00:00:00Z"},
	}
	src := sourceFor(api, "v1")

	calls := 0
	src.decryptFn = func(_, _ []byte) (json.RawMessage, string, error) {
		calls++
		if calls == 1 {
			return nil, "", context.DeadlineExceeded // stand-in for a decrypt failure
		}
		return json.RawMessage(`{}`), "discovery", nil
	}

	got, _, err := src.Fetch(context.Background(), Cursor{}, 100)
	if err != nil {
		t.Fatalf("one undecryptable record failed the whole fetch: %v", err)
	}
	if len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("got %+v, want only the decryptable record", got)
	}
}

func TestTimestampsComeFromTheServerNotThePayload(t *testing.T) {
	// The cursor orders by what the server paginates by. Taking UpdatedAt from
	// inside the record would let the two disagree and skip everything between.
	api := newFakeAPI(t)
	api.items = []encryptedObservation{
		{ID: "a", VaultID: "v1", Payload: "AAAA",
			CreatedAt: "2026-01-01T00:00:00Z", UpdatedAt: "2026-03-04T05:06:07Z"},
	}
	src := sourceFor(api, "v1")

	got, _, err := src.Fetch(context.Background(), Cursor{}, 100)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := time.Parse(time.RFC3339, "2026-03-04T05:06:07Z")
	if !got[0].UpdatedAt.Equal(want) {
		t.Fatalf("UpdatedAt = %v, want the server's %v", got[0].UpdatedAt, want)
	}
}

func TestFetchReportsMore(t *testing.T) {
	api := newFakeAPI(t)
	api.more = true
	src := sourceFor(api, "v1")

	if _, more, err := src.Fetch(context.Background(), Cursor{}, 100); err != nil || !more {
		t.Fatalf("more = %v, err = %v; want the server's answer carried through", more, err)
	}
}
