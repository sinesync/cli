//go:build postgres

// #104: every piece of the export chain was tested in isolation and the chain
// itself never ran. The source had a fake server but short-circuited the vault
// key lookup, so the real crypto path never executed inside it. The adapter had
// a real database but was handed plaintext. The loop had fakes at both ends.
//
// This joins them: genuinely encrypted observations in one end, plaintext rows
// in a real PostgreSQL out the other, through the real APISource, the real
// X25519 unwrap, the real AES open, the real gunzip, the real loop and the real
// adapter. The only stand-in is the HTTP server, which answers the three
// endpoints the way #172 defines them.
//
// What it therefore does not prove: that the live service answers in that shape.
// That is the remaining gap on #104 and it needs an org owner login.
//
//	docker run -d --name pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=sinesync_export \
//	  -p 55432:5432 postgres:16-alpine
//	SINESYNC_TEST_POSTGRES='postgres://postgres:test@localhost:55432/sinesync_export?sslmode=disable' \
//	  go test -tags postgres ./internal/export/ -run Chain -v

package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sinesync/cli/internal/crypto"
)

// fakeService answers the three endpoints an APISource calls, with real
// ciphertext it produced itself.
type fakeService struct {
	t            *testing.T
	orgPublicKey string
	vaultKeys    map[string][]byte // vaultID -> raw key
	items        []encryptedObservation
	tokenIssued  int

	// Every export request's cursor parameters, in order. Recorded because the
	// adapter upserts on id: a run that ignored the cursor and refetched
	// everything produces exactly the same rows as one that resumed correctly,
	// so the outcome cannot tell them apart and the request can.
	asked []askedFor
}

type askedFor struct{ updatedAfter, afterID string }

func newFakeService(t *testing.T, orgPublicKey string) *fakeService {
	return &fakeService{t: t, orgPublicKey: orgPublicKey, vaultKeys: map[string][]byte{}}
}

// add encrypts one observation exactly as the product does: gzip the canonical
// JSON, then seal it under the vault key with the observation AAD.
func (f *fakeService) add(id, vaultID, obsType, title, updatedAt string) {
	f.t.Helper()

	key, ok := f.vaultKeys[vaultID]
	if !ok {
		// Derived from the id's bytes, not its length: two vaults whose ids are
		// the same length must not end up with the same key, or a mix-up
		// between them decrypts cleanly and the test cannot see it.
		sum := sha256.Sum256([]byte("vault-key-" + vaultID))
		key = sum[:]
		f.vaultKeys[vaultID] = key
	}

	canonical := fmt.Sprintf(`{"core":{"id":%q,"type":%q,"title":%q},"meta":{"classification":"private"}}`,
		id, obsType, title)

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	if _, err := zw.Write([]byte(canonical)); err != nil {
		f.t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		f.t.Fatal(err)
	}

	sealed, err := crypto.Encrypt(gz.Bytes(), key, aadObservation)
	if err != nil {
		f.t.Fatal(err)
	}

	f.items = append(f.items, encryptedObservation{
		ID:        id,
		VaultID:   vaultID,
		Type:      obsType,
		Payload:   base64.StdEncoding.EncodeToString(sealed),
		CreatedAt: "2026-01-01T00:00:00Z",
		UpdatedAt: updatedAt,
	})
}

func (f *fakeService) server() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/service-accounts/token", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ KeyId, Secret string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.KeyId != "key-1" || in.Secret != "shhh" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.tokenIssued++
		json.NewEncoder(w).Encode(map[string]any{"token": "tok", "expiresIn": 3600})
	})

	mux.HandleFunc("/v1/service-accounts/vaults/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// .../vaults/<id>/key
		vaultID := r.URL.Path[len("/v1/service-accounts/vaults/"):]
		vaultID = vaultID[:len(vaultID)-len("/key")]

		key, ok := f.vaultKeys[vaultID]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		// Wrapped to the org's public key, which only the org private key opens
		// -- the same shape the real provisioning produces.
		wrapped, err := crypto.X25519Seal(key, f.orgPublicKey)
		if err != nil {
			f.t.Fatal(err)
		}
		json.NewEncoder(w).Encode(map[string]string{"encryptedVaultKey": wrapped})
	})

	mux.HandleFunc("/v1/service-accounts/export", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Names taken from backend/src/routes/serviceAccounts.ts, not invented
		// here: a fake that answers a different contract from the real service
		// proves the source talks to a fiction.
		afterTS := r.URL.Query().Get("afterUpdatedAt")
		afterID := r.URL.Query().Get("afterId")
		f.asked = append(f.asked, askedFor{afterTS, afterID})

		// The real endpoint refuses one without the other (serviceAccounts.ts:89),
		// so this does too -- a source that sent half a cursor would otherwise
		// look fine here and fail in production.
		if (afterTS == "") != (afterID == "") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		// vaultId is required by the real endpoint (a z.union, not optional), and
		// the export is scoped to it. Enforced here so a source that stopped
		// sending the scope fails against the fake the way it would in
		// production, rather than quietly exporting every vault.
		scope := r.URL.Query()["vaultId"]
		if len(scope) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		inScope := map[string]bool{}
		for _, v := range scope {
			inScope[v] = true
		}

		var page []encryptedObservation
		for _, it := range f.items {
			if !inScope[it.VaultID] {
				continue
			}
			if afterTS == "" || it.UpdatedAt > afterTS || (it.UpdatedAt == afterTS && it.ID > afterID) {
				page = append(page, it)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"items": page, "more": false})
	})

	srv := httptest.NewServer(mux)
	f.t.Cleanup(srv.Close)
	return srv
}

// runOnePass drives the real Run loop and stops it after its first pass, so the
// loop, the cursor read and the retry wrapper are all exercised rather than
// bypassed by calling onePass directly.
func runOnePass(t *testing.T, src Source, dst Adapter) Metrics {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var m Metrics
	var seen bool
	opts := Options{
		BatchSize: 10,
		Interval:  time.Millisecond,
		Report: func(got Metrics) {
			if !seen {
				m, seen = got, true
				cancel()
			}
		},
	}
	if err := Run(ctx, src, dst, opts); err != nil && !errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("export run: %v", err)
	}
	if !seen {
		t.Fatal("the run ended without reporting a pass")
	}
	return m
}

func TestChainEncryptedInPlaintextOutOfARealDatabase(t *testing.T) {
	pg := liveDB(t)
	ctx := context.Background()

	pub, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	svc := newFakeService(t, pub)
	svc.add("o1", "v1", "memory", "first", "2026-02-01T10:00:00Z")
	svc.add("o2", "v1", "decision", "second", "2026-02-02T10:00:00Z")
	svc.add("o3", "v2", "memory", "other vault", "2026-02-03T10:00:00Z")
	srv := svc.server()

	src := NewAPISource(srv.URL, "key-1", "shhh", []string{"v1", "v2"}, []byte(priv))

	runOnePass(t, src, pg)

	rows, err := pg.db.QueryContext(ctx,
		`SELECT id, vault_id, type, content, created_at, updated_at FROM observations ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	type got struct {
		id, vaultID, typ, content string
		created, updated          time.Time
	}
	var all []got
	for rows.Next() {
		var g got
		if err := rows.Scan(&g.id, &g.vaultID, &g.typ, &g.content, &g.created, &g.updated); err != nil {
			t.Fatal(err)
		}
		all = append(all, g)
	}
	if len(all) != 3 {
		t.Fatalf("rows = %d, want 3", len(all))
	}

	// The decisive assertion: what landed is readable. If any link in the chain
	// were wrong the row would be absent, not merely different.
	for i, want := range []struct{ id, vaultID, typ, title, updated string }{
		{"o1", "v1", "memory", "first", "2026-02-01T10:00:00Z"},
		{"o2", "v1", "decision", "second", "2026-02-02T10:00:00Z"},
		{"o3", "v2", "memory", "other vault", "2026-02-03T10:00:00Z"},
	} {
		if all[i].id != want.id || all[i].vaultID != want.vaultID || all[i].typ != want.typ {
			t.Errorf("row %d = %+v, want %v/%v/%v", i, all[i], want.id, want.vaultID, want.typ)
		}
		var parsed struct {
			Core struct{ Title string }          `json:"core"`
			Meta struct{ Classification string } `json:"meta"`
		}
		if err := json.Unmarshal([]byte(all[i].content), &parsed); err != nil {
			t.Fatalf("row %d content is not JSON: %v", i, err)
		}
		if parsed.Core.Title != want.title {
			t.Errorf("row %d title = %q, want %q — decryption produced the wrong plaintext",
				i, parsed.Core.Title, want.title)
		}
		// #173: classification rides along in the content and restricts nothing.
		// Asserted so that a future filter cannot be added without this failing.
		if parsed.Meta.Classification != "private" {
			t.Errorf("row %d classification = %q, want private carried through verbatim",
				i, parsed.Meta.Classification)
		}
		// The server's metadata, not the payload's. The cursor paginates by
		// exactly this, so a row whose updated_at came from inside the
		// ciphertext would put the cursor out of step with the server and skip
		// everything between the two values.
		if !all[i].updated.Equal(liveAt(want.updated)) {
			t.Errorf("row %d updated_at = %v, want %v from the server metadata",
				i, all[i].updated.UTC(), want.updated)
		}
		if !all[i].created.Equal(liveAt("2026-01-01T00:00:00Z")) {
			t.Errorf("row %d created_at = %v, want the server's value", i, all[i].created.UTC())
		}
	}

	if svc.tokenIssued != 1 {
		t.Errorf("exchanged %d tokens for one pass, want 1", svc.tokenIssued)
	}
}

func TestChainResumesFromWhatTheDatabaseAlreadyHolds(t *testing.T) {
	// The cursor is read back out of the target rather than tracked separately,
	// so a second run must pick up exactly where the first stopped -- across the
	// real query, the real ordering and the real HTTP round trip.
	pg := liveDB(t)
	ctx := context.Background()

	pub, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	svc := newFakeService(t, pub)
	svc.add("o1", "v1", "memory", "first", "2026-02-01T10:00:00Z")
	srv := svc.server()
	src := NewAPISource(srv.URL, "key-1", "shhh", []string{"v1"}, []byte(priv))

	runOnePass(t, src, pg)

	// New record, strictly after the cursor the first run left behind.
	svc.add("o2", "v1", "memory", "second", "2026-02-02T10:00:00Z")

	src2 := NewAPISource(srv.URL, "key-1", "shhh", []string{"v1"}, []byte(priv))
	runOnePass(t, src2, pg)

	var n int
	pg.db.QueryRowContext(ctx, `SELECT count(*) FROM observations`).Scan(&n)
	if n != 2 {
		t.Fatalf("rows = %d, want 2 — the resume either skipped or duplicated", n)
	}

	c, err := pg.Cursor(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.ID != "o2" {
		t.Errorf("cursor = %q, want o2", c.ID)
	}

	// The decisive part. Two rows would also be the result of ignoring the
	// cursor entirely and re-exporting o1 on top of itself, because Write
	// upserts on id -- so assert what the second pass actually asked the server
	// for, which is the only place the two behaviours differ.
	if len(svc.asked) != 2 {
		t.Fatalf("export requests = %d, want 2", len(svc.asked))
	}
	if svc.asked[0] != (askedFor{"", ""}) {
		t.Errorf("first pass asked %+v, want an empty cursor against an empty target", svc.asked[0])
	}
	if svc.asked[1].afterID != "o1" {
		t.Errorf("second pass asked %+v, want to resume strictly after o1", svc.asked[1])
	}
	if svc.asked[1].updatedAfter == "" {
		t.Error("the second pass sent no timestamp, so it refetched from the beginning")
	}
}

func TestChainSurvivesARecordItCannotDecrypt(t *testing.T) {
	// A record sealed under a key this daemon does not hold must not stop the
	// export: the rest of the vault still has to reach the database.
	pg := liveDB(t)
	ctx := context.Background()

	pub, priv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}

	svc := newFakeService(t, pub)
	svc.add("good", "v1", "memory", "readable", "2026-02-01T10:00:00Z")
	svc.add("bad", "v1", "memory", "unreadable", "2026-02-02T10:00:00Z")
	// Corrupt the second payload after sealing.
	svc.items[1].Payload = base64.StdEncoding.EncodeToString([]byte("not ciphertext"))
	srv := svc.server()

	src := NewAPISource(srv.URL, "key-1", "shhh", []string{"v1"}, []byte(priv))
	runOnePass(t, src, pg)

	var ids []string
	rows, _ := pg.db.QueryContext(ctx, `SELECT id FROM observations ORDER BY id`)
	defer rows.Close()
	for rows.Next() {
		var id string
		rows.Scan(&id)
		ids = append(ids, id)
	}
	if len(ids) != 1 || ids[0] != "good" {
		t.Fatalf("ids = %v, want just [good]", ids)
	}
}
