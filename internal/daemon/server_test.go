package daemon

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sinesync/cli/internal/storage"
)

// hostCase is one Host header and whether strict loopback validation accepts it.
type hostCase struct {
	name  string
	host  string
	allow bool
}

// hostCases covers every Host header form we care about for a server on port 5741.
var hostCases = []hostCase{
	// Accepted: the exact loopback forms the server listens on.
	{"ipv4 loopback", "127.0.0.1:5741", true},
	{"localhost name", "localhost:5741", true},
	{"ipv6 loopback", "[::1]:5741", true},

	// Wrong port — a rebound name pointed at a different local service.
	{"ipv4 wrong port", "127.0.0.1:5742", false},
	{"localhost wrong port", "localhost:80", false},
	{"ipv6 wrong port", "[::1]:1234", false},
	{"port with leading zero", "127.0.0.1:05741", false},

	// Missing port.
	{"ipv4 no port", "127.0.0.1", false},
	{"localhost no port", "localhost", false},
	{"ipv6 no port", "[::1]", false},
	{"bare ipv6 no brackets", "::1", false},

	// Non-loopback addresses.
	{"lan ipv4", "192.168.1.42:5741", false},
	{"private ipv4", "10.0.0.1:5741", false},
	{"wildcard", "0.0.0.0:5741", false},
	{"public ipv4", "203.0.113.7:5741", false},
	{"ipv4-mapped ipv6 loopback", "[::ffff:127.0.0.1]:5741", false},
	{"alternate loopback ipv4", "127.0.0.2:5741", false},

	// Deceptive hostnames that merely resemble a loopback address.
	{"localhost subdomain", "localhost.evil.example.com:5741", false},
	{"localhost prefix", "localhostevil:5741", false},
	{"ip-looking hostname", "127.0.0.1.evil.example.com:5741", false},
	{"loopback as userinfo", "127.0.0.1@evil.example.com:5741", false},
	{"suffixed loopback", "evil.example.com#127.0.0.1:5741", false},
	{"uppercase localhost", "LOCALHOST:5741", false},

	// Malformed / abusive Host values.
	{"empty", "", false},
	{"whitespace only", " ", false},
	{"leading space", " 127.0.0.1:5741", false},
	{"trailing space", "127.0.0.1:5741 ", false},
	{"trailing slash", "127.0.0.1:5741/", false},
	{"double port", "127.0.0.1:5741:5741", false},
	{"unclosed bracket", "[::1:5741", false},
	{"scheme included", "http://127.0.0.1:5741", false},
	{"port only", ":5741", false},
	{"null byte", "127.0.0.1:5741\x00", false},

	// The canonical DNS-rebinding attacker origin.
	{"evil host with port", "evil.example.com:5741", false},
	{"evil host no port", "evil.example.com", false},
}

const testPort = 5741

func TestHostAllowed(t *testing.T) {
	for _, tc := range hostCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostAllowed(tc.host, testPort); got != tc.allow {
				t.Errorf("hostAllowed(%q, %d) = %v, want %v", tc.host, testPort, got, tc.allow)
			}
		})
	}
}

// targetCases cover absoluteFormTarget, the second half of the guard. The Host
// header cannot be cross-checked against an absolute-form target — net/http
// deletes the header once it takes the authority from the target — so a
// non-origin-form target is rejected outright.
var targetCases = []struct {
	name   string
	rawURL string
	isAbs  bool
}{
	// Origin-form: the only shape a legitimate client sends to this server.
	{"origin form root", "/", false},
	{"origin form path", "/api/health", false},
	{"origin form with query", "/api/search?q=secret", false},

	// Scheme-relative targets are NOT absolute-form on the wire. url.Parse would
	// read "//evil.example.com/x" as an authority, but a server parses the
	// request-target with url.ParseRequestURI, which without a scheme leaves
	// Host empty and treats the whole thing as a path. r.Host therefore still
	// comes from the Host header and the loopback check still governs them.
	{"scheme relative path", "//api/health", false},
	{"scheme relative authority-looking", "//evil.example.com/api/health", false},

	// Absolute-form: proxy shape. The authority here overrides the Host header,
	// so accepting it would let any Host value through the loopback check.
	{"absolute loopback authority", "http://127.0.0.1:5741/api/health", true},
	{"absolute evil authority", "http://evil.example.com/api/health", true},
	{"absolute https", "https://127.0.0.1:5741/", true},
	{"absolute no path", "http://127.0.0.1:5741", true},
}

func TestAbsoluteFormTarget(t *testing.T) {
	for _, tc := range targetCases {
		t.Run(tc.name, func(t *testing.T) {
			// ParseRequestURI, not Parse: this is the function net/http uses on
			// the request-target, and the two disagree on "//host/path".
			u, err := url.ParseRequestURI(tc.rawURL)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.rawURL, err)
			}
			if got := absoluteFormTarget(u); got != tc.isAbs {
				t.Errorf("absoluteFormTarget(%q) = %v, want %v", tc.rawURL, got, tc.isAbs)
			}
		})
	}
}

// TestRequireLoopbackHostRejectsAbsoluteForm drives the whole guard: an
// absolute-form target must be refused even when its authority is the exact
// loopback address the server listens on, because that authority is what r.Host
// is built from and is therefore attacker-controlled.
func TestRequireLoopbackHostRejectsAbsoluteForm(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	h := s.routes()

	for _, tc := range targetCases {
		if !tc.isAbs {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.rawURL, nil)
			// The value a legitimate request would carry. It must not rescue
			// an absolute-form target.
			req.Host = "127.0.0.1:5741"
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Errorf("target %q with valid Host: got status %d, want 403", tc.rawURL, rec.Code)
			}
		})
	}
}

// TestSchemeRelativeTargetsStillGovernedByHost pins the other half: targets that
// merely look like an authority are ordinary paths on the wire, so they must
// still be judged on their Host header — rejected with a hostile one, admitted
// with a valid one. If a future net/url ever started filling in Host for these,
// the first case would fail rather than silently become a bypass.
func TestSchemeRelativeTargetsStillGovernedByHost(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	h := s.routes()

	for _, tc := range targetCases {
		if tc.isAbs {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			bad := httptest.NewRequest(http.MethodGet, tc.rawURL, nil)
			bad.Host = "evil.example.com"
			recBad := httptest.NewRecorder()
			h.ServeHTTP(recBad, bad)
			if recBad.Code != http.StatusForbidden {
				t.Errorf("target %q with hostile Host: got %d, want 403", tc.rawURL, recBad.Code)
			}

			good := httptest.NewRequest(http.MethodGet, tc.rawURL, nil)
			good.Host = "127.0.0.1:5741"
			recGood := httptest.NewRecorder()
			h.ServeHTTP(recGood, good)
			if recGood.Code == http.StatusForbidden {
				t.Errorf("target %q with valid Host: got 403, want it to reach the mux", tc.rawURL)
			}
		})
	}
}

// TestRequireLoopbackHostGatesAllRoutes verifies the guard wraps the whole mux,
// including the unauthenticated status route and the static file server.
func TestRequireLoopbackHostGatesAllRoutes(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	h := s.routes()

	// Rejected hosts are checked against every kind of route, including ones
	// whose handlers need server state the test does not construct — the guard
	// must stop them before routing. Accepted hosts only exercise routes that
	// are safe to actually run with a bare Server.
	allPaths := []string{"/", "/index.html", "/api/health", "/api/stats", "/api/capture", "/does-not-exist"}
	safePaths := []string{"/", "/index.html", "/api/health", "/does-not-exist"}

	for _, tc := range hostCases {
		paths := allPaths
		if tc.allow {
			paths = safePaths
		}
		for _, path := range paths {
			t.Run(tc.name+" "+path, func(t *testing.T) {
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Host = tc.host
				rec := httptest.NewRecorder()

				h.ServeHTTP(rec, req)

				if !tc.allow {
					if rec.Code != http.StatusForbidden {
						t.Errorf("Host %q on %s: got status %d, want 403", tc.host, path, rec.Code)
					}
					return
				}
				// Accepted hosts must reach the mux — any status except 403 proves
				// the guard let the request through to routing.
				if rec.Code == http.StatusForbidden {
					t.Errorf("Host %q on %s: got 403, want the request to reach the mux", tc.host, path)
				}
			})
		}
	}
}

// TestRequireLoopbackHostOverRealSocket runs the same table through a real TCP
// listener and a real HTTP client, confirming the Host header reaches the guard
// unmodified rather than being normalized somewhere in net/http.
func TestRequireLoopbackHostOverRealSocket(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	client := &http.Client{}

	for _, tc := range hostCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/health", nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Host = tc.host

			resp, err := client.Do(req)
			if err != nil {
				if tc.allow {
					t.Fatalf("Host %q: request failed: %v", tc.host, err)
				}
				// net/http refuses to put some malformed values on the wire at
				// all; that is a rejection too.
				return
			}
			defer resp.Body.Close()

			if tc.allow {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("Host %q: got status %d, want 200", tc.host, resp.StatusCode)
				}
				return
			}
			// Rejected either by our guard (403) or by net/http's own Host
			// parsing (400) — never served.
			if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Host %q: got status %d, want 403 (or 400 from net/http)", tc.host, resp.StatusCode)
			}
		})
	}
}

// authedPaths are the routes that must reject a request carrying no hook
// secret. They return observation content, so an unauthenticated local process
// must not be able to read them.
var authedPaths = []struct {
	method string
	path   string
}{
	{http.MethodGet, "/api/stats"},
	{http.MethodGet, "/api/observations"},
	{http.MethodGet, "/api/observations/abc123"},
	{http.MethodGet, "/api/projects"},
	{http.MethodGet, "/api/tags"},
	{http.MethodGet, "/api/search?q=secret"},
	{http.MethodGet, "/api/sync"},
	{http.MethodGet, "/api/vaults"},
	{http.MethodGet, "/api/analytics/activity-heatmap"},
	{http.MethodGet, "/api/analytics/activity-by-hour"},
	{http.MethodGet, "/api/analytics/type-trend"},
	{http.MethodGet, "/api/analytics/sessions"},
	{http.MethodGet, "/api/analytics/file-hotspots"},
	{http.MethodGet, "/api/analytics/project-breakdown"},
	{http.MethodGet, "/api/analytics/concepts"},
	{http.MethodGet, "/api/analytics/summary"},
	{http.MethodGet, "/api/analytics/bugfix-ratio"},
	{http.MethodGet, "/api/analytics/devices"},
	{http.MethodGet, "/api/mcp/search?query=secret"},
	{http.MethodGet, "/api/mcp/timeline"},
	{http.MethodPost, "/api/mcp/observations"},
	// Pre-existing hook API — included so a refactor cannot quietly drop it.
	{http.MethodPost, "/api/capture"},
	{http.MethodGet, "/api/context"},
	{http.MethodPost, "/api/shutdown"},
}

// TestReadEndpointsRequireHookSecret verifies every content-returning route is
// gated by the hook secret. The Host header is valid throughout, so a 401 can
// only come from the auth wrapper.
func TestReadEndpointsRequireHookSecret(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone", hookSecret: "s3cret"}
	h := s.routes()

	for _, tc := range authedPaths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			for _, header := range []string{"", "wrong-secret"} {
				req := httptest.NewRequest(tc.method, tc.path, nil)
				req.Host = "127.0.0.1:5741"
				if header != "" {
					req.Header.Set("X-Hook-Secret", header)
				}
				rec := httptest.NewRecorder()

				h.ServeHTTP(rec, req)

				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s %s with secret %q: got status %d, want 401",
						tc.method, tc.path, header, rec.Code)
				}
			}
		})
	}
}

// TestHealthAndStatusStayUnauthenticated pins the two exceptions. process.go
// polls /api/health to detect a running daemon before any client has read the
// secret, and neither route exposes observation content — only mode, port,
// counts, byte totals, and the embedder model name.
func TestHealthAndStatusStayUnauthenticated(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone", hookSecret: "s3cret"}
	h := s.routes()

	// /api/health touches no server state, so it can be asserted directly.
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Host = "127.0.0.1:5741"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("/api/health without a secret: got status %d, want 200", rec.Code)
	}

	// /api/status reads the storage backend, which this bare Server does not
	// have. Reaching the handler at all — success or nil-backend panic — proves
	// the auth wrapper did not intercept it, which is the property under test.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Logf("/api/status reached its handler and panicked on the absent backend: %v", r)
			}
		}()
		req := httptest.NewRequest(http.MethodGet, "/api/status", nil)
		req.Host = "127.0.0.1:5741"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized {
			t.Error("/api/status without a secret: got 401, want the request to reach the handler")
		}
	}()
}

// TestRequireHookAuthFailsClosed covers the auth wrapper's decision table. The
// critical rows are the empty-configured-secret ones: a daemon that failed to
// generate a secret cannot authenticate anyone, so it must reject every request
// rather than admit all of them.
func TestRequireHookAuthFailsClosed(t *testing.T) {
	const secret = "s3cret"

	cases := []struct {
		name string
		// configured is the server's secret; "" means generation failed.
		configured string
		// header is the X-Hook-Secret value sent; sendHeader false omits it.
		header     string
		sendHeader bool
		wantAuthed bool
	}{
		{name: "empty secret, no header", configured: "", sendHeader: false, wantAuthed: false},
		{name: "empty secret, empty header", configured: "", header: "", sendHeader: true, wantAuthed: false},
		{name: "empty secret, arbitrary header", configured: "", header: "anything", sendHeader: true, wantAuthed: false},
		{name: "empty secret, header matching the empty secret", configured: "", header: "", sendHeader: true, wantAuthed: false},
		{name: "secret set, no header", configured: secret, sendHeader: false, wantAuthed: false},
		{name: "secret set, empty header", configured: secret, header: "", sendHeader: true, wantAuthed: false},
		{name: "secret set, wrong header", configured: secret, header: "wrong", sendHeader: true, wantAuthed: false},
		{name: "secret set, prefix of secret", configured: secret, header: "s3cre", sendHeader: true, wantAuthed: false},
		{name: "secret set, secret plus suffix", configured: secret, header: secret + "x", sendHeader: true, wantAuthed: false},
		{name: "secret set, correct header", configured: secret, header: secret, sendHeader: true, wantAuthed: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A sentinel handler stands in for a real endpoint so the outcome is
			// observable without constructing storage.
			var reached bool
			s := &Server{port: testPort, mode: "standalone", hookSecret: tc.configured}
			h := s.requireHookAuth(func(w http.ResponseWriter, r *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
			req.Host = "127.0.0.1:5741"
			if tc.sendHeader {
				req.Header.Set("X-Hook-Secret", tc.header)
			}
			rec := httptest.NewRecorder()

			h(rec, req)

			if reached != tc.wantAuthed {
				t.Errorf("handler reached = %v, want %v (status %d)", reached, tc.wantAuthed, rec.Code)
			}
			if !tc.wantAuthed && rec.Code != http.StatusUnauthorized {
				t.Errorf("got status %d, want 401", rec.Code)
			}
			if tc.wantAuthed && rec.Code != http.StatusOK {
				t.Errorf("got status %d, want 200", rec.Code)
			}
		})
	}
}

// TestSecretlessServerRejectsEveryGatedRoute is the end-to-end form of the
// fail-closed rule: a Server whose secret generation failed serves none of the
// gated routes, whatever header a caller supplies.
func TestSecretlessServerRejectsEveryGatedRoute(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"} // no hookSecret
	h := s.routes()

	for _, tc := range authedPaths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Host = "127.0.0.1:5741"
			req.Header.Set("X-Hook-Secret", "anything at all")
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s on a secretless daemon: got status %d, want 401",
					tc.method, tc.path, rec.Code)
			}
		})
	}
}

// TestRequireLoopbackHostUsesServerPort verifies the accepted set follows the
// configured port rather than being hardcoded to the default.
func TestRequireLoopbackHostUsesServerPort(t *testing.T) {
	s := &Server{port: 9999, mode: "standalone"}
	h := s.routes()

	checks := []struct {
		host string
		want int
	}{
		{"127.0.0.1:9999", http.StatusOK},
		{"localhost:9999", http.StatusOK},
		{"[::1]:9999", http.StatusOK},
		{"127.0.0.1:5741", http.StatusForbidden},
	}

	for _, c := range checks {
		req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
		req.Host = c.host
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		if rec.Code != c.want {
			t.Errorf("Host %q: got status %d, want %d", c.host, rec.Code, c.want)
		}
	}
}

// --- PATCH /api/observations/{id} ---------------------------------------

// fakeBackend is an in-memory storage.StorageBackend for handler tests. It
// deep-copies on the way in and on the way out, exactly as the real SQLCipher
// backend does by virtue of serializing through a database. Without that, a
// handler that mutated the value it read from GetObservation would appear to
// persist even if it never called SaveObservation, and the partial-update
// assertions below would pass vacuously.
type fakeBackend struct {
	mu    sync.Mutex
	obs   map[string]storage.Observation
	saves int
}

func newFakeBackend(seed ...storage.Observation) *fakeBackend {
	b := &fakeBackend{obs: make(map[string]storage.Observation)}
	for _, o := range seed {
		b.obs[o.ID] = cloneObservation(o)
	}
	return b
}

// cloneObservation copies the fields these tests mutate deeply enough that the
// caller and the store never share backing arrays.
func cloneObservation(o storage.Observation) storage.Observation {
	c := o
	if o.Meta.Tags != nil {
		c.Meta.Tags = append([]string(nil), o.Meta.Tags...)
	}
	return c
}

func (b *fakeBackend) SaveObservation(obs *storage.Observation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.obs[obs.ID] = cloneObservation(*obs)
	b.saves++
	return nil
}

func (b *fakeBackend) GetObservation(id string) (*storage.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	o, ok := b.obs[id]
	if !ok {
		return nil, fmt.Errorf("not found: %s", id)
	}
	c := cloneObservation(o)
	return &c, nil
}

func (b *fakeBackend) ListObservations() ([]storage.Observation, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]storage.Observation, 0, len(b.obs))
	for _, o := range b.obs {
		out = append(out, cloneObservation(o))
	}
	return out, nil
}

func (b *fakeBackend) DeleteObservation(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.obs, id)
	return nil
}

func (b *fakeBackend) ObservationExists(obs *storage.Observation) (bool, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.obs[obs.ID]
	return ok, nil
}

func (b *fakeBackend) ExistsBySource(adapter, machine, sourceID string) (bool, error) {
	return false, nil
}

func (b *fakeBackend) GetStatus() (int, int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.obs), 0, nil
}

func (b *fakeBackend) Close() error { return nil }

// stored reads an observation straight out of the fake, bypassing the handler.
func (b *fakeBackend) stored(t *testing.T, id string) storage.Observation {
	t.Helper()
	o, err := b.GetObservation(id)
	if err != nil {
		t.Fatalf("observation %s missing from backend: %v", id, err)
	}
	return *o
}

const patchTestSecret = "s3cret"

// seedTime is a fixed past timestamp so "UpdatedAt advanced" is unambiguous.
var seedTime = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

// seedObservation is the fixture for the patch tests: every patchable field is
// non-zero, so a handler that clobbers an untouched field is visible.
func seedObservation() storage.Observation {
	return storage.Observation{
		ID: "obs-1",
		Core: storage.Core{
			Title:     "seed title",
			Summary:   "seed summary",
			Type:      "discovery",
			Project:   "sinesync",
			CreatedAt: seedTime,
			UpdatedAt: seedTime,
		},
		Meta: storage.Meta{
			Tags:           []string{"seed-tag"},
			Classification: "private",
			Starred:        true,
			Archived:       true,
		},
		Source: storage.Source{Adapter: "sinesync"},
	}
}

// newPatchTestServer builds a Server complete enough to serve PATCH: a backend,
// a syncManager whose activityChan can absorb a NotifyActivity without blocking
// (NotifyActivity has no nil-receiver guard, so a nil syncManager would panic),
// and a long cache TTL so cache staleness is caused only by the handler.
func newPatchTestServer(seed ...storage.Observation) (*Server, http.Handler, *fakeBackend) {
	backend := newFakeBackend(seed...)
	s := &Server{
		port:        testPort,
		mode:        "standalone",
		hookSecret:  patchTestSecret,
		backend:     backend,
		syncManager: &SyncManager{activityChan: make(chan struct{}, 1)},
		obsCacheTTL: time.Hour,
	}
	return s, s.routes(), backend
}

// patchRequest issues a real HTTP round trip through the full route stack —
// loopback guard, auth wrapper, mux, handler.
func patchRequest(t *testing.T, h http.Handler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/api/observations/"+id, strings.NewReader(body))
	req.Host = "127.0.0.1:5741"
	req.Header.Set("X-Hook-Secret", patchTestSecret)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestPatchObservationUIActions covers the four bodies app.js actually sends,
// including the combined save whose `classification: null` means "clear it".
func TestPatchObservationUIActions(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		check func(t *testing.T, got storage.Observation)
	}{
		{
			name: "star",
			body: `{"starred":true}`,
			check: func(t *testing.T, got storage.Observation) {
				if !got.Meta.Starred {
					t.Error("starred = false, want true")
				}
			},
		},
		{
			name: "unstar",
			body: `{"starred":false}`,
			check: func(t *testing.T, got storage.Observation) {
				if got.Meta.Starred {
					t.Error("starred = true, want false")
				}
			},
		},
		{
			name: "archive",
			body: `{"archived":true}`,
			check: func(t *testing.T, got storage.Observation) {
				if !got.Meta.Archived {
					t.Error("archived = false, want true")
				}
			},
		},
		{
			name: "unarchive",
			body: `{"archived":false}`,
			check: func(t *testing.T, got storage.Observation) {
				if got.Meta.Archived {
					t.Error("archived = true, want false")
				}
			},
		},
		{
			name: "add tag",
			body: `{"tags":["a"]}`,
			check: func(t *testing.T, got storage.Observation) {
				if len(got.Meta.Tags) != 1 || got.Meta.Tags[0] != "a" {
					t.Errorf("tags = %v, want [a]", got.Meta.Tags)
				}
			},
		},
		{
			// The btn-save body: tags plus an explicit null classification,
			// which is how the dashboard's "None" option clears the field.
			name: "combined save clearing classification",
			body: `{"tags":["seed-tag","b"],"classification":null}`,
			check: func(t *testing.T, got storage.Observation) {
				if got.Meta.Classification != "" {
					t.Errorf("classification = %q, want it cleared to \"\"", got.Meta.Classification)
				}
				if len(got.Meta.Tags) != 2 || got.Meta.Tags[0] != "seed-tag" || got.Meta.Tags[1] != "b" {
					t.Errorf("tags = %v, want [seed-tag b]", got.Meta.Tags)
				}
			},
		},
		{
			name: "set classification",
			body: `{"classification":"team"}`,
			check: func(t *testing.T, got storage.Observation) {
				if got.Meta.Classification != "team" {
					t.Errorf("classification = %q, want team", got.Meta.Classification)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, h, backend := newPatchTestServer(seedObservation())

			rec := patchRequest(t, h, "obs-1", tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("PATCH %s: got status %d (%s), want 200", tc.body, rec.Code, rec.Body.String())
			}
			tc.check(t, backend.stored(t, "obs-1"))
		})
	}
}

// TestPatchObservationLeavesOtherFieldsUnchanged is the property the whole
// load-read-merge-save shape exists to protect: patching one field must not
// reset the three it did not mention, nor any core content.
func TestPatchObservationLeavesOtherFieldsUnchanged(t *testing.T) {
	// Each case names the field it patches; every other patchable field must
	// still hold its seeded value afterwards.
	cases := []struct {
		field string
		body  string
	}{
		{"starred", `{"starred":false}`},
		{"archived", `{"archived":false}`},
		{"tags", `{"tags":["replaced"]}`},
		{"classification", `{"classification":"public"}`},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			seed := seedObservation()
			_, h, backend := newPatchTestServer(seed)

			rec := patchRequest(t, h, "obs-1", tc.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("got status %d (%s), want 200", rec.Code, rec.Body.String())
			}
			got := backend.stored(t, "obs-1")

			if tc.field != "starred" && got.Meta.Starred != seed.Meta.Starred {
				t.Errorf("patching %s changed starred: %v, want %v", tc.field, got.Meta.Starred, seed.Meta.Starred)
			}
			if tc.field != "archived" && got.Meta.Archived != seed.Meta.Archived {
				t.Errorf("patching %s changed archived: %v, want %v", tc.field, got.Meta.Archived, seed.Meta.Archived)
			}
			if tc.field != "tags" && !reflect.DeepEqual(got.Meta.Tags, seed.Meta.Tags) {
				t.Errorf("patching %s changed tags: %v, want %v", tc.field, got.Meta.Tags, seed.Meta.Tags)
			}
			if tc.field != "classification" && got.Meta.Classification != seed.Meta.Classification {
				t.Errorf("patching %s changed classification: %q, want %q", tc.field, got.Meta.Classification, seed.Meta.Classification)
			}

			// Core content is not patchable at all and must survive untouched.
			if got.Core.Title != seed.Core.Title || got.Core.Summary != seed.Core.Summary ||
				got.Core.Type != seed.Core.Type || got.Core.Project != seed.Core.Project {
				t.Errorf("patching %s altered core content: %+v", tc.field, got.Core)
			}
			if !got.Core.CreatedAt.Equal(seed.Core.CreatedAt) {
				t.Errorf("patching %s altered createdAt: %v, want %v", tc.field, got.Core.CreatedAt, seed.Core.CreatedAt)
			}
		})
	}
}

// TestPatchObservationRejectsUnknownFields verifies the allowlist. A rejected
// body must leave the stored observation exactly as it was — no partial
// application of the fields that happened to be valid.
func TestPatchObservationRejectsUnknownFields(t *testing.T) {
	bodies := []string{
		`{"notes":"injected"}`,
		`{"vaultId":"other-vault"}`,
		`{"title":"rewritten"}`,
		`{"id":"obs-2"}`,
		`{"core":{"title":"rewritten"}}`,
		// A valid field alongside an invalid one must still reject wholesale.
		`{"starred":false,"notes":"injected"}`,
		`{"tags":["a"],"embedding":{"vector":[1]}}`,
	}

	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			seed := seedObservation()
			_, h, backend := newPatchTestServer(seed)

			rec := patchRequest(t, h, "obs-1", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PATCH %s: got status %d (%s), want 400", body, rec.Code, rec.Body.String())
			}

			got := backend.stored(t, "obs-1")
			if !reflect.DeepEqual(got, seed) {
				t.Errorf("rejected PATCH still modified the observation:\n got %+v\nwant %+v", got, seed)
			}
			if backend.saves != 0 {
				t.Errorf("rejected PATCH called SaveObservation %d times, want 0", backend.saves)
			}
		})
	}
}

// TestPatchObservationInvalidValues covers well-named fields carrying values
// the handler cannot honour.
func TestPatchObservationInvalidValues(t *testing.T) {
	bodies := []string{
		`{"starred":"yes"}`,
		`{"starred":null}`,
		`{"archived":1}`,
		`{"tags":"a"}`,
		`{"tags":[1]}`,
		`{"classification":"top-secret"}`,
		`{"classification":5}`,
		`not json at all`,
	}

	for _, body := range bodies {
		t.Run(body, func(t *testing.T) {
			seed := seedObservation()
			_, h, backend := newPatchTestServer(seed)

			rec := patchRequest(t, h, "obs-1", body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PATCH %s: got status %d (%s), want 400", body, rec.Code, rec.Body.String())
			}
			if got := backend.stored(t, "obs-1"); !reflect.DeepEqual(got, seed) {
				t.Errorf("rejected PATCH modified the observation:\n got %+v\nwant %+v", got, seed)
			}
		})
	}
}

// TestPatchObservationInvalidatesCache pins the reason invalidateCache is
// called: the dashboard's list view is served from obsCache, so a PATCH that
// does not invalidate leaves the UI showing the pre-edit value for a full TTL.
// The TTL here is an hour, so only the invalidation can refresh it.
func TestPatchObservationInvalidatesCache(t *testing.T) {
	s, h, _ := newPatchTestServer(seedObservation())

	// Prime the cache with the pre-edit value.
	before := s.getObservations()
	if len(before) != 1 {
		t.Fatalf("primed cache has %d observations, want 1", len(before))
	}
	if !before[0].Meta.Starred {
		t.Fatalf("primed cache: starred = false, want the seeded true")
	}

	rec := patchRequest(t, h, "obs-1", `{"starred":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d (%s), want 200", rec.Code, rec.Body.String())
	}

	after := s.getObservations()
	if len(after) != 1 {
		t.Fatalf("cache has %d observations after PATCH, want 1", len(after))
	}
	if after[0].Meta.Starred {
		t.Error("cache still reports starred = true after PATCH; invalidateCache did not run")
	}
}

// TestPatchObservationAdvancesUpdatedAt guards the sync path. SaveObservation
// persists Core.UpdatedAt verbatim and the push decision gates on comparing it
// to the last-uploaded timestamp, so a PATCH that leaves UpdatedAt alone is
// never pushed to the cloud — the edit would be silently local-only forever.
func TestPatchObservationAdvancesUpdatedAt(t *testing.T) {
	_, h, backend := newPatchTestServer(seedObservation())

	start := time.Now()
	rec := patchRequest(t, h, "obs-1", `{"starred":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d (%s), want 200", rec.Code, rec.Body.String())
	}

	got := backend.stored(t, "obs-1").Core.UpdatedAt
	if !got.After(seedTime) {
		t.Errorf("updatedAt = %v, want strictly after the seeded %v", got, seedTime)
	}
	if got.Before(start) {
		t.Errorf("updatedAt = %v, want at or after the request time %v", got, start)
	}
}

// TestObservationRejectsUnsupportedMethods keeps the default arm of the method
// switch covered: adding PATCH must not have opened the route to everything.
func TestObservationRejectsUnsupportedMethods(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPost, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			_, h, backend := newPatchTestServer(seedObservation())

			req := httptest.NewRequest(method, "/api/observations/obs-1", strings.NewReader(`{"starred":false}`))
			req.Host = "127.0.0.1:5741"
			req.Header.Set("X-Hook-Secret", patchTestSecret)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s: got status %d (%s), want 405", method, rec.Code, rec.Body.String())
			}
			if backend.saves != 0 {
				t.Errorf("%s called SaveObservation %d times, want 0", method, backend.saves)
			}
		})
	}
}

// TestPatchUnknownObservationIsNotFound checks the load step fails cleanly and
// does not create an observation as a side effect.
func TestPatchUnknownObservationIsNotFound(t *testing.T) {
	_, h, backend := newPatchTestServer(seedObservation())

	rec := patchRequest(t, h, "does-not-exist", `{"starred":true}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got status %d (%s), want 404", rec.Code, rec.Body.String())
	}
	if backend.saves != 0 {
		t.Errorf("PATCH of a missing id called SaveObservation %d times, want 0", backend.saves)
	}
}
