package daemon

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
