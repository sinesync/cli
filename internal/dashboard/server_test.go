package dashboard

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

const testPort = DefaultPort

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
// including the static file server.
func TestRequireLoopbackHostGatesAllRoutes(t *testing.T) {
	s := &Server{port: testPort}
	h := s.routes()

	// Rejected hosts are checked against every kind of route, including API
	// handlers that need a storage backend the test does not construct — the
	// guard must stop them before routing. Accepted hosts only exercise the
	// static routes, which are safe to run against a bare Server.
	allPaths := []string{"/", "/index.html", "/api/stats", "/api/observations", "/does-not-exist"}
	safePaths := []string{"/", "/index.html", "/does-not-exist"}

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

// TestRequireLoopbackHostUsesServerPort verifies the accepted set follows the
// configured port rather than being hardcoded to the default.
func TestRequireLoopbackHostUsesServerPort(t *testing.T) {
	s := &Server{port: 9999}
	h := s.routes()

	checks := []struct {
		host   string
		reject bool
	}{
		{"127.0.0.1:9999", false},
		{"localhost:9999", false},
		{"[::1]:9999", false},
		{"127.0.0.1:5741", true},
	}

	for _, c := range checks {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = c.host
		rec := httptest.NewRecorder()

		h.ServeHTTP(rec, req)

		if got := rec.Code == http.StatusForbidden; got != c.reject {
			t.Errorf("Host %q: forbidden=%v (status %d), want forbidden=%v", c.host, got, rec.Code, c.reject)
		}
	}
}
