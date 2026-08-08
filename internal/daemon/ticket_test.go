package daemon

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const ticketTestSecret = "test-hook-secret"

func newTicketServer() *Server {
	return &Server{port: 5741, mode: "standalone", hookSecret: ticketTestSecret}
}

// A ticket is worth exactly one redemption. This is the property the whole
// mechanism exists for: a value scraped out of argv after the page loaded must
// be useless.
func TestTicketIsSingleUse(t *testing.T) {
	s := newTicketServer()

	ticket, err := s.mintTicket()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !s.redeemTicket(ticket) {
		t.Fatal("first redemption failed; a freshly minted ticket must be valid")
	}
	if s.redeemTicket(ticket) {
		t.Fatal("SECOND redemption succeeded — ticket is replayable, which defeats the fix")
	}
}

func TestTicketRejects(t *testing.T) {
	s := newTicketServer()
	valid, err := s.mintTicket()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	cases := []struct {
		name   string
		ticket string
	}{
		{"empty", ""},
		{"never minted", "deadbeef"},
		{"prefix of a valid ticket", valid[:len(valid)-1]},
		{"valid ticket with suffix", valid + "0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if s.redeemTicket(tc.ticket) {
				t.Errorf("redeemTicket(%q) accepted a ticket it should reject", tc.ticket)
			}
		})
	}
	// The valid one must still work — the rejections above must not have consumed it.
	if !s.redeemTicket(valid) {
		t.Error("a failed redemption consumed an unrelated valid ticket")
	}
}

func TestTicketExpires(t *testing.T) {
	s := newTicketServer()
	ticket, err := s.mintTicket()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	// Reach in and backdate rather than sleeping for the real TTL.
	s.ticketsMu.Lock()
	s.tickets[ticket] = time.Now().Add(-time.Second)
	s.ticketsMu.Unlock()

	if s.redeemTicket(ticket) {
		t.Fatal("an expired ticket was accepted")
	}
}

func TestTicketMintingIsBounded(t *testing.T) {
	s := newTicketServer()
	for i := 0; i < maxLiveTicket; i++ {
		if _, err := s.mintTicket(); err != nil {
			t.Fatalf("mint %d returned %v before the cap was reached", i, err)
		}
	}
	if _, err := s.mintTicket(); err == nil {
		t.Fatal("minting past maxLiveTicket succeeded; outstanding tickets are unbounded")
	}
}

// Sessions must keep being issued past the cap. There is no logout, and every
// `sinesync dashboard` mints one, so refusing at the cap would mean the
// dashboard silently stops working after enough ordinary launches.
func TestSessionMintingEvictsRatherThanRefusing(t *testing.T) {
	s := newTicketServer()

	var first string
	for i := 0; i < maxLiveSession; i++ {
		token, err := s.mintSession()
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		if i == 0 {
			first = token
		}
	}

	// Well past the cap: every one of these must succeed.
	for i := 0; i < 10; i++ {
		token, err := s.mintSession()
		if err != nil {
			t.Fatalf("mint past cap (%d) failed: %v — the dashboard would be locked out", i, err)
		}
		if !s.validSession(token) {
			t.Fatalf("mint past cap (%d) returned a token that is not valid", i)
		}
	}

	// The oldest was evicted to make room, and the cap still holds.
	if s.validSession(first) {
		t.Error("the oldest session survived; eviction is not happening and the map is unbounded")
	}
	s.sessionsMu.Lock()
	live := len(s.sessions)
	s.sessionsMu.Unlock()
	if live > maxLiveSession {
		t.Errorf("live sessions = %d, exceeds cap %d", live, maxLiveSession)
	}
}

func TestSessionExpires(t *testing.T) {
	s := newTicketServer()
	token, err := s.mintSession()
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	s.sessionsMu.Lock()
	s.sessions[token] = time.Now().Add(-time.Second)
	s.sessionsMu.Unlock()

	if s.validSession(token) {
		t.Fatal("an expired session was accepted")
	}
}

func TestTicketsAreDistinct(t *testing.T) {
	s := newTicketServer()
	seen := map[string]bool{}
	for i := 0; i < maxLiveTicket; i++ {
		ticket, err := s.mintTicket()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if seen[ticket] {
			t.Fatalf("mintTicket returned a duplicate: %s", ticket)
		}
		seen[ticket] = true
	}
}

// The HTTP surface: minting is gated on the secret, redeeming deliberately is
// not, and both sit behind the loopback Host check.
func TestTicketEndpoints(t *testing.T) {
	s := newTicketServer()
	srv := httptest.NewServer(s.routes())
	defer srv.Close()

	const goodHost = "127.0.0.1:5741"

	do := func(method, path, host, secret, body string) *http.Response {
		req, err := http.NewRequest(method, srv.URL+path, bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Host = host
		if secret != "" {
			req.Header.Set("X-Hook-Secret", secret)
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		return resp
	}

	t.Run("minting requires the hook secret", func(t *testing.T) {
		resp := do(http.MethodPost, "/api/auth/ticket", goodHost, "", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("no secret: got %d, want 401", resp.StatusCode)
		}
	})

	t.Run("minting is host gated", func(t *testing.T) {
		resp := do(http.MethodPost, "/api/auth/ticket", "evil.example.com", ticketTestSecret, "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("evil host: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("redeeming is host gated", func(t *testing.T) {
		resp := do(http.MethodPost, "/api/auth/redeem", "evil.example.com", "", `{"ticket":"x"}`)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("evil host: got %d, want 403", resp.StatusCode)
		}
	})

	t.Run("redeeming is POST only", func(t *testing.T) {
		resp := do(http.MethodGet, "/api/auth/redeem", goodHost, "", "")
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET redeem: got %d, want 405", resp.StatusCode)
		}
	})

	t.Run("full round trip yields a session token exactly once", func(t *testing.T) {
		mint := do(http.MethodPost, "/api/auth/ticket", goodHost, ticketTestSecret, "")
		defer mint.Body.Close()
		if mint.StatusCode != http.StatusOK {
			t.Fatalf("mint: got %d, want 200", mint.StatusCode)
		}
		var minted struct {
			Ticket string `json:"ticket"`
		}
		if err := json.NewDecoder(mint.Body).Decode(&minted); err != nil {
			t.Fatalf("decode mint: %v", err)
		}
		if minted.Ticket == "" {
			t.Fatal("mint returned an empty ticket")
		}

		payload := fmt.Sprintf(`{"ticket":%q}`, minted.Ticket)

		first := do(http.MethodPost, "/api/auth/redeem", goodHost, "", payload)
		defer first.Body.Close()
		if first.StatusCode != http.StatusOK {
			t.Fatalf("first redeem: got %d, want 200", first.StatusCode)
		}
		var redeemed struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(first.Body).Decode(&redeemed); err != nil {
			t.Fatalf("decode redeem: %v", err)
		}
		// The whole point of the scoped session: redemption must NOT hand back
		// the master credential, because the ticket can be raced out of argv.
		if redeemed.Token == "" {
			t.Fatal("redeem returned an empty token")
		}
		if redeemed.Token == ticketTestSecret {
			t.Error("redeem returned the HOOK SECRET; a ticket raced out of argv would yield the master credential")
		}
		if !s.validSession(redeemed.Token) {
			t.Error("redeem returned a token the daemon does not recognise as a session")
		}

		second := do(http.MethodPost, "/api/auth/redeem", goodHost, "", payload)
		defer second.Body.Close()
		if second.StatusCode != http.StatusUnauthorized {
			t.Errorf("replayed ticket: got %d, want 401 — this is the argv-scrape case", second.StatusCode)
		}
	})

	t.Run("redeemed token actually authenticates", func(t *testing.T) {
		mint := do(http.MethodPost, "/api/auth/ticket", goodHost, ticketTestSecret, "")
		defer mint.Body.Close()
		if mint.StatusCode != http.StatusOK {
			t.Fatalf("mint: got %d, want 200", mint.StatusCode)
		}
		var minted struct {
			Ticket string `json:"ticket"`
		}
		if err := json.NewDecoder(mint.Body).Decode(&minted); err != nil {
			t.Fatalf("decode mint: %v", err)
		}

		redeem := do(http.MethodPost, "/api/auth/redeem", goodHost, "", fmt.Sprintf(`{"ticket":%q}`, minted.Ticket))
		defer redeem.Body.Close()
		if redeem.StatusCode != http.StatusOK {
			t.Fatalf("redeem: got %d, want 200", redeem.StatusCode)
		}
		var redeemed struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(redeem.Body).Decode(&redeemed); err != nil {
			t.Fatalf("decode redeem: %v", err)
		}
		if redeemed.Token == "" {
			t.Fatal("redeem returned an empty token")
		}

		// Probe the auth layers directly rather than real endpoints: every
		// protected handler needs a storage backend this harness does not wire
		// up, and their nil-backend panic would mask the thing under test.
		probe := func(mw func(http.HandlerFunc) http.HandlerFunc, token string) (reached bool, code int) {
			h := mw(func(http.ResponseWriter, *http.Request) { reached = true })
			req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
			req.Header.Set("X-Hook-Secret", token)
			rec := httptest.NewRecorder()
			h(rec, req)
			return reached, rec.Code
		}

		// A session token reaches the dashboard endpoints...
		if ok, _ := probe(s.requireDashboardAuth, redeemed.Token); !ok {
			t.Error("the session token was rejected by requireDashboardAuth")
		}

		// ...and not the hook API. This is what the scoping exists for: an
		// attacker who wins the argv race cannot capture, shut the daemon down,
		// or mint further tickets.
		if ok, code := probe(s.requireHookAuth, redeemed.Token); ok {
			t.Error("a session token satisfied requireHookAuth — scoping is not enforced")
		} else if code != http.StatusUnauthorized {
			t.Errorf("session token on hook-only route: got %d, want 401", code)
		}

		// The hook secret still reaches both.
		if ok, _ := probe(s.requireHookAuth, ticketTestSecret); !ok {
			t.Error("the hook secret was rejected by requireHookAuth")
		}
		if ok, _ := probe(s.requireDashboardAuth, ticketTestSecret); !ok {
			t.Error("the hook secret was rejected by requireDashboardAuth")
		}

		// And neither layer is trivially permissive.
		if ok, code := probe(s.requireDashboardAuth, redeemed.Token+"x"); ok {
			t.Error("requireDashboardAuth accepted a corrupted session token")
		} else if code != http.StatusUnauthorized {
			t.Errorf("corrupted token: got %d, want 401", code)
		}

		// A session must not DELETE. handleObservation's DELETE removes local
		// data AND marks it for cloud deletion, so it propagates to every
		// device — not something a credential raced out of argv may do.
		probeMethod := func(method, token string) (reached bool, code int) {
			h := s.requireDashboardAuth(func(http.ResponseWriter, *http.Request) { reached = true })
			req := httptest.NewRequest(method, "/api/observations/abc", nil)
			req.Header.Set("X-Hook-Secret", token)
			rec := httptest.NewRecorder()
			h(rec, req)
			return reached, rec.Code
		}

		if ok, code := probeMethod(http.MethodDelete, redeemed.Token); ok {
			t.Error("a session token reached a DELETE handler — it could destroy observations across every device")
		} else if code != http.StatusForbidden {
			t.Errorf("session DELETE: got %d, want 403 (the credential is valid, the scope is not)", code)
		}

		// The hook secret may still delete, or the CLI stops working.
		if ok, _ := probeMethod(http.MethodDelete, ticketTestSecret); !ok {
			t.Error("the hook secret was denied DELETE; the CLI can no longer remove observations")
		}

		// And the mutations the dashboard legitimately needs still pass, or the
		// carve-out has quietly broken tagging and sync.
		for _, m := range []string{http.MethodGet, http.MethodPatch, http.MethodPost} {
			if ok, code := probeMethod(m, redeemed.Token); !ok {
				t.Errorf("session %s was rejected (%d); the dashboard needs it", m, code)
			}
		}
	})
}
