package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// errTooManyTickets means too many unredeemed tickets are outstanding. Minting
// refuses rather than evicting, so a flood cannot displace a ticket a genuine
// dashboard launch is about to redeem.
var errTooManyTickets = errors.New("too many outstanding tickets")

// Single-use tickets exist so no long-lived credential appears in a process
// argument list.
//
// `sinesync dashboard` has to hand something to a browser it is launching, and
// the only channel it has is the URL. A fragment keeps that value out of the
// request line, access logs, and Referer headers — but the URL is still passed
// to `open`/`xdg-open`/`start` as an argv element, and argv is readable by every
// account on the machine via `ps` or /proc/<pid>/cmdline. If the browser was not
// already running, the opener may exec it WITH that URL, so the exposure lasts
// as long as the browser rather than milliseconds. The hook secret must never go
// there: that is exactly the local attacker its 0600 file mode excludes.
//
// RESIDUAL RISK, stated plainly because the ticket does not remove it.
//
// Single-use makes this a race, not a barrier. Another local account polling
// /proc or process-exec events can read the ticket while the browser is still
// starting and redeem it first; the dashboard then gets a 401 and the attacker
// gets whatever redemption returns.
//
// So redemption returns a scoped SESSION TOKEN, never the hook secret. What a
// session can do is bounded on two axes: it reaches only the routes behind
// requireDashboardAuth — no capture, no summarize, no shutdown, no minting
// further tickets, none of the MCP routes — and within those it cannot DELETE,
// because deletion propagates to every synced device. It also expires, and is
// invalidated by a daemon restart. Losing the race therefore costs a bounded,
// recoverable disclosure rather than the master credential.
//
// Closing the race entirely needs a bootstrap channel that is not argv — an
// interactive confirmation code, or a 0600 file handoff. Both cost the
// one-command auto-open, which is why neither was taken here.
const (
	ticketTTL     = 60 * time.Second
	ticketBytes   = 32
	maxLiveTicket = 32 // bounds memory if something mints in a loop

	// Dashboard sessions outlive the ticket that created them but not the
	// daemon: they live in memory only, so a restart invalidates every one.
	sessionTTL     = 12 * time.Hour
	sessionBytes   = 32
	maxLiveSession = 64
)

// mintTicket issues a single-use ticket and records its expiry.
func (s *Server) mintTicket() (string, error) {
	raw := make([]byte, ticketBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	ticket := hex.EncodeToString(raw)

	s.ticketsMu.Lock()
	defer s.ticketsMu.Unlock()
	if s.tickets == nil {
		s.tickets = make(map[string]time.Time)
	}
	s.pruneTicketsLocked()
	// Refuse to grow without bound rather than evicting, so a flood cannot push
	// out a ticket a legitimate dashboard launch is about to redeem.
	if len(s.tickets) >= maxLiveTicket {
		return "", errTooManyTickets
	}
	s.tickets[ticket] = time.Now().Add(ticketTTL)
	return ticket, nil
}

// redeemTicket consumes a ticket, returning false if it is unknown or expired.
// A ticket is deleted on the first successful redemption, so a second use of
// the same value — including one recovered from argv — fails.
func (s *Server) redeemTicket(ticket string) bool {
	if ticket == "" {
		return false
	}
	s.ticketsMu.Lock()
	defer s.ticketsMu.Unlock()
	if s.tickets == nil {
		return false
	}
	expiry, ok := s.tickets[ticket]
	if !ok {
		return false
	}
	delete(s.tickets, ticket)
	return time.Now().Before(expiry)
}

func (s *Server) pruneTicketsLocked() {
	now := time.Now()
	for t, expiry := range s.tickets {
		if now.After(expiry) {
			delete(s.tickets, t)
		}
	}
}

// handleAuthTicket mints a ticket for a caller that already proved it can read
// the hook secret. Registered behind requireHookAuth, so only a process able to
// read the 0600 secret file can obtain one.
func (s *Server) handleAuthTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ticket, err := s.mintTicket()
	if err != nil {
		http.Error(w, "could not mint ticket", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]string{"ticket": ticket})
}

// handleAuthRedeem exchanges a valid ticket for a scoped session token.
//
// This endpoint deliberately does NOT require the hook secret: it is what the
// browser calls before it has any credential at all. It is still reachable only
// through the loopback Host check, and POST-only so it cannot be driven by a
// bare navigation or an <img> tag.
func (s *Server) handleAuthRedeem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Ticket string `json:"ticket"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.redeemTicket(body.Ticket) {
		http.Error(w, "ticket is invalid, expired, or already used", http.StatusUnauthorized)
		return
	}

	// Deliberately NOT s.hookSecret — see the residual-risk note above. The
	// ticket can be raced out of argv, so what it buys must be worth less than
	// the master credential.
	session, err := s.mintSession()
	if err != nil {
		http.Error(w, "could not create a session", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, map[string]string{"token": session})
}

// mintSession issues a dashboard session token: scoped, expiring, and
// invalidated by a daemon restart because it is never persisted.
func (s *Server) mintSession() (string, error) {
	raw := make([]byte, sessionBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := hex.EncodeToString(raw)

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	if s.sessions == nil {
		s.sessions = make(map[string]time.Time)
	}
	now := time.Now()
	for t, expiry := range s.sessions {
		if now.After(expiry) {
			delete(s.sessions, t)
		}
	}

	// Evict the oldest rather than refusing, which is the opposite of the ticket
	// policy and deliberately so. A ticket lives 60s, so refusing protects one
	// that is about to be redeemed from being displaced by a flood. A session
	// lives 12h, and every `sinesync dashboard` mints another with no logout to
	// release it — so refusing at the cap would mean the dashboard simply stops
	// working after enough ordinary launches. Evicting costs a stale tab its
	// session; refusing costs the user the feature.
	for len(s.sessions) >= maxLiveSession {
		var oldest string
		var oldestExpiry time.Time
		for t, expiry := range s.sessions {
			if oldest == "" || expiry.Before(oldestExpiry) {
				oldest, oldestExpiry = t, expiry
			}
		}
		if oldest == "" {
			break
		}
		delete(s.sessions, oldest)
	}

	s.sessions[token] = now.Add(sessionTTL)
	return token, nil
}

// validSession reports whether token is a live dashboard session. Unlike a
// ticket it is NOT consumed — the dashboard makes many calls per page load.
func (s *Server) validSession(token string) bool {
	if token == "" {
		return false
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	expiry, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		delete(s.sessions, token)
		return false
	}
	return true
}
