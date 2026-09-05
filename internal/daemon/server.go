package daemon

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sinesync/cli/internal/adapters"
	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/embeddings"
	"github.com/sinesync/cli/internal/keychain"
	"github.com/sinesync/cli/internal/storage"
)

//go:embed static/*
var staticFiles embed.FS

// Server is the unified daemon server (dashboard + hook API)
type Server struct {
	port        int
	backend     storage.StorageBackend
	config      *config.Config
	embedder    *embeddings.Provider
	httpServer  *http.Server
	mode        string // "standalone" or "adapter"
	syncManager *SyncManager

	// Observation cache
	obsCache     []storage.Observation
	obsCacheTime time.Time
	obsCacheTTL  time.Duration
	obsCacheMu   sync.Mutex

	// Async hook processing queue
	hookQueue    chan func()
	hookDone     chan struct{}
	hookShutdown atomic.Bool

	// Shared secret for hook API authentication
	hookSecret string

	// Single-use tickets the dashboard exchanges for a session token, so no
	// long-lived credential ever travels in a URL and therefore never in argv.
	ticketsMu sync.Mutex
	tickets   map[string]time.Time

	// Dashboard sessions: read-only, expiring, memory-only. Weaker than the
	// hook secret on purpose — see internal/daemon/ticket.go.
	sessionsMu sync.Mutex
	sessions   map[string]time.Time

	// Graceful shutdown channel (used by /api/shutdown endpoint)
	shutdownChan chan struct{}

	// Subagent tracking
	pendingSubagents   map[string]*pendingSubagent // keyed by agent_id
	pendingSubagentsMu sync.Mutex
}

// pendingSubagent tracks an in-flight subagent between SubagentStart and SubagentStop.
type pendingSubagent struct {
	AgentID   string
	AgentType string
	SessionID string
	Project   string
	StartedAt time.Time
}

// NewServer creates a new daemon server
func NewServer(port int) *Server {
	if port == 0 {
		port = DefaultPort
	}

	cfg, _ := config.Load()

	// Determine mode from config, fall back to auto-detect for unconfigured installs
	mode := cfg.Mode
	if mode == "" {
		if adapters.IsClaudeMemInstalled() {
			mode = "adapter"
		} else {
			mode = "standalone"
		}
	}

	embedder, _ := embeddings.NewProvider()

	// Try SQLCipher backend first, fall back to LocalStorage
	var backend storage.StorageBackend
	sqlBackend := initSQLCipherBackend()
	if sqlBackend != nil {
		backend = sqlBackend

		// Auto-migrate legacy JSON observations if they exist
		if storage.HasLegacyObservations(config.DataDir()) {
			localSource := storage.NewLocalStorage()
			migrated, err := storage.MigrateLocalToSQLCipher(localSource, sqlBackend)
			if err != nil {
				log.Printf("[daemon] Migration error: %v", err)
			} else if migrated > 0 {
				log.Printf("[daemon] Migrated %d observations from JSON to SQLCipher", migrated)
				if err := storage.RenameLegacyDir(config.DataDir()); err != nil {
					log.Printf("[daemon] Failed to rename legacy dir: %v", err)
				}
			}
		}

		// Backfill embeddings for any observations missing them on startup
		// (e.g. embedder was unavailable when they were captured)
		if embedder != nil {
			go backfillEmbeddings(sqlBackend, embedder)
		}
	} else {
		// initSQLCipherBackend has already explained why, at length. This line
		// only records what was chosen as a result.
		log.Printf("[daemon] Falling back to UNENCRYPTED JSON file storage")
		backend = storage.NewLocalStorage()
	}

	return &Server{
		port:        port,
		backend:     backend,
		config:      cfg,
		embedder:    embedder,
		mode:        mode,
		syncManager: NewSyncManager(backend, mode),
		obsCacheTTL: 30 * time.Second, // Cache for 30 seconds
	}
}

// initSQLCipherBackend attempts to create a SQLCipher storage backend.
// Returns nil if the key is unavailable or the database cannot be opened.
//
// Every failure here is loud, and deliberately so: the caller's fallback writes
// observations as PLAINTEXT JSON. That is a silent reversal of the product's
// central claim, and a one-line log is not enough warning for it. Worse, if an
// encrypted memory.db already exists, falling back does not just lose
// encryption — it hides everything already in that database, which reads to the
// user as data loss.
func initSQLCipherBackend() *storage.SQLCipherStorage {
	dbPath := filepath.Join(config.DataDir(), "memory.db")
	_, dbExists := func() (os.FileInfo, bool) {
		fi, err := os.Stat(dbPath)
		return fi, err == nil
	}()

	warnPlaintext := func(reason, remedy string) {
		log.Printf("[daemon] ================ ENCRYPTION UNAVAILABLE ================")
		log.Printf("[daemon] %s", reason)
		log.Printf("[daemon] Observations will be written as PLAINTEXT JSON under %s.", config.DataDir())
		if dbExists {
			log.Printf("[daemon] An encrypted database exists at %s and will NOT be readable", dbPath)
			log.Printf("[daemon] in this session. Its contents are intact but hidden — this is not data loss.")
		}
		log.Printf("[daemon] %s", remedy)
		log.Printf("[daemon] ========================================================")
	}

	key, err := keychain.GetOrCreateDBKey()
	if err != nil {
		if errors.Is(err, keychain.ErrNoKeychainSession) {
			// Expected whenever the daemon is started outside a desktop session:
			// nohup, SSH, CI, or spawned by another tool. No keychain call was
			// made, so nothing prompted and no key was replaced.
			warnPlaintext(
				"No OS keychain is reachable from this process, so the database key could not be resolved.",
				"Start the daemon from a desktop session, or set SINESYNC_NO_KEYCHAIN=1 to acknowledge this deliberately.",
			)
		} else {
			// Off darwin this is the only branch a missing keychain can reach:
			// there is no availability probe outside macOS, so an unreachable
			// Secret Service arrives here as its own D-Bus error rather than as
			// ErrNoKeychainSession. The remedy has to cover that case too.
			warnPlaintext(
				fmt.Sprintf("The database key could not be resolved: %v", err),
				"In a desktop session this is unexpected — check the keychain entry for 'sinesync'. "+
					"On a machine with no keyring service at all, set SINESYNC_NO_KEYCHAIN=1 to acknowledge this deliberately.",
			)
		}
		return nil
	}

	db, err := storage.NewSQLCipherStorage(dbPath, key)
	if err != nil {
		warnPlaintext(
			fmt.Sprintf("The encrypted database could not be opened: %v", err),
			"If the keychain entry was replaced, the existing database cannot be decrypted with the current key.",
		)
		return nil
	}

	log.Printf("[daemon] Using SQLCipher encrypted storage")
	return db
}

// backfillEmbeddings generates embeddings for observations that lack them.
func backfillEmbeddings(backend *storage.SQLCipherStorage, embedder *embeddings.Provider) {
	if !embedder.IsReady() {
		log.Printf("[backfill] Skipping: embedder not ready")
		return
	}

	observations, err := backend.ListObservations()
	if err != nil {
		log.Printf("[backfill] Failed to list observations: %v", err)
		return
	}

	// Count how many need embeddings
	needsEmbedding := 0
	for _, obs := range observations {
		if !obs.Embedding.IsCompatibleWith(embeddings.ModelName, embeddings.TokenizerType, embeddings.Dimensions) {
			needsEmbedding++
		}
	}
	if needsEmbedding == 0 {
		log.Printf("[backfill] All %d observations have compatible embeddings", len(observations))
		return
	}
	log.Printf("[backfill] Starting: %d/%d observations need embeddings", needsEmbedding, len(observations))

	backfilled := 0
	failed := 0
	for _, obs := range observations {
		if obs.Embedding.IsCompatibleWith(embeddings.ModelName, embeddings.TokenizerType, embeddings.Dimensions) {
			continue
		}
		obsCopy := obs
		text := obsCopy.TextForEmbedding()
		vec, err := embedder.Embed(text)
		if err != nil {
			failed++
			if failed <= 3 {
				log.Printf("[migrate] WARNING: embedding failed for %s: %v", obsCopy.ID, err)
			}
			continue
		}
		obsCopy.Embedding.Vector = vec
		obsCopy.Embedding.Model = embeddings.ModelName
		obsCopy.Embedding.Tokenizer = embedder.TokenizerType()
		obsCopy.Embedding.Dims = embeddings.Dimensions
		if err := backend.SaveObservation(&obsCopy); err == nil {
			backfilled++
		}
	}

	log.Printf("[backfill] Complete: %d embedded, %d failed, %d already had embeddings", backfilled, failed, len(observations)-needsEmbedding)
}

// getObservations returns cached observations, refreshing if stale
func (s *Server) getObservations() []storage.Observation {
	s.obsCacheMu.Lock()
	defer s.obsCacheMu.Unlock()

	if time.Since(s.obsCacheTime) > s.obsCacheTTL || s.obsCache == nil {
		log.Printf("[cache] Loading observations into cache...")
		start := time.Now()
		s.obsCache, _ = s.backend.ListObservations()
		s.obsCacheTime = time.Now()
		log.Printf("[cache] Cached %d observations in %v", len(s.obsCache), time.Since(start))
	}
	return s.obsCache
}

// invalidateCache forces a cache refresh on next access
func (s *Server) invalidateCache() {
	s.obsCacheMu.Lock()
	s.obsCacheTime = time.Time{}
	s.obsCacheMu.Unlock()
}

// processHookQueue drains the async work queue with panic recovery.
func (s *Server) processHookQueue() {
	defer close(s.hookDone)
	for work := range s.hookQueue {
		s.safeExec(work)
	}
}

func (s *Server) safeExec(fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[hook] Panic in queued work: %v", r)
		}
	}()
	fn()
}

// enqueueHook submits work to the async queue. Drops if shutting down or full.
func (s *Server) enqueueHook(fn func()) {
	if s.hookShutdown.Load() {
		return
	}
	select {
	case s.hookQueue <- fn:
	default:
		log.Printf("[hook] Queue full, dropping work item")
	}
}

// requireHookAuth wraps a handler to require the hook secret in the X-Hook-Secret header.
//
// It fails closed: if s.hookSecret is empty the server has no way to
// authenticate anyone, so every request is rejected rather than admitted. An
// empty secret means secret generation failed, and the endpoints behind this
// wrapper return observation content — serving them unauthenticated to every
// local account would be worse than serving nothing. Run refuses to start in
// that state, so this branch is a backstop rather than a live path.
func (s *Server) requireHookAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.hookSecret == "" {
			http.Error(w, "unauthorized: daemon has no hook secret configured", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Hook-Secret")), []byte(s.hookSecret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

// requireDashboardAuth guards the endpoints the browser dashboard needs. It
// accepts either the hook secret or a live dashboard session token, both
// presented in X-Hook-Secret.
//
// The two are deliberately not equivalent, and the gap is the containment the
// ticket race needs. The hook secret is the master credential and reaches
// everything. A session token reaches only the handlers behind this wrapper —
// capture, summarize, shutdown, ticket minting and the MCP routes all stay on
// requireHookAuth — and, within them, cannot DELETE.
//
// DELETE is carved out specifically, rather than sessions being restricted to
// GET, because the dashboard has a real non-GET feature that works: the sync
// button POSTs to /api/sync, which is behind this wrapper and triggers a sync.
// A GET-only session token would break it for no security gain — the worst a
// spurious sync does is cost bandwidth, and it is repeatable.
//
// Deleting an observation is the opposite. handleDeleteObservation also marks
// it for cloud deletion, so it propagates to every device and there is nothing
// to undo it with. A credential that can be raced out of argv must not be able
// to destroy data, so DELETE requires the hook secret, which in practice means
// the CLI.
//
// PATCH on /api/observations/{id} is deliberately on the permitted side. The
// dashboard's star, archive, tag and classification controls issue it, and a
// session token can reach it. That is a considered position, not an oversight:
// every field PATCH can touch is inert display metadata. Starred and Archived
// are read only by the stats counters, by the archived filter on the list view,
// and by the JSON projection; Classification is read only by a stats counter
// and that same projection. Nothing in the tree branches on a classification
// value — "sensitive" in particular gates no encryption, no vault routing and
// no access decision. So the worst a raced session token achieves is scrambling
// metadata the user can re-edit from the same UI, which is categorically unlike
// DELETE destroying data on every device with nothing to undo it.
//
// Note for anyone widening this further: that argument is about these four
// fields specifically, not about PATCH as a method. Admitting a field that some
// other code path actually branches on — a vault ID, a notes body that gets
// indexed, anything consulted for an access decision — would need this
// reasoning redone, not merely extended.
func (s *Server) requireDashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.hookSecret == "" {
			http.Error(w, "unauthorized: daemon has no hook secret configured", http.StatusUnauthorized)
			return
		}
		presented := r.Header.Get("X-Hook-Secret")
		if subtle.ConstantTimeCompare([]byte(presented), []byte(s.hookSecret)) == 1 {
			next(w, r)
			return
		}
		if s.validSession(presented) {
			if r.Method == http.MethodDelete {
				// 403 not 401: the credential is valid, the scope is not. A 401
				// would tell the dashboard its token had expired and send the
				// user round a re-authentication loop that cannot help.
				http.Error(w, "forbidden: deleting requires the hook secret; use 'sinesync forget <id>'", http.StatusForbidden)
				return
			}
			next(w, r)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// HookSecretPath is where the daemon writes its shared secret, mode 0600.
func HookSecretPath() string {
	return filepath.Join(config.DataDir(), "hook-secret")
}

// ReadHookSecret reads the secret a running daemon wrote at startup. Returns ""
// when it cannot be read, which callers treat as "send no header" and let the
// daemon answer 401 rather than guessing.
func ReadHookSecret() string {
	data, err := os.ReadFile(HookSecretPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// generateHookSecret creates a random secret and writes it to a 0600 file.
func (s *Server) generateHookSecret() error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("generate hook secret: %w", err)
	}
	s.hookSecret = fmt.Sprintf("%x", b)

	return os.WriteFile(HookSecretPath(), []byte(s.hookSecret), 0600)
}

// hostAllowed reports whether a request's Host header is exactly one of the
// loopback forms this server listens on. The comparison is deliberately exact:
// anything else (wrong port, missing port, non-loopback address, or a hostname
// that merely resembles one) is rejected, which blocks DNS rebinding attacks
// that resolve an attacker-controlled name to 127.0.0.1.
func hostAllowed(host string, port int) bool {
	p := strconv.Itoa(port)
	switch host {
	case "127.0.0.1:" + p, "localhost:" + p, "[::1]:" + p:
		return true
	}
	return false
}

// absoluteFormTarget reports whether a request arrived with a non origin-form
// request-target — an absolute-form target (`GET http://host/path HTTP/1.1`) or
// the authority-form CONNECT uses.
//
// This has to be checked separately from hostAllowed because of how net/http
// populates the request. Per RFC 7230 §5.3.2 the authority in an absolute-form
// target takes precedence over the Host header, so net/http sets r.Host from the
// target's authority and then DELETES the Host header from r.Header entirely.
// The handler cannot see the header at all: r.Header.Get("Host") is "".
//
// So a request-target naming the loopback authority satisfies hostAllowed no
// matter what the Host header said, and the header the guard exists to police is
// unreachable by the time the guard runs:
//
//	GET http://127.0.0.1:5741/api/health HTTP/1.1
//	Host: evil.example.com          <- discarded; r.Host is 127.0.0.1:5741
//
// Cross-checking the two against each other is therefore not implementable in an
// http.Handler, and rejecting is the option that remains. It costs nothing: an
// absolute-form target is what a client sends to a PROXY, and this is an origin
// server on loopback. No browser emits one for an origin request, and no
// legitimate client of this daemon has a reason to.
func absoluteFormTarget(u *url.URL) bool {
	return u.IsAbs() || u.Host != ""
}

// requireLoopbackHost wraps h so every request — API, status, and static alike —
// is rejected with 403 unless it is an ordinary origin-form request whose Host
// header names this server's loopback address.
func (s *Server) requireLoopbackHost(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Before hostAllowed, not after: for a proxy-form target r.Host is
		// attacker-chosen and would sail through the check below.
		if absoluteFormTarget(r.URL) {
			http.Error(w, "forbidden: absolute-form request-target", http.StatusForbidden)
			return
		}
		if !hostAllowed(r.Host, s.port) {
			http.Error(w, "forbidden: invalid Host header", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// contentSecurityPolicy is served with every dashboard asset.
//
// The dashboard needs nothing off-origin: d3 is vendored as static/d3.min.js,
// index.html has no inline <script>, and style.css contains no url() or
// @import. So 'self' everywhere costs the page nothing. 'unsafe-inline'
// survives under style-src alone, for the one style="display:none" attribute
// in index.html.
//
// This is defence in depth, not the defence. app.js builds every node with
// textContent and DOM properties, so a project named
//
//	<img src=x onerror=alert(1)>"'&
//
// is text, never markup — see TestDashboardScriptHasNoHTMLSinks. The policy is
// what narrows the damage if that invariant is ever broken. What each part
// does, stated no more strongly than it is true:
//
//   - script-src 'self' blocks the injected onerror/onload handler and any
//     remote or data: script it would try to pull in. This is the directive
//     doing the real work against an injected node.
//   - object-src 'none' and base-uri 'none' close the plugin and <base>
//     hijack routes; frame-ancestors 'none' stops the dashboard being framed.
//   - connect-src 'self' confines Fetch, XMLHttpRequest, WebSocket, EventSource
//     and sendBeacon to this origin. It is NOT a guarantee that nothing can
//     leave. Top-level navigation and window.open are not governed by any
//     directive here (navigate-to was never shipped by browsers), form
//     submission is unconstrained because we set no form-action, and any
//     script gadget already running same-origin — including app.js itself —
//     is by definition allowed to talk to this origin. It also offers nothing
//     against a compromise of the origin itself, since 'self' is then the
//     attacker. Read it as removing the easy channel, not as closing the door.
//   - style-src 'unsafe-inline' permits inline styling only: <style> blocks and
//     style="" attributes. It does not re-enable event-handler attributes —
//     those are script and remain blocked by script-src. It is not free
//     either: injected CSS can overlay or restyle the page, and can leak
//     coarse information through attribute selectors that trigger resource
//     loads, which is part of why default-src and img-src stay on 'self'.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'none'; " +
	// The dashboard contains no <form> element, so submission to any origin is
	// pure attack surface: an injected form is one of the few exfiltration
	// channels script-src 'self' leaves open, since navigation is not fetch and
	// connect-src does not constrain it.
	"form-action 'none'; " +
	"frame-ancestors 'none'"

// withDashboardCSP attaches contentSecurityPolicy to static responses. It wraps
// only the file server: the API returns application/json, which a browser never
// renders as a document, so the policy that matters is the one delivered with
// index.html and inherited by everything it loads.
func withDashboardCSP(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", contentSecurityPolicy)
		// CSP governs what a document may load; it does not decide what the
		// browser treats a response AS. Without nosniff, a response whose bytes
		// look like HTML can be sniffed into a document regardless of its
		// declared type, which sidesteps the policy above rather than violating
		// it.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h.ServeHTTP(w, r)
	})
}

// routes builds the full request handler: the mux wrapped in Host validation.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// Health/status endpoints (no auth required). Both return only daemon
	// metadata — liveness, mode, port, counts, byte totals, embedder model —
	// and never observation content. handleHealth in particular is polled by
	// process.go to decide whether a daemon is already running, which happens
	// before any client has a reason to have read the secret.
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/shutdown", s.requireHookAuth(s.handleShutdown))

	// Dashboard bootstrap. Minting needs the secret; redeeming deliberately
	// does not, because it is what the browser calls before it has one. Both
	// still sit behind the loopback Host check applied in routes().
	mux.HandleFunc("/api/auth/ticket", s.requireHookAuth(s.handleAuthTicket))
	mux.HandleFunc("/api/auth/redeem", s.handleAuthRedeem)

	// Hook API endpoints (require hook secret)
	mux.HandleFunc("/api/context", s.requireHookAuth(s.handleContext))
	mux.HandleFunc("/api/capture", s.requireHookAuth(s.handleCapture))
	mux.HandleFunc("/api/summarize", s.requireHookAuth(s.handleSummarize))
	mux.HandleFunc("/api/prompt", s.requireHookAuth(s.handlePrompt))
	mux.HandleFunc("/api/codex-capture", s.requireHookAuth(s.handleCodexCapture))
	mux.HandleFunc("/api/subagent-start", s.requireHookAuth(s.handleSubagentStart))
	mux.HandleFunc("/api/subagent-stop", s.requireHookAuth(s.handleSubagentStop))

	// Dashboard API endpoints (require hook secret — they return observation
	// content, so they are no less sensitive than the hook write API).
	mux.HandleFunc("/api/stats", s.requireDashboardAuth(s.handleStats))
	mux.HandleFunc("/api/observations", s.requireDashboardAuth(s.handleObservations))
	mux.HandleFunc("/api/observations/", s.requireDashboardAuth(s.handleObservation))
	mux.HandleFunc("/api/projects", s.requireDashboardAuth(s.handleProjects))
	mux.HandleFunc("/api/tags", s.requireDashboardAuth(s.handleTags))
	mux.HandleFunc("/api/search", s.requireDashboardAuth(s.handleSearch))
	mux.HandleFunc("/api/sync", s.requireDashboardAuth(s.handleSync))
	mux.HandleFunc("/api/vaults", s.requireDashboardAuth(s.handleVaults))

	// Analytics API endpoints (require hook secret)
	mux.HandleFunc("/api/analytics/activity-heatmap", s.requireDashboardAuth(s.handleActivityHeatmap))
	mux.HandleFunc("/api/analytics/activity-by-hour", s.requireDashboardAuth(s.handleActivityByHour))
	mux.HandleFunc("/api/analytics/type-trend", s.requireDashboardAuth(s.handleTypeTrend))
	mux.HandleFunc("/api/analytics/sessions", s.requireDashboardAuth(s.handleAnalyticsSessions))
	mux.HandleFunc("/api/analytics/file-hotspots", s.requireDashboardAuth(s.handleFileHotspots))
	mux.HandleFunc("/api/analytics/project-breakdown", s.requireDashboardAuth(s.handleProjectBreakdown))
	mux.HandleFunc("/api/analytics/concepts", s.requireDashboardAuth(s.handleConcepts))
	mux.HandleFunc("/api/analytics/summary", s.requireDashboardAuth(s.handleAnalyticsSummary))
	mux.HandleFunc("/api/analytics/bugfix-ratio", s.requireDashboardAuth(s.handleBugfixRatio))
	mux.HandleFunc("/api/analytics/devices", s.requireDashboardAuth(s.handleDevices))

	// MCP API endpoints (3-layer workflow, require hook secret)
	mux.HandleFunc("/api/mcp/search", s.requireHookAuth(s.handleMCPSearch))
	mux.HandleFunc("/api/mcp/timeline", s.requireHookAuth(s.handleMCPTimeline))
	mux.HandleFunc("/api/mcp/observations", s.requireHookAuth(s.handleMCPGetObservations))

	// Static files for dashboard
	staticFS, _ := fs.Sub(staticFiles, "static")
	mux.Handle("/", withDashboardCSP(http.FileServer(http.FS(staticFS))))

	return s.requireLoopbackHost(mux)
}

// Run starts the server and blocks until shutdown
func (s *Server) Run() error {
	// Generate shared secret for hook API authentication. This is fatal: the
	// secret is the only thing standing between the API and every other user
	// account on this machine, and requireHookAuth rejects everything without
	// it, so a daemon that cannot write its secret would serve nothing useful
	// while still holding the port.
	if err := s.generateHookSecret(); err != nil {
		return fmt.Errorf("cannot start daemon: %w", err)
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.routes(),
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	// Write PID file
	if err := WritePIDInfo(&PIDInfo{
		PID:       os.Getpid(),
		Port:      s.port,
		StartedAt: time.Now(),
		Version:   "0.1.0",
	}); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Start async hook processing queue
	s.hookQueue = make(chan func(), 256)
	s.hookDone = make(chan struct{})
	s.shutdownChan = make(chan struct{}, 1)
	s.pendingSubagents = make(map[string]*pendingSubagent)
	go s.processHookQueue()

	// Start background sync
	s.syncManager.Start()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigChan:
		case <-s.shutdownChan:
		}
		log.Printf("[daemon] Shutting down...")
		s.syncManager.Stop()
		s.hookShutdown.Store(true)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx) // stop accepting, wait for in-flight handlers
		close(s.hookQueue)
		<-s.hookDone // drain queued work
		if err := s.backend.Close(); err != nil {
			log.Printf("[daemon] Error closing storage backend: %v", err)
		}
		RemovePIDFile()
	}()

	log.Printf("[daemon] sine~sync starting on http://%s", addr)
	log.Printf("[daemon]   Mode: %s", s.mode)
	log.Printf("[daemon]   Dashboard: run 'sinesync dashboard' (listening on %s)", addr)
	log.Printf("[daemon]   Hook API: http://%s/api/", addr)
	log.Printf("[daemon]   Cloud sync: adaptive (base: %v, max: 60m)", SyncInterval)

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// === Health endpoints ===

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]interface{}{"status": "shutting down"})
	// Trigger graceful shutdown after responding
	select {
	case s.shutdownChan <- struct{}{}:
	default:
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"status": "ok",
		"mode":   s.mode,
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	itemCount, storageBytes, _ := s.backend.GetStatus()

	status := map[string]interface{}{
		"mode": s.mode,
		"port": s.port,
		"storage": map[string]interface{}{
			"observations": itemCount,
			"bytes":        storageBytes,
		},
		"embeddings": map[string]interface{}{
			"ready": s.embedder != nil && s.embedder.IsReady(),
			"model": embeddings.ModelName,
		},
	}

	if s.mode == "adapter" && adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			defer adapter.Close()
			count, _ := adapter.GetObservationCount()
			status["adapter"] = map[string]interface{}{
				"name":         "claude-mem",
				"observations": count,
			}
		}
	}

	writeJSON(w, status)
}

// === Hook API endpoints ===

func (s *Server) handleContext(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	sessionID := r.URL.Query().Get("session_id")
	limit := 20

	// Ensure session exists in SQLCipher
	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			_ = sqlBackend.EnsureSession(sessionID, project, time.Now().Unix())
		}
	}

	observations := s.getObservations()

	// Filter by project if specified
	if project != "" {
		var filtered []storage.Observation
		for _, obs := range observations {
			if obs.Core.Project == project {
				filtered = append(filtered, obs)
			}
		}
		observations = filtered
	}

	// Sort by relevance (for now, just by date)
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Core.CreatedAt.After(observations[j].Core.CreatedAt)
	})

	// Limit
	if len(observations) > limit {
		observations = observations[:limit]
	}

	// Format context output
	var sb strings.Builder
	sb.WriteString("# [sinesync] Recent context\n\n")

	// Check auth status and add sync info
	syncing, lastSync, syncErr := s.syncManager.Status()
	authenticated := s.isAuthenticated()

	if !authenticated {
		sb.WriteString("**Cloud sync disabled** - Run `sinesync login` to enable cross-device sync\n\n")
	} else if syncErr != "" {
		sb.WriteString(fmt.Sprintf("**Sync error**: %s\n\n", syncErr))
	} else if syncing {
		sb.WriteString("**Syncing** to cloud...\n\n")
	} else if !lastSync.IsZero() {
		sb.WriteString(fmt.Sprintf("**Last sync**: %s\n\n", formatRelativeTime(lastSync)))
	}

	for _, obs := range observations {
		sb.WriteString(fmt.Sprintf("**%s** (%s)\n", obs.Core.Title, obs.Core.Type))
		if obs.Core.Summary != "" {
			sb.WriteString(fmt.Sprintf("%s\n", obs.Core.Summary))
		}
		sb.WriteString("\n")
	}

	// Return as hook output format
	writeJSON(w, map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":     "SessionStart",
			"additionalContext": sb.String(),
		},
	})
}

// isAuthenticated checks if user has valid auth tokens
func (s *Server) isAuthenticated() bool {

	// Check keyring first (preferred secure storage)
	if token, err := keychain.Get("token"); err == nil && token != "" {
		return true
	}
	if deviceToken, err := keychain.Get("deviceToken"); err == nil && deviceToken != "" {
		return true
	}

	// Fallback to JSON file
	authPath := filepath.Join(config.ConfigDir(), "auth.json")
	data, err := os.ReadFile(authPath)
	if err != nil {
		return false
	}

	var auth struct {
		DeviceToken string `json:"deviceToken"`
		Token       string `json:"token"`
	}
	if err := json.Unmarshal(data, &auth); err != nil {
		return false
	}

	return auth.DeviceToken != "" || auth.Token != ""
}

func formatRelativeTime(t time.Time) string {
	diff := time.Since(t)
	if diff < time.Minute {
		return "just now"
	}
	if diff < time.Hour {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(diff.Hours()/24))
}

func (s *Server) handleCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID    string          `json:"session_id"`
		ToolName     string          `json:"tool_name"`
		ToolInput    json.RawMessage `json:"tool_input"`
		ToolResponse json.RawMessage `json:"tool_response"`
		CWD          string          `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if skipCaptureTool(hookInput.ToolName) {
		writeJSON(w, map[string]interface{}{"status": "skipped"})
		return
	}

	// Ack immediately — do heavy work (extraction, embedding, save) async
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	s.enqueueHook(func() {
		s.processCapture(hookInput.SessionID, hookInput.ToolName, hookInput.ToolInput, hookInput.ToolResponse, hookInput.CWD)
	})
}

// processCapture does the actual observation extraction, embedding, and save.
func (s *Server) processCapture(sessionID, toolName string, toolInput, toolResponse json.RawMessage, cwd string) {
	project := filepath.Base(cwd)
	log.Printf("[capture] Processing: tool=%s session=%s project=%s", toolName, sessionID, project)

	var toolInputData map[string]interface{}
	json.Unmarshal(toolInput, &toolInputData)

	var toolResponseStr string
	if err := json.Unmarshal(toolResponse, &toolResponseStr); err != nil {
		toolResponseStr = string(toolResponse)
	}

	obs := s.extractObservation(toolName, toolInputData, toolResponseStr, project)
	if obs == nil {
		return
	}

	textForEmbedding := obs.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			obs.Embedding.Vector = embedding
			obs.Embedding.Model = embeddings.ModelName
			obs.Embedding.Tokenizer = s.embedder.TokenizerType()
			obs.Embedding.Dims = embeddings.Dimensions
		} else {
			log.Printf("[capture] WARNING: embedding failed for %s: %v", obs.ID, err)
		}
	} else {
		log.Printf("[capture] WARNING: embedder not available, observation %s will have no embedding", obs.ID)
	}

	obs.Core.SessionID = sessionID

	// Ensure session row exists before saving (FK constraint)
	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			if err := sqlBackend.EnsureSession(sessionID, obs.Core.Project, obs.Source.Epoch); err != nil {
				log.Printf("[capture] Failed to ensure session %s for project %s: %v", sessionID, obs.Core.Project, err)
				return
			}
		}
	}

	if err := s.backend.SaveObservation(obs); err != nil {
		log.Printf("[capture] Failed to save observation: %v", err)
		return
	}
	s.invalidateCache()
	s.syncManager.NotifyActivity()

	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			_ = sqlBackend.IncrementSessionObservationCount(sessionID)
		}
	}

	log.Printf("[capture] Saved: id=%s type=%s project=%s", obs.ID, obs.Core.Type, obs.Core.Project)
}

// === Subagent hooks ===

func (s *Server) handleSubagentStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID string `json:"session_id"`
		AgentID   string `json:"agent_id"`
		AgentType string `json:"agent_type"`
		CWD       string `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if hookInput.AgentID != "" {
		s.pendingSubagentsMu.Lock()
		s.pendingSubagents[hookInput.AgentID] = &pendingSubagent{
			AgentID:   hookInput.AgentID,
			AgentType: hookInput.AgentType,
			SessionID: hookInput.SessionID,
			Project:   filepath.Base(hookInput.CWD),
			StartedAt: time.Now(),
		}
		s.pendingSubagentsMu.Unlock()
		log.Printf("[subagent-start] Recorded agent_id=%s type=%s", hookInput.AgentID, hookInput.AgentType)
	}

	writeJSON(w, map[string]interface{}{"status": "accepted"})
}

func (s *Server) handleSubagentStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID           string `json:"session_id"`
		AgentID             string `json:"agent_id"`
		AgentTranscriptPath string `json:"agent_transcript_path"`
		CWD                 string `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Ack immediately — do heavy work async
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	s.enqueueHook(func() {
		s.processSubagentStop(hookInput.SessionID, hookInput.AgentID, hookInput.AgentTranscriptPath, hookInput.CWD)
	})
}

func (s *Server) processSubagentStop(sessionID, agentID, transcriptPath, cwd string) {
	project := filepath.Base(cwd)

	// Look up and remove pending subagent info
	var agentType string
	s.pendingSubagentsMu.Lock()
	if ps, ok := s.pendingSubagents[agentID]; ok {
		agentType = ps.AgentType
		delete(s.pendingSubagents, agentID)
	}
	s.pendingSubagentsMu.Unlock()

	if agentType == "" {
		agentType = "unknown"
	}

	log.Printf("[subagent-stop] Processing agent_id=%s type=%s transcript=%s", agentID, agentType, transcriptPath)

	if transcriptPath == "" {
		log.Printf("[subagent-stop] No transcript path, skipping")
		return
	}

	// Retry with backoff — Claude Code may not have finished writing the transcript yet.
	// Retry on file-not-found (not yet created) and on empty results (partially written).
	var calls []transcriptToolCall
	var err error
	for attempt := 0; attempt < 6; attempt++ {
		calls, err = parseTranscript(transcriptPath)
		if err == nil && len(calls) > 0 {
			break
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			break // non-retryable error
		}
		if attempt < 5 {
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			log.Printf("[subagent-stop] Transcript not found (agent may have been short-lived): %s", transcriptPath)
		} else {
			log.Printf("[subagent-stop] Failed to parse transcript: %v", err)
		}
		return
	}
	if len(calls) == 0 {
		log.Printf("[subagent-stop] Transcript empty after retries: %s", transcriptPath)
		return
	}

	var filtered []transcriptToolCall
	for _, tc := range calls {
		if !skipCaptureTool(tc.ToolName) {
			filtered = append(filtered, tc)
		}
	}

	// Cap at 15 observations per subagent to prevent flooding
	const maxObsPerSubagent = 15
	if len(filtered) > maxObsPerSubagent {
		log.Printf("[subagent-stop] Capping observations from %d to %d", len(filtered), maxObsPerSubagent)
		filtered = filtered[:maxObsPerSubagent]
	}

	saved := 0
	for _, tc := range filtered {
		obs := s.extractObservation(tc.ToolName, tc.ToolInput, tc.ToolResponse, project)
		if obs == nil {
			continue
		}

		// Tag with subagent metadata
		obs.SetExtension("subagent", map[string]interface{}{
			"agent_id":   agentID,
			"agent_type": agentType,
		})
		obs.AddTag("agent:" + agentType)

		// Generate embedding
		if s.embedder != nil && s.embedder.IsReady() {
			embedding, err := s.embedder.Embed(obs.TextForEmbedding())
			if err == nil {
				obs.Embedding.Vector = embedding
				obs.Embedding.Model = embeddings.ModelName
				obs.Embedding.Tokenizer = s.embedder.TokenizerType()
				obs.Embedding.Dims = embeddings.Dimensions
			} else {
				log.Printf("[subagent-stop] WARNING: embedding failed for %s: %v", obs.ID, err)
			}
		}

		obs.Core.SessionID = sessionID

		// Ensure session row exists before saving
		if sessionID != "" {
			if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
				if err := sqlBackend.EnsureSession(sessionID, project, obs.Source.Epoch); err != nil {
					log.Printf("[subagent-stop] Failed to ensure session: %v", err)
					continue
				}
			}
		}

		if err := s.backend.SaveObservation(obs); err != nil {
			log.Printf("[subagent-stop] Failed to save observation: %v", err)
			continue
		}
		saved++

		if sessionID != "" {
			if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
				_ = sqlBackend.IncrementSessionObservationCount(sessionID)
			}
		}
	}

	if saved > 0 {
		s.invalidateCache()
		s.syncManager.NotifyActivity()
		log.Printf("[subagent-stop] Saved %d observations from agent %s (%s)", saved, agentID, agentType)
	}
}

func (s *Server) extractObservation(toolName string, toolInput map[string]interface{}, toolResponse, project string) *storage.Observation {
	now := time.Now()
	obs := &storage.Observation{
		ID: generateID(),
		Core: storage.Core{
			Project:   project,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Source: storage.Source{
			Adapter: "sinesync",
			Epoch:   now.Unix(),
		},
	}

	switch toolName {
	case "Write":
		filePath, _ := toolInput["file_path"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Created file: %s", filepath.Base(filePath))
		obs.Core.Summary = fmt.Sprintf("Created new file at %s", filePath)
		obs.Core.Content = truncate(toolResponse, 500)
		obs.Structured.Files.Modified = []string{filePath}
		obs.Structured.CodeRefs = []string{filePath}
		obs.Structured.Concepts = extractConceptsFromPath(filePath)

	case "Edit":
		filePath, _ := toolInput["file_path"].(string)
		oldString, _ := toolInput["old_string"].(string)
		newString, _ := toolInput["new_string"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Modified file: %s", filepath.Base(filePath))
		oldSnippet := truncate(oldString, 50)
		newSnippet := truncate(newString, 50)
		obs.Core.Summary = fmt.Sprintf("Changed '%s' to '%s'", oldSnippet, newSnippet)
		obs.Core.Content = truncate(toolResponse, 500)
		obs.Structured.Files.Modified = []string{filePath}
		obs.Structured.CodeRefs = []string{filePath}
		obs.Structured.Concepts = extractConceptsFromPath(filePath)

	case "Bash":
		command, _ := toolInput["command"].(string)
		description, _ := toolInput["description"].(string)

		obs.Core.Type = "change"
		if strings.Contains(command, "test") || strings.Contains(command, "pytest") || strings.Contains(command, "jest") {
			obs.Core.Type = "discovery"
		} else if strings.Contains(command, "git commit") {
			obs.Core.Type = "change"
		} else if strings.Contains(command, "build") || strings.Contains(command, "compile") {
			obs.Core.Type = "change"
		}

		if description != "" {
			obs.Core.Title = description
		} else {
			obs.Core.Title = fmt.Sprintf("Ran command: %s", truncate(command, 40))
		}
		obs.Core.Summary = truncate(command, 100)
		obs.Core.Content = truncate(toolResponse, 500)

		// Check if command failed
		if strings.Contains(toolResponse, "error") || strings.Contains(toolResponse, "Error") {
			obs.Core.Type = "bugfix"
			obs.Structured.Facts = append(obs.Structured.Facts, "Command encountered errors")
		}

		// Extract concepts from command
		obs.Structured.Concepts = extractConceptsFromCommand(command)

	case "Task":
		prompt, _ := toolInput["prompt"].(string)
		subagentType, _ := toolInput["subagent_type"].(string)
		description, _ := toolInput["description"].(string)
		obs.Core.Type = "discovery"
		if description != "" && subagentType != "" {
			obs.Core.Title = fmt.Sprintf("Delegated task (%s): %s", subagentType, description)
		} else if description != "" {
			obs.Core.Title = fmt.Sprintf("Delegated task: %s", description)
		} else if subagentType != "" {
			obs.Core.Title = fmt.Sprintf("Delegated task (%s)", subagentType)
		} else {
			obs.Core.Title = "Delegated task"
		}
		obs.Core.Summary = truncate(prompt, 200)
		obs.Core.Content = truncate(toolResponse, 2000)

	case "WebFetch", "WebSearch":
		obs.Core.Type = "discovery"
		if urlStr, ok := toolInput["url"].(string); ok {
			obs.Core.Title = fmt.Sprintf("Fetched: %s", truncate(urlStr, 50))
		} else if query, ok := toolInput["query"].(string); ok {
			obs.Core.Title = fmt.Sprintf("Searched: %s", truncate(query, 50))
		}
		obs.Core.Summary = truncate(toolResponse, 100)
		obs.Core.Content = truncate(toolResponse, 500)

	case "NotebookEdit":
		notebookPath, _ := toolInput["notebook_path"].(string)
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Edited notebook: %s", filepath.Base(notebookPath))
		obs.Core.Summary = truncate(toolResponse, 100)
		obs.Structured.Files.Modified = []string{notebookPath}
		obs.Structured.Concepts = []string{"jupyter", "notebook"}

	default:
		obs.Core.Type = "change"
		obs.Core.Title = fmt.Sprintf("Used tool: %s", toolName)
		obs.Core.Summary = truncate(toolResponse, 100)
		obs.Core.Content = truncate(toolResponse, 500)
	}

	// Skip if we couldn't generate a meaningful title
	if obs.Core.Title == "" {
		return nil
	}

	return obs
}

// extractConceptsFromPath extracts language/framework concepts from a file path.
func extractConceptsFromPath(filePath string) []string {
	var concepts []string
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".go":
		concepts = append(concepts, "go")
	case ".ts", ".tsx":
		concepts = append(concepts, "typescript")
	case ".js", ".jsx":
		concepts = append(concepts, "javascript")
	case ".py":
		concepts = append(concepts, "python")
	case ".rs":
		concepts = append(concepts, "rust")
	case ".svelte":
		concepts = append(concepts, "svelte")
	case ".sql":
		concepts = append(concepts, "sql")
	case ".tf":
		concepts = append(concepts, "terraform")
	case ".yaml", ".yml":
		concepts = append(concepts, "yaml")
	case ".json":
		concepts = append(concepts, "json")
	}

	// Extract directory-based concepts
	dir := strings.ToLower(filePath)
	if strings.Contains(dir, "test") || strings.Contains(dir, "_test.") {
		concepts = append(concepts, "testing")
	}
	if strings.Contains(dir, "api") || strings.Contains(dir, "routes") {
		concepts = append(concepts, "api")
	}
	if strings.Contains(dir, "config") {
		concepts = append(concepts, "configuration")
	}
	if strings.Contains(dir, "migration") {
		concepts = append(concepts, "migration")
	}

	return concepts
}

// extractConceptsFromCommand extracts concepts from a shell command.
func extractConceptsFromCommand(command string) []string {
	var concepts []string
	cmd := strings.ToLower(command)

	if strings.Contains(cmd, "go ") {
		concepts = append(concepts, "go")
	}
	if strings.Contains(cmd, "npm ") || strings.Contains(cmd, "yarn ") || strings.Contains(cmd, "pnpm ") {
		concepts = append(concepts, "nodejs")
	}
	if strings.Contains(cmd, "docker") {
		concepts = append(concepts, "docker")
	}
	if strings.Contains(cmd, "git ") {
		concepts = append(concepts, "git")
	}
	if strings.Contains(cmd, "terraform") || strings.Contains(cmd, "tf ") {
		concepts = append(concepts, "terraform")
	}
	if strings.Contains(cmd, "test") || strings.Contains(cmd, "pytest") || strings.Contains(cmd, "jest") {
		concepts = append(concepts, "testing")
	}
	if strings.Contains(cmd, "build") || strings.Contains(cmd, "compile") {
		concepts = append(concepts, "build")
	}

	return concepts
}

// skipCaptureTool returns true for tools that don't produce meaningful observations.
// Used by both handleCapture (PostToolUse) and processSubagentStop (transcript parsing).
func skipCaptureTool(toolName string) bool {
	switch toolName {
	case "Read", "Glob", "Grep",
		"ListMcpResourcesTool", "SlashCommand",
		"Skill", "TodoWrite", "AskUserQuestion",
		"TaskList", "TaskGet",
		"TaskCreate", "TaskUpdate", "TaskStop",
		"EnterPlanMode", "ExitPlanMode":
		return true
	}
	return false
}

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\t", " ")
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func generateID() string {
	// Simple UUID-like ID
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func (s *Server) handleSummarize(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID      string `json:"session_id"`
		CWD            string `json:"cwd"`
		TranscriptPath string `json:"transcript_path"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		hookInput.CWD, _ = os.Getwd()
	}

	// Ack immediately — queue summary generation
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	sessionID := hookInput.SessionID
	project := filepath.Base(hookInput.CWD)

	s.enqueueHook(func() {
		s.processSummarize(sessionID, project)
	})
}

// processSummarize generates and saves a session summary observation.
func (s *Server) processSummarize(sessionID, project string) {
	observations := s.getObservations()
	hourAgo := time.Now().Add(-1 * time.Hour)

	var sessionObs []storage.Observation
	for _, obs := range observations {
		if obs.Core.Project == project && obs.Core.CreatedAt.After(hourAgo) {
			sessionObs = append(sessionObs, obs)
		}
	}

	if len(sessionObs) == 0 {
		log.Printf("[summarize] No observations for session=%s project=%s", sessionID, project)
		return
	}

	now := time.Now()
	typeCount := make(map[string]int)
	var files []string
	var titles []string
	filesMap := make(map[string]bool)

	for _, obs := range sessionObs {
		typeCount[obs.Core.Type]++
		titles = append(titles, obs.Core.Title)
		for _, f := range obs.Structured.AllFiles() {
			if !filesMap[f] {
				filesMap[f] = true
				files = append(files, f)
			}
		}
	}

	var summaryParts []string
	for t, c := range typeCount {
		summaryParts = append(summaryParts, fmt.Sprintf("%d %s", c, t))
	}

	summary := &storage.Observation{
		ID: generateID(),
		Core: storage.Core{
			Type:      "decision",
			Title:     fmt.Sprintf("Session summary: %s", project),
			Summary:   fmt.Sprintf("Session included %s across %d files", strings.Join(summaryParts, ", "), len(files)),
			Project:   project,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Structured: storage.Structured{
			Facts: titles,
			Files: storage.Files{
				Modified: files,
			},
		},
		Source: storage.Source{
			Adapter: "sinesync",
			ID:      sessionID,
			Epoch:   now.Unix(),
		},
	}

	textForEmbedding := summary.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			summary.Embedding.Vector = embedding
			summary.Embedding.Model = embeddings.ModelName
			summary.Embedding.Tokenizer = s.embedder.TokenizerType()
			summary.Embedding.Dims = embeddings.Dimensions
		} else {
			log.Printf("[summarize] WARNING: embedding failed for summary %s: %v", summary.ID, err)
		}
	}

	if err := s.backend.SaveObservation(summary); err != nil {
		log.Printf("[summarize] Failed to save summary: %v", err)
		return
	}
	s.invalidateCache()
	s.syncManager.NotifyActivity()

	if sessionID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			summaryText := fmt.Sprintf("Session included %s across %d files", strings.Join(summaryParts, ", "), len(files))
			_ = sqlBackend.CompleteSession(sessionID, time.Now(), summaryText, len(sessionObs))
			_ = sqlBackend.InsertSessionSummary(sessionID, project, summaryText, len(sessionObs), files, time.Now().Unix())
		}
	}

	log.Printf("[summarize] Saved summary for session=%s project=%s (%d observations, %d files)",
		sessionID, project, len(sessionObs), len(files))
}

func (s *Server) handlePrompt(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var hookInput struct {
		SessionID string `json:"session_id"`
		Prompt    string `json:"prompt"`
		CWD       string `json:"cwd"`
	}

	if err := json.Unmarshal(body, &hookInput); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if hookInput.Prompt == "" {
		writeJSON(w, map[string]interface{}{"status": "skipped"})
		return
	}

	// Ack immediately — queue DB writes
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	sessionID := hookInput.SessionID
	prompt := hookInput.Prompt
	project := filepath.Base(hookInput.CWD)

	s.enqueueHook(func() {
		if sessionID == "" {
			return
		}
		sqlBackend, ok := s.backend.(*storage.SQLCipherStorage)
		if !ok {
			return
		}

		_ = sqlBackend.EnsureSession(sessionID, project, time.Now().Unix())

		promptNumber := 1
		if err := sqlBackend.DB().QueryRow(
			"SELECT COALESCE(MAX(prompt_number), 0) + 1 FROM user_prompts WHERE session_id = ?",
			sessionID,
		).Scan(&promptNumber); err != nil {
			log.Printf("[prompt] Failed to get prompt number for session=%s: %v", sessionID, err)
		}

		_ = sqlBackend.InsertUserPrompt(sessionID, prompt, project, promptNumber, time.Now().Unix())
		log.Printf("[prompt] Recorded prompt for session=%s project=%s", sessionID, project)
	})
}

// === Codex capture endpoint ===

func (s *Server) handleCodexCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var payload struct {
		Type                 string   `json:"type"`
		ThreadID             string   `json:"thread-id"`
		TurnID               string   `json:"turn-id"`
		CWD                  string   `json:"cwd"`
		InputMessages        []string `json:"input-messages"`
		LastAssistantMessage string   `json:"last-assistant-message"`
	}

	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if payload.Type != "agent-turn-complete" {
		writeJSON(w, map[string]interface{}{"status": "skipped", "reason": "unsupported event type"})
		return
	}

	if payload.LastAssistantMessage == "" {
		writeJSON(w, map[string]interface{}{"status": "skipped"})
		return
	}

	// Ack immediately — do heavy work async
	writeJSON(w, map[string]interface{}{"status": "accepted"})

	s.enqueueHook(func() {
		s.processCodexCapture(payload.ThreadID, payload.TurnID, payload.CWD, payload.InputMessages, payload.LastAssistantMessage)
	})
}

// processCodexCapture extracts an observation from a Codex agent-turn-complete event.
func (s *Server) processCodexCapture(threadID, turnID, cwd string, inputMessages []string, lastAssistantMessage string) {
	project := ""
	if cwd != "" && cwd != string(os.PathSeparator) {
		project = filepath.Base(cwd)
		if project == "." {
			project = ""
		}
	}
	log.Printf("[codex-capture] Processing: thread=%s project=%s", threadID, project)

	now := time.Now()

	// Derive title from first input message (the user prompt)
	title := "Codex agent turn"
	if len(inputMessages) > 0 && inputMessages[0] != "" {
		title = truncate(inputMessages[0], 80)
	}

	// Derive observation type from user prompt (intent), not assistant message
	userPrompt := ""
	if len(inputMessages) > 0 {
		userPrompt = inputMessages[0]
	}
	obsType := classifyCodexMessage(userPrompt)

	// Extract file paths from the assistant message
	files := extractFilePathsFromText(lastAssistantMessage)

	// Extract concepts from the assistant message
	concepts := extractConceptsFromText(lastAssistantMessage)

	obs := &storage.Observation{
		ID: generateID(),
		Core: storage.Core{
			Type:      obsType,
			Title:     title,
			Summary:   truncate(lastAssistantMessage, 200),
			Content:   truncate(lastAssistantMessage, 2000),
			Project:   project,
			SessionID: threadID,
			CreatedAt: now,
			UpdatedAt: now,
		},
		Structured: storage.Structured{
			Concepts: concepts,
			Files: storage.Files{
				Modified: files,
			},
		},
		Source: storage.Source{
			Adapter: "sinesync-codex",
			ID:      threadID + ":" + turnID,
			Epoch:   now.Unix(),
		},
	}

	// Ensure session exists before saving (FK constraint)
	if threadID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			_ = sqlBackend.EnsureSession(threadID, project, now.Unix())
		}
	}

	// Generate embedding
	textForEmbedding := obs.TextForEmbedding()
	if s.embedder != nil && s.embedder.IsReady() {
		embedding, err := s.embedder.Embed(textForEmbedding)
		if err == nil {
			obs.Embedding.Vector = embedding
			obs.Embedding.Model = embeddings.ModelName
			obs.Embedding.Tokenizer = s.embedder.TokenizerType()
			obs.Embedding.Dims = embeddings.Dimensions
		} else {
			log.Printf("[codex-capture] WARNING: embedding failed: %v", err)
		}
	}

	if err := s.backend.SaveObservation(obs); err != nil {
		log.Printf("[codex-capture] Failed to save observation: %v", err)
		return
	}
	s.invalidateCache()
	s.syncManager.NotifyActivity()

	if threadID != "" {
		if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
			_ = sqlBackend.IncrementSessionObservationCount(threadID)
		}
	}

	log.Printf("[codex-capture] Saved: id=%s type=%s project=%s", obs.ID, obs.Core.Type, obs.Core.Project)
}

// classifyCodexMessage heuristically determines the observation type from the user prompt.
func classifyCodexMessage(prompt string) string {
	p := strings.ToLower(prompt)
	switch {
	case strings.Contains(p, "fix ") || strings.Contains(p, "debug") || strings.Contains(p, "broken") ||
		strings.HasPrefix(p, "why is") || strings.HasPrefix(p, "why does"):
		return "bugfix"
	case strings.Contains(p, "review") || strings.Contains(p, "search") || strings.Contains(p, "find ") ||
		strings.Contains(p, "explain") || strings.Contains(p, "what is") || strings.Contains(p, "how does") ||
		strings.Contains(p, "look at") || strings.Contains(p, "check "):
		return "discovery"
	case strings.Contains(p, "refactor") || strings.Contains(p, "clean up") || strings.Contains(p, "reorganize"):
		return "refactor"
	case strings.Contains(p, "add ") || strings.Contains(p, "implement") || strings.Contains(p, "create ") ||
		strings.Contains(p, "build ") || strings.Contains(p, "write "):
		return "feature"
	default:
		return "change"
	}
}

// extractFilePathsFromText scans text for file path patterns.
func extractFilePathsFromText(text string) []string {
	seen := make(map[string]bool)
	var files []string

	// Split on whitespace and common delimiters
	for _, word := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ' ' || r == '\n' || r == '\t' || r == '`' || r == '\'' || r == '"' || r == '(' || r == ')' || r == ','
	}) {
		// Trim trailing punctuation that commonly follows file paths (e.g., "file.go:")
		clean := strings.TrimRight(word, ":;.")
		if clean == "" {
			continue
		}
		if isFilePath(clean) {
			if !seen[clean] {
				seen[clean] = true
				files = append(files, clean)
			}
		}
	}

	return files
}

// isFilePath checks if a string looks like a file path.
func isFilePath(s string) bool {
	// Must contain a dot (for extension) or a slash
	if !strings.Contains(s, "/") && !strings.Contains(s, ".") {
		return false
	}
	// Must have a recognizable file extension
	ext := strings.ToLower(filepath.Ext(s))
	switch ext {
	case ".go", ".ts", ".tsx", ".js", ".jsx", ".py", ".rs", ".rb", ".java",
		".svelte", ".vue", ".css", ".scss", ".html", ".sql", ".tf", ".toml",
		".yaml", ".yml", ".json", ".md", ".sh", ".bash", ".zsh",
		".c", ".h", ".cpp", ".hpp", ".swift", ".kt", ".scala":
		return true
	}
	return false
}

// extractConceptsFromText extracts language/framework concepts from free text.
func extractConceptsFromText(text string) []string {
	txt := strings.ToLower(text)
	var concepts []string
	seen := make(map[string]bool)

	checks := []struct {
		pattern string
		concept string
	}{
		{"golang", "go"}, {".go", "go"}, {"go build", "go"},
		{"typescript", "typescript"}, {".ts", "typescript"}, {".tsx", "typescript"},
		{"javascript", "javascript"}, {".js", "javascript"},
		{"python", "python"}, {".py", "python"},
		{"rust", "rust"}, {".rs", "rust"},
		{"terraform", "terraform"}, {".tf", "terraform"},
		{"docker", "docker"}, {"dockerfile", "docker"},
		{"svelte", "svelte"}, {".svelte", "svelte"},
		{"react", "react"}, {"jsx", "react"},
		{"git commit", "git"}, {"git push", "git"},
		{"npm ", "nodejs"}, {"yarn ", "nodejs"}, {"pnpm ", "nodejs"},
		{"test", "testing"}, {"pytest", "testing"}, {"jest", "testing"},
		{"build", "build"}, {"compile", "build"},
		{"sql", "sql"}, {"database", "sql"},
		{"api", "api"}, {"endpoint", "api"},
	}

	for _, c := range checks {
		if strings.Contains(txt, c.pattern) && !seen[c.concept] {
			seen[c.concept] = true
			concepts = append(concepts, c.concept)
		}
	}

	return concepts
}

// === Dashboard API endpoints ===

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	stats := map[string]interface{}{
		"totalObservations": len(observations),
		"byType":            countByField(observations, func(o storage.Observation) string { return o.Core.Type }),
		"byProject":         countByField(observations, func(o storage.Observation) string { return o.Core.Project }),
		"byClassification":  countByField(observations, func(o storage.Observation) string { return o.Meta.Classification }),
		"starred":           countIf(observations, func(o storage.Observation) bool { return o.Meta.Starred }),
		"archived":          countIf(observations, func(o storage.Observation) bool { return o.Meta.Archived }),
		"tagged":            countIf(observations, func(o storage.Observation) bool { return len(o.Meta.Tags) > 0 }),
	}

	itemCount, storageBytes, _ := s.backend.GetStatus()
	stats["storageItems"] = itemCount
	stats["storageBytes"] = storageBytes

	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			count, _ := adapter.GetObservationCount()
			stats["claudeMemObservations"] = count
			adapter.Close()
		}
	}

	weekAgo := time.Now().AddDate(0, 0, -7)
	recentCount := 0
	for _, obs := range observations {
		if obs.Core.CreatedAt.After(weekAgo) {
			recentCount++
		}
	}
	stats["recentWeek"] = recentCount

	// Sync status
	syncing, lastSync, lastError := s.syncManager.Status()
	syncManifest := storage.GetSyncManifest()
	stats["syncedCount"] = syncManifest.GetSyncedCount()
	stats["syncing"] = syncing
	if !lastSync.IsZero() {
		stats["lastSync"] = lastSync.Format(time.RFC3339)
	}
	if lastError != "" {
		stats["syncError"] = lastError
	}

	// Vault breakdown
	vaultCfg, _ := loadLocalVaultConfig()
	if vaultCfg != nil && len(vaultCfg.Vaults) > 0 {
		byVault := make(map[string]int)
		vaultNames := make(map[string]string)

		// Build project-to-vault mapping
		projectVault := make(map[string]string)
		var defaultVaultID string
		for _, v := range vaultCfg.Vaults {
			vaultNames[v.VaultID] = v.Name
			if v.IsDefault {
				defaultVaultID = v.VaultID
			}
			for _, p := range v.Projects {
				projectVault[p] = v.VaultID
			}
		}

		// Count observations per vault
		for _, obs := range observations {
			vaultID := projectVault[obs.Core.Project]
			if vaultID == "" {
				vaultID = defaultVaultID
			}
			if vaultID != "" {
				byVault[vaultID]++
			}
		}

		stats["byVault"] = byVault
		stats["vaultNames"] = vaultNames
	}

	writeJSON(w, stats)
}

func (s *Server) handleVaults(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()
	syncManifest := storage.GetSyncManifest()

	vaultCfg, err := loadLocalVaultConfig()
	if err != nil || vaultCfg == nil || len(vaultCfg.Vaults) == 0 {
		writeJSON(w, map[string]interface{}{
			"vaults":      []interface{}{},
			"totalItems":  len(observations),
			"totalSynced": syncManifest.GetSyncedCount(),
		})
		return
	}

	// Build project-to-vault mapping
	projectVault := make(map[string]string)
	var defaultVaultID string
	for _, v := range vaultCfg.Vaults {
		if v.IsDefault {
			defaultVaultID = v.VaultID
		}
		for _, p := range v.Projects {
			projectVault[p] = v.VaultID
		}
	}

	// Count observations per vault
	vaultCounts := make(map[string]int)
	for _, obs := range observations {
		vaultID := projectVault[obs.Core.Project]
		if vaultID == "" {
			vaultID = defaultVaultID
		}
		if vaultID != "" {
			vaultCounts[vaultID]++
		}
	}

	// Build vault response
	type vaultInfo struct {
		ID          string   `json:"id"`
		Name        string   `json:"name"`
		IsDefault   bool     `json:"isDefault"`
		Projects    []string `json:"projects"`
		ItemCount   int      `json:"itemCount"`
		SyncedCount int      `json:"syncedCount"`
	}

	vaults := make([]vaultInfo, 0, len(vaultCfg.Vaults))
	for _, v := range vaultCfg.Vaults {
		vaults = append(vaults, vaultInfo{
			ID:          v.VaultID,
			Name:        v.Name,
			IsDefault:   v.IsDefault,
			Projects:    v.Projects,
			ItemCount:   vaultCounts[v.VaultID],
			SyncedCount: vaultCounts[v.VaultID], // Approximation - synced items are tracked globally
		})
	}

	writeJSON(w, map[string]interface{}{
		"vaults":      vaults,
		"totalItems":  len(observations),
		"totalSynced": syncManifest.GetSyncedCount(),
	})
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		// Trigger immediate sync
		s.syncManager.TriggerSync()
		writeJSON(w, map[string]interface{}{"status": "triggered"})
		return
	}

	// GET - return sync status
	syncing, lastSync, lastError := s.syncManager.Status()
	syncManifest := storage.GetSyncManifest()
	authenticated := s.isAuthenticated()

	// Get local observation count
	localCount, _, _ := s.backend.GetStatus()

	status := map[string]interface{}{
		"syncing":       syncing,
		"syncedCount":   syncManifest.GetSyncedCount(),
		"localCount":    localCount,
		"authenticated": authenticated,
	}
	if !lastSync.IsZero() {
		status["lastSync"] = lastSync.Format(time.RFC3339)
	}
	if lastError != "" {
		status["syncError"] = lastError
	}

	// Add backfill status
	backfillRunning, backfillProgress, backfillTotal, backfillElapsed := s.syncManager.BackfillStatus()
	if backfillRunning {
		status["backfill"] = map[string]interface{}{
			"running":  true,
			"progress": backfillProgress,
			"total":    backfillTotal,
			"elapsed":  backfillElapsed.Round(time.Second).String(),
		}
	}

	// Add claude-mem status if in adapter mode
	if s.mode == "adapter" && adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(true)
		if err == nil && adapter != nil {
			defer adapter.Close()
			claudeMemCount, _ := adapter.GetObservationCount()
			backlog := adapter.GetEmbeddingBacklog()
			status["claudeMem"] = map[string]interface{}{
				"observations":     claudeMemCount,
				"embeddingBacklog": backlog,
			}
		}
	}

	writeJSON(w, status)
}

func (s *Server) handleObservations(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()
	query := r.URL.Query()

	// Apply filters
	if project := query.Get("project"); project != "" {
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return o.Core.Project == project
		})
	}

	if obsType := query.Get("type"); obsType != "" {
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return o.Core.Type == obsType
		})
	}

	if query.Get("archived") != "true" {
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return !o.Meta.Archived
		})
	}

	if search := query.Get("search"); search != "" {
		searchLower := strings.ToLower(search)
		observations = filterObservations(observations, func(o storage.Observation) bool {
			return strings.Contains(strings.ToLower(o.Core.Title), searchLower) ||
				strings.Contains(strings.ToLower(o.Core.Summary), searchLower)
		})
	}

	// Sort by date
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Core.CreatedAt.After(observations[j].Core.CreatedAt)
	})

	totalFiltered := len(observations)

	// Pagination
	page, limit := 1, 50
	fmt.Sscanf(query.Get("page"), "%d", &page)
	fmt.Sscanf(query.Get("limit"), "%d", &limit)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	offset := (page - 1) * limit
	if offset >= len(observations) {
		observations = []storage.Observation{}
	} else {
		end := offset + limit
		if end > len(observations) {
			end = len(observations)
		}
		observations = observations[offset:end]
	}

	totalPages := (totalFiltered + limit - 1) / limit

	result := make([]map[string]interface{}, len(observations))
	for i, obs := range observations {
		result[i] = observationToMap(obs)
	}

	writeJSON(w, map[string]interface{}{
		"observations": result,
		"total":        totalFiltered,
		"page":         page,
		"limit":        limit,
		"totalPages":   totalPages,
		"hasNext":      page < totalPages,
		"hasPrev":      page > 1,
	})
}

func (s *Server) handleObservation(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/observations/")
	if id == "" {
		http.Error(w, "ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		obs, err := s.backend.GetObservation(id)
		if err != nil {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		writeJSON(w, observationToMap(*obs))

	case http.MethodPatch:
		s.handlePatchObservation(w, r, id)

	case http.MethodDelete:
		s.handleDeleteObservation(w, r, id)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// patchableFields are the only observation fields a PATCH may touch.
var patchableFields = map[string]bool{
	"starred":        true,
	"archived":       true,
	"tags":           true,
	"classification": true,
}

// validClassifications are the values classification may be set to. The empty
// string clears it, which is what the UI sends as JSON null.
var validClassifications = map[string]bool{
	"":          true,
	"public":    true,
	"team":      true,
	"private":   true,
	"sensitive": true,
}

// handlePatchObservation applies a partial update to user-managed metadata.
// The body is decoded into a presence map so that an absent field and an
// explicit JSON null are distinguishable — the UI clears classification by
// sending null, which a plain *string could not tell apart from "not sent".
//
// How far an edit made here travels, because it is not obvious and the answer
// is "less far than you would assume":
//
// Upload works. Bumping Core.UpdatedAt below is what makes it work — the push
// decision compares the last-uploaded timestamp against Core.UpdatedAt, so an
// edit that left UpdatedAt alone would never be pushed at all. Do not remove
// that line.
//
// Download does not. The pull step only fetches IDs that are absent locally, so
// a peer that already holds this observation never re-fetches it and keeps its
// stale copy indefinitely. It will not push over the cloud copy either — it has
// not modified the record, so its timestamps match and it correctly stays
// quiet. Propagation is therefore upload-only: star something on one machine
// and the second machine goes on showing it unstarred.
//
// Worse, if that second machine later edits the same observation, it pushes its
// whole record and the first machine's edit is silently gone. There is no
// field-level merge and no conflict detection; last writer wins at whole-record
// granularity.
//
// This is a pre-existing property of the sync design, not something PATCH
// introduced — PATCH is simply the first feature that makes it reachable from
// the UI. Fixing it means giving the pull step a reason to re-fetch changed
// records (a manifest that carries UpdatedAt, or per-record versioning) and is
// deliberately out of scope here.
func (s *Server) handlePatchObservation(w http.ResponseWriter, r *http.Request, id string) {
	var updates map[string]json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&updates); err != nil {
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	for field := range updates {
		if !patchableFields[field] {
			http.Error(w, "Field not patchable: "+field, http.StatusBadRequest)
			return
		}
	}

	obs, err := s.backend.GetObservation(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	if raw, ok := updates["starred"]; ok {
		var v *bool
		if err := json.Unmarshal(raw, &v); err != nil || v == nil {
			http.Error(w, "starred must be a boolean", http.StatusBadRequest)
			return
		}
		obs.Meta.Starred = *v
	}

	if raw, ok := updates["archived"]; ok {
		var v *bool
		if err := json.Unmarshal(raw, &v); err != nil || v == nil {
			http.Error(w, "archived must be a boolean", http.StatusBadRequest)
			return
		}
		obs.Meta.Archived = *v
	}

	if raw, ok := updates["tags"]; ok {
		// null clears the list; anything but an array of strings is a 400.
		var v []string
		if err := json.Unmarshal(raw, &v); err != nil {
			http.Error(w, "tags must be an array of strings or null", http.StatusBadRequest)
			return
		}
		obs.Meta.Tags = v
	}

	if raw, ok := updates["classification"]; ok {
		// null means "clear", which is stored as the empty string.
		var v *string
		if err := json.Unmarshal(raw, &v); err != nil {
			http.Error(w, "classification must be a string or null", http.StatusBadRequest)
			return
		}
		value := ""
		if v != nil {
			value = *v
		}
		if !validClassifications[value] {
			http.Error(w, "Invalid classification: "+value, http.StatusBadRequest)
			return
		}
		obs.Meta.Classification = value
	}

	// SaveObservation persists UpdatedAt verbatim, and the sync push decision
	// gates on it, so an edit that does not bump it never reaches the cloud.
	obs.Core.UpdatedAt = time.Now()

	if err := s.backend.SaveObservation(obs); err != nil {
		http.Error(w, "Failed to update: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.invalidateCache()
	s.syncManager.NotifyActivity()

	log.Printf("[server] Updated observation %s (fields: %d)", id, len(updates))
	writeJSON(w, observationToMap(*obs))
}

func (s *Server) handleDeleteObservation(w http.ResponseWriter, r *http.Request, id string) {
	// Get observation first to get project/title for claude-mem deletion
	obs, err := s.backend.GetObservation(id)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Delete from local sinesync storage
	if err := s.backend.DeleteObservation(id); err != nil {
		http.Error(w, "Failed to delete: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Delete from claude-mem if it exists there
	if adapters.IsClaudeMemInstalled() {
		adapter, err := adapters.NewClaudeMemAdapter(false)
		if err == nil && adapter != nil {
			defer adapter.Close()
			ctx := context.Background()

			// Try deleting by source ID first (if it came from claude-mem)
			if obs.Source.Adapter == adapters.ClaudeMemAdapterName && obs.Source.ID != "" {
				adapter.DeleteBySourceID(ctx, obs.Source.ID)
			} else {
				// Fall back to project+title match
				adapter.DeleteByProjectAndTitle(ctx, obs.Core.Project, obs.Core.Title)
			}
		}
	}

	// Mark for cloud deletion on next sync (explicit delete, safe to propagate)
	syncManifest := storage.GetSyncManifest()
	syncManifest.MarkPendingDelete(id)
	syncManifest.Save()

	// Clear observation cache to force refresh
	s.obsCache = nil
	s.syncManager.NotifyActivity()

	log.Printf("[server] Deleted observation %s (project: %s, title: %s)", id, obs.Core.Project, obs.Core.Title)
	writeJSON(w, map[string]bool{"success": true})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	projects := make(map[string]int)
	for _, obs := range observations {
		if obs.Core.Project != "" {
			projects[obs.Core.Project]++
		}
	}

	// Build project-to-vault mapping
	projectVault := make(map[string]string)
	vaultCfg, _ := loadLocalVaultConfig()
	if vaultCfg != nil {
		for _, v := range vaultCfg.Vaults {
			for _, p := range v.Projects {
				projectVault[p] = v.Name
			}
		}
	}

	type projectInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
		Vault string `json:"vault,omitempty"`
	}

	result := make([]projectInfo, 0, len(projects))
	for name, count := range projects {
		result = append(result, projectInfo{
			Name:  name,
			Count: count,
			Vault: projectVault[name],
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	writeJSON(w, result)
}

func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	observations := s.getObservations()

	tags := make(map[string]int)
	for _, obs := range observations {
		for _, tag := range obs.Meta.Tags {
			tags[tag]++
		}
	}

	type tagInfo struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	result := make([]tagInfo, 0, len(tags))
	for name, count := range tags {
		result = append(result, tagInfo{Name: name, Count: count})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})

	writeJSON(w, result)
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("q")
	if query == "" {
		writeJSON(w, map[string]interface{}{"observations": []interface{}{}, "total": 0})
		return
	}

	// Pagination
	params := r.URL.Query()
	page, limit := 1, 50
	fmt.Sscanf(params.Get("page"), "%d", &page)
	fmt.Sscanf(params.Get("limit"), "%d", &limit)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	// Use hybrid search (FTS5 + vector) when SQLCipher is available
	if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
		var queryVec []float32
		if s.embedder != nil && s.embedder.IsReady() {
			if vec, err := s.embedder.Embed(query); err == nil {
				queryVec = vec
			} else {
				log.Printf("[search] Embed failed, using fallback: %v", err)
				queryVec = embeddings.FallbackEmbed(query)
			}
		}

		// Fetch page*limit+1 so we can slice to the requested page
		// and detect whether more results exist beyond it
		fetchLimit := page*limit + 1
		allResults, err := sqlBackend.HybridSearch(query, queryVec, fetchLimit, storage.SearchFilters{})
		if err == nil {
			hasNext := len(allResults) > page*limit
			if hasNext {
				allResults = allResults[:page*limit]
			}

			// Slice to current page
			offset := (page - 1) * limit
			var pageResults []storage.SearchResult
			if offset < len(allResults) {
				end := offset + limit
				if end > len(allResults) {
					end = len(allResults)
				}
				pageResults = allResults[offset:end]
			}

			totalPages := page
			if hasNext {
				totalPages = page + 1
			}

			output := make([]map[string]interface{}, len(pageResults))
			for i, r := range pageResults {
				output[i] = map[string]interface{}{
					"id":             r.ID,
					"title":          r.Title,
					"summary":        r.Summary,
					"type":           r.Type,
					"project":        r.Project,
					"createdAt":      r.CreatedAt,
					"created_at":     r.CreatedAt,
					"score":          r.Score,
					"tags":           []string{},
					"classification": "",
					"starred":        false,
				}
			}

			writeJSON(w, map[string]interface{}{
				"observations": output,
				"total":        len(allResults),
				"page":         page,
				"limit":        limit,
				"totalPages":   totalPages,
				"hasNext":      hasNext,
				"hasPrev":      page > 1,
				"query":        query,
			})
			return
		}
	}

	// Fallback: brute-force vector search for LocalStorage backend
	observations := s.getObservations()

	var queryEmbedding []float32
	if s.embedder != nil && s.embedder.IsReady() {
		if vec, err := s.embedder.Embed(query); err == nil {
			queryEmbedding = vec
		} else {
			queryEmbedding = embeddings.FallbackEmbed(query)
		}
	} else {
		queryEmbedding = embeddings.FallbackEmbed(query)
	}

	type scoredObs struct {
		obs   storage.Observation
		score float32
	}

	var results []scoredObs
	for _, obs := range observations {
		if len(obs.Embedding.Vector) > 0 {
			score := embeddings.CosineSimilarity(queryEmbedding, obs.Embedding.Vector)
			results = append(results, scoredObs{obs: obs, score: score})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	totalResults := len(results)
	totalPages := (totalResults + limit - 1) / limit

	offset := (page - 1) * limit
	if offset >= len(results) {
		results = []scoredObs{}
	} else {
		end := offset + limit
		if end > len(results) {
			end = len(results)
		}
		results = results[offset:end]
	}

	output := make([]map[string]interface{}, len(results))
	for i, r := range results {
		m := observationToMap(r.obs)
		m["score"] = r.score
		output[i] = m
	}

	writeJSON(w, map[string]interface{}{
		"observations": output,
		"total":        totalResults,
		"page":         page,
		"limit":        limit,
		"totalPages":   totalPages,
		"hasNext":      page < totalPages,
		"hasPrev":      page > 1,
		"query":        query,
	})
}

// === MCP API endpoints (3-layer workflow) ===

func (s *Server) handleMCPSearch(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query().Get("query")
	if query == "" {
		writeJSON(w, map[string]interface{}{"results": []interface{}{}, "total": 0})
		return
	}

	limit := 20
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	if limit < 1 || limit > 200 {
		limit = 20
	}

	// Build filters
	filters := storage.SearchFilters{
		Project: r.URL.Query().Get("project"),
		Type:    r.URL.Query().Get("type"),
	}
	if ds := r.URL.Query().Get("dateStart"); ds != "" {
		if t, err := time.Parse(time.RFC3339, ds); err == nil {
			filters.DateStart = &t
		}
	}
	if de := r.URL.Query().Get("dateEnd"); de != "" {
		if t, err := time.Parse(time.RFC3339, de); err == nil {
			filters.DateEnd = &t
		}
	}

	// Try SQLCipher hybrid search first
	if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
		var queryVec []float32
		if s.embedder != nil && s.embedder.IsReady() {
			queryVec, _ = s.embedder.Embed(query)
		}

		results, err := sqlBackend.HybridSearch(query, queryVec, limit, filters)
		if err == nil {
			writeJSON(w, map[string]interface{}{
				"results": results,
				"total":   len(results),
				"query":   query,
			})
			return
		}
	}

	// Fallback: brute-force search for LocalStorage backend
	observations := s.getObservations()
	var queryEmbedding []float32
	if s.embedder != nil && s.embedder.IsReady() {
		if vec, err := s.embedder.Embed(query); err == nil {
			queryEmbedding = vec
		} else {
			queryEmbedding = embeddings.FallbackEmbed(query)
		}
	} else {
		queryEmbedding = embeddings.FallbackEmbed(query)
	}

	type scoredResult struct {
		obs   storage.Observation
		score float32
	}
	var scored []scoredResult
	for _, obs := range observations {
		if filters.Project != "" && obs.Core.Project != filters.Project {
			continue
		}
		if filters.Type != "" && obs.Core.Type != filters.Type {
			continue
		}
		if filters.DateStart != nil && obs.Core.CreatedAt.Before(*filters.DateStart) {
			continue
		}
		if filters.DateEnd != nil && obs.Core.CreatedAt.After(*filters.DateEnd) {
			continue
		}
		if len(obs.Embedding.Vector) > 0 {
			score := embeddings.CosineSimilarity(queryEmbedding, obs.Embedding.Vector)
			scored = append(scored, scoredResult{obs: obs, score: score})
		} else if strings.Contains(strings.ToLower(obs.Core.Title+" "+obs.Core.Summary+" "+obs.Core.Content), strings.ToLower(query)) {
			// Text match fallback for observations without embeddings
			scored = append(scored, scoredResult{obs: obs, score: 0.1})
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}

	results := make([]storage.SearchResult, len(scored))
	for i, sr := range scored {
		results[i] = storage.SearchResult{
			ID:        sr.obs.ID,
			Title:     sr.obs.Core.Title,
			Summary:   sr.obs.Core.Summary,
			Type:      sr.obs.Core.Type,
			Project:   sr.obs.Core.Project,
			CreatedAt: sr.obs.Core.CreatedAt.Format(time.RFC3339),
			Score:     float64(sr.score),
		}
	}

	writeJSON(w, map[string]interface{}{
		"results": results,
		"total":   len(results),
		"query":   query,
	})
}

func (s *Server) handleMCPTimeline(w http.ResponseWriter, r *http.Request) {
	anchorID := r.URL.Query().Get("anchor")
	query := r.URL.Query().Get("query")

	depthBefore := 5
	depthAfter := 5
	fmt.Sscanf(r.URL.Query().Get("depth_before"), "%d", &depthBefore)
	fmt.Sscanf(r.URL.Query().Get("depth_after"), "%d", &depthAfter)
	if depthBefore < 0 {
		depthBefore = 0
	} else if depthBefore > 50 {
		depthBefore = 50
	}
	if depthAfter < 0 {
		depthAfter = 0
	} else if depthAfter > 50 {
		depthAfter = 50
	}

	sqlBackend, ok := s.backend.(*storage.SQLCipherStorage)
	if !ok {
		// Fallback for LocalStorage: just return recent observations
		observations := s.getObservations()
		total := depthBefore + depthAfter + 1
		if total > len(observations) {
			total = len(observations)
		}
		result := make([]map[string]interface{}, total)
		for i := 0; i < total; i++ {
			result[i] = observationToMap(observations[i])
		}
		writeJSON(w, map[string]interface{}{"observations": result})
		return
	}

	var observations []storage.Observation
	var err error

	if anchorID != "" {
		observations, err = sqlBackend.TimelineSearch(anchorID, depthBefore, depthAfter)
	} else if query != "" {
		var queryVec []float32
		if s.embedder != nil && s.embedder.IsReady() {
			queryVec, _ = s.embedder.Embed(query)
		}
		observations, err = sqlBackend.TimelineSearchByQuery(query, queryVec, depthBefore, depthAfter)
	} else {
		writeJSON(w, map[string]interface{}{"error": "anchor or query required"})
		return
	}

	if err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}

	result := make([]map[string]interface{}, len(observations))
	for i, obs := range observations {
		result[i] = observationToMap(obs)
	}
	writeJSON(w, map[string]interface{}{"observations": result})
}

func (s *Server) handleMCPGetObservations(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	observations := make([]map[string]interface{}, 0, len(req.IDs))
	for _, id := range req.IDs {
		obs, err := s.backend.GetObservation(id)
		if err != nil {
			continue
		}
		observations = append(observations, observationToMap(*obs))
	}

	writeJSON(w, map[string]interface{}{"observations": observations})
}

// === Analytics API endpoints ===

// parseEpochRange extracts from/to epoch range from query params
func parseEpochRange(r *http.Request) (from, to time.Time) {
	if f := r.URL.Query().Get("from"); f != "" {
		if epoch, err := strconv.ParseInt(f, 10, 64); err == nil {
			from = time.Unix(epoch, 0)
		}
	}
	if t := r.URL.Query().Get("to"); t != "" {
		if epoch, err := strconv.ParseInt(t, 10, 64); err == nil {
			to = time.Unix(epoch, 0)
		}
	}
	return
}

// filterByDateRange filters observations by epoch range
func filterByDateRange(observations []storage.Observation, from, to time.Time) []storage.Observation {
	if from.IsZero() && to.IsZero() {
		return observations
	}
	var filtered []storage.Observation
	for _, obs := range observations {
		if !from.IsZero() && obs.Core.CreatedAt.Before(from) {
			continue
		}
		if !to.IsZero() && obs.Core.CreatedAt.After(to) {
			continue
		}
		filtered = append(filtered, obs)
	}
	return filtered
}

func (s *Server) handleActivityHeatmap(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	type dayEntry struct {
		Date   string         `json:"date"`
		Count  int            `json:"count"`
		ByType map[string]int `json:"byType"`
	}

	dayMap := make(map[string]*dayEntry)
	for _, obs := range observations {
		date := obs.Core.CreatedAt.Format("2006-01-02")
		if _, ok := dayMap[date]; !ok {
			dayMap[date] = &dayEntry{Date: date, ByType: make(map[string]int)}
		}
		dayMap[date].Count++
		dayMap[date].ByType[obs.Core.Type]++
	}

	days := make([]*dayEntry, 0, len(dayMap))
	for _, d := range dayMap {
		days = append(days, d)
	}
	sort.Slice(days, func(i, j int) bool { return days[i].Date < days[j].Date })

	writeJSON(w, map[string]interface{}{"days": days})
}

func (s *Server) handleActivityByHour(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	type hourEntry struct {
		Hour   int            `json:"hour"`
		Count  int            `json:"count"`
		ByType map[string]int `json:"byType"`
	}

	hours := make([]*hourEntry, 24)
	for i := 0; i < 24; i++ {
		hours[i] = &hourEntry{Hour: i, ByType: make(map[string]int)}
	}

	for _, obs := range observations {
		h := obs.Core.CreatedAt.Hour()
		hours[h].Count++
		hours[h].ByType[obs.Core.Type]++
	}

	writeJSON(w, map[string]interface{}{"hours": hours})
}

func (s *Server) handleTypeTrend(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	type periodEntry struct {
		Period    string         `json:"period"`
		StartDate string         `json:"startDate"`
		ByType    map[string]int `json:"byType"`
	}

	periodMap := make(map[string]*periodEntry)
	for _, obs := range observations {
		year, week := obs.Core.CreatedAt.ISOWeek()
		key := fmt.Sprintf("%d-W%02d", year, week)
		if _, ok := periodMap[key]; !ok {
			// Find the Monday of this ISO week
			jan1 := time.Date(year, 1, 1, 0, 0, 0, 0, obs.Core.CreatedAt.Location())
			offset := int(time.Monday - jan1.Weekday())
			if offset > 0 {
				offset -= 7
			}
			weekStart := jan1.AddDate(0, 0, offset+(week-1)*7)
			periodMap[key] = &periodEntry{
				Period:    key,
				StartDate: weekStart.Format("2006-01-02"),
				ByType:    make(map[string]int),
			}
		}
		periodMap[key].ByType[obs.Core.Type]++
	}

	series := make([]*periodEntry, 0, len(periodMap))
	for _, p := range periodMap {
		series = append(series, p)
	}
	sort.Slice(series, func(i, j int) bool { return series[i].Period < series[j].Period })

	writeJSON(w, map[string]interface{}{"series": series})
}

func (s *Server) handleAnalyticsSessions(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	sqlBackend, ok := s.backend.(*storage.SQLCipherStorage)
	if !ok {
		writeJSON(w, map[string]interface{}{"sessions": []interface{}{}})
		return
	}

	// Query sessions with aggregated data (exclude empty sessions, use actual counts from linked tables)
	query := `SELECT s.session_id, s.project, s.started_at_epoch, s.ended_at,
		(SELECT COUNT(*) FROM observations o WHERE o.session_id = s.session_id) as obs_count,
		s.summary, s.status,
		(SELECT COUNT(*) FROM user_prompts up WHERE up.session_id = s.session_id) as prompt_count
		FROM sessions s WHERE (
			EXISTS (SELECT 1 FROM observations o WHERE o.session_id = s.session_id)
			OR EXISTS (SELECT 1 FROM user_prompts up WHERE up.session_id = s.session_id)
		)`
	var args []interface{}

	if !from.IsZero() {
		query += " AND s.started_at_epoch >= ?"
		args = append(args, from.Unix())
	}
	if !to.IsZero() {
		query += " AND s.started_at_epoch <= ?"
		args = append(args, to.Unix())
	}
	query += " ORDER BY s.started_at_epoch DESC LIMIT ?"
	args = append(args, limit)

	rows, err := sqlBackend.DB().Query(query, args...)
	if err != nil {
		writeJSON(w, map[string]interface{}{"sessions": []interface{}{}, "error": err.Error()})
		return
	}
	defer rows.Close()

	type sessionEntry struct {
		SessionID        string         `json:"sessionId"`
		Project          string         `json:"project"`
		StartedAt        int64          `json:"startedAt"`
		EndedAt          *string        `json:"endedAt"`
		DurationMinutes  float64        `json:"durationMinutes"`
		ObservationCount int            `json:"observationCount"`
		PromptCount      int            `json:"promptCount"`
		Summary          *string        `json:"summary"`
		TopTypes         map[string]int `json:"topTypes"`
	}

	var sessions []sessionEntry
	for rows.Next() {
		var se sessionEntry
		var endedAt, summary, status *string
		if err := rows.Scan(&se.SessionID, &se.Project, &se.StartedAt, &endedAt,
			&se.ObservationCount, &summary, &status, &se.PromptCount); err != nil {
			continue
		}
		se.EndedAt = endedAt
		se.Summary = summary

		// Calculate duration
		startTime := time.Unix(se.StartedAt, 0)
		if endedAt != nil && *endedAt != "" {
			if endTime, err := time.Parse(time.RFC3339, *endedAt); err == nil {
				se.DurationMinutes = endTime.Sub(startTime).Minutes()
			}
		} else {
			se.DurationMinutes = 30 // default when ended_at is missing
		}

		se.TopTypes = make(map[string]int)
		sessions = append(sessions, se)
	}

	if sessions == nil {
		sessions = []sessionEntry{}
	}

	// Batch-fetch top types for all sessions in a single query (avoids N+1)
	if len(sessions) > 0 {
		placeholders := make([]string, len(sessions))
		typeArgs := make([]interface{}, len(sessions))
		sessionIdx := make(map[string]int, len(sessions))
		for i, se := range sessions {
			placeholders[i] = "?"
			typeArgs[i] = se.SessionID
			sessionIdx[se.SessionID] = i
		}
		typeQuery := fmt.Sprintf(
			"SELECT session_id, type, COUNT(*) as cnt FROM observations WHERE session_id IN (%s) GROUP BY session_id, type",
			strings.Join(placeholders, ","))
		typeRows, err := sqlBackend.DB().Query(typeQuery, typeArgs...)
		if err == nil {
			for typeRows.Next() {
				var sid, t string
				var cnt int
				if typeRows.Scan(&sid, &t, &cnt) == nil {
					if idx, ok := sessionIdx[sid]; ok {
						sessions[idx].TopTypes[t] = cnt
					}
				}
			}
			typeRows.Close()
		}
	}

	writeJSON(w, map[string]interface{}{"sessions": sessions})
}

func (s *Server) handleFileHotspots(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	type fileEntry struct {
		Path          string         `json:"path"`
		Project       string         `json:"project"`
		Directory     string         `json:"directory"`
		TotalCount    int            `json:"totalCount"`
		ModifiedCount int            `json:"modifiedCount"`
		ReadCount     int            `json:"readCount"`
		ByType        map[string]int `json:"byType"`
		DominantType  string         `json:"dominantType"`
	}

	fileMap := make(map[string]*fileEntry)

	for _, obs := range observations {
		for _, f := range obs.Structured.Files.Modified {
			if _, ok := fileMap[f]; !ok {
				fileMap[f] = &fileEntry{
					Path:      f,
					Project:   obs.Core.Project,
					Directory: filepath.Dir(f),
					ByType:    make(map[string]int),
				}
			}
			fileMap[f].TotalCount++
			fileMap[f].ModifiedCount++
			fileMap[f].ByType[obs.Core.Type]++
		}
		for _, f := range obs.Structured.Files.Read {
			if _, ok := fileMap[f]; !ok {
				fileMap[f] = &fileEntry{
					Path:      f,
					Project:   obs.Core.Project,
					Directory: filepath.Dir(f),
					ByType:    make(map[string]int),
				}
			}
			fileMap[f].TotalCount++
			fileMap[f].ReadCount++
			fileMap[f].ByType[obs.Core.Type]++
		}
	}

	// Determine dominant type and collect
	files := make([]*fileEntry, 0, len(fileMap))
	for _, fe := range fileMap {
		maxCount := 0
		for t, c := range fe.ByType {
			if c > maxCount {
				maxCount = c
				fe.DominantType = t
			}
		}
		files = append(files, fe)
	}

	// Sort by total count desc
	sort.Slice(files, func(i, j int) bool { return files[i].TotalCount > files[j].TotalCount })
	if len(files) > limit {
		files = files[:limit]
	}

	writeJSON(w, map[string]interface{}{"files": files})
}

func (s *Server) handleProjectBreakdown(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	type projectEntry struct {
		Name         string         `json:"name"`
		Total        int            `json:"total"`
		ByType       map[string]int `json:"byType"`
		SessionCount int            `json:"sessionCount"`
	}

	projMap := make(map[string]*projectEntry)
	projSessions := make(map[string]map[string]bool)

	for _, obs := range observations {
		p := obs.Core.Project
		if p == "" {
			p = "(none)"
		}
		if _, ok := projMap[p]; !ok {
			projMap[p] = &projectEntry{Name: p, ByType: make(map[string]int)}
			projSessions[p] = make(map[string]bool)
		}
		projMap[p].Total++
		projMap[p].ByType[obs.Core.Type]++
		if obs.Core.SessionID != "" {
			projSessions[p][obs.Core.SessionID] = true
		}
	}

	projects := make([]*projectEntry, 0, len(projMap))
	for _, pe := range projMap {
		pe.SessionCount = len(projSessions[pe.Name])
		projects = append(projects, pe)
	}

	sort.Slice(projects, func(i, j int) bool { return projects[i].Total > projects[j].Total })

	writeJSON(w, map[string]interface{}{"projects": projects})
}

func (s *Server) handleConcepts(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)
	limit := 30
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}

	type conceptEntry struct {
		Name     string         `json:"name"`
		Count    int            `json:"count"`
		ByType   map[string]int `json:"byType"`
		Projects []string       `json:"projects"`
	}

	conceptMap := make(map[string]*conceptEntry)
	conceptProjects := make(map[string]map[string]bool)

	for _, obs := range observations {
		for _, c := range obs.Structured.Concepts {
			if _, ok := conceptMap[c]; !ok {
				conceptMap[c] = &conceptEntry{Name: c, ByType: make(map[string]int)}
				conceptProjects[c] = make(map[string]bool)
			}
			conceptMap[c].Count++
			conceptMap[c].ByType[obs.Core.Type]++
			if obs.Core.Project != "" {
				conceptProjects[c][obs.Core.Project] = true
			}
		}
	}

	concepts := make([]*conceptEntry, 0, len(conceptMap))
	for _, ce := range conceptMap {
		for p := range conceptProjects[ce.Name] {
			ce.Projects = append(ce.Projects, p)
		}
		concepts = append(concepts, ce)
	}

	sort.Slice(concepts, func(i, j int) bool { return concepts[i].Count > concepts[j].Count })
	if len(concepts) > limit {
		concepts = concepts[:limit]
	}

	writeJSON(w, map[string]interface{}{"concepts": concepts})
}

func (s *Server) handleAnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	// Sort by date for sparkline computation
	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Core.CreatedAt.Before(observations[j].Core.CreatedAt)
	})

	// Use the 'to' param as reference so date range selections work correctly;
	// fall back to the latest observation timestamp or time.Now()
	now := to
	if now.IsZero() && len(observations) > 0 {
		now = observations[len(observations)-1].Core.CreatedAt
	}
	if now.IsZero() {
		now = time.Now()
	}
	weekAgo := now.AddDate(0, 0, -7)
	twoWeeksAgo := now.AddDate(0, 0, -14)

	// Observations per day (7-day moving average)
	var currentWeekObs, prevWeekObs int
	dailyCounts := make(map[string]int)
	for _, obs := range observations {
		date := obs.Core.CreatedAt.Format("2006-01-02")
		dailyCounts[date]++
		if obs.Core.CreatedAt.After(weekAgo) {
			currentWeekObs++
		} else if obs.Core.CreatedAt.After(twoWeeksAgo) {
			prevWeekObs++
		}
	}

	obsPerDay := float64(currentWeekObs) / 7.0
	prevObsPerDay := float64(prevWeekObs) / 7.0
	obsPerDayDelta := obsPerDay - prevObsPerDay

	// Build sparkline for last 30 days
	obsSparkline := make([]int, 30)
	for i := 29; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		obsSparkline[29-i] = dailyCounts[day]
	}

	// Average session duration
	var avgDuration float64
	var prevAvgDuration float64
	durationSparkline := make([]float64, 0)
	if sqlBackend, ok := s.backend.(*storage.SQLCipherStorage); ok {
		row := sqlBackend.DB().QueryRow(`SELECT AVG(
			CASE WHEN ended_at IS NOT NULL AND ended_at != ''
			THEN (julianday(ended_at) - julianday(datetime(started_at_epoch, 'unixepoch'))) * 24 * 60
			ELSE 30 END
		) FROM sessions WHERE started_at_epoch >= ?`, weekAgo.Unix())
		row.Scan(&avgDuration)

		row = sqlBackend.DB().QueryRow(`SELECT AVG(
			CASE WHEN ended_at IS NOT NULL AND ended_at != ''
			THEN (julianday(ended_at) - julianday(datetime(started_at_epoch, 'unixepoch'))) * 24 * 60
			ELSE 30 END
		) FROM sessions WHERE started_at_epoch >= ? AND started_at_epoch < ?`, twoWeeksAgo.Unix(), weekAgo.Unix())
		row.Scan(&prevAvgDuration)

		// Weekly sparkline for sessions
		rows, err := sqlBackend.DB().Query(`SELECT DATE(datetime(started_at_epoch, 'unixepoch')) as d,
			AVG(CASE WHEN ended_at IS NOT NULL AND ended_at != ''
			THEN (julianday(ended_at) - julianday(datetime(started_at_epoch, 'unixepoch'))) * 24 * 60
			ELSE 30 END) as avg_dur
			FROM sessions WHERE started_at_epoch >= ?
			GROUP BY d ORDER BY d`, now.AddDate(0, 0, -30).Unix())
		if err == nil {
			for rows.Next() {
				var d string
				var dur float64
				if rows.Scan(&d, &dur) == nil {
					durationSparkline = append(durationSparkline, math.Round(dur*10)/10)
				}
			}
			rows.Close()
		}
	}

	// Bugfix ratio
	var bugfixCount, totalCount int
	var prevBugfixCount, prevTotalCount int
	bugfixSparkline := make([]float64, 0)
	weeklyBugfix := make(map[string][2]int) // [bugfix, total]

	for _, obs := range observations {
		if obs.Core.CreatedAt.After(weekAgo) {
			totalCount++
			if obs.Core.Type == "bugfix" {
				bugfixCount++
			}
		} else if obs.Core.CreatedAt.After(twoWeeksAgo) {
			prevTotalCount++
			if obs.Core.Type == "bugfix" {
				prevBugfixCount++
			}
		}
		year, week := obs.Core.CreatedAt.ISOWeek()
		key := fmt.Sprintf("%d-W%02d", year, week)
		entry := weeklyBugfix[key]
		entry[1]++
		if obs.Core.Type == "bugfix" {
			entry[0]++
		}
		weeklyBugfix[key] = entry
	}

	bugfixRatio := 0.0
	if totalCount > 0 {
		bugfixRatio = float64(bugfixCount) / float64(totalCount)
	}
	prevBugfixRatio := 0.0
	if prevTotalCount > 0 {
		prevBugfixRatio = float64(prevBugfixCount) / float64(prevTotalCount)
	}

	// Build bugfix sparkline from weekly data
	type weekKey struct {
		key  string
		data [2]int
	}
	var weeks []weekKey
	for k, v := range weeklyBugfix {
		weeks = append(weeks, weekKey{k, v})
	}
	sort.Slice(weeks, func(i, j int) bool { return weeks[i].key < weeks[j].key })
	for _, wk := range weeks {
		if wk.data[1] > 0 {
			bugfixSparkline = append(bugfixSparkline, math.Round(float64(wk.data[0])/float64(wk.data[1])*100)/100)
		}
	}

	// Unique files per day
	dailyFiles := make(map[string]map[string]bool)
	for _, obs := range observations {
		date := obs.Core.CreatedAt.Format("2006-01-02")
		if dailyFiles[date] == nil {
			dailyFiles[date] = make(map[string]bool)
		}
		for _, f := range obs.Structured.AllFiles() {
			dailyFiles[date][f] = true
		}
	}

	var currentWeekFiles, prevWeekFiles int
	filesSparkline := make([]int, 30)
	for i := 29; i >= 0; i-- {
		day := now.AddDate(0, 0, -i)
		dayStr := day.Format("2006-01-02")
		cnt := len(dailyFiles[dayStr])
		filesSparkline[29-i] = cnt
		if day.After(weekAgo) {
			currentWeekFiles += cnt
		} else if day.After(twoWeeksAgo) {
			prevWeekFiles += cnt
		}
	}

	filesPerDay := float64(currentWeekFiles) / 7.0
	prevFilesPerDay := float64(prevWeekFiles) / 7.0

	writeJSON(w, map[string]interface{}{
		"observationsPerDay": map[string]interface{}{
			"current":   math.Round(obsPerDay*10) / 10,
			"previous":  math.Round(prevObsPerDay*10) / 10,
			"delta":     math.Round(obsPerDayDelta*10) / 10,
			"sparkline": obsSparkline,
		},
		"avgSessionDuration": map[string]interface{}{
			"current":   math.Round(avgDuration*10) / 10,
			"previous":  math.Round(prevAvgDuration*10) / 10,
			"delta":     math.Round((avgDuration-prevAvgDuration)*10) / 10,
			"sparkline": durationSparkline,
		},
		"bugfixRatio": map[string]interface{}{
			"current":   math.Round(bugfixRatio*100) / 100,
			"previous":  math.Round(prevBugfixRatio*100) / 100,
			"delta":     math.Round((bugfixRatio-prevBugfixRatio)*100) / 100,
			"sparkline": bugfixSparkline,
		},
		"uniqueFilesPerDay": map[string]interface{}{
			"current":   math.Round(filesPerDay*10) / 10,
			"previous":  math.Round(prevFilesPerDay*10) / 10,
			"delta":     math.Round((filesPerDay-prevFilesPerDay)*10) / 10,
			"sparkline": filesSparkline,
		},
	})
}

func (s *Server) handleBugfixRatio(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	type periodEntry struct {
		Period       string  `json:"period"`
		Total        int     `json:"total"`
		BugfixCount  int     `json:"bugfixCount"`
		FeatureCount int     `json:"featureCount"`
		BugfixRatio  float64 `json:"bugfixRatio"`
	}

	periodMap := make(map[string]*periodEntry)
	for _, obs := range observations {
		year, week := obs.Core.CreatedAt.ISOWeek()
		key := fmt.Sprintf("%d-W%02d", year, week)
		if _, ok := periodMap[key]; !ok {
			periodMap[key] = &periodEntry{Period: key}
		}
		periodMap[key].Total++
		if obs.Core.Type == "bugfix" {
			periodMap[key].BugfixCount++
		}
		if obs.Core.Type == "feature" {
			periodMap[key].FeatureCount++
		}
	}

	series := make([]*periodEntry, 0, len(periodMap))
	for _, p := range periodMap {
		if p.Total > 0 {
			p.BugfixRatio = math.Round(float64(p.BugfixCount)/float64(p.Total)*100) / 100
		}
		series = append(series, p)
	}

	sort.Slice(series, func(i, j int) bool { return series[i].Period < series[j].Period })

	writeJSON(w, map[string]interface{}{"series": series})
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	from, to := parseEpochRange(r)
	observations := filterByDateRange(s.getObservations(), from, to)

	// Collect unique devices
	deviceSet := make(map[string]bool)
	type dayDeviceEntry struct {
		Date     string         `json:"date"`
		ByDevice map[string]int `json:"byDevice"`
	}

	dayMap := make(map[string]*dayDeviceEntry)
	for _, obs := range observations {
		machine := obs.Source.Machine
		if machine == "" {
			machine = "local"
		}
		deviceSet[machine] = true
		date := obs.Core.CreatedAt.Format("2006-01-02")
		if _, ok := dayMap[date]; !ok {
			dayMap[date] = &dayDeviceEntry{Date: date, ByDevice: make(map[string]int)}
		}
		dayMap[date].ByDevice[machine]++
	}

	devices := make([]string, 0, len(deviceSet))
	for d := range deviceSet {
		devices = append(devices, d)
	}
	sort.Strings(devices)

	series := make([]*dayDeviceEntry, 0, len(dayMap))
	for _, d := range dayMap {
		series = append(series, d)
	}
	sort.Slice(series, func(i, j int) bool { return series[i].Date < series[j].Date })

	writeJSON(w, map[string]interface{}{
		"devices": devices,
		"series":  series,
	})
}

// === Helpers ===

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func observationToMap(obs storage.Observation) map[string]interface{} {
	return map[string]interface{}{
		"id":             obs.ID,
		"type":           obs.Core.Type,
		"title":          obs.Core.Title,
		"summary":        obs.Core.Summary,
		"content":        obs.Core.Content,
		"project":        obs.Core.Project,
		"facts":          obs.Structured.Facts,
		"concepts":       obs.Structured.Concepts,
		"files":          obs.Structured.AllFiles(),
		"source":         obs.Source.Adapter,
		"tags":           obs.Meta.Tags,
		"classification": obs.Meta.Classification,
		"starred":        obs.Meta.Starred,
		"archived":       obs.Meta.Archived,
		"createdAt":      obs.Core.CreatedAt.Format(time.RFC3339),
		"updatedAt":      obs.Core.UpdatedAt.Format(time.RFC3339),
	}
}

func countByField(observations []storage.Observation, getter func(storage.Observation) string) map[string]int {
	counts := make(map[string]int)
	for _, obs := range observations {
		val := getter(obs)
		if val != "" {
			counts[val]++
		}
	}
	return counts
}

func countIf(observations []storage.Observation, predicate func(storage.Observation) bool) int {
	count := 0
	for _, obs := range observations {
		if predicate(obs) {
			count++
		}
	}
	return count
}

func filterObservations(observations []storage.Observation, predicate func(storage.Observation) bool) []storage.Observation {
	result := make([]storage.Observation, 0)
	for _, obs := range observations {
		if predicate(obs) {
			result = append(result, obs)
		}
	}
	return result
}
