package daemon

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/storage"
)

// hostileProjectName is the payload these tests are organised around: a project
// name that is simultaneously an HTML element, an attribute breakout, and a set
// of characters that a naive escaper gets wrong. Nothing stops a user from
// naming a directory this, and the daemon stores and returns project names
// verbatim (TestHostileProjectNameIsReturnedVerbatim), so the dashboard is the
// only thing standing between it and script execution.
const hostileProjectName = `<img src=x onerror=alert(1)>"'&`

// dashboardAssets are the paths the browser actually fetches to run the
// dashboard. "/" is included because that is what the user navigates to and
// what carries the policy the rest of the page inherits. "/index.html" is
// included for its 301: http.FileServer canonicalises it to "/", and a
// redirect that shipped without the policy would be a hole if anything ever
// rendered from it.
var dashboardAssets = []struct {
	path       string
	wantStatus int
}{
	{"/", http.StatusOK},
	{"/index.html", http.StatusMovedPermanently},
	{"/app.js", http.StatusOK},
	{"/charts.js", http.StatusOK},
	{"/auth.js", http.StatusOK},
	{"/style.css", http.StatusOK},
	{"/d3.min.js", http.StatusOK},
}

func getAsset(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "127.0.0.1:5741"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// TestStaticAssetsCarryCSP pins the header onto every dashboard asset, through
// the real route stack rather than by calling the wrapper directly — a future
// refactor that reorders routes() and drops the wrapper would otherwise pass.
func TestStaticAssetsCarryCSP(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	h := s.routes()

	for _, tc := range dashboardAssets {
		t.Run(tc.path, func(t *testing.T) {
			rec := getAsset(t, h, tc.path)

			if rec.Code != tc.wantStatus {
				t.Fatalf("GET %s: status %d, want %d (asset missing or route changed)", tc.path, rec.Code, tc.wantStatus)
			}
			got := rec.Header().Get("Content-Security-Policy")
			if got != contentSecurityPolicy {
				t.Errorf("GET %s: Content-Security-Policy =\n  %q\nwant\n  %q", tc.path, got, contentSecurityPolicy)
			}
		})
	}
}

// TestDashboardCSPDirectives asserts the served policy directive by directive,
// so a weakening edit fails with a message naming the directive that changed
// rather than a wall of diffed string. Each value is spelled out because each
// one is load-bearing; see the comment on contentSecurityPolicy.
func TestDashboardCSPDirectives(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	rec := getAsset(t, s.routes(), "/")

	got := parseCSP(rec.Header().Get("Content-Security-Policy"))
	want := map[string]string{
		"default-src":     "'self'",
		"script-src":      "'self'",
		"style-src":       "'self' 'unsafe-inline'",
		"img-src":         "'self' data:",
		"connect-src":     "'self'",
		"object-src":      "'none'",
		"base-uri":        "'none'",
		"form-action":     "'none'",
		"frame-ancestors": "'none'",
	}

	for _, name := range sortedKeys(want) {
		value, ok := got[name]
		if !ok {
			t.Errorf("policy is missing %s (want %q)", name, want[name])
			continue
		}
		if value != want[name] {
			t.Errorf("%s = %q, want %q", name, value, want[name])
		}
	}
	for _, name := range sortedKeys(got) {
		if _, ok := want[name]; !ok {
			t.Errorf("policy gained an unreviewed directive: %s %s", name, got[name])
		}
	}

	// 'unsafe-inline' under script-src would give the injected onerror handler
	// back everything the rest of the policy takes away, so call it out by name.
	if strings.Contains(got["script-src"], "unsafe-inline") || strings.Contains(got["script-src"], "unsafe-eval") {
		t.Errorf("script-src %q re-enables inline script; the policy exists to block exactly that", got["script-src"])
	}
}

func parseCSP(header string) map[string]string {
	out := map[string]string{}
	for _, directive := range strings.Split(header, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		out[fields[0]] = strings.Join(fields[1:], " ")
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// htmlSink is one way a string can reach an HTML parser, and the reason it is
// banned from app.js. Everything else app.js does with API data — textContent,
// dataset, value, selected, classList, style.width — treats the string as data.
type htmlSink struct {
	pattern string
	why     string
}

// htmlSinks is deliberately wider than the obvious three properties. An
// injection reintroduced through DOMParser or a d3 .html() call is exactly as
// exploitable as one reintroduced through innerHTML, and is likelier to look
// harmless in review.
//
// Two entries are prefixes on purpose: "document.write" also matches
// document.writeln, and "setHTML" also matches setHTMLUnsafe. Listing the
// longer spellings separately would report one line of code twice.
// TestHTMLSinkPatternsCoverKnownSpellings proves the prefixes really do cover
// them rather than leaving it to the reader to trust the comment.
var htmlSinks = []htmlSink{
	{"innerHTML", "parses the assigned string as markup"},
	{"outerHTML", "same parser, and replaces the element itself"},
	{"insertAdjacentHTML", "same parser, positioned"},
	{"document.write", "parses into the document stream; also covers document.writeln"},
	{".html(", "d3 and jQuery both spell innerHTML this way, which is how charts.js has a sink at all"},
	{"srcdoc", "an entire attacker-authored document, parsed in a same-origin frame"},
	{"parseFromString", "DOMParser: builds a tree from markup, ready to be adopted into this one"},
	{"createContextualFragment", "Range: the same parse, without even the DOMParser ceremony"},
	{"setHTML", "sanitizer-based parsing is still parsing; also covers setHTMLUnsafe"},
}

// matchedSinks returns the sinks present in source, in declaration order.
func matchedSinks(source string) []htmlSink {
	var found []htmlSink
	for _, sink := range htmlSinks {
		if strings.Contains(source, sink.pattern) {
			found = append(found, sink)
		}
	}
	return found
}

// TestDashboardScriptHasNoHTMLSinks is the invariant the CSP is a backstop for.
//
// app.js used to render every card, chart bar, option and modal by
// concatenating API values into markup and assigning it to innerHTML. A project
// named
//
//	<img src=x onerror=alert(1)>"'&
//
// escaped that in three separate ways: the escapeHtml helper was applied to
// some interpolations and not others, it did not escape ' at all, and the
// values that mattered most — data-id, data-project, data-tag, the chart-label
// title, the observation type in a class attribute, and the option value —
// were interpolated into attributes with no escaping whatsoever, so the payload
// closed the attribute and opened a live event handler.
//
// The fix was structural: build every node with DOM APIs, so an API value can
// only ever land in textContent or a property and there is no parser to trick.
// That property is invisible in a diff and easy to undo with one convenient
// line, which is what this test is for. It is deliberately blunt — a sink named
// anywhere in the file, comments included, fails it — because the point is that
// there is no correct use of these four in this file.
//
// It reads the embedded copy, not the working tree, so it asserts against the
// bytes that actually ship in the binary.
//
// Only app.js is scanned, and the other two static scripts are excluded
// knowingly rather than by omission — both would trip the patterns above:
//
//   - charts.js line 44 does d3's tt.html(html) for the tooltip. Its dynamic
//     text goes through the local esc() helper and its inline colors come from
//     fixed palettes, so it is not currently exploitable, but ".html(" is in
//     htmlSinks and would fail it. It wants its own pass — an escaper is a
//     weaker guarantee than having no parser to escape for — not to be folded
//     into an invariant written for a different file.
//   - auth.js lines 142 and 172 assign innerHTML for the two failure banners.
//     Both strings are built from literals: the only interpolated value is
//     showAuthBanner's message parameter, and both call sites (lines 204 and
//     227) pass a string constant. No API or observation data reaches either.
//     They are static markup written by us, which is the one case innerHTML is
//     defensible, so they are left alone.
func TestDashboardScriptHasNoHTMLSinks(t *testing.T) {
	body, err := staticFiles.ReadFile("static/app.js")
	if err != nil {
		t.Fatalf("read embedded static/app.js: %v", err)
	}
	source := string(body)

	for _, sink := range matchedSinks(source) {
		t.Errorf("static/app.js contains %q — %s.\n\n"+
			"Every value app.js renders comes from the observation store, and a project may legitimately be named %s.\n"+
			"Reaching the HTML parser with it is script execution on the dashboard, which holds the user's whole memory store.\n"+
			"Build the node instead: document.createElement plus textContent, dataset, value, selected, classList or style.",
			sink.pattern, sink.why, hostileProjectName)
	}

	// A guard that passes because the file is empty, renamed or no longer
	// embedded would be worse than no guard.
	for _, marker := range []string{"function renderObservations", "function renderBarChart", "textContent"} {
		if !strings.Contains(source, marker) {
			t.Errorf("embedded static/app.js is missing %q — this test is no longer scanning the dashboard script", marker)
		}
	}
}

// TestHostileProjectNameIsReturnedVerbatim is the other half of the argument.
// The daemon does not sanitise observation content on the way out — it cannot,
// since the CLI and MCP server consume the same JSON and want the real string —
// so the payload arrives at the browser intact and the DOM-only rendering in
// app.js is the entire defence, not a redundant second layer.
//
// If this ever starts failing because the server began escaping, the escaping
// is the bug: it would corrupt every non-browser consumer while leaving the
// dashboard's real protection unchanged.
func TestHostileProjectNameIsReturnedVerbatim(t *testing.T) {
	hostile := storage.Observation{
		ID: "obs-hostile",
		Core: storage.Core{
			Title:     hostileProjectName,
			Summary:   hostileProjectName,
			Type:      "discovery",
			Project:   hostileProjectName,
			CreatedAt: seedTime,
			UpdatedAt: seedTime,
		},
		Meta:   storage.Meta{Tags: []string{hostileProjectName}},
		Source: storage.Source{Adapter: "sinesync"},
	}

	_, h, _ := newPatchTestServer(hostile)

	req := httptest.NewRequest(http.MethodGet, "/api/observations", nil)
	req.Host = "127.0.0.1:5741"
	req.Header.Set("X-Hook-Secret", patchTestSecret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/observations: status %d, want 200", rec.Code)
	}

	var payload struct {
		Observations []struct {
			Project string   `json:"project"`
			Title   string   `json:"title"`
			Tags    []string `json:"tags"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Observations) != 1 {
		t.Fatalf("got %d observations, want 1", len(payload.Observations))
	}

	got := payload.Observations[0]
	if got.Project != hostileProjectName {
		t.Errorf("project = %q, want it returned verbatim as %q", got.Project, hostileProjectName)
	}
	if got.Title != hostileProjectName {
		t.Errorf("title = %q, want it returned verbatim as %q", got.Title, hostileProjectName)
	}
	if len(got.Tags) != 1 || got.Tags[0] != hostileProjectName {
		t.Errorf("tags = %q, want [%q] verbatim", got.Tags, hostileProjectName)
	}

	// And the API response carries no CSP of its own to fall back on: the
	// policy is attached to the documents that render, which is why the
	// invariant on app.js is the thing doing the work here.
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "" {
		t.Logf("note: API responses now carry a CSP too (%q); harmless, but the static handler is still the one that matters", csp)
	}
}

// TestHTMLSinkPatternsCoverKnownSpellings checks the guard from both sides.
//
// The positive half is the point of the prefix entries: a reviewer should not
// have to take "document.write also catches writeln" on faith. The negative
// half matters just as much — a pattern broad enough to flag textContent or
// replaceChildren would get the whole invariant deleted the first time it cried
// wolf, which is a slower path to the same XSS.
func TestHTMLSinkPatternsCoverKnownSpellings(t *testing.T) {
	mustMatch := []string{
		`el.innerHTML = value`,
		`el.outerHTML = value`,
		`el.insertAdjacentHTML('beforeend', value)`,
		`document.write(value)`,
		`document.writeln(value)`,
		`d3.select('#tip').html(value)`,
		`$('#tip').html(value)`,
		`iframe.srcdoc = value`,
		`new DOMParser().parseFromString(value, 'text/html')`,
		`document.createRange().createContextualFragment(value)`,
		`el.setHTML(value)`,
		`el.setHTMLUnsafe(value)`,
	}
	for _, snippet := range mustMatch {
		if len(matchedSinks(snippet)) == 0 {
			t.Errorf("no sink pattern matches %q — the guard would let this through", snippet)
		}
	}

	// The DOM-only idioms app.js is now built from. If any of these ever trip
	// the guard, the pattern that did it is too broad and must be narrowed,
	// not the code that uses it.
	mustNotMatch := []string{
		`node.textContent = value`,
		`Object.assign(node.dataset, value)`,
		`option.selected = value === current`,
		`fill.style.width = pct + '%'`,
		`card.classList.add('starred')`,
		`container.replaceChildren(...nodes)`,
		`el('span', { class: 'chart-bar-label', title: label, text: label })`,
		`document.createElement(tag)`,
		`node.append(child)`,
		`modalBody.replaceChildren(content)`,
	}
	for _, snippet := range mustNotMatch {
		if found := matchedSinks(snippet); len(found) > 0 {
			t.Errorf("pattern %q falsely flags the safe idiom %q", found[0].pattern, snippet)
		}
	}
}

// A response the browser sniffs into a document escapes the CSP above rather
// than breaching it: the policy applies to what a document may load, not to
// what the browser decides a response is.
func TestDashboardSendsNosniff(t *testing.T) {
	s := &Server{port: testPort, mode: "standalone"}
	rec := getAsset(t, s.routes(), "/")

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want %q", got, "nosniff")
	}
}
