package cli

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Sync used to seal the org private key to every admin the server listed as
// pending, unattended. That key opens every vault key in the org, and the only
// thing that catches a substituted recipient is a human checking a fingerprint
// with that admin directly — which a background sync has no way to do. The
// distribution now lives in 'sinesync admin provision', and what sync must do
// with pending admins is say so and stop.

// syncEndpointLog records which endpoints a sync path reaches. The three that
// matter are the ones the removed code needed: the admin's own key material, the
// org key holder record, and the holders upload.
type syncEndpointLog struct {
	adminsPending int
	keypair       int
	orgKey        int
	holderUploads int
}

func startSyncServer(t *testing.T, log *syncEndpointLog, pendingAdmins []AdminPendingHolder) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/org-key/admins-pending"):
			log.adminsPending++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{"admins": pendingAdmins})

		// Everything below would have let the old code succeed. It is served
		// rather than refused so that a reintroduced auto-distribution would
		// work and be caught, instead of failing for an unrelated reason.
		case r.URL.Path == "/users/keypair":
			log.keypair++
			_ = json.NewEncoder(w).Encode(map[string]string{"encryptedPrivateKey": "", "publicKey": ""})

		case strings.HasSuffix(r.URL.Path, "/org-key"):
			log.orgKey++
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"orgPublicKey": "",
				"keyHolder":    map[string]string{"encryptedOrgPrivateKey": ""},
			})

		case strings.HasSuffix(r.URL.Path, "/org-key/holders"):
			log.holderUploads++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"success":true}`))

		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv("SINESYNC_API_URL", srv.URL)
}

func TestSyncNeverUploadsKeyHoldersForPendingAdmins(t *testing.T) {
	var log syncEndpointLog
	startSyncServer(t, &log, []AdminPendingHolder{
		{UserID: "admin-2", PublicKey: "c3Vic3RpdHV0ZWQta2V5LWZyb20tdGhlLXNlcnZlcg=="},
		{UserID: "admin-3", PublicKey: "YW5vdGhlci1zdWJzdGl0dXRlZC1zZXJ2ZXIta2V5MDA="},
	})

	var out bytes.Buffer
	waiting := reportPendingAdminKeyHolders(&out, "test-token", "org-1")

	if waiting != 2 {
		t.Errorf("reported %d pending admins, want 2", waiting)
	}
	if log.holderUploads != 0 {
		t.Errorf("sync uploaded key holders %d time(s); the org private key was distributed unattended", log.holderUploads)
	}
	if log.keypair != 0 || log.orgKey != 0 {
		t.Errorf("sync fetched key material it has no use for (keypair %d, org-key %d); nothing on this path should be able to decrypt the org private key",
			log.keypair, log.orgKey)
	}
	if log.adminsPending != 1 {
		t.Errorf("listed pending admins %d time(s), want 1", log.adminsPending)
	}

	// The operator has to be told where the distribution actually happens.
	text := out.String()
	for _, want := range []string{"waiting for the org key", "sinesync admin provision", "fingerprint"} {
		if !strings.Contains(text, want) {
			t.Errorf("warning does not mention %q:\n%s", want, text)
		}
	}
}

func TestSyncSaysNothingWhenNoAdminIsWaiting(t *testing.T) {
	var log syncEndpointLog
	startSyncServer(t, &log, nil)

	var out bytes.Buffer
	if waiting := reportPendingAdminKeyHolders(&out, "test-token", "org-1"); waiting != 0 {
		t.Errorf("reported %d pending admins, want 0", waiting)
	}
	if out.Len() != 0 {
		t.Errorf("printed a warning with no admins waiting:\n%s", out.String())
	}
	if log.holderUploads != 0 {
		t.Errorf("uploaded key holders %d time(s)", log.holderUploads)
	}
}

// A failed listing must not be fatal to sync — the rest of it still has work to
// do — and must not be silent either.
func TestSyncSurvivesAFailedPendingAdminListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("SINESYNC_API_URL", srv.URL)

	var out bytes.Buffer
	if waiting := reportPendingAdminKeyHolders(&out, "test-token", "org-1"); waiting != 0 {
		t.Errorf("reported %d pending admins from a failed listing, want 0", waiting)
	}
	if !strings.Contains(out.String(), "Warning") {
		t.Errorf("a failed listing was not reported:\n%s", out.String())
	}
}

// The runtime tests above cover the path that exists. This one covers the path
// that must not come back: a comment saying "do not distribute from sync" would
// not have stopped the original code, because the original code came first.
func TestSyncSourceCannotReachTheHoldersEndpoint(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "vault.go", nil, 0)
	if err != nil {
		t.Fatalf("parse vault.go: %v", err)
	}

	// Sealing helpers are legitimate elsewhere in vault.go (normalizing an
	// invited member's own vault key, for one), so this names the calls that
	// only a key-holder distribution would make.
	banned := map[string]string{
		"submitKeyHolders":             "uploads org key holder records",
		"fetchAdminsPendingKeyHolders": "lists admins to distribute to",
		"fetchOrgKey":                  "reads the org key holder record",
	}
	// One function may list who is waiting, and that is all it may do. Allowing
	// the whole function rather than the single call would let a distribution be
	// rebuilt inside the very function that replaced it.
	allowed := map[string]map[string]bool{
		"reportPendingAdminKeyHolders": {"fetchAdminsPendingKeyHolders": true},
	}

	var offenders []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			if allowed[fn.Name.Name][ident.Name] {
				return true
			}
			if why, banned := banned[ident.Name]; banned {
				offenders = append(offenders, fn.Name.Name+" calls "+ident.Name+" ("+why+")")
			}
			return true
		})
	}

	if len(offenders) > 0 {
		t.Errorf("vault.go reaches org key holder distribution again:\n  %s\n\nThat path cannot confirm a recipient's key with a human. It belongs in 'sinesync admin provision'.",
			strings.Join(offenders, "\n  "))
	}
}
