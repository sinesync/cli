package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/sinesync/cli/internal/crypto"
)

// Provisioning seals key material to public keys the server itself supplies:
// vault keys to /org-key/pending's members, and the org private key — which
// opens every vault key in the org — to /org-key/admins-pending's admins. A
// server that substitutes a key it holds gets a working, silent read on
// everything sealed to it. The typed fingerprint is the only thing that stops
// that, so what matters in these tests is not that a warning was printed but
// that the upload endpoint was never reached.

// recordingUploads reports whether the provision and holders endpoints were hit.
type recordingUploads struct {
	provisionCalls int
	holderCalls    int
	lastBody       map[string]interface{}
}

func uploadServer(t *testing.T, rec *recordingUploads) {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		parsed := map[string]interface{}{}
		_ = json.Unmarshal(body, &parsed)
		rec.lastBody = parsed

		switch {
		case strings.HasSuffix(r.URL.Path, "/org-key/provision"):
			rec.provisionCalls++
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true}`))
		case strings.HasSuffix(r.URL.Path, "/org-key/holders"):
			rec.holderCalls++
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.Error(w, "unexpected path "+r.URL.Path, http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	t.Setenv("SINESYNC_API_URL", srv.URL)
}

// orgWithOneVault builds an org keypair and a single vault whose key is sealed
// to it, which is the state provisioning starts from.
func orgWithOneVault(t *testing.T) (orgPub, orgPriv string, vaults []OrgVaultResponse) {
	t.Helper()

	orgPub, orgPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate org keypair: %v", err)
	}
	vaultKey, err := crypto.GenerateKey(32)
	if err != nil {
		t.Fatalf("generate vault key: %v", err)
	}
	sealed, err := crypto.X25519Seal(vaultKey, orgPub)
	if err != nil {
		t.Fatalf("seal vault key: %v", err)
	}
	return orgPub, orgPriv, []OrgVaultResponse{{ID: "vault-1", Name: "Team", EncryptedVaultKey: sealed}}
}

func fingerprintOf(t *testing.T, publicKey string) string {
	t.Helper()
	fp, err := crypto.KeyFingerprint(publicKey)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return fp
}

// The member's own machine shows the fingerprint of the key they hold. The
// server lists a different key. Typing what the member reads out must therefore
// disagree with what this machine computed, and nothing may be uploaded.
func TestProvisionMemberAbortsWhenServerSubstitutesTheKey(t *testing.T) {
	var rec recordingUploads
	uploadServer(t, &rec)

	_, orgPriv, vaults := orgWithOneVault(t)

	memberPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate member keypair: %v", err)
	}
	attackerPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate attacker keypair: %v", err)
	}

	pending := []PendingProvision{{UserID: "member-1", PublicKey: attackerPub, VaultIDs: []string{"vault-1"}}}

	// The operator types the genuine fingerprint, read from the member.
	typed := strings.Repeat(fingerprintOf(t, memberPub)+"\n", maxFingerprintAttempts)

	var out bytes.Buffer
	provisioned, unconfirmed, err := provisionPendingMembers(
		&out, bufio.NewReader(strings.NewReader(typed)),
		"test-token", "org-1", pending, vaults, orgPriv)
	if err != nil {
		t.Fatalf("provisionPendingMembers: %v", err)
	}

	if rec.provisionCalls != 0 {
		t.Errorf("provision endpoint was called %d time(s); an unconfirmed member's vault key was uploaded", rec.provisionCalls)
	}
	if provisioned != 0 {
		t.Errorf("provisioned = %d, want 0", provisioned)
	}
	if unconfirmed != 1 {
		t.Errorf("unconfirmed = %d, want 1", unconfirmed)
	}
	assertNeverPrinted(t, out.String(), fingerprintOf(t, attackerPub))
}

// The org private key is the whole org's escrow. Same substitution, same
// requirement: the holders endpoint must not be reached.
func TestDistributeOrgKeyAbortsWhenServerSubstitutesAdminKey(t *testing.T) {
	var rec recordingUploads
	uploadServer(t, &rec)

	_, orgPriv, _ := orgWithOneVault(t)

	adminPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate admin keypair: %v", err)
	}
	attackerPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate attacker keypair: %v", err)
	}

	admins := []AdminPendingHolder{{UserID: "admin-2", PublicKey: attackerPub}}
	typed := strings.Repeat(fingerprintOf(t, adminPub)+"\n", maxFingerprintAttempts)

	var out bytes.Buffer
	distributed, unconfirmed, err := distributeOrgKeyToAdmins(
		&out, bufio.NewReader(strings.NewReader(typed)),
		"test-token", "org-1", admins, []byte(orgPriv))
	if err != nil {
		t.Fatalf("distributeOrgKeyToAdmins: %v", err)
	}

	if rec.holderCalls != 0 {
		t.Errorf("holders endpoint was called %d time(s); the org private key was sealed to an unconfirmed key", rec.holderCalls)
	}
	if distributed != 0 {
		t.Errorf("distributed = %d, want 0", distributed)
	}
	if unconfirmed != 1 {
		t.Errorf("unconfirmed = %d, want 1", unconfirmed)
	}
	assertNeverPrinted(t, out.String(), fingerprintOf(t, attackerPub))
}

// Empty input is a refusal, not a default-yes. This is also what a cron run
// looks like from inside the prompt: stdin at EOF.
func TestProvisionRefusesOnEmptyInput(t *testing.T) {
	var rec recordingUploads
	uploadServer(t, &rec)

	_, orgPriv, vaults := orgWithOneVault(t)
	memberPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate member keypair: %v", err)
	}

	pending := []PendingProvision{{UserID: "member-1", PublicKey: memberPub, VaultIDs: []string{"vault-1"}}}
	admins := []AdminPendingHolder{{UserID: "admin-2", PublicKey: memberPub}}

	var out bytes.Buffer
	provisioned, unconfirmed, err := provisionPendingMembers(
		&out, bufio.NewReader(strings.NewReader("")),
		"test-token", "org-1", pending, vaults, orgPriv)
	if err != nil {
		t.Fatalf("provisionPendingMembers: %v", err)
	}
	if provisioned != 0 || unconfirmed != 1 || rec.provisionCalls != 0 {
		t.Errorf("empty stdin provisioned %d (unconfirmed %d, %d uploads); want 0, 1, 0",
			provisioned, unconfirmed, rec.provisionCalls)
	}

	distributed, unconfirmed, err := distributeOrgKeyToAdmins(
		&out, bufio.NewReader(strings.NewReader("\n")),
		"test-token", "org-1", admins, []byte(orgPriv))
	if err != nil {
		t.Fatalf("distributeOrgKeyToAdmins: %v", err)
	}
	if distributed != 0 || unconfirmed != 1 || rec.holderCalls != 0 {
		t.Errorf("bare Enter distributed %d (unconfirmed %d, %d uploads); want 0, 1, 0",
			distributed, unconfirmed, rec.holderCalls)
	}
}

// A public key that will not fingerprint cannot be confirmed by anyone, so it
// must not reach a prompt-and-seal path that could accept it.
func TestProvisionRefusesUnusableKey(t *testing.T) {
	var rec recordingUploads
	uploadServer(t, &rec)

	_, orgPriv, vaults := orgWithOneVault(t)
	pending := []PendingProvision{{UserID: "member-1", PublicKey: "not-base64!!", VaultIDs: []string{"vault-1"}}}

	var out bytes.Buffer
	// Stdin holds a plausible-looking answer: if the code prompted anyway, a
	// blank reader would hide the bug.
	provisioned, unconfirmed, err := provisionPendingMembers(
		&out, bufio.NewReader(strings.NewReader("ABCD-EFGH-JKLM\n")),
		"test-token", "org-1", pending, vaults, orgPriv)
	if err != nil {
		t.Fatalf("provisionPendingMembers: %v", err)
	}
	if provisioned != 0 || unconfirmed != 1 || rec.provisionCalls != 0 {
		t.Errorf("unusable key provisioned %d (unconfirmed %d, %d uploads); want 0, 1, 0",
			provisioned, unconfirmed, rec.provisionCalls)
	}
}

// The confirmed case has to still work, or the check would just be a way of
// breaking provisioning. One prompt per recipient, and the sealed key must open
// with the member's own private key.
func TestProvisionSealsToAConfirmedMember(t *testing.T) {
	var rec recordingUploads
	uploadServer(t, &rec)

	_, orgPriv, vaults := orgWithOneVault(t)
	memberPub, memberPriv, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate member keypair: %v", err)
	}

	pending := []PendingProvision{{UserID: "member-1", PublicKey: memberPub, VaultIDs: []string{"vault-1"}}}

	var out bytes.Buffer
	provisioned, unconfirmed, err := provisionPendingMembers(
		&out, bufio.NewReader(strings.NewReader(fingerprintOf(t, memberPub)+"\n")),
		"test-token", "org-1", pending, vaults, orgPriv)
	if err != nil {
		t.Fatalf("provisionPendingMembers: %v", err)
	}
	if provisioned != 1 || unconfirmed != 0 || rec.provisionCalls != 1 {
		t.Fatalf("confirmed member: provisioned %d, unconfirmed %d, %d uploads; want 1, 0, 1",
			provisioned, unconfirmed, rec.provisionCalls)
	}

	// Exactly one prompt for one recipient.
	if n := strings.Count(out.String(), "Fingerprint they read out:"); n != 1 {
		t.Errorf("prompted %d times for one recipient, want 1", n)
	}

	// And what was uploaded really is sealed to the member.
	sealed := uploadedVaultKey(t, rec.lastBody)
	if _, err := crypto.X25519Open(sealed, memberPriv); err != nil {
		t.Errorf("uploaded vault key does not open with the member's key: %v", err)
	}
}

// Confirming one recipient must not carry over to the next: two members, one
// confirmed, one refused, and only the confirmed one may appear in the batch.
func TestProvisionPromptsPerRecipient(t *testing.T) {
	var rec recordingUploads
	uploadServer(t, &rec)

	_, orgPriv, vaults := orgWithOneVault(t)
	goodPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	otherPub, _, err := crypto.GenerateX25519Keypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}

	pending := []PendingProvision{
		{UserID: "member-good", PublicKey: goodPub, VaultIDs: []string{"vault-1"}},
		{UserID: "member-bad", PublicKey: otherPub, VaultIDs: []string{"vault-1"}},
	}

	// Correct answer for the first, then a bare Enter to refuse the second.
	input := fingerprintOf(t, goodPub) + "\n\n"

	var out bytes.Buffer
	provisioned, unconfirmed, err := provisionPendingMembers(
		&out, bufio.NewReader(strings.NewReader(input)),
		"test-token", "org-1", pending, vaults, orgPriv)
	if err != nil {
		t.Fatalf("provisionPendingMembers: %v", err)
	}
	if provisioned != 1 || unconfirmed != 1 {
		t.Fatalf("provisioned %d, unconfirmed %d; want 1 and 1", provisioned, unconfirmed)
	}
	if n := strings.Count(out.String(), "Fingerprint they read out:"); n != 2 {
		t.Errorf("prompted %d times for two recipients, want 2", n)
	}

	provisions, _ := rec.lastBody["provisions"].([]interface{})
	if len(provisions) != 1 {
		t.Fatalf("uploaded %d provisions, want only the confirmed one", len(provisions))
	}
	entry := provisions[0].(map[string]interface{})
	if entry["userId"] != "member-good" {
		t.Errorf("uploaded provision for %v, want member-good", entry["userId"])
	}
}

// The prompt must never print the value it is asking for. An operator who can
// read it off this screen never contacts the other person, and the check
// silently becomes a typing exercise.
func assertNeverPrinted(t *testing.T, output, fingerprint string) {
	t.Helper()
	if strings.Contains(output, fingerprint) {
		t.Errorf("the expected fingerprint %q was printed to the operator:\n%s", fingerprint, output)
	}
	// The first group alone is enough to type-match by eye.
	if first, _, ok := strings.Cut(fingerprint, "-"); ok && strings.Contains(output, first) {
		t.Errorf("a leading group %q of the expected fingerprint was printed:\n%s", first, output)
	}
}

func uploadedVaultKey(t *testing.T, body map[string]interface{}) string {
	t.Helper()
	provisions, ok := body["provisions"].([]interface{})
	if !ok || len(provisions) == 0 {
		t.Fatalf("no provisions in uploaded body: %v", body)
	}
	vaults := provisions[0].(map[string]interface{})["vaults"].([]interface{})
	if len(vaults) == 0 {
		t.Fatalf("no vaults in uploaded provision: %v", body)
	}
	return vaults[0].(map[string]interface{})["encryptedVaultKey"].(string)
}
