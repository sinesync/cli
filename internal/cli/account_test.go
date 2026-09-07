package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/pbkdf2"

	"github.com/sinesync/cli/internal/crypto"
	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/srp"
	"github.com/sinesync/cli/internal/vaultroute"
)

// The command wiring, driven entirely through injected dependencies: no
// terminal, no server, no keychain. What is asserted is the order — because the
// one property that matters is that nothing on this device changes until the
// server has confirmed the change.

const (
	flowEmail     = "user@example.com"
	flowCurrent   = "current-password"
	flowNew       = "brand-new-password"
	flowSecretKey = "AAAA-BBBB-CCCC-DDDD"
	flowToken     = "session-token"
)

var flowSalt = []byte("0123456789abcdef")

// flowHarness records every dependency call in order and lets any of them fail.
type flowHarness struct {
	t *testing.T

	prompts      []string
	answers      []string
	typedCurrent string
	promptErr    error
	// handed keeps the exact slices the flow was given, so a test can look at
	// the memory afterwards and see whether it was wiped.
	handed [][]byte

	authCfg    *AuthConfig
	authCfgErr error
	tokenErr   error
	secretErr  error
	saltErr    error

	vaults    *vaultroute.Config
	vaultsErr error

	encryptedPrivateKey string
	fetchErr            error
	challengeErr        error
	postErr             error
	commitErr           error

	calls []string
	out   bytes.Buffer

	// what the flow handed to each step
	postedToken   string
	postedPayload *changePasswordPayload
	committedKey  []byte
	committedCfg  *vaultroute.Config
	committedRes  *changePasswordResult
	result        *changePasswordResult
}

func (h *flowHarness) record(name string) { h.calls = append(h.calls, name) }

func (h *flowHarness) deps() passwordChangeDeps {
	h.result = &changePasswordResult{Token: "new-access", RefreshToken: "new-refresh", ExpiresAt: "2099-01-01T00:00:00Z"}

	return passwordChangeDeps{
		out: &h.out,
		readPassword: func(prompt string) ([]byte, error) {
			h.record("prompt")
			h.prompts = append(h.prompts, prompt)
			if h.promptErr != nil {
				return nil, h.promptErr
			}
			if len(h.answers) == 0 {
				h.t.Fatalf("the flow asked for more passwords than the test supplied: %q", prompt)
			}
			answer := h.answers[0]
			h.answers = h.answers[1:]
			if len(h.prompts) == 1 {
				h.typedCurrent = answer
			}
			buf := []byte(answer)
			h.handed = append(h.handed, buf)
			return buf, nil
		},
		apiBase:    func() string { return "https://api.test" },
		authConfig: func() (*AuthConfig, error) { h.record("auth-config"); return h.authCfg, h.authCfgErr },
		authToken:  func() (string, error) { h.record("auth-token"); return flowToken, h.tokenErr },
		secretKey:  func() (string, error) { h.record("secret-key"); return flowSecretKey, h.secretErr },
		userSalt:   func() ([]byte, error) { h.record("salt"); return flowSalt, h.saltErr },
		loadVaults: func() (*vaultroute.Config, error) { h.record("load-vaults"); return h.vaults, h.vaultsErr },

		fetchEncryptedPrivateKey: func(token string) (string, error) {
			h.record("fetch-private-key")
			if token != flowToken {
				h.t.Errorf("keypair fetched with token %q", token)
			}
			return h.encryptedPrivateKey, h.fetchErr
		},
		requestSRPChallenge: func(apiBase, email, password string) (*srpChallenge, error) {
			h.record("srp-challenge")
			if email != flowEmail {
				h.t.Errorf("challenge for %q", email)
			}
			// The challenge proves the password the user typed as their current
			// one; building it from the new password would make the server
			// reject a change that is otherwise correct.
			if password != h.typedCurrent {
				h.t.Errorf("challenge built from %q, want the typed current password %q", password, h.typedCurrent)
			}
			if h.challengeErr != nil {
				return nil, h.challengeErr
			}
			return &srpChallenge{client: srp.NewClient(email, password), clientPublic: "A-hex", clientProof: "M1-hex"}, nil
		},
		postPasswordChange: func(token string, payload *changePasswordPayload) (*changePasswordResult, error) {
			h.record("post")
			h.postedToken, h.postedPayload = token, payload
			if h.postErr != nil {
				return nil, h.postErr
			}
			return h.result, nil
		},
		commit: func(newDerivedKey []byte, result *changePasswordResult, cfg *vaultroute.Config) error {
			h.record("commit")
			h.committedKey = append([]byte(nil), newDerivedKey...)
			h.committedRes, h.committedCfg = result, cfg
			return h.commitErr
		},
	}
}

// newFlow is a device that can change its password: an SRP account, two vaults
// wrapped under the current password, and a private key to match.
func newFlow(t *testing.T) *flowHarness {
	t.Helper()

	oldMgr := encryption.NewManager()
	if err := oldMgr.SetKeyInMemory(crypto.DeriveKey(flowCurrent, flowSecretKey, flowSalt)); err != nil {
		t.Fatal(err)
	}

	encPriv, err := oldMgr.EncryptUserPrivateKey([]byte(testPrivateKey))
	if err != nil {
		t.Fatal(err)
	}

	cfg := &vaultroute.Config{}
	for i, name := range []string{"Personal", "Team"} {
		raw := make([]byte, 32)
		for j := range raw {
			raw[j] = byte(i*11 + j)
		}
		wrapped, err := oldMgr.EncryptVaultKey(raw)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Vaults = append(cfg.Vaults, vaultroute.Vault{
			VaultID:           "vault-" + strings.ToLower(name),
			Name:              name,
			EncryptedVaultKey: wrapped,
			IsDefault:         i == 0,
		})
	}

	return &flowHarness{
		t:                   t,
		answers:             []string{flowCurrent, flowNew, flowNew},
		authCfg:             &AuthConfig{Email: flowEmail, UserID: "user-1", AuthMethod: "srp"},
		vaults:              cfg,
		encryptedPrivateKey: encPriv,
	}
}

// assertNoLocalChange is the invariant every failure test shares.
func (h *flowHarness) assertNoLocalChange(t *testing.T) {
	t.Helper()
	for _, call := range h.calls {
		if call == "commit" {
			t.Error("the flow committed local changes despite failing")
		}
	}
}

func TestTheCommandIsRegisteredUnderAccount(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"account", "change-password"})
	if err != nil {
		t.Fatalf("finding the command: %v", err)
	}
	if cmd.Name() != "change-password" || cmd.Parent().Name() != "account" {
		t.Errorf("found %q under %q", cmd.Name(), cmd.Parent().Name())
	}
	if cmd.RunE == nil {
		t.Error("the command does nothing")
	}
}

func TestTheHappyPathOrderAndBody(t *testing.T) {
	h := newFlow(t)
	if err := runChangePassword(h.deps()); err != nil {
		t.Fatalf("runChangePassword: %v", err)
	}

	// Every read and both network calls precede the commit, and the commit is
	// last. This ordering IS the safety property.
	want := []string{
		"auth-config", "auth-token",
		"prompt", "prompt", "prompt",
		"secret-key", "salt",
		"load-vaults", "fetch-private-key", "srp-challenge",
		"post", "commit",
	}
	if strings.Join(h.calls, ",") != strings.Join(want, ",") {
		t.Errorf("call order:\n got: %v\nwant: %v", h.calls, want)
	}

	if len(h.prompts) != 3 || !strings.Contains(h.prompts[0], "Current") ||
		!strings.Contains(h.prompts[1], "New") || !strings.Contains(h.prompts[2], "Confirm") {
		t.Errorf("prompts = %q", h.prompts)
	}

	if h.postedToken != flowToken {
		t.Errorf("posted with token %q", h.postedToken)
	}

	p := h.postedPayload
	if p.ClientPublic != "A-hex" || p.ClientProof != "M1-hex" {
		t.Errorf("the current-password proof did not reach the payload: %+v", p)
	}
	// The verifier must be the one the new password produces, under the salt
	// sent with it — anything else locks the user out of their own account.
	if p.SRPSalt == "" || p.SRPVerifier == "" {
		t.Fatal("no new verifier was sent")
	}
	if !verifierMatches(t, flowEmail, flowNew, p.SRPSalt, p.SRPVerifier) {
		t.Error("the verifier sent does not correspond to the new password")
	}
	if verifierMatches(t, flowEmail, flowCurrent, p.SRPSalt, p.SRPVerifier) {
		t.Error("the verifier sent corresponds to the CURRENT password")
	}

	// Every vault, in file order, re-wrapped under the new key.
	if len(p.VaultKeys) != 2 || p.VaultKeys[0].VaultID != "vault-personal" || p.VaultKeys[1].VaultID != "vault-team" {
		t.Fatalf("vaultKeys = %+v", p.VaultKeys)
	}
	newMgr := encryption.NewManager()
	newKey := crypto.DeriveKey(flowNew, flowSecretKey, flowSalt)
	if err := newMgr.SetKeyInMemory(newKey); err != nil {
		t.Fatal(err)
	}
	for _, entry := range p.VaultKeys {
		if _, err := newMgr.DecryptVaultKey(entry.EncryptedVaultKey); err != nil {
			t.Errorf("vault %s is not readable with the new password: %v", entry.VaultID, err)
		}
	}
	priv, err := newMgr.DecryptUserPrivateKey(p.EncryptedPrivateKey)
	if err != nil || priv != testPrivateKey {
		t.Errorf("the private key was not re-wrapped under the new password (%v)", err)
	}

	// The commit gets the key derived from the NEW password, the server's
	// result, and the re-wrapped config.
	if string(h.committedKey) != string(newKey) {
		t.Error("the committed key is not the one derived from the new password")
	}
	if h.committedRes != h.result {
		t.Error("the commit did not receive the server's result")
	}
	if len(h.committedCfg.Vaults) != 2 || h.committedCfg.Vaults[0].EncryptedVaultKey != p.VaultKeys[0].EncryptedVaultKey {
		t.Errorf("the committed config is not the re-wrapped one: %+v", h.committedCfg)
	}
	if !strings.Contains(h.out.String(), "Password changed") {
		t.Errorf("output was %q", h.out.String())
	}
}

// verifierMatches recomputes v = g^x mod N from the password and the salt that
// was sent, the way the server will when this account next logs in. If these
// disagree, the user is locked out of their own account by their own password
// change.
func verifierMatches(t *testing.T, email, password, saltHex, verifier string) bool {
	t.Helper()

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		t.Fatalf("the salt sent is not hex: %v", err)
	}
	x := pbkdf2.Key([]byte(password), salt, 310000, 32, sha256.New)
	v := new(big.Int).Exp(big.NewInt(5), new(big.Int).SetBytes(x), srp.N)

	// srp renders values zero-padded to the width of N, in lower case.
	width := (srp.N.BitLen() + 7) / 8
	padded := make([]byte, width)
	b := v.Bytes()
	copy(padded[width-len(b):], b)
	return strings.ToLower(hex.EncodeToString(padded)) == verifier
}

func TestPromptValidationHappensBeforeAnyNetworkActivity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		answers []string
		wantErr string
	}{
		{"empty current password", []string{"", flowNew, flowNew}, "current password is required"},
		{"empty new password", []string{flowCurrent, "", ""}, "new password is required"},
		{"mismatched confirmation", []string{flowCurrent, flowNew, "something else"}, "do not match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFlow(t)
			h.answers = tc.answers

			err := runChangePassword(h.deps())
			if err == nil {
				t.Fatal("bad input was accepted")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q, want %q", err, tc.wantErr)
			}
			for _, call := range h.calls {
				switch call {
				case "fetch-private-key", "srp-challenge", "post", "commit":
					t.Errorf("bad input still reached %q", call)
				}
			}
			h.assertNoLocalChange(t)
		})
	}
}

func TestAnSSOAccountIsRefusedBeforeAnythingIsTyped(t *testing.T) {
	h := newFlow(t)
	h.authCfg = &AuthConfig{Email: flowEmail, AuthMethod: "saml"}

	err := runChangePassword(h.deps())
	if err == nil {
		t.Fatal("an SSO account was allowed to change a password it does not have")
	}
	if !strings.Contains(err.Error(), "SSO") {
		t.Errorf("error %q does not explain why", err)
	}
	if len(h.calls) != 1 || h.calls[0] != "auth-config" {
		t.Errorf("it did more than read the auth config: %v", h.calls)
	}
	h.assertNoLocalChange(t)
}

func TestEveryPreConfirmationFailureChangesNothingLocally(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*flowHarness)
		wantErr string
	}{
		{"not logged in", func(h *flowHarness) { h.authCfg, h.authCfgErr = nil, fmt.Errorf("no auth.json") }, "not logged in"},
		{"no token", func(h *flowHarness) { h.tokenErr = fmt.Errorf("no token found") }, "no token"},
		{"prompt fails", func(h *flowHarness) { h.promptErr = fmt.Errorf("not a terminal") }, "not a terminal"},
		{"secret key unreadable", func(h *flowHarness) { h.secretErr = fmt.Errorf("keychain locked") }, "secret key"},
		{"salt unreadable", func(h *flowHarness) { h.saltErr = fmt.Errorf("keychain locked") }, "salt"},
		{"vault config unreadable", func(h *flowHarness) { h.vaultsErr = fmt.Errorf("vaults.json is corrupt") }, "vault configuration"},
		{"keypair fetch fails", func(h *flowHarness) { h.fetchErr = fmt.Errorf("keypair unavailable") }, "keypair"},
		{"srp init fails", func(h *flowHarness) { h.challengeErr = fmt.Errorf("server returned 500") }, "500"},
		{"wrong current password", func(h *flowHarness) { h.answers = []string{"not-the-password", flowNew, flowNew} }, "current password"},
		{"a vault key will not open", func(h *flowHarness) {
			h.vaults.Vaults[1].EncryptedVaultKey = crypto.EncodeBase64([]byte("not a vault key"))
		}, "vault-team"},
		{"a vault has no key at all", func(h *flowHarness) { h.vaults.Vaults[1].EncryptedVaultKey = "" }, "vault-team"},
		{"the server rejects the change", func(h *flowHarness) { h.postErr = fmt.Errorf("server returned 401: INVALID_CREDENTIALS") }, "401"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFlow(t)
			tc.arrange(h)

			err := runChangePassword(h.deps())
			if err == nil {
				t.Fatal("a failing flow reported success")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
			h.assertNoLocalChange(t)
		})
	}
}

// A wrong current password must fail locally, before the account is touched at
// all: everything the old key protects fails to open together.
func TestAWrongCurrentPasswordNeverReachesTheServer(t *testing.T) {
	h := newFlow(t)
	h.answers = []string{"not-the-password", flowNew, flowNew}

	if err := runChangePassword(h.deps()); err == nil {
		t.Fatal("a wrong current password was accepted")
	}
	for _, call := range h.calls {
		if call == "post" {
			t.Error("a wrong current password was posted to the server")
		}
	}
	h.assertNoLocalChange(t)
}

// A failing commit is reported rather than swallowed: the server has already
// changed the password, and a user who is told nothing will not know to log in
// again.
func TestAFailedCommitIsReported(t *testing.T) {
	h := newFlow(t)
	h.commitErr = fmt.Errorf("keychain unavailable")

	err := runChangePassword(h.deps())
	if err == nil {
		t.Fatal("a failed commit reported success")
	}
	if !strings.Contains(err.Error(), "keychain unavailable") {
		t.Errorf("error %q loses the reason", err)
	}
	if strings.Contains(h.out.String(), "Password changed") {
		t.Error("it announced success after a failed commit")
	}
}

// A password must not outlive the command in memory. Go cannot wipe the strings
// these are converted into, but the buffers the terminal filled are ours, and
// leaving them intact leaves the user's password sitting in a heap that may be
// swapped, cored, or read by a later allocation.

// assertPasswordBuffersWiped inspects the actual memory the flow was handed.
func (h *flowHarness) assertPasswordBuffersWiped(t *testing.T) {
	t.Helper()

	if len(h.handed) == 0 {
		t.Fatal("no password buffers were handed to the flow")
	}
	for i, buf := range h.handed {
		for _, b := range buf {
			if b != 0 {
				t.Errorf("password buffer %d still holds %q after the command returned", i, buf)
				break
			}
		}
	}
}

func TestPasswordBuffersAreWipedOnSuccess(t *testing.T) {
	h := newFlow(t)
	if err := runChangePassword(h.deps()); err != nil {
		t.Fatalf("runChangePassword: %v", err)
	}
	if len(h.handed) != 3 {
		t.Fatalf("the flow read %d passwords, want 3", len(h.handed))
	}
	h.assertPasswordBuffersWiped(t)
}

func TestPasswordBuffersAreWipedWhenTheConfirmationDoesNotMatch(t *testing.T) {
	h := newFlow(t)
	h.answers = []string{flowCurrent, flowNew, "something else"}

	if err := runChangePassword(h.deps()); err == nil {
		t.Fatal("a mismatch was accepted")
	}
	// All three, including the confirmation that caused the failure: the
	// mismatched one is still a password the user typed.
	if len(h.handed) != 3 {
		t.Fatalf("the flow read %d passwords, want 3", len(h.handed))
	}
	h.assertPasswordBuffersWiped(t)
}

func TestPasswordBuffersAreWipedWhenAlaterStepFails(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*flowHarness)
	}{
		{"the server rejects the change", func(h *flowHarness) { h.postErr = fmt.Errorf("server returned 401") }},
		{"the commit fails", func(h *flowHarness) { h.commitErr = fmt.Errorf("keychain unavailable") }},
		{"a vault key will not open", func(h *flowHarness) {
			h.vaults.Vaults[1].EncryptedVaultKey = crypto.EncodeBase64([]byte("not a vault key"))
		}},
		{"the keypair fetch fails", func(h *flowHarness) { h.fetchErr = fmt.Errorf("keypair unavailable") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFlow(t)
			tc.arrange(h)

			if err := runChangePassword(h.deps()); err == nil {
				t.Fatal("a failing flow reported success")
			}
			h.assertPasswordBuffersWiped(t)
		})
	}
}

// The prompt text is part of what the command says, so it goes to the command's
// writer like everything else — otherwise nothing can see what was asked.
func TestThePromptIsWrittenToTheCommandsWriter(t *testing.T) {
	var out bytes.Buffer

	// A descriptor that is not this process's terminal: the read fails at once
	// rather than waiting for input that a test will never type.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	password, err := promptPasswordFrom(&out, int(devNull.Fd()), "Current password: ")
	if err == nil {
		t.Fatal("reading a password from /dev/null succeeded")
	}
	if password != nil {
		t.Errorf("a failed read still handed back %q", password)
	}
	if got := out.String(); got != "Current password: \n" {
		t.Errorf("the writer got %q, want the prompt and the newline after the unechoed Return", got)
	}
}

func TestNeitherAccountCommandTakesArguments(t *testing.T) {
	for _, args := range [][]string{{"account", "extra"}, {"account", "change-password", "extra"}} {
		cmd, remaining, err := rootCmd.Find(args)
		if err != nil {
			// cobra already refuses an unknown subcommand of account.
			continue
		}
		if cmd.Args == nil {
			t.Errorf("%s has no argument validator, so stray arguments are ignored", cmd.Name())
			continue
		}
		if err := cmd.Args(cmd, remaining); err == nil {
			t.Errorf("%v was accepted with arguments %v", args, remaining)
		}
	}
}
