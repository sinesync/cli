// ABOUTME: Covers the service-account command's argument validation.
// ABOUTME: These run before any network call, which is the point of them.

package cli

import (
	"strings"
	"testing"
)

// The validation exists so a mistake costs an error message rather than a
// half-made account, or worse a correct-looking one scoped to the wrong vaults.
// It has to run before the request, not be inferred from a 400.
func TestServiceAccountCreateRefusesIncompleteArguments(t *testing.T) {
	cases := []struct {
		name       string
		label      string
		vaults     []string
		allVaults  bool
		wantErrSub string
	}{
		{
			name:       "no label",
			vaults:     []string{"v1"},
			wantErrSub: "--label is required",
		},
		{
			name:       "no vaults named and no --all-vaults",
			label:      "exporter",
			wantErrSub: "--vault",
		},
		{
			name:       "both --vault and --all-vaults",
			label:      "exporter",
			vaults:     []string{"v1"},
			allVaults:  true,
			wantErrSub: "mutually exclusive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			saLabel, saVaultIDs, saAllVault = tc.label, tc.vaults, tc.allVaults
			t.Cleanup(func() { saLabel, saVaultIDs, saAllVault = "", nil, false })

			err := runServiceAccountCreate(nil, nil)
			if err == nil {
				t.Fatal("accepted incomplete arguments")
			}
			if !strings.Contains(err.Error(), tc.wantErrSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantErrSub)
			}
		})
	}
}

// The complete case must NOT be rejected by validation. Without this, a
// validation bug that refused everything would pass every case above.
func TestServiceAccountCreateAcceptsCompleteArguments(t *testing.T) {
	saLabel, saVaultIDs, saAllVault = "exporter", []string{"v1"}, false
	t.Cleanup(func() { saLabel, saVaultIDs, saAllVault = "", nil, false })

	// Reaches the network and fails there, which is as far as this can go
	// without a server. What matters is that it is not a validation message.
	err := runServiceAccountCreate(nil, nil)
	if err == nil {
		return // a configured environment; nothing to assert
	}
	for _, rejected := range []string{"--label is required", "mutually exclusive", "name the vaults"} {
		if strings.Contains(err.Error(), rejected) {
			t.Errorf("complete arguments were rejected by validation: %v", err)
		}
	}
}

// The role gate, tested without a server. The route enforces this too, so a bug
// here is a worse message rather than an escalation — but "the server will catch
// it" is how a client-side check drifts into being decorative.
func TestOnlyTheOwnerMayManageServiceAccounts(t *testing.T) {
	for role, want := range map[string]bool{
		"owner":   true,
		"admin":   false,
		"member":  false,
		"billing": false,
		"":        false,
		"Owner":   false, // roles are lowercase on the wire; no case-folding
	} {
		if got := roleMayManageServiceAccounts(role); got != want {
			t.Errorf("role %q: got %v, want %v", role, got, want)
		}
	}
}
