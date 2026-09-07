package vaultroute

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := filepath.Join(home, ".sinesync")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vaults.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const twoVaults = `{"vaults":[
  {"vaultId":"personal","name":"Personal","isDefault":true,"projects":[]},
  {"vaultId":"shared","name":"sine","isDefault":false,"projects":["sinesync","cli"]}
]}`

func TestAnAssignedProjectRoutesToItsVault(t *testing.T) {
	writeConfig(t, twoVaults)

	if got := ForProject("cli", "personal"); got != "shared" {
		t.Errorf("ForProject(cli) = %q, want shared", got)
	}
}

func TestAnUnassignedProjectFallsBackToTheDefault(t *testing.T) {
	writeConfig(t, twoVaults)

	if got := ForProject("something-else", "personal"); got != "personal" {
		t.Errorf("ForProject(unassigned) = %q, want the default", got)
	}
}

func TestNoProjectMeansTheDefault(t *testing.T) {
	writeConfig(t, twoVaults)

	if got := ForProject("", "personal"); got != "personal" {
		t.Errorf("ForProject(\"\") = %q, want the default", got)
	}
}

// A missing config is a fresh install, not a failure: everything routes to
// whatever default the caller already resolved.
func TestAMissingConfigRoutesToTheDefault(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	if got := ForProject("anything", "personal"); got != "personal" {
		t.Errorf("ForProject with no config = %q, want the default", got)
	}
}

// The state `add-project` now refuses to create, which nonetheless exists on
// disk for anyone who made it before that check. Reporting both is what lets a
// caller notice the ambiguity rather than silently resolving it.
func TestBothClaimantsAreReportedWhenAProjectIsAssignedTwice(t *testing.T) {
	writeConfig(t, `{"vaults":[
	  {"vaultId":"first","name":"A","isDefault":true,"projects":["shared-project"]},
	  {"vaultId":"second","name":"B","isDefault":false,"projects":["shared-project"]}
	]}`)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	claiming := cfg.VaultsForProject("shared-project")
	if len(claiming) != 2 {
		t.Fatalf("VaultsForProject = %v, want both vaults", claiming)
	}

	// And routing still answers, deterministically, with the first in file
	// order — the pre-existing behaviour, not a new choice.
	if got := ForProject("shared-project", "first"); got != "first" {
		t.Errorf("ForProject = %q, want the first claimant in file order", got)
	}
}

func TestDefaultVaultIDReadsTheFlag(t *testing.T) {
	writeConfig(t, twoVaults)

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DefaultVaultID(); got != "personal" {
		t.Errorf("DefaultVaultID = %q", got)
	}
}

func TestNameOfResolvesAConfiguredVault(t *testing.T) {
	writeConfig(t, twoVaults)

	if got := NameOf("shared"); got != "sine" {
		t.Errorf("NameOf(shared) = %q, want sine", got)
	}
	if got := NameOf("not-configured"); got != "" {
		t.Errorf("NameOf(unknown) = %q, want empty", got)
	}
}
