// Package vaultroute decides which vault an observation belongs to.
//
// This existed twice: once in the CLI and once in the daemon, each with its own
// copy of the config type, its own loader, and its own fallback. They agreed,
// but nothing made them — and what they agree about is where a user's data
// goes. A capture routed one way by the daemon and another by `sinesync sync`
// would split a project across vaults, and the only symptom would be data
// quietly landing somewhere the user did not expect, possibly a vault shared
// with someone else.
//
// Read-only on purpose. Writing the config stays with the CLI, which owns the
// commands that change it; this package answers questions about it.
package vaultroute

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/sinesync/cli/internal/config"
)

// Vault is one entry in the local vault configuration.
type Vault struct {
	VaultID           string   `json:"vaultId"`
	Name              string   `json:"name"`
	EncryptedVaultKey string   `json:"encryptedVaultKey"`
	Projects          []string `json:"projects"`
	IsDefault         bool     `json:"isDefault"`
	IsOrgVault        bool     `json:"isOrgVault,omitempty"`
	OrgID             string   `json:"orgId,omitempty"`
}

// Config is the local vault configuration as stored on disk.
type Config struct {
	Vaults []Vault `json:"vaults"`
}

// Path is where the local vault configuration lives.
func Path() string {
	return filepath.Join(config.ConfigDir(), "vaults.json")
}

// Load reads the local vault configuration. A missing file is an empty
// configuration rather than an error: a fresh install has no vaults yet.
func Load() (*Config, error) {
	data, err := os.ReadFile(Path())
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// DefaultVaultID returns the vault an unassigned project routes to, or "" when
// no vault is marked default.
func (c *Config) DefaultVaultID() string {
	for _, v := range c.Vaults {
		if v.IsDefault {
			return v.VaultID
		}
	}
	return ""
}

// VaultsForProject names every vault claiming this project.
//
// Returns a slice rather than one id because more than one is possible and is
// a real state on disk: assignment used to append without clearing a previous
// one. Callers that need a single answer use ForProject; callers that need to
// notice the ambiguity ask for all of them.
func (c *Config) VaultsForProject(project string) []string {
	if project == "" {
		return nil
	}

	var claiming []string
	for _, v := range c.Vaults {
		for _, p := range v.Projects {
			if p == project {
				claiming = append(claiming, v.VaultID)
				break
			}
		}
	}
	return claiming
}

// ForProject returns the vault an observation in this project belongs to,
// falling back to the default vault.
//
// When more than one vault claims the project the first in file order wins,
// which is arbitrary — but it is the behaviour that already exists, and
// changing which arbitrary answer is given would move data without saying so.
// The commands that create that state refuse to now; this reports it rather
// than resolving it differently.
func ForProject(project, defaultVaultID string) string {
	if project == "" {
		return defaultVaultID
	}

	cfg, err := Load()
	if err != nil {
		return defaultVaultID
	}

	if claiming := cfg.VaultsForProject(project); len(claiming) > 0 {
		return claiming[0]
	}
	return defaultVaultID
}

// NameOf returns a vault's display name, or "" when it is not configured.
func NameOf(vaultID string) string {
	cfg, err := Load()
	if err != nil {
		return ""
	}
	for _, v := range cfg.Vaults {
		if v.VaultID == vaultID {
			return v.Name
		}
	}
	return ""
}
