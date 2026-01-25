package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// Config represents the sinesync configuration
type Config struct {
	ClaudeMemMode bool        `json:"claudeMemMode"`
	Sync          *SyncConfig `json:"sync,omitempty"`

	// Multi-vault support (like 1Password)
	DefaultVault string            `json:"defaultVault,omitempty"` // default: "personal"
	Vaults       map[string]*Vault `json:"vaults,omitempty"`
	Routes       map[string]string `json:"routes,omitempty"` // project -> vault mapping
}

// Vault represents a sync destination with its own key
type Vault struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"` // "personal" | "shared"
	Backend *Backend `json:"backend,omitempty"`
	KeyID   string   `json:"keyId,omitempty"` // keychain reference

	// For shared vaults (teams)
	TeamID   string   `json:"teamId,omitempty"`
	TeamName string   `json:"teamName,omitempty"`
	Members  []string `json:"members,omitempty"` // for display only
}

// Backend represents a storage backend configuration
type Backend struct {
	Type string `json:"type"` // "sinesync" | "s3" | "azure" | "gcs" | "minio" | "local"

	// S3-compatible options
	Endpoint  string `json:"endpoint,omitempty"`
	Bucket    string `json:"bucket,omitempty"`
	Region    string `json:"region,omitempty"`
	AccessKey string `json:"accessKey,omitempty"` // reference to keychain, not actual key
	SecretKey string `json:"secretKey,omitempty"` // reference to keychain, not actual key

	// Azure options
	Container     string `json:"container,omitempty"`
	AccountName   string `json:"accountName,omitempty"`
	AccountKey    string `json:"accountKey,omitempty"` // reference to keychain

	// Local/self-hosted options
	Path string `json:"path,omitempty"` // for local file backend
}

// SyncConfig contains sync-related settings (legacy, kept for compatibility)
type SyncConfig struct {
	ExcludeProjects []string `json:"excludeProjects,omitempty"`
	IncludeProjects []string `json:"includeProjects,omitempty"`
}

// ConfigDir returns the sinesync config directory
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".sinesync")
}

// ConfigPath returns the path to the config file
func ConfigPath() string {
	return filepath.Join(ConfigDir(), "config.json")
}

// DataDir returns the sinesync data directory
func DataDir() string {
	return filepath.Join(ConfigDir(), "data")
}

// VaultDataDir returns the data directory for a specific vault
func VaultDataDir(vaultID string) string {
	return filepath.Join(ConfigDir(), "vaults", vaultID, "data")
}

// Load loads the configuration from disk
func Load() (*Config, error) {
	path := ConfigPath()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Ensure defaults
	if cfg.DefaultVault == "" {
		cfg.DefaultVault = "personal"
	}
	if cfg.Vaults == nil {
		cfg.Vaults = make(map[string]*Vault)
	}
	if cfg.Routes == nil {
		cfg.Routes = make(map[string]string)
	}

	return &cfg, nil
}

// DefaultConfig returns a config with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		DefaultVault: "personal",
		Vaults: map[string]*Vault{
			"personal": {
				ID:   "personal",
				Name: "Personal",
				Type: "personal",
				Backend: &Backend{
					Type: "sinesync",
				},
			},
		},
		Routes: make(map[string]string),
	}
}

// Save saves the configuration to disk
func Save(cfg *Config) error {
	// Ensure directory exists
	if err := os.MkdirAll(ConfigDir(), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(), data, 0644)
}

// ShouldSyncProject checks if a project should be synced based on config
func (c *Config) ShouldSyncProject(project string) bool {
	if c.Sync == nil {
		return true
	}

	// If includeProjects is set, only sync those
	if len(c.Sync.IncludeProjects) > 0 {
		for _, p := range c.Sync.IncludeProjects {
			if p == project {
				return true
			}
		}
		return false
	}

	// Otherwise, exclude specified projects
	for _, p := range c.Sync.ExcludeProjects {
		if p == project {
			return false
		}
	}

	return true
}

// GetVaultForProject returns the vault ID for a given project
func (c *Config) GetVaultForProject(project string) string {
	if c.Routes != nil {
		if vault, ok := c.Routes[project]; ok {
			return vault
		}
	}
	if c.DefaultVault != "" {
		return c.DefaultVault
	}
	return "personal"
}

// GetVault returns a vault by ID
func (c *Config) GetVault(id string) *Vault {
	if c.Vaults == nil {
		return nil
	}
	return c.Vaults[id]
}

// ListVaults returns all configured vaults
func (c *Config) ListVaults() []*Vault {
	if c.Vaults == nil {
		return nil
	}
	vaults := make([]*Vault, 0, len(c.Vaults))
	for _, v := range c.Vaults {
		vaults = append(vaults, v)
	}
	return vaults
}

// AddVault adds a new vault
func (c *Config) AddVault(vault *Vault) {
	if c.Vaults == nil {
		c.Vaults = make(map[string]*Vault)
	}
	c.Vaults[vault.ID] = vault
}

// RemoveVault removes a vault
func (c *Config) RemoveVault(id string) {
	if c.Vaults != nil {
		delete(c.Vaults, id)
	}
	// Clean up routes pointing to this vault
	if c.Routes != nil {
		for project, vault := range c.Routes {
			if vault == id {
				delete(c.Routes, project)
			}
		}
	}
}

// SetRoute sets the vault for a project
func (c *Config) SetRoute(project, vaultID string) {
	if c.Routes == nil {
		c.Routes = make(map[string]string)
	}
	c.Routes[project] = vaultID
}

// ClearRoute removes a project routing
func (c *Config) ClearRoute(project string) {
	if c.Routes != nil {
		delete(c.Routes, project)
	}
}
