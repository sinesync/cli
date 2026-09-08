package export

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is the export daemon's configuration file (#104).
//
// A file rather than flags, because it names a database DSN and a credentials
// passphrase source: both belong in something with file permissions, not in a
// process listing every user on the host can read.
type Config struct {
	// APIBase is the sinesync API to pull from.
	APIBase string `json:"apiBase"`

	// ServiceAccount credentials, exchanged for a short-lived scoped token.
	KeyID string `json:"keyId"`
	// SecretEnv names the environment variable holding the secret, rather than
	// the secret itself: a config file gets copied, reviewed and backed up in
	// ways a secret store does not.
	SecretEnv string `json:"secretEnv"`

	// CredentialsFile holds the org private key, written by
	// `sinesync admin export-key`.
	CredentialsFile string `json:"credentialsFile"`
	// PassphraseEnv names the environment variable holding its passphrase. Kept
	// apart from the file on purpose: the file alone must not be enough.
	PassphraseEnv string `json:"passphraseEnv"`

	// VaultIDs to export. Must be a subset of what the service account is
	// scoped to; the server refuses anything else regardless.
	VaultIDs []string `json:"vaultIds"`

	// TargetDSN is the export database.
	TargetDSN string `json:"targetDsn"`
	// TargetDSNEnv is an alternative to TargetDSN, for the common case where
	// the DSN carries a password.
	TargetDSNEnv string `json:"targetDsnEnv"`

	// PollSeconds between passes once caught up. Zero means the default.
	PollSeconds int `json:"pollSeconds"`
	// BatchSize per fetch. Zero means the default.
	BatchSize int `json:"batchSize"`
}

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var c Config
	// Unknown fields are an error, not a shrug: a typo in a key silently
	// disables whatever it was meant to configure, and "vaultId" instead of
	// "vaultIds" would export nothing while looking configured.
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	var missing []string
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"apiBase", c.APIBase != ""},
		{"keyId", c.KeyID != ""},
		{"secretEnv", c.SecretEnv != ""},
		{"credentialsFile", c.CredentialsFile != ""},
		{"passphraseEnv", c.PassphraseEnv != ""},
		{"targetDsn or targetDsnEnv", c.TargetDSN != "" || c.TargetDSNEnv != ""},
	} {
		if !f.set {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config is missing: %s", strings.Join(missing, ", "))
	}

	// An empty vault list would look like "export everything" and silently
	// export nothing, which is the worst of both.
	if len(c.VaultIDs) == 0 {
		return fmt.Errorf("config names no vaultIds; list the vaults to export")
	}
	return nil
}

// Secret returns the service account secret from the environment.
func (c *Config) Secret() (string, error) { return c.fromEnv(c.SecretEnv) }

// Passphrase returns the credentials file passphrase from the environment.
func (c *Config) Passphrase() (string, error) { return c.fromEnv(c.PassphraseEnv) }

// DSN returns the export target DSN, preferring the environment form.
func (c *Config) DSN() (string, error) {
	if c.TargetDSNEnv != "" {
		return c.fromEnv(c.TargetDSNEnv)
	}
	return c.TargetDSN, nil
}

func (c *Config) fromEnv(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		// Named rather than described, so the operator knows exactly what to
		// set without reading the config back.
		return "", fmt.Errorf("environment variable %s is empty", name)
	}
	return v, nil
}

// Interval is the configured poll interval, or the default.
func (c *Config) Interval() time.Duration {
	if c.PollSeconds <= 0 {
		return time.Minute
	}
	return time.Duration(c.PollSeconds) * time.Second
}
