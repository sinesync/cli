package export

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// #104: a misconfigured export daemon that starts anyway is the dangerous case,
// because it looks like it is working. These check it refuses instead.

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validConfig = `{
  "apiBase": "https://api.sinesync.ai",
  "keyId": "sa_abc",
  "secretEnv": "SA_SECRET",
  "credentialsFile": "/etc/sinesync/org.key",
  "passphraseEnv": "ORG_PASSPHRASE",
  "vaultIds": ["v1"],
  "targetDsn": "postgres://localhost/export"
}`

func TestLoadsAValidConfig(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if c.KeyID != "sa_abc" || len(c.VaultIDs) != 1 {
		t.Fatalf("parsed wrongly: %+v", c)
	}
}

func TestRefusesAConfigWithNoVaults(t *testing.T) {
	// An empty list reads as "everything" and exports nothing, which is the
	// worst of both.
	body := strings.Replace(validConfig, `"vaultIds": ["v1"],`, `"vaultIds": [],`, 1)
	if _, err := LoadConfig(writeConfig(t, body)); err == nil {
		t.Fatal("a config naming no vaults was accepted")
	}
}

func TestRefusesAMistypedKey(t *testing.T) {
	// A typo in an optional key is the sharp case: everything required is
	// present, so nothing else can reject it and the daemon would run with the
	// setting silently ignored. Using a typo of a REQUIRED key would not test
	// this, because the missing-field check catches that one anyway.
	body := strings.Replace(validConfig,
		`"vaultIds": ["v1"],`, `"vaultIds": ["v1"], "pollSecondz": 30,`, 1)

	_, err := LoadConfig(writeConfig(t, body))
	if err == nil {
		t.Fatal("a mistyped optional key was silently ignored")
	}
	if !strings.Contains(err.Error(), "pollSecondz") {
		t.Fatalf("error does not name the offending key: %v", err)
	}
}

func TestNamesEveryMissingField(t *testing.T) {
	// One error listing everything missing, rather than one restart per field.
	_, err := LoadConfig(writeConfig(t, `{"apiBase":"https://x"}`))
	if err == nil {
		t.Fatal("an almost-empty config was accepted")
	}
	for _, want := range []string{"keyId", "secretEnv", "credentialsFile", "passphraseEnv"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention missing %q: %v", want, err)
		}
	}
}

func TestSecretsComeFromTheEnvironmentNotTheFile(t *testing.T) {
	// A config file gets copied, reviewed and backed up in ways a secret store
	// does not, so the file names the variable rather than holding the value.
	c, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Secret(); err == nil {
		t.Fatal("an unset secret variable was accepted")
	} else if !strings.Contains(err.Error(), "SA_SECRET") {
		t.Fatalf("error does not name the variable to set: %v", err)
	}

	t.Setenv("SA_SECRET", "s3cret")
	got, err := c.Secret()
	if err != nil || got != "s3cret" {
		t.Fatalf("Secret() = %q, %v", got, err)
	}
}

func TestDSNPrefersTheEnvironmentForm(t *testing.T) {
	body := strings.Replace(validConfig,
		`"targetDsn": "postgres://localhost/export"`,
		`"targetDsn": "postgres://ignored", "targetDsnEnv": "TARGET_DSN"`, 1)
	c, err := LoadConfig(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("TARGET_DSN", "postgres://real/export")
	got, err := c.DSN()
	if err != nil || got != "postgres://real/export" {
		t.Fatalf("DSN() = %q, %v; the environment form must win", got, err)
	}
}

func TestIntervalDefaults(t *testing.T) {
	c, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval() != time.Minute {
		t.Fatalf("default interval %s, want 1m", c.Interval())
	}
}

func TestMissingConfigFileIsAnError(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("a missing config file was accepted")
	}
}
