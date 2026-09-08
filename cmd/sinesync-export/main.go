// Command sinesync-export runs a self-hosted export daemon (#104).
//
// It is a separate binary, not a mode of the sinesync CLI, so the PostgreSQL
// driver and the export machinery are not linked into the binary every user
// installs. Enterprise customers get this one directly, which they are already
// in contact with us about.
//
// It pulls encrypted observations, decrypts them locally with the organization
// key from a credentials file, and writes plaintext to a database the customer
// runs. Nothing decrypted returns to sinesync.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sinesync/cli/internal/export"
	"github.com/sinesync/cli/internal/orgkey"
)

var version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/sinesync/export.json", "path to the export config file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	once := flag.Bool("once", false, "run a single pass and exit, for verifying a new deployment")
	flag.Parse()

	if *showVersion {
		fmt.Println("sinesync-export", version)
		return
	}

	if err := run(*cfgPath, *once); err != nil {
		log.Fatalf("sinesync-export: %v", err)
	}
}

func run(cfgPath string, once bool) error {
	cfg, err := export.LoadConfig(cfgPath)
	if err != nil {
		return err
	}

	// Cancelled on SIGINT/SIGTERM so a pass in flight finishes its write rather
	// than being killed between fetch and commit.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	orgKey, err := loadOrgKey(cfg)
	if err != nil {
		return err
	}
	defer zero(orgKey)

	secret, err := cfg.Secret()
	if err != nil {
		return err
	}

	dsn, err := cfg.DSN()
	if err != nil {
		return err
	}

	target, err := export.OpenPostgres(ctx, dsn)
	if err != nil {
		return err
	}
	defer target.Close()

	src := export.NewAPISource(cfg.APIBase, cfg.KeyID, secret, cfg.VaultIDs, orgKey)

	opts := export.Options{
		BatchSize: cfg.BatchSize,
		Interval:  cfg.Interval(),
		Report:    report,
	}

	if once {
		// A single pass, so a new deployment can be verified without leaving a
		// daemon running against a target nobody has checked yet.
		opts.Interval = time.Nanosecond
		ctx, cancel := context.WithCancel(ctx)
		done := 0
		opts.Report = func(m export.Metrics) {
			report(m)
			if done++; done >= 1 {
				cancel()
			}
		}
		err := export.Run(ctx, src, target, opts)
		if err != nil && ctx.Err() == nil {
			return err
		}
		return nil
	}

	log.Printf("exporting vaults %v from %s every %s", cfg.VaultIDs, cfg.APIBase, cfg.Interval())
	if err := export.Run(ctx, src, target, opts); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

// loadOrgKey reads the credentials file written by `sinesync admin export-key`.
func loadOrgKey(cfg *export.Config) ([]byte, error) {
	raw, err := os.ReadFile(cfg.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("reading credentials file: %w", err)
	}

	var file orgkey.File
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("parsing credentials file: %w", err)
	}

	passphrase, err := cfg.Passphrase()
	if err != nil {
		return nil, err
	}

	key, err := orgkey.Open(&file, passphrase)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// report logs one line per pass, so an operator can see progress without
// querying the export database.
func report(m export.Metrics) {
	if m.Err != nil {
		log.Printf("pass failed after %d attempt(s) in %s: %v", m.Attempts, m.Duration.Round(time.Millisecond), m.Err)
		return
	}
	if m.Fetched == 0 {
		log.Printf("up to date (cursor %s)", m.Cursor.UpdatedAt.Format(time.RFC3339))
		return
	}
	log.Printf("exported %d observation(s) in %s (cursor %s)",
		m.Written, m.Duration.Round(time.Millisecond), m.Cursor.UpdatedAt.Format(time.RFC3339))
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
