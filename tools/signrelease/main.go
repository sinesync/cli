// Command signrelease produces the detached Ed25519 signature that
// `sinesync update` requires before it will install a release.
//
// It is a committed tool rather than a few lines of shell in the workflow on
// purpose: reconstructing a PKCS#8 wrapper around a raw seed so that `openssl
// pkeyutl` will accept it needs a hard-coded DER prefix, and a silently wrong
// prefix yields a signature that fails only at update time on user machines.
// This does the same thing the verifier does, in the same library.
//
// Usage:
//
//	RELEASE_ED25519_PRIVATE_KEY=<base64 32-byte seed> signrelease <file>
//
// The base64-encoded signature is written to stdout. The public half is NOT
// derived or printed here — the committed sinesync-release-ed25519.pub is the
// authority, and a mismatch between them must fail the release rather than be
// papered over, so pass --expect-pubkey to assert they agree.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	expectPub := flag.String("expect-pubkey", "", "base64 public key the seed must correspond to; release fails if it does not")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: signrelease [--expect-pubkey <base64>] <file>")
		os.Exit(2)
	}

	seedB64 := strings.TrimSpace(os.Getenv("RELEASE_ED25519_PRIVATE_KEY"))
	if seedB64 == "" {
		fatal("RELEASE_ED25519_PRIVATE_KEY is not set. A release built without it would be rejected by every client that verifies signatures, so this is a hard failure rather than a skip.")
	}

	seed, err := base64.StdEncoding.DecodeString(seedB64)
	if err != nil {
		fatal("RELEASE_ED25519_PRIVATE_KEY is not valid base64: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		fatal("RELEASE_ED25519_PRIVATE_KEY decodes to %d bytes, want %d", len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	// Catch a seed/pubkey mismatch here, where it costs a failed CI run, rather
	// than after publication where it costs every user a broken update.
	if *expectPub != "" {
		want := strings.TrimSpace(*expectPub)
		got := base64.StdEncoding.EncodeToString(pub)
		if want != got {
			fatal("signing key does not match the committed public key.\n  committed: %s\n  from seed: %s\nThe release would install nowhere.", want, got)
		}
	}

	message, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fatal("cannot read %s: %v", flag.Arg(0), err)
	}

	sig := ed25519.Sign(priv, message)

	// Verify what we just produced. Cheap, and it means a signature that cannot
	// validate never leaves this process.
	if !ed25519.Verify(pub, message, sig) {
		fatal("self-check failed: the signature just produced does not verify")
	}

	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "signrelease: "+format+"\n", args...)
	os.Exit(1)
}
