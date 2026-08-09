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
//	RELEASE_ED25519_PRIVATE_KEY=<base64 32-byte seed> \
//	  signrelease --pubkey-file sinesync-release-ed25519.pub <file>
//
// The base64-encoded signature is written to stdout. The public half is NOT
// derived from the seed and trusted — the committed sinesync-release-ed25519.pub
// is the authority, and a mismatch between them must fail the release rather
// than be papered over.
//
// --pubkey-file takes the PATH and this tool reads it. It used to take the key
// material itself, which the workflow filled in with a command substitution:
//
//	--expect-pubkey "$(tr -d '\n' < sinesync-release-ed25519.pub)"
//
// If that file was ever missing or renamed, the substitution collapsed to an
// empty string, an empty value meant "no key to check against, skip", and the
// release was signed by whatever seed was in the environment and published with
// a signature no client could verify — exit 0, no failure anywhere. Reading the
// file here means an unreadable key is an error raised by the code that needs
// it, and there is no value of the flag that means "skip".
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
	pubFile := flag.String("pubkey-file", "", "path to the committed base64 Ed25519 public key the seed must correspond to (required)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: signrelease --pubkey-file <path> <file>")
		os.Exit(2)
	}
	if strings.TrimSpace(*pubFile) == "" {
		fmt.Fprintln(os.Stderr, "signrelease: --pubkey-file is required. The signing key must be checked against the committed public key; there is no mode that skips that check.")
		os.Exit(2)
	}

	wantPub := loadPublicKey(*pubFile)

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
	if !pub.Equal(wantPub) {
		fatal("signing key does not match the public key in %s.\n  committed: %s\n  from seed: %s\nThe release would install nowhere.",
			*pubFile,
			base64.StdEncoding.EncodeToString(wantPub),
			base64.StdEncoding.EncodeToString(pub))
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

// loadPublicKey reads and validates the committed public key. Every failure
// path is fatal and names the path, because the only reason to be lenient here
// would be to let a release through unchecked.
func loadPublicKey(path string) ed25519.PublicKey {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal("cannot read public key file %s: %v", path, err)
	}

	text := strings.TrimSpace(string(raw))
	if text == "" {
		fatal("public key file %s is empty (or contains only whitespace); it must contain the base64 Ed25519 public key", path)
	}

	pub, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		fatal("public key file %s is not valid base64: %v", path, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		fatal("public key file %s decodes to %d bytes, want %d", path, len(pub), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pub)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "signrelease: "+format+"\n", args...)
	os.Exit(1)
}
