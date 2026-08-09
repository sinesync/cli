package cli

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// maxFingerprintAttempts bounds retyping after a mismatch.
//
// Retries do not weaken the check: the fingerprint is not a secret being
// guessed, it is a value the operator is copying from another device, and this
// machine never reveals what it expected. What they buy is that a typo does not
// cost the whole flow — without them, one slip means re-running a vault confirm
// or a device approval, and a check that is expensive to fail is a check people
// route around.
const maxFingerprintAttempts = 3

// fingerprintPromptText is the wording around a typed fingerprint check. The
// two call sites differ in what the operator is looking at; they must not
// differ in how the comparison is made.
type fingerprintPromptText struct {
	// intro tells the operator where to get the value from. Printed once.
	intro []string
	// label is the input prompt, e.g. "Fingerprint they read out: ".
	label string
	// declined is printed on every refusal, including a bare Enter. It says
	// what did not happen, in the words the old [y/N] prompt used.
	declined []string
	// mismatchHint is printed in addition when a wrong value was actually
	// typed, which is a different situation from declining: something on the
	// other device disagrees with what the server relayed. It must not hint at
	// the expected value.
	mismatchHint []string
}

// normalizeFingerprint reduces a fingerprint to the characters that carry key
// material, so the comparison rejects on the key and not on formatting.
//
// Someone reading twelve characters down a phone line and someone typing them
// back will not agree on case, on where the dashes go, or on whether there are
// spaces — and a chat client may well have turned the hyphens into en-dashes on
// the way. None of that is evidence about the key.
//
// Case folding is lossless here because the fingerprint alphabet
// (ABCDEFGHJKLMNPQRSTUVWXYZ23456789) is single-case. Deliberately NOT folding
// the lookalikes: I, O, 0 and 1 are absent from that alphabet precisely so they
// never occur, so a typed 0 is a misread rather than a legitimate O, and
// quietly repairing it would be inventing agreement where there is none. It
// mismatches, and the operator is told to check again — which is the correct
// outcome for a value that was not read correctly.
func normalizeFingerprint(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			continue
		case r == '-' || r == '_' ||
			r == '‐' || r == '‑' || r == '‒' ||
			r == '–' || r == '—' || r == '−':
			// ASCII hyphen, underscore, and the dashes a chat client or word
			// processor substitutes for one.
			continue
		default:
			b.WriteRune(unicode.ToUpper(r))
		}
	}
	return b.String()
}

// confirmFingerprintByTyping makes the operator type the fingerprint the other
// device is showing, and compares it here. It reports whether to proceed.
//
// Showing two strings and asking "do they match? [y/N]" checks however many
// characters the human actually looked at. Twelve base32 characters are 60
// bits, but a glance at the first group is 20, and 20 bits of key grinding is
// about a second of laptop time — so a substituted key whose fingerprint starts
// the same way passes a check that felt like it was doing something. The vault
// side is the worse case, because that fingerprint comes from the invitee's
// long-term keypair: stable across every invite they ever accept, visible to
// anyone who has confirmed one, and therefore grindable at leisure well before
// the attack.
//
// Typing moves the comparison off the human's eye and onto all 60 bits.
//
// Which is why this deliberately does NOT print the expected value first. An
// operator who can see the string they are being asked to type will copy it off
// their own screen, and the check degrades to a slower [y/N] — worse than
// before, because it now looks rigorous. The value is shown only after a match.
func confirmFingerprintByTyping(w io.Writer, r *bufio.Reader, expected string, t fingerprintPromptText) bool {
	for _, line := range t.intro {
		fmt.Fprintln(w, line)
	}

	want := normalizeFingerprint(expected)
	typedSomethingWrong := false

	for attempt := 1; attempt <= maxFingerprintAttempts; attempt++ {
		fmt.Fprint(w, t.label)
		line, readErr := r.ReadString('\n')
		typed := normalizeFingerprint(line)

		// Fail closed on nothing at all. This covers a bare Enter — preserving
		// the "just hit return to say no" default of the [y/N] prompt it
		// replaces — and equally a closed or empty stdin, which is what a
		// non-interactive context looks like. Neither is consent, and neither
		// spends an attempt: it ends here.
		if typed == "" {
			fmt.Fprintln(w, "Nothing entered.")
			break
		}

		if typed == want {
			fmt.Fprintf(w, "✓ Fingerprint matches: %s\n", expected)
			return true
		}

		typedSomethingWrong = true

		// A mismatch with no way to read another line is final.
		if attempt == maxFingerprintAttempts || readErr != nil {
			break
		}
		fmt.Fprintf(w, "That does not match what this machine has. Attempt %d of %d — check you have the whole value and try again.\n",
			attempt+1, maxFingerprintAttempts)
	}

	for _, line := range t.declined {
		fmt.Fprintln(w, line)
	}
	// Only when a value was actually entered and disagreed. Saying this after a
	// deliberate Enter-to-cancel would cry wolf at the one person who used the
	// prompt correctly.
	if typedSomethingWrong {
		for _, line := range t.mismatchHint {
			fmt.Fprintln(w, line)
		}
	}
	return false
}
