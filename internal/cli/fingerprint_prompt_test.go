package cli

import (
	"bufio"
	"bytes"
	"strings"
	"testing"
	"time"
)

// The pair the advisor ground out: two usable X25519 keys whose fingerprints
// share a first group. 20 bits is about a second of laptop time, so this is not
// a hypothetical near-miss — it is the cheapest forgery against a human who
// checks the part their eye lands on.
const (
	genuineFP = "5HCJ-YXNH-YGXQ"
	forgedFP  = "5HCJ-4CHQ-WCH8"
)

func promptText() fingerprintPromptText {
	return fingerprintPromptText{
		intro:        []string{"intro"},
		label:        "type it: ",
		declined:     []string{"DECLINED-TEXT"},
		mismatchHint: []string{"MISMATCH-HINT"},
	}
}

// ask runs the prompt against a fake stdin and returns the decision plus what
// the operator would have seen.
func ask(t *testing.T, expected, stdin string) (bool, string) {
	t.Helper()
	var out bytes.Buffer
	ok := confirmFingerprintByTyping(&out, bufio.NewReader(strings.NewReader(stdin)), expected, promptText())
	return ok, out.String()
}

// The whole point of typing: a value that a glance would wave through must be
// rejected on the bits the glance skipped.
func TestTypedFingerprintRejectsSharedPrefixForgery(t *testing.T) {
	ok, out := ask(t, genuineFP, forgedFP+"\n")
	if ok {
		t.Fatalf("accepted a forgery sharing only the first group (%s vs %s)", forgedFP, genuineFP)
	}
	if !strings.Contains(out, "DECLINED-TEXT") {
		t.Errorf("decline text not shown; got %q", out)
	}
	if !strings.Contains(out, "MISMATCH-HINT") {
		t.Errorf("a value was typed and disagreed; the substitution warning must be shown. got %q", out)
	}
	// It must not leak what it wanted, or the next run is a copy exercise.
	if strings.Contains(out, genuineFP) {
		t.Errorf("output revealed the expected fingerprint: %q", out)
	}

	// Symmetric: the victim's value must not pass a machine holding the forgery.
	if ok, _ := ask(t, forgedFP, genuineFP+"\n"); ok {
		t.Error("accepted the genuine value against a forged expectation")
	}
}

// A first-group-only answer is exactly what the old prompt effectively checked.
func TestTypedFingerprintRejectsPartialAnswers(t *testing.T) {
	for _, partial := range []string{"5HCJ", "5HCJ-YXNH", "YGXQ", "5HCJ-YXNH-YGX", "5HCJ-YXNH-YGXQQ"} {
		if ok, _ := ask(t, genuineFP, partial+"\n"); ok {
			t.Errorf("accepted partial/oversized answer %q", partial)
		}
	}
}

// Someone reading twelve characters down a phone line and typing them back will
// not reproduce the formatting. Rejecting on that would train people to give up
// on the check, so it must reject on key material only.
func TestTypedFingerprintAcceptsRealisticRetyping(t *testing.T) {
	variants := []struct {
		name  string
		typed string
	}{
		{"exact", "5HCJ-YXNH-YGXQ"},
		{"lowercase", "5hcj-yxnh-ygxq"},
		{"no dashes", "5HCJYXNHYGXQ"},
		{"lowercase, no dashes", "5hcjyxnhygxq"},
		{"spaces instead of dashes", "5hcj yxnh ygxq"},
		{"stray leading and trailing space", "   5HCJ-YXNH-YGXQ   "},
		{"internal double spaces", "5hcj  yxnh   ygxq"},
		{"mixed case, ragged grouping", "5Hc jYX-nhy GxQ"},
		{"tab separated", "5HCJ\tYXNH\tYGXQ"},
		{"en-dashes from a chat client", "5HCJ–YXNH–YGXQ"},
		{"em-dashes", "5HCJ—YXNH—YGXQ"},
		{"underscores", "5hcj_yxnh_ygxq"},
		{"carriage return line ending", "5HCJ-YXNH-YGXQ\r"},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			ok, out := ask(t, genuineFP, v.typed+"\n")
			if !ok {
				t.Fatalf("rejected a correct value typed as %q; output: %q", v.typed, out)
			}
			if !strings.Contains(out, genuineFP) {
				t.Errorf("a match should echo the confirmed fingerprint; got %q", out)
			}
		})
	}
}

// The [y/N] form this replaces defaulted to no on a bare Enter and on a closed
// stdin. That property is the reason it was safe; it has to survive.
func TestTypedFingerprintFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
	}{
		{"EOF immediately, no input at all", ""},
		{"bare Enter", "\n"},
		{"whitespace only", "   \t  \n"},
		{"dashes only", "---\n"},
		{"EOF after a blank line", "\n"},
		{"windows blank line", "\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, out := ask(t, genuineFP, tc.stdin)
			if ok {
				t.Fatalf("proceeded on %q — this prompt must fail closed", tc.stdin)
			}
			if strings.Contains(out, genuineFP) {
				t.Errorf("leaked the expected fingerprint on a non-answer: %q", out)
			}
			if !strings.Contains(out, "DECLINED-TEXT") {
				t.Errorf("a refusal must still say what did not happen; got %q", out)
			}
			// Nobody typed a wrong value here, so do not tell them a key may
			// have been substituted.
			if strings.Contains(out, "MISMATCH-HINT") {
				t.Errorf("cried substitution at someone who simply cancelled; got %q", out)
			}
		})
	}
}

// A wrong value followed by EOF must not spin, and must not proceed.
func TestTypedFingerprintStopsAtEOFAfterMismatch(t *testing.T) {
	done := make(chan bool, 1)
	go func() {
		ok, _ := ask(t, genuineFP, forgedFP) // no trailing newline, then EOF
		done <- ok
	}()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("accepted a mismatch that ended at EOF")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prompt did not terminate at EOF")
	}
}

// A typo must not cost the whole flow, but three wrong answers must end it.
func TestTypedFingerprintRetriesThenGivesUp(t *testing.T) {
	// Two fumbles, then the right value.
	ok, out := ask(t, genuineFP, "5HCJ-YXNH-YGX\n5hcj yxnh ygxz\n5hcj-yxnh-ygxq\n")
	if !ok {
		t.Fatalf("should accept a correct value on the third attempt; output: %q", out)
	}

	// Three wrong answers, with a fourth correct one that must never be read.
	ok, out = ask(t, genuineFP, forgedFP+"\n"+forgedFP+"\n"+forgedFP+"\n"+genuineFP+"\n")
	if ok {
		t.Fatal("kept accepting attempts past the limit")
	}
	if !strings.Contains(out, "DECLINED-TEXT") || !strings.Contains(out, "MISMATCH-HINT") {
		t.Errorf("expected decline plus substitution warning after exhausting attempts; got %q", out)
	}
	// An empty line still short-circuits rather than burning an attempt.
	if ok, _ := ask(t, genuineFP, "\n"+genuineFP+"\n"); ok {
		t.Error("a bare Enter must decline immediately, not fall through to another attempt")
	}
}

func TestNormalizeFingerprintKeepsDistinctKeysDistinct(t *testing.T) {
	if normalizeFingerprint(genuineFP) == normalizeFingerprint(forgedFP) {
		t.Fatal("normalisation collapsed two different fingerprints")
	}
	if got, want := normalizeFingerprint(" 5hcj-yxnh ygxq\n"), "5HCJYXNHYGXQ"; got != want {
		t.Errorf("normalizeFingerprint = %q, want %q", got, want)
	}
	// The alphabet has no I, O, 0 or 1, so a typed lookalike is a misread and
	// must not be silently repaired into agreement.
	if normalizeFingerprint("5HCJ-YXNH-YGXO") == normalizeFingerprint(genuineFP) {
		t.Error("folded a character that is not in the fingerprint alphabet")
	}
}
