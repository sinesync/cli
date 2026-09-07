package cli

import (
	"bytes"
	"strings"
	"testing"
)

// A vault migration once moved 25 of 2,134 observations and reported a tick
// with exit 0. The server had refused the rest, one reason per item, inside a
// 200 response. Nothing printed the reasons and nothing failed, so the
// migration looked like it had worked for as long as nobody counted.
func TestSuccessfulMigrationSaysSoAndSucceeds(t *testing.T) {
	var out bytes.Buffer

	if err := reportMigrationOutcome(&out, 1138, 0, nil); err != nil {
		t.Fatalf("no failures, but returned %v", err)
	}
	if !strings.Contains(out.String(), "1138 observations uploaded") {
		t.Errorf("does not report what was uploaded: %q", out.String())
	}
}

func TestRefusedItemsFailTheCommand(t *testing.T) {
	var out bytes.Buffer

	err := reportMigrationOutcome(&out, 12, 1111, map[string]int{
		"Item belongs to a different vault": 1111,
	})

	if err == nil {
		t.Fatal("1111 of 1123 items were refused and the command still succeeded")
	}
	if !strings.Contains(err.Error(), "1111") || !strings.Contains(err.Error(), "1123") {
		t.Errorf("the error should say how many of how many: %v", err)
	}
}

func TestRefusalReasonsArePrinted(t *testing.T) {
	var out bytes.Buffer

	reportMigrationOutcome(&out, 1, 5, map[string]int{
		"Item belongs to a different vault": 4,
		"Vault access denied":               1,
	})

	got := out.String()
	for _, want := range []string{"4 x Item belongs to a different vault", "1 x Vault access denied"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// Commonest first, then alphabetically, so two runs over the same outcome
// produce the same output and a diff means something changed.
func TestReasonsAreOrderedDeterministically(t *testing.T) {
	reasons := map[string]int{
		"zebra":  2,
		"alpha":  2,
		"common": 9,
		"rare":   1,
	}

	var first bytes.Buffer
	reportMigrationOutcome(&first, 0, 14, reasons)

	want := []string{"9 x common", "2 x alpha", "2 x zebra", "1 x rare"}
	lines := []string{}
	for _, l := range strings.Split(strings.TrimSpace(first.String()), "\n") {
		if strings.Contains(l, " x ") {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	if len(lines) != len(want) {
		t.Fatalf("got %d reason lines, want %d:\n%s", len(lines), len(want), first.String())
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}

	// Same input, same output, across runs.
	for i := 0; i < 5; i++ {
		var again bytes.Buffer
		reportMigrationOutcome(&again, 0, 14, reasons)
		if again.String() != first.String() {
			t.Fatal("output is not stable across runs")
		}
	}
}

// A refusal the server did not explain still has to be counted and shown,
// rather than silently becoming zero reasons for N failures.
func TestUnexplainedRefusalsAreStillReported(t *testing.T) {
	var out bytes.Buffer

	err := reportMigrationOutcome(&out, 0, 3, map[string]int{"refused without a reason": 3})

	if err == nil {
		t.Fatal("refusals without a reason still have to fail the command")
	}
	if !strings.Contains(out.String(), "3 x refused without a reason") {
		t.Errorf("missing the unexplained refusals: %q", out.String())
	}
}
