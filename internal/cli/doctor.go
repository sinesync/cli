package cli

import (
	"context"
	"fmt"

	"github.com/miclip/sinesync/internal/adapters"
	"github.com/miclip/sinesync/internal/doctor"
	"github.com/spf13/cobra"
)

var doctorFix bool

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Run diagnostic checks on sinesync health",
	Long: `Run diagnostic checks across sinesync core and all adapters.

Checks include:
  - Local storage integrity (valid JSON files)
  - Source index consistency
  - Adapter-specific health checks (stuck sessions, embedding backlog, etc.)

Use --fix to automatically repair issues where possible.`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorFix, "fix", false, "Automatically fix issues where possible")
}

func runDoctor(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	fmt.Println("sine~sync doctor")

	runner := doctor.NewRunner()

	// Register core checks
	runner.RegisterAll(doctor.CoreChecks())

	// Register adapter checks
	registry := adapters.DefaultRegistry()
	defer registry.Close()

	for _, adapter := range registry.Available() {
		if d, ok := adapter.(adapters.Diagnosable); ok {
			runner.RegisterAll(d.DoctorChecks())
		}
	}

	// Run all checks
	results := runner.Run(ctx, doctorFix)

	// Display results grouped by category
	categories := []string{}
	categorized := map[string][]doctor.CheckResult{}
	for _, r := range results {
		if _, seen := categorized[r.Category]; !seen {
			categories = append(categories, r.Category)
		}
		categorized[r.Category] = append(categorized[r.Category], r)
	}

	passed, warnings, failures, fixed, skipped := 0, 0, 0, 0, 0

	for _, cat := range categories {
		fmt.Printf("\n%s:\n", cat)
		for _, r := range categorized[cat] {
			icon := statusIcon(r.Status)
			fmt.Printf("  %s %s\n", icon, r.Message)

			// Show details (max 5)
			shown := len(r.Details)
			if shown > 5 {
				shown = 5
			}
			for _, d := range r.Details[:shown] {
				fmt.Printf("       - %s\n", d)
			}
			if len(r.Details) > 5 {
				fmt.Printf("       ... and %d more\n", len(r.Details)-5)
			}

			switch r.Status {
			case doctor.StatusPass:
				passed++
			case doctor.StatusWarn:
				warnings++
			case doctor.StatusFail:
				failures++
			case doctor.StatusFixed:
				fixed++
			case doctor.StatusSkip:
				skipped++
			}
		}
	}

	// Summary
	fmt.Println()
	parts := []string{}
	if passed > 0 {
		parts = append(parts, fmt.Sprintf("%d passed", passed))
	}
	if fixed > 0 {
		parts = append(parts, fmt.Sprintf("%d fixed", fixed))
	}
	if warnings > 0 {
		parts = append(parts, fmt.Sprintf("%d warnings", warnings))
	}
	if failures > 0 {
		parts = append(parts, fmt.Sprintf("%d failures", failures))
	}
	if skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", skipped))
	}

	summary := ""
	for i, p := range parts {
		if i > 0 {
			summary += ", "
		}
		summary += p
	}
	fmt.Printf("Summary: %s\n", summary)

	if failures > 0 && !doctorFix {
		// Count fixable failures
		fixable := 0
		for _, r := range results {
			if (r.Status == doctor.StatusFail || r.Status == doctor.StatusWarn) && r.CanFix {
				fixable++
			}
		}
		if fixable > 0 {
			fmt.Printf("  Run with --fix to resolve %d fixable issues\n", fixable)
		}
	}

	return nil
}

func statusIcon(s doctor.Status) string {
	switch s {
	case doctor.StatusPass:
		return "[PASS]"
	case doctor.StatusWarn:
		return "[WARN]"
	case doctor.StatusFail:
		return "[FAIL]"
	case doctor.StatusFixed:
		return "[FIXED]"
	case doctor.StatusSkip:
		return "[SKIP]"
	default:
		return "[????]"
	}
}
