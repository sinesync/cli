package doctor

import "context"

// Severity indicates how serious an issue is
type Severity int

const (
	SeverityInfo    Severity = iota // Informational, not a problem
	SeverityWarning                 // Degraded but functional
	SeverityError                   // Something is broken
)

// Status is the outcome of a check
type Status int

const (
	StatusPass  Status = iota // Everything is fine
	StatusWarn                // Issue found but not critical
	StatusFail                // Issue found, needs attention
	StatusFixed               // Issue was found and --fix resolved it
	StatusSkip                // Check was skipped (e.g., adapter not available)
)

// CheckResult represents the outcome of a single diagnostic check
type CheckResult struct {
	Name       string
	Category   string
	Status     Status
	Severity   Severity
	Message    string
	Details    []string // Specific issues found (e.g., file paths, session IDs)
	CanFix     bool     // Whether --fix can resolve this
	FixApplied bool     // Whether --fix actually resolved it
}

// Check is a single diagnostic check
type Check struct {
	Name     string
	Category string
	Severity Severity
	Run      func(ctx context.Context, fix bool) CheckResult
}

// Runner executes all registered checks
type Runner struct {
	checks []Check
}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Register(check Check) {
	r.checks = append(r.checks, check)
}

func (r *Runner) RegisterAll(checks []Check) {
	r.checks = append(r.checks, checks...)
}

func (r *Runner) Run(ctx context.Context, fix bool) []CheckResult {
	var results []CheckResult
	for _, check := range r.checks {
		result := check.Run(ctx, fix)
		results = append(results, result)
	}
	return results
}
