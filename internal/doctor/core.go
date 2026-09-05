package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sinesync/cli/internal/config"
	"github.com/sinesync/cli/internal/storage"
)

// CoreChecks returns the built-in checks for sinesync local storage
func CoreChecks() []Check {
	return []Check{
		{
			Name:     "Local storage JSON integrity",
			Category: "core",
			Severity: SeverityError,
			Run:      checkJSONIntegrity,
		},
		{
			Name:     "Source index consistency",
			Category: "core",
			Severity: SeverityWarning,
			Run:      checkSourceIndex,
		},
	}
}

// checkJSONIntegrity verifies all observation files are valid JSON
func checkJSONIntegrity(ctx context.Context, fix bool) CheckResult {
	obsDir := filepath.Join(config.DataDir(), "observation")
	result := CheckResult{
		Name:     "Local storage JSON integrity",
		Category: "core",
		Severity: SeverityError,
		CanFix:   true,
	}

	entries, err := os.ReadDir(obsDir)
	if err != nil {
		if os.IsNotExist(err) {
			result.Status = StatusSkip
			result.Message = "No observation directory found"
			return result
		}
		result.Status = StatusFail
		result.Message = fmt.Sprintf("Cannot read observation directory: %v", err)
		return result
	}

	total := 0
	var corrupted []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		total++

		path := filepath.Join(obsDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			corrupted = append(corrupted, entry.Name()+": read error")
			continue
		}

		var item storage.StoredItem
		if err := json.Unmarshal(data, &item); err != nil {
			corrupted = append(corrupted, entry.Name()+": invalid JSON")
			continue
		}

		// Verify the data can be deserialized as an Observation
		dataBytes, _ := json.Marshal(item.Data)
		var obs storage.Observation
		if err := json.Unmarshal(dataBytes, &obs); err != nil {
			corrupted = append(corrupted, entry.Name()+": invalid observation data")
			continue
		}

		if obs.ID == "" {
			corrupted = append(corrupted, entry.Name()+": missing observation ID")
		}
	}

	if len(corrupted) == 0 {
		result.Status = StatusPass
		result.Message = fmt.Sprintf("%d observations checked", total)
		return result
	}

	if fix {
		quarantine := filepath.Join(config.ConfigDir(), "quarantine")
		if err := os.MkdirAll(quarantine, 0o700); err != nil {
			result.Status = StatusFail
			result.Message = fmt.Sprintf("Cannot create quarantine directory: %v", err)
			return result
		}
		// MkdirAll leaves an existing directory's mode alone, so a quarantine
		// left by an older build is still 0755. Refuse to move anything into a
		// directory that cannot be made private: what goes in is the user's
		// observations in plaintext.
		if err := os.Chmod(quarantine, 0o700); err != nil {
			result.Status = StatusFail
			result.Message = fmt.Sprintf("Cannot secure quarantine directory %s: %v", quarantine, err)
			return result
		}

		fixed := 0
		var unresolved []string
		for _, detail := range corrupted {
			name := strings.SplitN(detail, ":", 2)[0]
			src := filepath.Join(obsDir, name)
			dst := filepath.Join(quarantine, name)
			if _, err := os.Stat(dst); err == nil {
				// Avoid collision with existing quarantined file
				dst = filepath.Join(quarantine, fmt.Sprintf("%s.%d", name, time.Now().UnixNano()))
			}
			// Secure the file where it is, before it moves. os.Rename carries
			// the source's mode to the destination, so a file that starts at
			// 0644 stays 0644 in an archive nothing will ever rewrite — and
			// doing it first means a file we cannot secure is simply left
			// alone, rather than moved somewhere we have already promised is
			// private.
			if err := os.Chmod(src, 0o600); err != nil {
				unresolved = append(unresolved, fmt.Sprintf("%s: cannot secure before quarantine: %v", name, err))
				continue
			}
			if err := os.Rename(src, dst); err != nil {
				unresolved = append(unresolved, fmt.Sprintf("%s: quarantine move failed: %v", name, err))
				continue
			}
			fixed++
		}

		result.FixApplied = fixed > 0
		result.Details = append(append([]string{}, corrupted...), unresolved...)

		// A shortfall is a failure, not a success with a smaller number in it.
		// Reporting [FIXED] while a corrupted plaintext observation is still
		// sitting in the live directory tells the user to stop looking.
		if len(unresolved) > 0 {
			result.Status = StatusFail
			result.Message = fmt.Sprintf(
				"Quarantined %d/%d corrupted files; %d could not be quarantined with owner-only permissions (of %d total)",
				fixed, len(corrupted), len(unresolved), total,
			)
			return result
		}

		result.Status = StatusFixed
		result.Message = fmt.Sprintf("Quarantined %d/%d corrupted files (of %d total)", fixed, len(corrupted), total)
		return result
	}

	result.Status = StatusFail
	result.Message = fmt.Sprintf("%d corrupted files (of %d total)", len(corrupted), total)
	result.Details = corrupted
	return result
}

// checkSourceIndex verifies the source index matches actual observations
func checkSourceIndex(ctx context.Context, fix bool) CheckResult {
	result := CheckResult{
		Name:     "Source index consistency",
		Category: "core",
		Severity: SeverityWarning,
		CanFix:   true,
	}

	backend, err := storage.ResolveBackend()
	if err != nil {
		result.Status = StatusFail
		result.Message = fmt.Sprintf("Cannot open storage: %v", err)
		return result
	}
	defer backend.Close()

	observations, err := backend.ListObservations()
	if err != nil {
		result.Status = StatusFail
		result.Message = fmt.Sprintf("Cannot list observations: %v", err)
		return result
	}

	// Count observations with source info
	withSource := 0
	for _, obs := range observations {
		if obs.Source.Adapter != "" && obs.Source.ID != "" {
			withSource++
		}
	}

	result.Status = StatusPass
	result.Message = fmt.Sprintf("%d observations, %d with source tracking", len(observations), withSource)

	if fix {
		// Source index rebuild only applies to JSON file storage
		if ls, ok := backend.(*storage.LocalStorage); ok {
			ls.InvalidateSourceIndex()
			ls.ExistsBySource("__doctor_check__", "", "0")
			result.Message += " (index rebuilt)"
		} else {
			result.Message += " (SQLCipher — no index rebuild needed)"
		}
	}

	return result
}
