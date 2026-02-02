package adapters

import (
	"testing"
)

func TestFormatObservationDocs(t *testing.T) {
	ids, _, metas := FormatObservationDocs(
		12345,
		"sinesync-test-123",
		"sinesync",
		"discovery",
		"Test Title",
		"Test Subtitle",
		"Test narrative content",
		[]string{"fact 1", "fact 2"},
		[]string{"testing", "unit-test"},
		[]string{"file1.go"},
		[]string{"file2.go"},
		1234567890,
	)

	// Should have 3 docs: 1 narrative + 2 facts
	if len(ids) != 3 {
		t.Errorf("Expected 3 documents, got %d", len(ids))
	}

	// Check IDs format
	if ids[0] != "obs_12345_narrative" {
		t.Errorf("Expected narrative ID 'obs_12345_narrative', got '%s'", ids[0])
	}
	if ids[1] != "obs_12345_fact_0" {
		t.Errorf("Expected fact ID 'obs_12345_fact_0', got '%s'", ids[1])
	}

	// Check metadata
	if metas[0]["sqlite_id"] != int64(12345) {
		t.Errorf("Expected sqlite_id 12345, got %v", metas[0]["sqlite_id"])
	}
	if metas[0]["doc_type"] != "observation" {
		t.Errorf("Expected doc_type 'observation', got %v", metas[0]["doc_type"])
	}

	t.Log("FormatObservationDocs works correctly!")
}
