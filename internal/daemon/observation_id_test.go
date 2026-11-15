package daemon

import (
	"testing"

	"github.com/google/uuid"
)

// TestExtractObservationIDsAreUUIDv4 guards against observation IDs that
// merely look like UUIDs. The previous generator formatted 16 random bytes
// as 8-4-4-4-12 hex without setting the version or variant bits, so each ID
// passed both checks below with probability 1/64. Over 200 iterations the
// chance of that generator passing is (1/64)^200, a negligible probability.
func TestExtractObservationIDsAreUUIDv4(t *testing.T) {
	const iterations = 200
	s := &Server{}
	seen := make(map[string]bool, iterations)

	for i := 0; i < iterations; i++ {
		obs := s.extractObservation("Write", map[string]interface{}{"file_path": "/tmp/x.go"}, "ok", "proj")
		if obs == nil {
			t.Fatalf("iteration %d: extractObservation returned nil", i)
		}
		id, err := uuid.Parse(obs.ID)
		if err != nil {
			t.Fatalf("iteration %d: ID %q does not parse as a UUID: %v", i, obs.ID, err)
		}
		if v := id.Version(); v != 4 {
			t.Fatalf("iteration %d: ID %q has version %d, want 4", i, obs.ID, v)
		}
		if v := id.Variant(); v != uuid.RFC4122 {
			t.Fatalf("iteration %d: ID %q has variant %v, want %v", i, obs.ID, v, uuid.RFC4122)
		}
		if seen[obs.ID] {
			t.Fatalf("iteration %d: duplicate ID %q", i, obs.ID)
		}
		seen[obs.ID] = true
	}
}
