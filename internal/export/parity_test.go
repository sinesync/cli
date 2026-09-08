package export

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sinesync/cli/internal/encryption"
	"github.com/sinesync/cli/internal/storage"
)

// decryptObservation reimplements the observation format so the export daemon
// does not have to link SQLCipher and sqlite-vec for code it never runs. That
// duplication is only safe while the two agree, and a format change on the other
// side would otherwise show up as observations this daemon silently skips.
//
// So: encrypt with the real manager, open with ours. This test imports
// internal/encryption deliberately — a test may pull in cgo, the shipped binary
// may not.
func TestDecryptsWhatTheRealEncrypterProduces(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	obs := &storage.Observation{ID: "obs-1"}
	obs.Core.Type = "discovery"
	obs.Core.Title = "a title"
	obs.Core.CreatedAt = time.Unix(1000, 0).UTC()
	obs.Core.UpdatedAt = time.Unix(2000, 0).UTC()

	sealed, err := encryption.NewManager().EncryptObservationWithKey(obs, key)
	if err != nil {
		t.Fatalf("encrypting with the real manager: %v", err)
	}

	raw, obsType, err := decryptObservation(sealed, key)
	if err != nil {
		t.Fatalf("the export daemon could not open what the manager produced: %v", err)
	}
	if obsType != "discovery" {
		t.Fatalf("type %q, want discovery", obsType)
	}

	// The whole record must survive verbatim, since it is what lands in the
	// content column.
	var back storage.Observation
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("content is not the canonical observation: %v", err)
	}
	if back.ID != "obs-1" || back.Core.Title != "a title" {
		t.Fatalf("round trip lost fields: %+v", back)
	}
}

func TestTheAADMatchesTheRealOne(t *testing.T) {
	// A mismatch here decrypts nothing at all, which would look like every
	// observation being undecryptable and silently skipped.
	if aadObservation != encryption.AADObservation {
		t.Fatalf("AAD %q does not match encryption.AADObservation %q",
			aadObservation, encryption.AADObservation)
	}
}

func TestARecordEncryptedUnderAnotherKeyIsRefused(t *testing.T) {
	key := make([]byte, 32)
	other := make([]byte, 32)
	for i := range other {
		other[i] = 0xAA
	}

	obs := &storage.Observation{ID: "obs-2"}
	sealed, err := encryption.NewManager().EncryptObservationWithKey(obs, key)
	if err != nil {
		t.Fatal(err)
	}

	if _, _, err := decryptObservation(sealed, other); err == nil {
		t.Fatal("an observation opened under the wrong vault key")
	}
}
