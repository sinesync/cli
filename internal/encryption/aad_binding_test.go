package encryption

import (
	"testing"

	"github.com/sinesync/cli/internal/storage"
)

// Every observation is sealed under the same constant AAD, so GCM
// authentication proves "some observation of this account, under this key" and
// nothing about WHICH observation. This test exists to make that property
// explicit, because it is the reason the sync download path must compare the
// decrypted id against the id it requested.
//
// If someone later makes the item id part of the AAD, this test fails — and
// that is the signal to revisit the comparison in downloadAndProcess, which
// would then be redundant rather than load-bearing.
func TestCiphertextIsNotBoundToItsObservationID(t *testing.T) {
	m := NewManager()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	wanted := &storage.Observation{}
	wanted.ID = "observation-A"
	substituted := &storage.Observation{}
	substituted.ID = "observation-B"

	blob, err := m.EncryptObservationWithKey(substituted, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// A client asked for observation-A. The server answers with the sealed
	// bytes of observation-B. Decryption succeeds: the AAD matched, because it
	// does not mention either id.
	got, err := m.DecryptObservationWithKey(blob, key)
	if err != nil {
		t.Fatalf("decrypting a substituted observation failed, so AAD may now bind the id — revisit the check in downloadAndProcess: %v", err)
	}

	if got.ID == wanted.ID {
		t.Fatalf("expected the substituted id %q, got the requested id %q", substituted.ID, got.ID)
	}
	if got.ID != substituted.ID {
		t.Fatalf("decrypted id = %q, want %q", got.ID, substituted.ID)
	}

	// Which is exactly the condition downloadAndProcess now refuses on.
	if got.ID == wanted.ID {
		t.Fatal("guard condition would not fire")
	}
}
