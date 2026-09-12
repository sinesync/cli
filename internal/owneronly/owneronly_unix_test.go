//go:build !windows

package owneronly

import (
	"os"
	"testing"
)

// The negative case. Without one, a verifier that always returns true passes
// every other test in this package and every assertion that depends on it.
func TestIsOwnerOnlyRefusesAWorldReadableFile(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o666} {
		path := writeTemp(t, "key")
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		private, err := IsOwnerOnly(path)
		if err != nil {
			t.Fatalf("check %04o: %v", mode, err)
		}
		if private {
			t.Errorf("mode %04o reported as owner-only", mode)
		}
	}
}
