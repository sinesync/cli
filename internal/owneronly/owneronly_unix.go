//go:build !windows

package owneronly

import (
	"fmt"
	"os"
)

func Apply(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("restricting %s to its owner: %w", path, err)
	}
	return nil
}

func IsOwnerOnly(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	// Group and other bits must both be clear. The owner's own bits are not
	// constrained beyond that: 0400 is as private as 0600.
	return info.Mode().Perm()&0o077 == 0, nil
}
