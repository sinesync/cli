//go:build !windows

package owneronly

import (
	"fmt"
	"os"
)

func Apply(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("restricting %s to its owner: %w", path, err)
	}
	// A directory needs the owner's execute bit or nothing inside it can be
	// reached -- including by the process that just restricted it. The Windows
	// half does not need this distinction: one DACL granting the owner covers
	// traversal as well as read and write.
	mode := os.FileMode(0o600)
	if info.IsDir() {
		mode = 0o700
	}
	if err := os.Chmod(path, mode); err != nil {
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
