package keychain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The availability guard is only worth something if it cannot be walked around,
// and it was: the daemon and CLI imported go-keyring directly with the same
// "sinesync" service name, so the guard covered database-key resolution while
// session tokens and sync credentials went straight to the Security framework
// and could still raise the modal it exists to prevent.
//
// A comment saying "do not import go-keyring elsewhere" would not have caught
// that, because the bypass predated the comment. This does.
func TestOnlyThisPackageImportsGoKeyring(t *testing.T) {
	root := filepath.Join("..", "..")

	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // unreadable paths are not this test's business
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "node_modules", "vendor", ".gocache":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// This package is the one place it belongs.
		if strings.Contains(filepath.ToSlash(path), "internal/keychain/") {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if strings.Contains(string(body), "zalando/go-keyring") {
			offenders = append(offenders, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("go-keyring is imported outside internal/keychain, which bypasses the availability guard:\n  %s\n\nUse keychain.Get/Set/Delete instead.",
			strings.Join(offenders, "\n  "))
	}
}
