//go:build !unix

package cli

import "testing"

// Windows has no inode, so the swap-versus-truncate check cannot be made this
// way. The original helper meant to skip here and could not: syscall.Stat_t
// does not exist on this platform, so the file failed to compile before
// reaching its own t.Skip. Splitting it lets every other test in the package
// run on Windows, which is where a truncating replacement would be just as
// destructive.
func inodeOf(t *testing.T, _ string) uint64 {
	t.Skip("no inode information on this platform")
	return 0
}
