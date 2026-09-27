//go:build windows

package writeperm

import "io/fs"

// Windows has no UIDs and os.Getuid returns -1, so there is nothing to compare.
// The sudo failure this package explains does not arise there; the original
// error is returned unchanged.
func ownerUID(fs.FileInfo) (int, bool) { return 0, false }
