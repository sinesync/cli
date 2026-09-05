//go:build !windows

package daemon

import (
	"os"
	"syscall"
)

// openLogFileNoFollow opens the log for appending, refusing a symlink at the
// final component and refusing to block on a FIFO.
//
// O_NOFOLLOW makes the kernel reject a symlinked final component, so a planted
// link fails the open rather than redirecting the write.
//
// O_NONBLOCK is what stops a FIFO hanging the daemon. Opening a FIFO write-only
// BLOCKS until a reader appears, so a type check after the open never runs —
// the process is already stuck. With O_NONBLOCK the open fails immediately
// (ENXIO). On a regular file the flag has no effect.
func openLogFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
}
