//go:build windows

package daemon

import "os"

// openLogFileNoFollow opens the log for appending.
//
// Windows has no O_NOFOLLOW or O_NONBLOCK — syscall does not define either — so
// this cannot make the kernel refuse a reparse point the way the Unix build
// does. Say that plainly rather than imply a guarantee that is not there: on
// Windows the protection is the Lstat check in openDaemonLog, which closes the
// ordinary case and not a race.
//
// The mode argument is ignored by Windows, which derives permissions from the
// parent directory ACL; openDaemonLog's chmod is likewise a no-op here beyond
// the read-only bit. The directory check is what carries the weight.
func openLogFileNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}
