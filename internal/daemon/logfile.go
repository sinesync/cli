package daemon

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

// openDaemonLog opens the daemon log for appending, refusing to follow a symlink
// at any component it is responsible for.
//
// An earlier attempt checked the paths with Lstat and then handed the SAME
// pathname to os.OpenFile, which follows links — so it announced that it had
// refused a symlink and then wrote through it anyway. Checking a path and then
// acting on the path is not a check: only the syscall that opens it can refuse,
// which is what O_NOFOLLOW does.
//
// It also refuses a symlinked log DIRECTORY. O_NOFOLLOW only constrains the
// final component, so with a linked directory the open would still land on a
// file inside somebody else's tree.
//
// The residual TOCTOU window is stated rather than papered over: a process
// already running as this user can swap a component between the directory check
// and the open. That is a strictly narrower position than the other-account
// reader these modes exist to keep out, and closing it needs openat2-style
// resolution Go does not portably expose.
func openDaemonLog(dir, path string) (*os.File, error) {
	if err := requireOwnDirectory(dir); err != nil {
		return nil, err
	}

	// O_NOFOLLOW makes the kernel refuse a symlink at the final component, so a
	// planted link fails the open instead of redirecting the write.
	//
	// O_NONBLOCK is what stops a FIFO hanging the daemon. Opening a FIFO
	// write-only BLOCKS until a reader appears, so checking the type after the
	// open never runs — the process is already stuck. With O_NONBLOCK the open
	// fails immediately (ENXIO) and the type check below catches anything else
	// exotic. On a regular file the flag has no effect.
	fd, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening daemon log %s: %w", path, err)
	}

	// A FIFO passes O_NOFOLLOW and would block the daemon forever on write, so
	// the type has to be checked on the descriptor actually opened — not on the
	// pathname, which may no longer refer to the same object.
	info, err := fd.Stat()
	if err != nil {
		fd.Close()
		return nil, fmt.Errorf("inspecting daemon log %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		fd.Close()
		return nil, fmt.Errorf("refusing to use %s as the daemon log: it is %v, not a regular file", path, info.Mode().Type())
	}

	if info.Mode().Perm() != 0o600 {
		if err := fd.Chmod(0o600); err != nil {
			// Chmod on the descriptor, so it cannot be redirected to another
			// path between the check and the change. Reported, not fatal: a
			// readable log is better than a daemon that will not start.
			log.Printf("[daemon] could not tighten permissions on %s: %v", path, err)
		}
	}
	return fd, nil
}

// requireOwnDirectory refuses a log directory that is a symlink or not a
// directory at all, creating it 0700 when absent.
func requireOwnDirectory(dir string) error {
	info, err := os.Lstat(dir)
	switch {
	case os.IsNotExist(err):
		return os.MkdirAll(dir, 0o700)
	case err != nil:
		return fmt.Errorf("checking log directory %s: %w", dir, err)
	case info.Mode()&os.ModeSymlink != 0:
		return fmt.Errorf("refusing to use log directory %s: it is a symlink, and writing through it would touch files the daemon does not own", dir)
	case !info.IsDir():
		return fmt.Errorf("refusing to use log directory %s: it is %v, not a directory", dir, info.Mode().Type())
	}

	if info.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			log.Printf("[daemon] could not tighten permissions on %s: %v", dir, err)
		}
	}
	return nil
}
