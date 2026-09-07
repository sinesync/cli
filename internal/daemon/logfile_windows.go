//go:build windows

package daemon

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openLogFileNoFollow opens the log for appending, refusing a reparse point at
// the final component.
//
// Windows has no O_NOFOLLOW — syscall defines neither it nor O_NONBLOCK — so
// os.OpenFile cannot express the refusal the Unix build gets from the kernel.
// FILE_FLAG_OPEN_REPARSE_POINT is the equivalent: it tells the object manager to
// open the link itself rather than traverse it, so a planted symlink, junction
// or mount point never redirects the write. The handle is then inspected and a
// reparse point refused.
//
// Doing it in that order matters. Checking with Lstat and then opening is two
// operations on a name, and a name can be replaced between them; opening without
// traversal and asking the handle what it is describes the object actually
// opened, so there is no window to win.
//
// FILE_APPEND_DATA rather than GENERIC_WRITE, because that is what gives O_APPEND
// semantics on Windows: every write goes to the end of file regardless of the
// file pointer, which is what a log shared with a concurrent writer needs.
//
// The mode argument is still ignored: Windows derives permissions from the parent
// directory ACL, so openDaemonLog's chmod remains a no-op here beyond the
// read-only bit, and the directory check continues to carry that weight.
func openLogFileNoFollow(path string) (*os.File, error) {
	pathp, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	handle, err := windows.CreateFile(
		pathp,
		windows.FILE_APPEND_DATA,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		windows.CloseHandle(handle)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}

	// Refused rather than followed: this is the case the Unix build gets for
	// free from O_NOFOLLOW.
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return nil, &os.PathError{
			Op:   "open",
			Path: path,
			Err:  fmt.Errorf("refusing to write the daemon log through a reparse point"),
		}
	}

	return os.NewFile(uintptr(handle), path), nil
}
