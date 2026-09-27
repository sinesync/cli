// Package writeperm explains a permission failure users cannot diagnose from a
// bare "permission denied": a file in the data directory that belongs to
// another account.
//
// The usual cause is starting the daemon once with sudo, which leaves files in
// the data directory owned by root. A later write to such a file as the user
// fails with an error that names the path and says nothing about why. Explain
// names the owner, the account the process is running as, and the command that
// fixes it.
package writeperm

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Foreign describes a path owned by an account other than the one the process
// runs as. The names are empty when the UID does not resolve to a user.
type Foreign struct {
	Path        string
	OwnerUID    int
	ProcessUID  int
	Mode        fs.FileMode
	OwnerName   string
	ProcessName string
}

// Error wraps a permission error with the explanation for it. It unwraps to
// the original, so errors.Is(err, fs.ErrPermission) still holds.
type Error struct {
	Foreign Foreign
	Err     error
}

func (e *Error) Error() string { return e.Err.Error() + "\n\n" + Message(e.Foreign) }
func (e *Error) Unwrap() error { return e.Err }

// Explain returns err unchanged unless it is a permission error and path
// exists and belongs to another account. Then it returns an *Error that says
// so. Only path itself is inspected: a missing path keeps the original error.
func Explain(path string, err error) error {
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	info, statErr := os.Stat(path)
	if statErr != nil {
		return err
	}
	owner, ok := ownerUID(info)
	if !ok {
		return err
	}
	proc := os.Getuid()
	if owner == proc {
		return err
	}
	return &Error{
		Foreign: Foreign{
			Path:        path,
			OwnerUID:    owner,
			ProcessUID:  proc,
			Mode:        info.Mode(),
			OwnerName:   lookupName(owner),
			ProcessName: lookupName(proc),
		},
		Err: err,
	}
}

func lookupName(uid int) string {
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return u.Username
}

// Message builds the explanation. It is pure so the root-owned case can be
// tested without root.
func Message(f Foreign) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s is owned by %s, but sinesync is running as %s.\n",
		f.Path, account(f.OwnerName, f.OwnerUID), account(f.ProcessName, f.ProcessUID))
	if f.OwnerUID == 0 {
		b.WriteString("This usually means the daemon was started with sudo, which left a root-owned file behind.\n")
	} else {
		b.WriteString("This usually means sinesync was run as that account, which left its file behind.\n")
	}
	fmt.Fprintf(&b, "Remove it and try again; sinesync will recreate it:\n\n    sudo rm %s\n", shellQuote(f.Path))
	return b.String()
}

func account(name string, uid int) string {
	if name == "" {
		return fmt.Sprintf("uid %d", uid)
	}
	return fmt.Sprintf("%s (uid %d)", name, uid)
}

// shellQuote leaves ordinary paths alone and single-quotes anything else, so
// the printed command is safe to paste.
func shellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+:@,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
