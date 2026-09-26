//go:build !windows

package writeperm

import (
	"io/fs"
	"syscall"
)

func ownerUID(info fs.FileInfo) (int, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(st.Uid), true
}
