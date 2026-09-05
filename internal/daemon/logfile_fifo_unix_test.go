//go:build !windows

package daemon

import (
	"path/filepath"
	"syscall"
	"testing"
)

// A FIFO survives O_NOFOLLOW and would block the daemon forever on write, so
// the type is checked on the descriptor that was actually opened.
func TestOpenDaemonLogRefusesNonRegularFile(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "daemon.log")
	if err := mkfifoForTest(fifo); err != nil {
		t.Skipf("cannot create a FIFO here: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if f, err := openDaemonLog(dir, fifo); err == nil {
			f.Close()
			t.Error("accepted a FIFO as the daemon log")
		}
	}()
	<-done
}

func mkfifoForTest(path string) error { return syscall.Mkfifo(path, 0o600) }
