//go:build unix

package ingest

import (
	"fmt"
	"os"
	"syscall"
)

// fileIdentity returns a stable POSIX device+inode identifier for fi so replacement
// files created at the same path after `genesis burn` are detected even when they
// share an identical byte prefix and exceed the saved offset.
func fileIdentity(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st == nil {
		return ""
	}
	return fmt.Sprintf("unix:%d:%d", uint64(st.Dev), uint64(st.Ino))
}
