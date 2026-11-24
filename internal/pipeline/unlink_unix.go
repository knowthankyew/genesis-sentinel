//go:build unix

package pipeline

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// unlinkFileInRoot removes a non-directory entry inside root r using POSIX unlink(2),
// which strictly refuses to remove directories (returning EISDIR/EPERM) even if a file
// is replaced by an empty directory between Lstat and removal. Root identity is verified
// against the open os.Root directory handle before invoking unlink.
func unlinkFileInRoot(r *os.Root, rel string) error {
	if filepath.Base(rel) != rel || rel == "." || rel == ".." {
		return fmt.Errorf("invalid state filename %q", rel)
	}
	dirStat, err := r.Stat(".")
	if err != nil {
		return err
	}
	pathStat, err := os.Lstat(r.Name())
	if err != nil {
		return err
	}
	if !os.SameFile(dirStat, pathStat) {
		return fmt.Errorf("root directory identity changed during burn cleanup")
	}
	return syscall.Unlink(filepath.Join(r.Name(), rel))
}
