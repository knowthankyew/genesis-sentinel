//go:build unix

package feedback

import (
	"fmt"
	"os"
	"syscall"
)

// OpenRegularFileNonBlocking opens path with O_NONBLOCK so named pipes (FIFOs) never block
// before the descriptor-based regular-file check runs.
func OpenRegularFileNonBlocking(path string) (*os.File, os.FileInfo, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%q must be a regular file", path)
	}
	return f, fi, nil
}
