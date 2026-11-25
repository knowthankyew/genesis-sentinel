//go:build !unix

package feedback

import (
	"fmt"
	"os"
)

func openRegularFileNonBlocking(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open dataset %q: %w", path, err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, fmt.Errorf("stat dataset %q: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, fmt.Errorf("dataset %q must be a regular file", path)
	}
	return f, fi, nil
}
