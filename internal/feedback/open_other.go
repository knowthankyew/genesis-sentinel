//go:build !unix

package feedback

import (
	"fmt"
	"os"
)

// OpenRegularFileNonBlocking opens path and enforces a descriptor-based regular-file check.
func OpenRegularFileNonBlocking(path string) (*os.File, os.FileInfo, error) {
	f, err := os.Open(path)
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
