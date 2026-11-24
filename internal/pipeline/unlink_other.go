//go:build !unix

package pipeline

import "os"

func unlinkFileInRoot(r *os.Root, rel string) error {
	return r.Remove(rel)
}
