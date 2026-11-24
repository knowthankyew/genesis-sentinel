//go:build !unix

package ingest

import "os"

func fileIdentity(os.FileInfo) string {
	return ""
}
