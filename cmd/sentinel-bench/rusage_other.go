//go:build !unix

package main

import "runtime"

// maxRSSKB falls back to Go runtime Sys bytes in KiB on non-Unix platforms.
func maxRSSKB() int64 {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return int64(ms.Sys / 1024)
}
