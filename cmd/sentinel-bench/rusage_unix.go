//go:build unix

package main

import (
	"runtime"
	"syscall"
)

// maxRSSKB returns the process peak resident set size in KiB via getrusage.
// Darwin reports ru.Maxrss in bytes; Linux/BSD/AIX report KiB.
func maxRSSKB() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil || ru.Maxrss <= 0 {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		return int64(ms.Sys / 1024)
	}
	if runtime.GOOS == "darwin" {
		return int64(ru.Maxrss) / 1024
	}
	return int64(ru.Maxrss)
}
