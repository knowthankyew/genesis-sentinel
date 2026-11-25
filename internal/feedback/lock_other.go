//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package feedback

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	pathLocksMu sync.Mutex
	pathLocks   = make(map[string]*sync.Mutex)
)

func getPathMutex(cleanKey string) *sync.Mutex {
	pathLocksMu.Lock()
	defer pathLocksMu.Unlock()
	m, ok := pathLocks[cleanKey]
	if !ok {
		m = &sync.Mutex{}
		pathLocks[cleanKey] = m
	}
	return m
}

// acquireFileLock serializes access across all in-process Store/Journal instances targeting
// the same parent directory (normalized case-insensitively on Windows so equivalent filenames
// such as sentinel-feedback-Team.jsonl and sentinel-feedback-team.jsonl share one mutex).
func acquireFileLock(targetPath string, createDir bool) (func(), error) {
	absPath, err := filepath.Abs(targetPath)
	if err != nil {
		absPath = filepath.Clean(targetPath)
	}
	dir := filepath.Dir(absPath)
	if createDir {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("create directory %q: %w", dir, err)
		}
	}
	if evalDir, err := filepath.EvalSymlinks(dir); err == nil {
		dir = evalDir
	}
	lockKey := filepath.Clean(dir)
	if runtime.GOOS == "windows" {
		lockKey = strings.ToLower(lockKey)
	}
	pm := getPathMutex(lockKey)
	pm.Lock()
	return func() { pm.Unlock() }, nil
}
