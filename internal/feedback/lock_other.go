//go:build !unix

package feedback

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

var (
	pathLocksMu sync.Mutex
	pathLocks   = make(map[string]*sync.Mutex)
)

func getPathMutex(cleanPath string) *sync.Mutex {
	pathLocksMu.Lock()
	defer pathLocksMu.Unlock()
	m, ok := pathLocks[cleanPath]
	if !ok {
		m = &sync.Mutex{}
		pathLocks[cleanPath] = m
	}
	return m
}

// acquireFileLock serializes access to targetPath across all in-process instances.
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
		absPath = filepath.Join(evalDir, filepath.Base(absPath))
	}
	pm := getPathMutex(absPath)
	pm.Lock()
	return func() { pm.Unlock() }, nil
}
