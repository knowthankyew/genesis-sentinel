//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package feedback

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	pathLocksMu sync.Mutex
	pathLocks   = make(map[string]*sync.Mutex)
)

const (
	fallbackLockFilename = ".sentinel.lock"
	fallbackLockTimeout  = 30 * time.Second
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

// AcquireDirLock acquires a cross-process and in-process directory lock on fallback targets
// (such as AIX or Solaris) using atomic O_CREATE|O_EXCL lockfile creation combined with an
// in-process per-directory mutex so separate processes never race on journal or queue writes.
func AcquireDirLock(dir string) (func(), error) {
	return acquireFileLock(filepath.Join(dir, ".sentinel-dir-lock-anchor"), false)
}

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
	pm := getPathMutex(lockKey)
	pm.Lock()

	if !createDir {
		info, statErr := os.Stat(dir)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return func() { pm.Unlock() }, nil
			}
			pm.Unlock()
			return nil, fmt.Errorf("stat lock directory %q: %w", dir, statErr)
		}
		if !info.IsDir() {
			pm.Unlock()
			return nil, fmt.Errorf("lock path %q is not a directory", dir)
		}
	}

	lockPath := filepath.Join(dir, fallbackLockFilename)
	deadline := time.Now().Add(fallbackLockTimeout)
	for {
		f, openErr := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if openErr == nil {
			_ = f.Close()
			return func() {
				_ = os.Remove(lockPath)
				pm.Unlock()
			}, nil
		}
		if !errors.Is(openErr, os.ErrExist) {
			pm.Unlock()
			return nil, fmt.Errorf("acquire cross-process lock %q: %w", lockPath, openErr)
		}
		if time.Now().After(deadline) {
			pm.Unlock()
			return nil, fmt.Errorf("timed out waiting for cross-process directory lock %q", lockPath)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
