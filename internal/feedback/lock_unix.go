//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package feedback

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
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

// AcquireDirLock acquires the same cross-process and in-process directory lock used by
// Store and AlertJournal so destructive operations such as BurnLocalState serialize cleanly
// against concurrent appends and journal commits.
func AcquireDirLock(dir string) (func(), error) {
	return acquireFileLock(filepath.Join(dir, ".sentinel-dir-lock-anchor"), false)
}

// acquireFileLock serializes access to targetPath across both in-process Store/Journal
// instances and separate OS processes via an in-process per-directory mutex combined with an
// advisory flock on the parent directory descriptor (leaving zero stray lock files on disk;
// BurnLocalState only unlinks regular files and never removes or recreates directories).
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

	pm := getPathMutex(dir)
	pm.Lock()

	dirFile, err := os.Open(dir)
	if err != nil {
		if !createDir && os.IsNotExist(err) {
			return func() { pm.Unlock() }, nil
		}
		pm.Unlock()
		return nil, fmt.Errorf("open lock directory %q: %w", dir, err)
	}

	for {
		flockErr := syscall.Flock(int(dirFile.Fd()), syscall.LOCK_EX)
		if flockErr == nil {
			break
		}
		if errors.Is(flockErr, syscall.EINTR) {
			continue
		}
		_ = dirFile.Close()
		pm.Unlock()
		return nil, fmt.Errorf("flock directory %q: %w", dir, flockErr)
	}

	return func() {
		_ = syscall.Flock(int(dirFile.Fd()), syscall.LOCK_UN)
		_ = dirFile.Close()
		pm.Unlock()
	}, nil
}
