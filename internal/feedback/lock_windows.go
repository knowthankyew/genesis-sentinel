//go:build windows

package feedback

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	pathLocksMu sync.Mutex
	pathLocks   = make(map[string]*sync.Mutex)

	kernel32DLL      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32DLL.NewProc("LockFileEx")
	procUnlockFileEx = kernel32DLL.NewProc("UnlockFileEx")
)

const (
	lockfileExclusiveLock = 0x00000002
	windowsLockFilename   = ".sentinel.lock"
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

// AcquireDirLock acquires the same cross-process and in-process directory lock used by
// Store and AlertJournal so destructive operations such as BurnLocalState serialize cleanly
// against concurrent appends and journal commits across all Windows sessions.
func AcquireDirLock(dir string) (func(), error) {
	return acquireFileLock(filepath.Join(dir, ".sentinel-dir-lock-anchor"), false)
}

// acquireFileLock serializes access to targetPath across both in-process goroutines and
// separate Windows processes (including across distinct Windows sessions such as background
// services and interactive CLI invocations) via an in-process per-directory mutex combined
// with an exclusive Win32 LockFileEx filesystem lock on a 0-byte .sentinel.lock anchor file
// opened without FILE_SHARE_DELETE so BurnLocalState cannot unlink it while held.
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
	lockKey := strings.ToLower(filepath.Clean(dir))

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

	lockPath := filepath.Join(dir, windowsLockFilename)
	pathPtr, err := syscall.UTF16PtrFromString(lockPath)
	if err != nil {
		pm.Unlock()
		return nil, fmt.Errorf("encode windows lock path: %w", err)
	}

	// Open with FILE_SHARE_READ | FILE_SHARE_WRITE (intentionally omitting FILE_SHARE_DELETE)
	// so concurrent processes can open the same lock file while deletion is prevented during lock hold.
	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		pm.Unlock()
		return nil, fmt.Errorf("open windows lock file %q: %w", lockPath, err)
	}

	var overlapped syscall.Overlapped
	r1, _, callErr := procLockFileEx.Call(
		uintptr(handle),
		uintptr(lockfileExclusiveLock),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	if r1 == 0 {
		_ = syscall.CloseHandle(handle)
		pm.Unlock()
		return nil, fmt.Errorf("LockFileEx %q: %w", lockPath, callErr)
	}

	return func() {
		var unlockOv syscall.Overlapped
		_, _, _ = procUnlockFileEx.Call(
			uintptr(handle),
			0,
			1,
			0,
			uintptr(unsafe.Pointer(&unlockOv)),
		)
		_ = syscall.CloseHandle(handle)
		pm.Unlock()
	}, nil
}
