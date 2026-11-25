//go:build windows

package feedback

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

var (
	pathLocksMu sync.Mutex
	pathLocks   = make(map[string]*sync.Mutex)

	kernel32DLL      = syscall.NewLazyDLL("kernel32.dll")
	procCreateMutexW = kernel32DLL.NewProc("CreateMutexW")
	procReleaseMutex = kernel32DLL.NewProc("ReleaseMutex")
)

const waitAbandoned = 0x00000080

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
// against concurrent appends and journal commits on Windows.
func AcquireDirLock(dir string) (func(), error) {
	return acquireFileLock(filepath.Join(dir, ".sentinel-dir-lock-anchor"), false)
}

// acquireFileLock serializes access to targetPath across both in-process goroutines and
// separate Windows processes via an in-process per-directory mutex combined with a named
// Win32 Local\ kernel mutex hashed from the canonical lowercase directory path (leaving
// zero stray lock files on disk and remaining safe across BurnLocalState unlinks).
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

	sum := sha256.Sum256([]byte(lockKey))
	mutexName := "Local\\GenesisSentinel-Dir-" + hex.EncodeToString(sum[:16])
	namePtr, err := syscall.UTF16PtrFromString(mutexName)
	if err != nil {
		pm.Unlock()
		return nil, fmt.Errorf("encode windows mutex name: %w", err)
	}

	// Pin this goroutine to its OS thread before acquiring the Win32 kernel mutex because
	// Windows mutex ownership is thread-bound and ReleaseMutex must run on the acquiring thread.
	runtime.LockOSThread()

	r1, _, callErr := procCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(namePtr)))
	if r1 == 0 {
		runtime.UnlockOSThread()
		pm.Unlock()
		return nil, fmt.Errorf("create windows directory mutex: %w", callErr)
	}
	handle := syscall.Handle(r1)

	waitRes, waitErr := syscall.WaitForSingleObject(handle, syscall.INFINITE)
	if waitRes != syscall.WAIT_OBJECT_0 && waitRes != waitAbandoned {
		_ = syscall.CloseHandle(handle)
		runtime.UnlockOSThread()
		pm.Unlock()
		if waitErr != nil {
			return nil, fmt.Errorf("wait on windows directory mutex: %w", waitErr)
		}
		return nil, fmt.Errorf("wait on windows directory mutex returned status 0x%x", waitRes)
	}

	return func() {
		_, _, _ = procReleaseMutex.Call(uintptr(handle))
		_ = syscall.CloseHandle(handle)
		runtime.UnlockOSThread()
		pm.Unlock()
	}, nil
}
