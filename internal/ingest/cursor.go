package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SegCursor records Sentinel's lossless read position across Genesis .seg files.
// FileIdentity (POSIX device+inode where supported) and SegmentFingerprint
// (SHA-256 of the initial FingerprintLen bytes) let SegReader detect replacement
// files created after `genesis burn` even when they grow past Offset or repeat
// an identical prefix before the next poll.
type SegCursor struct {
	SegmentID          uint64    `json:"segment_id"`
	Offset             int64     `json:"offset"`
	NextID             uint64    `json:"next_id"`
	FileIdentity       string    `json:"file_identity,omitempty"`
	SegmentFingerprint string    `json:"segment_fingerprint,omitempty"`
	FingerprintLen     int       `json:"fingerprint_len,omitempty"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// LoadCursor reads a previously persisted SegCursor from path.
// If the file does not exist, a zero-valued cursor is returned without error.
func LoadCursor(path string) (SegCursor, error) {
	if path == "" {
		return SegCursor{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SegCursor{}, nil
		}
		return SegCursor{}, fmt.Errorf("read cursor %q: %w", path, err)
	}
	var c SegCursor
	if err := json.Unmarshal(data, &c); err != nil {
		return SegCursor{}, fmt.Errorf("parse cursor %q: %w", path, err)
	}
	return c, nil
}

// SaveCursor writes c to a unique temporary file in path's directory, calls Sync on
// the temp file, and replaces path via os.Rename (with best-effort parent directory
// Sync). On Unix/POSIX filesystems within a single directory, os.Rename replaces the
// destination atomically so concurrent readers never see partial contents; non-Unix
// platforms do not guarantee atomic rename, and power-loss durability depends on
// OS/filesystem fsync semantics.
func SaveCursor(path string, c SegCursor) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create cursor dir %q: %w", dir, err)
	}
	c.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal cursor: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".cursor-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp cursor in %q: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("chmod temp cursor %q: %w", tmpPath, err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp cursor %q: %w", tmpPath, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp cursor %q: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp cursor %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit cursor %q: %w", path, err)
	}
	cleanupTmp = false

	// Best-effort directory sync so the renamed directory entry reaches disk on POSIX systems.
	if d, openErr := os.Open(dir); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
