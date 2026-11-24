package ingest

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SegCursor records Sentinel's lossless read position across Genesis .seg files.
type SegCursor struct {
	SegmentID uint64    `json:"segment_id"`
	Offset    int64     `json:"offset"`
	NextID    uint64    `json:"next_id"`
	UpdatedAt time.Time `json:"updated_at"`
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

// SaveCursor persists c atomically via temp-file write + rename so crashes
// never leave a truncated cursor file on disk.
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
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp cursor %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("commit cursor %q: %w", path, err)
	}
	return nil
}
