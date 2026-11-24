package surprisal

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

const baselineSnapshotVersion = 1

// BaselineSnapshot is the on-disk JSON format for `~/.genesis-sentinel/baseline.json`.
// Written atomically via `.baseline-*.tmp` and purged cleanly by `sentinel burn`.
type BaselineSnapshot struct {
	Version   int           `json:"version"`
	MaxSize   int           `json:"max_size"`
	Cases     []LogFeatures `json:"cases"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// LoadBaselineSnapshot reads and validates a persisted BaselineSnapshot from path.
// If path is empty or the file does not exist, an empty snapshot is returned without error.
func LoadBaselineSnapshot(path string, maxCases int) (BaselineSnapshot, error) {
	if path == "" {
		return BaselineSnapshot{Version: baselineSnapshotVersion}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return BaselineSnapshot{Version: baselineSnapshotVersion}, nil
		}
		return BaselineSnapshot{}, fmt.Errorf("open baseline %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, MaxBaselineSnapshotBytes+1))
	if err != nil {
		return BaselineSnapshot{}, fmt.Errorf("read baseline %q: %w", path, err)
	}
	if len(data) > MaxBaselineSnapshotBytes {
		return BaselineSnapshot{}, fmt.Errorf("baseline %q exceeds %d-byte limit", path, MaxBaselineSnapshotBytes)
	}

	var snap BaselineSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return BaselineSnapshot{}, fmt.Errorf("parse baseline %q: %w", path, err)
	}
	if snap.Version != 0 && snap.Version != baselineSnapshotVersion {
		return BaselineSnapshot{}, fmt.Errorf("unsupported baseline snapshot version %d in %q", snap.Version, path)
	}

	cleaned := make([]LogFeatures, 0, len(snap.Cases))
	for _, c := range snap.Cases {
		valid := true
		for k := 0; k < ContinuousFeatureCount; k++ {
			if math.IsNaN(c.Continuous[k]) || math.IsInf(c.Continuous[k], 0) {
				valid = false
				break
			}
		}
		if !valid {
			continue
		}
		c.Nominal[0] = clampStr(c.Nominal[0], maxServiceFeatureBytes)
		c.Nominal[1] = clampStr(c.Nominal[1], maxLevelFeatureBytes)
		c.Nominal[2] = clampStr(c.Nominal[2], maxTemplateFeatureBytes)
		c.Nominal[3] = clampStr(c.Nominal[3], maxProtoFeatureBytes)
		cleaned = append(cleaned, c)
	}

	if maxCases > 0 && len(cleaned) > maxCases {
		// Retain the newest maxCases entries.
		cleaned = cleaned[len(cleaned)-maxCases:]
	}
	snap.Version = baselineSnapshotVersion
	snap.Cases = cleaned
	return snap, nil
}

// SaveBaselineSnapshot atomically writes snap to path using a `.baseline-*.tmp`
// file with 0600 permissions, Sync, Rename, and best-effort parent directory Sync.
// The temp naming matches pipeline.isOwnedTopLevelFile so `sentinel burn` removes it.
func SaveBaselineSnapshot(path string, snap BaselineSnapshot) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create baseline dir %q: %w", dir, err)
	}

	snap.Version = baselineSnapshotVersion
	snap.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	data = append(data, '\n')

	tmpFile, err := os.CreateTemp(dir, ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp baseline in %q: %w", dir, err)
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
		return fmt.Errorf("chmod temp baseline %q: %w", tmpPath, err)
	}
	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("write temp baseline %q: %w", tmpPath, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("sync temp baseline %q: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("close temp baseline %q: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit baseline %q: %w", path, err)
	}
	cleanupTmp = false

	if d, openErr := os.Open(dir); openErr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
