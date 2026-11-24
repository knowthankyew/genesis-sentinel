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

type rawCasePayload struct {
	Continuous *[]*float64 `json:"continuous"`
	Nominal    *[]*string  `json:"nominal"`
}

func validateRawCase(rc rawCasePayload) (LogFeatures, error) {
	if rc.Continuous == nil || len(*rc.Continuous) != ContinuousFeatureCount {
		return LogFeatures{}, fmt.Errorf("case missing required %d-element continuous feature array", ContinuousFeatureCount)
	}
	if rc.Nominal == nil || len(*rc.Nominal) != NominalFeatureCount {
		return LogFeatures{}, fmt.Errorf("case missing required %d-element nominal feature array", NominalFeatureCount)
	}
	var lf LogFeatures
	for k, ptr := range *rc.Continuous {
		if ptr == nil || math.IsNaN(*ptr) || math.IsInf(*ptr, 0) {
			return LogFeatures{}, fmt.Errorf("case continuous[%d] is null or non-finite", k)
		}
		lf.Continuous[k] = *ptr
	}
	maxLens := [NominalFeatureCount]int{
		maxServiceFeatureBytes,
		maxLevelFeatureBytes,
		maxTemplateFeatureBytes,
		maxProtoFeatureBytes,
	}
	for k, ptr := range *rc.Nominal {
		if ptr == nil {
			return LogFeatures{}, fmt.Errorf("case nominal[%d] is null", k)
		}
		lf.Nominal[k] = clampStr(*ptr, maxLens[k])
	}
	return lf, nil
}

// LoadBaselineSnapshot incrementally decodes and validates a persisted BaselineSnapshot
// from path under a strict byte ceiling (MaxBaselineSnapshotBytes) while keeping at most
// maxCases newest valid cases in RAM during decoding.
//
// Returns (snap, exists, err): when path is empty or does not exist, exists is false and
// err is nil; when an explicit empty snapshot file exists on disk, exists is true with
// len(snap.Cases) == 0 so callers can replace prior in-memory baselines cleanly.
func LoadBaselineSnapshot(path string, maxCases int) (BaselineSnapshot, bool, error) {
	if path == "" {
		return BaselineSnapshot{Version: baselineSnapshotVersion}, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return BaselineSnapshot{Version: baselineSnapshotVersion}, false, nil
		}
		return BaselineSnapshot{}, false, fmt.Errorf("open baseline %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if info, statErr := f.Stat(); statErr == nil && info.Size() > MaxBaselineSnapshotBytes {
		return BaselineSnapshot{}, true, fmt.Errorf("baseline %q exceeds %d-byte limit", path, MaxBaselineSnapshotBytes)
	}

	cr := &countingLimitReader{r: f, limit: MaxBaselineSnapshotBytes}
	dec := json.NewDecoder(cr)

	tok, err := dec.Token()
	if err != nil {
		return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: %w", path, err)
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: expected JSON object", path)
	}

	var (
		snap       = BaselineSnapshot{Version: baselineSnapshotVersion}
		hasVersion bool
		hasCases   bool
		ringBuf    []LogFeatures
		ringHead   int
		allCases   []LogFeatures
	)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q key: %w", path, err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: expected string key", path)
		}
		switch key {
		case "version":
			var v int
			if err := dec.Decode(&v); err != nil {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q version: %w", path, err)
			}
			if v != 0 && v != baselineSnapshotVersion {
				return BaselineSnapshot{}, true, fmt.Errorf("unsupported baseline snapshot version %d in %q", v, path)
			}
			hasVersion = true
		case "max_size":
			if err := dec.Decode(&snap.MaxSize); err != nil {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q max_size: %w", path, err)
			}
		case "updated_at":
			if err := dec.Decode(&snap.UpdatedAt); err != nil {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q updated_at: %w", path, err)
			}
		case "cases":
			if hasCases {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: duplicate cases field", path)
			}
			hasCases = true
			arrTok, err := dec.Token()
			if err != nil {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q cases: %w", path, err)
			}
			if arrTok == nil {
				continue
			}
			if delim, ok := arrTok.(json.Delim); !ok || delim != '[' {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: cases must be a JSON array", path)
			}
			for dec.More() {
				var rc rawCasePayload
				if err := dec.Decode(&rc); err != nil {
					return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q case: %w", path, err)
				}
				lf, valErr := validateRawCase(rc)
				if valErr != nil {
					return BaselineSnapshot{}, true, fmt.Errorf("invalid baseline %q: %w", path, valErr)
				}
				if maxCases > 0 {
					// Grow incrementally rather than pre-allocating maxCases up front,
					// then overwrite circularly once len(ringBuf) == maxCases.
					if len(ringBuf) < maxCases {
						ringBuf = append(ringBuf, lf)
					} else {
						ringBuf[ringHead] = lf
						ringHead = (ringHead + 1) % maxCases
					}
				} else {
					allCases = append(allCases, lf)
				}
			}
			endArr, err := dec.Token()
			if err != nil {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q cases end: %w", path, err)
			}
			if delim, ok := endArr.(json.Delim); !ok || delim != ']' {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: expected ']'", path)
			}
		default:
			var discard json.RawMessage
			if err := dec.Decode(&discard); err != nil {
				return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q field %q: %w", path, key, err)
			}
		}
	}

	endObj, err := dec.Token()
	if err != nil {
		return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q end: %w", path, err)
	}
	if delim, ok := endObj.(json.Delim); !ok || delim != '}' {
		return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: expected '}'", path)
	}
	// Reject trailing garbage after the root JSON object.
	if extraTok, err := dec.Token(); err != io.EOF {
		return BaselineSnapshot{}, true, fmt.Errorf("parse baseline %q: unexpected trailing token %v (%v)", path, extraTok, err)
	}
	if cr.exceeded {
		return BaselineSnapshot{}, true, fmt.Errorf("baseline %q exceeds %d-byte limit", path, MaxBaselineSnapshotBytes)
	}
	if !hasCases {
		return BaselineSnapshot{}, true, fmt.Errorf("invalid baseline %q: missing required field 'cases'", path)
	}
	_ = hasVersion

	if maxCases > 0 {
		ordered := make([]LogFeatures, 0, len(ringBuf))
		if len(ringBuf) < maxCases {
			ordered = append(ordered, ringBuf...)
		} else {
			ordered = append(ordered, ringBuf[ringHead:]...)
			ordered = append(ordered, ringBuf[:ringHead]...)
		}
		snap.Cases = ordered
	} else {
		snap.Cases = allCases
	}
	snap.Version = baselineSnapshotVersion
	return snap, true, nil
}

type countingLimitReader struct {
	r        io.Reader
	read     int64
	limit    int64
	exceeded bool
}

func (c *countingLimitReader) Read(p []byte) (int, error) {
	if c.read > c.limit {
		c.exceeded = true
		return 0, fmt.Errorf("exceeded %d-byte limit", c.limit)
	}
	rem := c.limit - c.read + 1
	if int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	if c.read > c.limit {
		c.exceeded = true
		return n, fmt.Errorf("exceeded %d-byte limit", c.limit)
	}
	return n, err
}

// SaveBaselineSnapshot atomically writes snap to path using a `.baseline-*.tmp`
// file with 0600 permissions, Sync, Rename, and best-effort parent directory Sync.
// Enforces MaxBaselineSnapshotBytes on the encoded payload (including newline) BEFORE
// replacing any previous snapshot so Save never produces a file LoadBaselineSnapshot rejects.
func SaveBaselineSnapshot(path string, snap BaselineSnapshot) error {
	if path == "" {
		return nil
	}
	snap.Version = baselineSnapshotVersion
	snap.UpdatedAt = time.Now().UTC()
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	data = append(data, '\n')
	if len(data) > MaxBaselineSnapshotBytes {
		return fmt.Errorf("encoded baseline snapshot (%d bytes) exceeds %d-byte limit", len(data), MaxBaselineSnapshotBytes)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create baseline dir %q: %w", dir, err)
	}

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
