package ingest

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

const (
	// MagicHeaderLen matches Genesis storage.MagicHeaderLen: 4-byte length + 4-byte IEEE CRC32.
	MagicHeaderLen = 8
	// MaxFrameBytes bounds single-frame allocation to protect against corrupted length headers.
	MaxFrameBytes = 1024 * 1024 // 1 MiB
)

// SegReaderStats reports diagnostic counters for lossless .seg ingestion.
type SegReaderStats struct {
	CurrentSegmentID uint64 `json:"current_segment_id"`
	CurrentOffset    int64  `json:"current_offset"`
	FramesRead       uint64 `json:"frames_read"`
	CorruptedFrames  uint64 `json:"corrupted_frames"`
	BurnResets       uint64 `json:"burn_resets"`
}

// SegReader follows Genesis append-only .seg segment files read-only without dropping
// events during traffic bursts. It safely handles rotation, partial writes, and `genesis burn`.
type SegReader struct {
	mu             sync.Mutex
	segDir         string
	cursorPath     string
	cursor         SegCursor
	maxLineLen     int
	defaultService string

	framesRead      uint64
	corruptedFrames uint64
	burnResets      uint64
}

// NewSegReader creates a read-only Genesis segment follower, resuming from cursorPath if present.
func NewSegReader(segDir, cursorPath string, maxLineLen int) (*SegReader, error) {
	if strings.TrimSpace(segDir) == "" {
		return nil, fmt.Errorf("segDir must not be empty")
	}
	if maxLineLen <= 0 {
		maxLineLen = DefaultMaxLineLength
	}
	cur, err := LoadCursor(cursorPath)
	if err != nil {
		return nil, err
	}
	return &SegReader{
		segDir:         segDir,
		cursorPath:     cursorPath,
		cursor:         cur,
		maxLineLen:     maxLineLen,
		defaultService: "genesis",
	}, nil
}

// ReadBatch reads up to maxEvents newly available valid frames across Genesis segments.
// Partial in-flight writes at the tail of the latest segment are left unread until complete.
func (r *SegReader) ReadBatch(maxEvents int) ([]model.LogEvent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if maxEvents <= 0 {
		maxEvents = 4096
	}

	segments, err := listSegmentIDs(r.segDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(segments) == 0 {
		return nil, nil
	}

	latestSegID := segments[len(segments)-1]

	// Detect `genesis burn` (which unlinks all segments and resets to 00000001.seg at size 0).
	if r.cursor.SegmentID > 0 {
		if r.cursor.SegmentID > latestSegID {
			r.cursor.SegmentID = segments[0]
			r.cursor.Offset = 0
			r.burnResets++
		} else if !containsSegment(segments, r.cursor.SegmentID) {
			// Cursor segment was pruned by retention; advance to earliest surviving segment.
			r.cursor.SegmentID = segments[0]
			r.cursor.Offset = 0
		} else {
			curPath := segmentPath(r.segDir, r.cursor.SegmentID)
			if info, statErr := os.Stat(curPath); statErr == nil && info.Size() < r.cursor.Offset {
				r.cursor.SegmentID = segments[0]
				r.cursor.Offset = 0
				r.burnResets++
			}
		}
	} else {
		r.cursor.SegmentID = segments[0]
		r.cursor.Offset = 0
	}

	var events []model.LogEvent
	for idx, segID := range segments {
		if segID < r.cursor.SegmentID {
			continue
		}
		isLatest := idx == len(segments)-1
		if segID > r.cursor.SegmentID {
			r.cursor.SegmentID = segID
			r.cursor.Offset = 0
		}

		segEvents, advancedToNext, readErr := r.readSegmentLocked(segID, isLatest, maxEvents-len(events))
		if readErr != nil {
			return events, readErr
		}
		events = append(events, segEvents...)

		if len(events) >= maxEvents {
			break
		}
		if !advancedToNext {
			break
		}
	}

	return events, nil
}

func (r *SegReader) readSegmentLocked(segID uint64, isLatest bool, budget int) ([]model.LogEvent, bool, error) {
	segPath := segmentPath(r.segDir, segID)
	f, err := os.Open(segPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("open segment %q: %w", segPath, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, false, err
	}
	fileSize := info.Size()
	if r.cursor.Offset >= fileSize {
		return nil, !isLatest, nil
	}

	if _, err := f.Seek(r.cursor.Offset, io.SeekStart); err != nil {
		return nil, false, err
	}

	var events []model.LogEvent
	var header [MagicHeaderLen]byte

	for len(events) < budget {
		remaining := fileSize - r.cursor.Offset
		if remaining < MagicHeaderLen {
			// Active segment may still be flushing a frame; wait without advancing.
			if isLatest {
				return events, false, nil
			}
			// Sealed older segment has truncated trailing bytes; skip remainder and move on.
			if remaining > 0 {
				r.corruptedFrames++
			}
			return events, true, nil
		}

		if _, err := io.ReadFull(f, header[:]); err != nil {
			return events, !isLatest, nil
		}

		payloadLen := binary.BigEndian.Uint32(header[0:4])
		expectedCRC := binary.BigEndian.Uint32(header[4:8])

		if payloadLen > MaxFrameBytes {
			r.corruptedFrames++
			// Cannot trust length in this segment; advance past sealed segment or pause active.
			if isLatest {
				return events, false, nil
			}
			return events, true, nil
		}

		frameBytes := int64(MagicHeaderLen) + int64(payloadLen)
		if remaining < frameBytes {
			if isLatest {
				// Partial write in progress; leave cursor at frame start.
				return events, false, nil
			}
			r.corruptedFrames++
			return events, true, nil
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			if isLatest {
				return events, false, nil
			}
			r.corruptedFrames++
			return events, true, nil
		}

		actualCRC := crc32.ChecksumIEEE(payload)
		if actualCRC != expectedCRC {
			r.corruptedFrames++
			if isLatest {
				// Torn write or mid-flush CRC mismatch at tail; wait for Genesis flush or rotation.
				return events, false, nil
			}
			return events, true, nil
		}

		r.cursor.Offset += frameBytes
		r.cursor.NextID++
		r.framesRead++

		ev, parseErr := ParseRawLog(r.cursor.NextID, payload, r.maxLineLen, r.defaultService)
		if parseErr != nil {
			continue
		}
		events = append(events, ev)
	}

	return events, r.cursor.Offset >= fileSize && !isLatest, nil
}

// SaveCursor flushes the current read cursor atomically to disk.
func (r *SegReader) SaveCursor() error {
	r.mu.Lock()
	cur := r.cursor
	path := r.cursorPath
	r.mu.Unlock()
	return SaveCursor(path, cur)
}

// ResetCursor zeros the in-memory cursor (used by `sentinel burn`).
func (r *SegReader) ResetCursor() {
	r.mu.Lock()
	r.cursor = SegCursor{}
	r.mu.Unlock()
}

// Stats returns a snapshot of reader metrics.
func (r *SegReader) Stats() SegReaderStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return SegReaderStats{
		CurrentSegmentID: r.cursor.SegmentID,
		CurrentOffset:    r.cursor.Offset,
		FramesRead:       r.framesRead,
		CorruptedFrames:  r.corruptedFrames,
		BurnResets:       r.burnResets,
	}
}

// WriteSegmentFrame appends a single Genesis-compatible CRC32 frame to w.
// Exported for deterministic testing, benchmarks, and synthetic corpus generation.
func WriteSegmentFrame(w io.Writer, raw []byte) error {
	var header [MagicHeaderLen]byte
	binary.BigEndian.PutUint32(header[0:4], uint32(len(raw)))
	binary.BigEndian.PutUint32(header[4:8], crc32.ChecksumIEEE(raw))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(raw)
	return err
}

func segmentPath(dir string, segID uint64) string {
	return filepath.Join(dir, fmt.Sprintf("%08d.seg", segID))
}

func listSegmentIDs(dir string) ([]uint64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []uint64
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".seg") {
			continue
		}
		base := strings.TrimSuffix(entry.Name(), ".seg")
		if id, err := strconv.ParseUint(base, 10, 64); err == nil {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

func containsSegment(ids []uint64, target uint64) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}
