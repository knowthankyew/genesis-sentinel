package ingest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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
	// maxFingerprintBytes is the prefix length hashed to identify segment identity across burn resets.
	maxFingerprintBytes = 256
	// maxRecoveryScanBytes bounds byte-by-byte forward resync after a corrupted frame.
	maxRecoveryScanBytes = 256 * 1024
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
// events during traffic bursts. It safely handles rotation, partial writes, bounded
// CRC recovery, and `genesis burn` replacement detection.
type SegReader struct {
	mu             sync.Mutex
	saveMu         sync.Mutex // serializes cursor snapshot + file writes without blocking ReadBatch across disk I/O
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

	// Detect `genesis burn` (segment rollback, truncation, OR replacement file with new content
	// even if the replacement grew >= saved offset).
	if r.cursor.SegmentID > 0 {
		if r.cursor.SegmentID > latestSegID {
			r.resetCursorToLocked(segments[0], true)
		} else if !containsSegment(segments, r.cursor.SegmentID) {
			// Cursor segment was pruned by retention; advance to earliest surviving segment.
			r.resetCursorToLocked(segments[0], false)
		} else {
			curPath := segmentPath(r.segDir, r.cursor.SegmentID)
			info, statErr := os.Stat(curPath)
			if statErr != nil {
				if os.IsNotExist(statErr) {
					r.resetCursorToLocked(segments[0], true)
				} else {
					return nil, fmt.Errorf("stat segment %q: %w", curPath, statErr)
				}
			} else if info.Size() < r.cursor.Offset {
				r.resetCursorToLocked(segments[0], true)
			} else if r.cursor.SegmentFingerprint != "" && r.cursor.FingerprintLen > 0 {
				fp, fpLen, fpErr := computeSegmentFingerprint(curPath, r.cursor.FingerprintLen)
				if fpErr != nil {
					return nil, fmt.Errorf("verify segment identity %q: %w", curPath, fpErr)
				}
				if fpLen < r.cursor.FingerprintLen || fp != r.cursor.SegmentFingerprint {
					r.resetCursorToLocked(segments[0], true)
				}
			}
		}
	} else {
		r.resetCursorToLocked(segments[0], false)
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
			r.cursor.SegmentFingerprint = ""
			r.cursor.FingerprintLen = 0
		}

		segEvents, advancedToNext, readErr := r.readSegmentLocked(segID, isLatest, maxEvents-len(events))
		events = append(events, segEvents...)
		if readErr != nil {
			return events, readErr
		}

		if len(events) >= maxEvents {
			break
		}
		if !advancedToNext {
			break
		}
	}

	return events, nil
}

func (r *SegReader) resetCursorToLocked(segID uint64, isBurn bool) {
	r.cursor.SegmentID = segID
	r.cursor.Offset = 0
	r.cursor.SegmentFingerprint = ""
	r.cursor.FingerprintLen = 0
	if isBurn {
		r.burnResets++
	}
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
		return nil, false, fmt.Errorf("stat segment %q: %w", segPath, err)
	}
	fileSize := info.Size()

	// Capture segment identity fingerprint as soon as enough header bytes exist.
	if r.cursor.SegmentFingerprint == "" && fileSize >= MagicHeaderLen {
		fp, fpLen, fpErr := computeSegmentFingerprintFromFile(f, maxFingerprintBytes)
		if fpErr != nil {
			return nil, false, fmt.Errorf("fingerprint segment %q: %w", segPath, fpErr)
		}
		r.cursor.SegmentFingerprint = fp
		r.cursor.FingerprintLen = fpLen
	}

	if r.cursor.Offset >= fileSize {
		return nil, !isLatest, nil
	}

	if _, err := f.Seek(r.cursor.Offset, io.SeekStart); err != nil {
		return nil, false, fmt.Errorf("seek segment %q: %w", segPath, err)
	}

	var events []model.LogEvent
	var header [MagicHeaderLen]byte

	for len(events) < budget {
		remaining := fileSize - r.cursor.Offset
		if remaining < MagicHeaderLen {
			if isLatest {
				// Active segment may still be flushing a frame; wait without advancing.
				return events, false, nil
			}
			if remaining > 0 {
				r.corruptedFrames++
			}
			return events, true, nil
		}

		if _, err := io.ReadFull(f, header[:]); err != nil {
			if isEOFError(err) {
				return events, !isLatest, nil
			}
			return events, false, fmt.Errorf("read header in %q at %d: %w", segPath, r.cursor.Offset, err)
		}

		payloadLen := binary.BigEndian.Uint32(header[0:4])
		expectedCRC := binary.BigEndian.Uint32(header[4:8])

		if payloadLen == 0 || payloadLen > MaxFrameBytes {
			r.corruptedFrames++
			nextOff, found, scanErr := findNextValidFrame(f, r.cursor.Offset+1, fileSize)
			if scanErr != nil {
				return events, false, scanErr
			}
			if found {
				r.cursor.Offset = nextOff
				if _, seekErr := f.Seek(nextOff, io.SeekStart); seekErr != nil {
					return events, false, seekErr
				}
				continue
			}
			if isLatest {
				return events, false, nil
			}
			return events, true, nil
		}

		frameBytes := int64(MagicHeaderLen) + int64(payloadLen)
		if remaining < frameBytes {
			if isLatest {
				// Partial in-flight write; leave cursor at frame start.
				return events, false, nil
			}
			r.corruptedFrames++
			nextOff, found, scanErr := findNextValidFrame(f, r.cursor.Offset+1, fileSize)
			if scanErr != nil {
				return events, false, scanErr
			}
			if found {
				r.cursor.Offset = nextOff
				if _, seekErr := f.Seek(nextOff, io.SeekStart); seekErr != nil {
					return events, false, seekErr
				}
				continue
			}
			return events, true, nil
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(f, payload); err != nil {
			if isEOFError(err) {
				if isLatest {
					return events, false, nil
				}
				r.corruptedFrames++
				return events, true, nil
			}
			return events, false, fmt.Errorf("read payload in %q at %d: %w", segPath, r.cursor.Offset, err)
		}

		actualCRC := crc32.ChecksumIEEE(payload)
		if actualCRC != expectedCRC {
			r.corruptedFrames++
			// Bounded recovery: scan forward for the next CRC-validated frame boundary.
			// Never advance past an unvalidated tail on the active segment.
			nextOff, found, scanErr := findNextValidFrame(f, r.cursor.Offset+1, fileSize)
			if scanErr != nil {
				return events, false, scanErr
			}
			if found {
				r.cursor.Offset = nextOff
				if _, seekErr := f.Seek(nextOff, io.SeekStart); seekErr != nil {
					return events, false, seekErr
				}
				continue
			}
			if isLatest {
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

// findNextValidFrame scans forward up to maxRecoveryScanBytes from startOff looking
// for the next byte offset whose 8-byte [len][crc32] header points to a complete
// payload within fileSize that passes IEEE CRC32 verification.
func findNextValidFrame(f *os.File, startOff, fileSize int64) (int64, bool, error) {
	if startOff+MagicHeaderLen >= fileSize {
		return 0, false, nil
	}
	limit := min(fileSize-MagicHeaderLen, startOff+maxRecoveryScanBytes)
	scanWindowSize := int(min(fileSize-startOff, maxRecoveryScanBytes+MaxFrameBytes+MagicHeaderLen))
	buf := make([]byte, scanWindowSize)
	n, err := f.ReadAt(buf, startOff)
	if err != nil && !isEOFError(err) {
		return 0, false, fmt.Errorf("scan recovery window at %d: %w", startOff, err)
	}
	buf = buf[:n]

	maxRel := int(limit - startOff)
	if maxRel > len(buf)-MagicHeaderLen {
		maxRel = len(buf) - MagicHeaderLen
	}
	for rel := 0; rel <= maxRel; rel++ {
		pLen := binary.BigEndian.Uint32(buf[rel : rel+4])
		if pLen == 0 || pLen > MaxFrameBytes {
			continue
		}
		end := rel + MagicHeaderLen + int(pLen)
		if end > len(buf) {
			continue
		}
		wantCRC := binary.BigEndian.Uint32(buf[rel+4 : rel+8])
		if crc32.ChecksumIEEE(buf[rel+MagicHeaderLen:end]) == wantCRC {
			return startOff + int64(rel), true, nil
		}
	}
	return 0, false, nil
}

func isEOFError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func computeSegmentFingerprint(path string, maxBytes int) (string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	return computeSegmentFingerprintFromFile(f, maxBytes)
}

func computeSegmentFingerprintFromFile(f *os.File, maxBytes int) (string, int, error) {
	if maxBytes <= 0 {
		maxBytes = maxFingerprintBytes
	}
	buf := make([]byte, maxBytes)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !isEOFError(err) {
		return "", 0, err
	}
	sum := sha256.Sum256(buf[:n])
	return hex.EncodeToString(sum[:]), n, nil
}

// SaveCursor snapshots the current cursor and persists it to disk serialized by
// saveMu so concurrent saves and resets publish strictly in snapshot order without
// holding r.mu across file I/O.
func (r *SegReader) SaveCursor() error {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()

	r.mu.Lock()
	cur := r.cursor
	path := r.cursorPath
	r.mu.Unlock()

	return SaveCursor(path, cur)
}

// ResetCursor zeros the in-memory cursor under saveMu + r.mu so an earlier
// in-flight SaveCursor snapshot cannot overwrite the reset.
func (r *SegReader) ResetCursor() {
	r.saveMu.Lock()
	defer r.saveMu.Unlock()

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
// Rejects payloads exceeding MaxFrameBytes before writing any bytes.
func WriteSegmentFrame(w io.Writer, raw []byte) error {
	if len(raw) == 0 {
		return fmt.Errorf("segment frame payload must not be empty")
	}
	if len(raw) > MaxFrameBytes {
		return fmt.Errorf("segment frame payload (%d bytes) exceeds MaxFrameBytes (%d)", len(raw), MaxFrameBytes)
	}
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
