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
	// DefaultMaxBatchBytes bounds total raw bytes read per ReadBatch call so large frames
	// cannot accumulate gigabytes before caller processing.
	DefaultMaxBatchBytes = 16 * 1024 * 1024 // 16 MiB
	// maxFingerprintBytes is the prefix length hashed alongside POSIX file identity.
	maxFingerprintBytes = 256
	// maxRecoveryScanBytes bounds total byte-by-byte forward resync offsets inspected across one ReadBatch call.
	maxRecoveryScanBytes = 256 * 1024
	// maxRecoveryChecksumBytes bounds total payload bytes hashed by IEEE CRC32 during recovery in one ReadBatch call.
	maxRecoveryChecksumBytes = 1024 * 1024 // 1 MiB
	// maxPendingRecoveryCandidates bounds incomplete active-segment candidate headers remembered for retry on growth.
	maxPendingRecoveryCandidates = 64
	// DefaultPartialTailStallPolls is the number of consecutive unchanged polls at the exact
	// same (segID, offset, fileSize) before a quiet active segment tests for a valid later frame
	// (distinguishing an in-flight write from a corrupt-length header on a quiet segment).
	DefaultPartialTailStallPolls = 8
)

type incompleteCandidate struct {
	offset   int64
	needSize int64
}

type batchBudget struct {
	eventsRemaining           int
	bytesRemaining            int64
	recoveryRemaining         int64
	recoveryChecksumRemaining int64
	recoveryChecksumsRun      int
	framesProcessed           int
}

// SegReaderStats reports diagnostic counters for lossless .seg ingestion.
type SegReaderStats struct {
	CurrentSegmentID uint64 `json:"current_segment_id"`
	CurrentOffset    int64  `json:"current_offset"`
	FramesRead       uint64 `json:"frames_read"`
	CorruptedFrames  uint64 `json:"corrupted_frames"`
	RecoveryStalls   uint64 `json:"recovery_stalls"`
	BurnResets       uint64 `json:"burn_resets"`
}

// SegReader follows Genesis append-only .seg segment files read-only without dropping
// events during traffic bursts. It validates segment identity on the exact open file
// handle before seeking, bounds batch byte retention, handles rotation, partial writes,
// incremental bounded CRC recovery across polls, and `genesis burn` replacement detection.
type SegReader struct {
	mu                sync.Mutex
	saveMu            sync.Mutex // serializes cursor snapshot + file writes without blocking ReadBatch across disk I/O
	segDir            string
	cursorPath        string
	cursor            SegCursor
	maxLineLen        int
	maxBatchBytes     int64
	partialStallPolls int
	defaultService    string

	// recoveryScanSeg and recoveryScanOffset track incremental bounded forward resync
	// progress across polls; pendingCandidates remembers incomplete active-segment headers
	// separately so forward scanning never stalls on a quiet segment while still retrying
	// incomplete candidates once the segment grows to their required size.
	recoveryScanSeg    uint64
	recoveryScanOffset int64
	pendingCandidates  []incompleteCandidate

	// partialTail tracking distinguishes in-flight writes from persistent corrupt lengths
	// on a quiet active segment.
	stallSegID    uint64
	stallOffset   int64
	stallFileSize int64
	stallCount    int

	framesRead      uint64
	corruptedFrames uint64
	recoveryStalls  uint64
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
		segDir:            segDir,
		cursorPath:        cursorPath,
		cursor:            cur,
		maxLineLen:        maxLineLen,
		maxBatchBytes:     DefaultMaxBatchBytes,
		partialStallPolls: DefaultPartialTailStallPolls,
		defaultService:    "genesis",
	}, nil
}

// SetMaxBatchBytes overrides the per-batch byte budget (primarily for testing).
func (r *SegReader) SetMaxBatchBytes(n int64) {
	r.mu.Lock()
	if n > 0 {
		r.maxBatchBytes = n
	}
	r.mu.Unlock()
}

// SetPartialTailStallPolls overrides consecutive unchanged-poll threshold before
// testing for a valid later frame past a quiet corrupt-length header.
func (r *SegReader) SetPartialTailStallPolls(n int) {
	r.mu.Lock()
	if n > 0 {
		r.partialStallPolls = n
	}
	r.mu.Unlock()
}

// ReadBatch reads up to maxEvents (bounded also by maxBatchBytes) newly available valid
// frames across Genesis segments. At least one valid frame can always make progress even
// if its size exceeds remaining batch budget.
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

	if r.cursor.SegmentID > 0 {
		if r.cursor.SegmentID > latestSegID {
			r.resetCursorToLocked(segments[0], true)
		} else if !containsSegment(segments, r.cursor.SegmentID) {
			r.resetCursorToLocked(segments[0], false)
		}
	} else {
		r.resetCursorToLocked(segments[0], false)
	}

	budget := &batchBudget{
		eventsRemaining:           maxEvents,
		bytesRemaining:            r.maxBatchBytes,
		recoveryRemaining:         maxRecoveryScanBytes,
		recoveryChecksumRemaining: maxRecoveryChecksumBytes,
	}
	var events []model.LogEvent
	for idx, segID := range segments {
		if segID < r.cursor.SegmentID {
			continue
		}
		isLatest := idx == len(segments)-1
		if segID > r.cursor.SegmentID {
			r.resetCursorToLocked(segID, false)
		}

		segEvents, advancedToNext, readErr := r.readSegmentLocked(segID, isLatest, budget)
		events = append(events, segEvents...)
		if readErr != nil {
			return events, readErr
		}

		if budget.eventsRemaining <= 0 || budget.bytesRemaining <= 0 || budget.recoveryRemaining <= 0 ||
			(budget.recoveryChecksumRemaining <= 0 && budget.recoveryChecksumsRun > 0) {
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
	r.cursor.FileIdentity = ""
	r.cursor.SegmentFingerprint = ""
	r.cursor.FingerprintLen = 0
	r.clearRecoveryStateLocked()
	r.clearStallStateLocked()
	if isBurn {
		r.burnResets++
	}
}

func (r *SegReader) clearRecoveryStateLocked() {
	r.recoveryScanSeg = 0
	r.recoveryScanOffset = 0
	r.pendingCandidates = nil
}

func (r *SegReader) clearStallStateLocked() {
	r.stallSegID = 0
	r.stallOffset = 0
	r.stallFileSize = 0
	r.stallCount = 0
}

func (r *SegReader) readSegmentLocked(segID uint64, isLatest bool, budget *batchBudget) ([]model.LogEvent, bool, error) {
	segPath := segmentPath(r.segDir, segID)
	f, err := os.Open(segPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("open segment %q: %w", segPath, err)
	}
	defer func() { _ = f.Close() }()

	// Validate size and file identity strictly on the SAME open file handle before seeking.
	info, err := f.Stat()
	if err != nil {
		return nil, false, fmt.Errorf("stat segment %q: %w", segPath, err)
	}
	fileSize := info.Size()
	currentFileID := fileIdentity(info)

	if r.cursor.Offset > 0 || r.cursor.FileIdentity != "" || r.cursor.SegmentFingerprint != "" {
		replaced := false
		if fileSize < r.cursor.Offset {
			replaced = true
		} else if r.cursor.FileIdentity != "" && currentFileID != "" && currentFileID != r.cursor.FileIdentity {
			replaced = true
		} else if r.cursor.SegmentFingerprint != "" && r.cursor.FingerprintLen > 0 {
			fp, fpLen, fpErr := computeSegmentFingerprintFromFile(f, r.cursor.FingerprintLen)
			if fpErr != nil {
				return nil, false, fmt.Errorf("verify segment identity %q: %w", segPath, fpErr)
			}
			if fpLen < r.cursor.FingerprintLen || fp != r.cursor.SegmentFingerprint {
				replaced = true
			}
		}
		if replaced {
			r.resetCursorToLocked(segID, true)
		}
	}

	if r.cursor.FileIdentity == "" && currentFileID != "" {
		r.cursor.FileIdentity = currentFileID
	}
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

	var (
		events []model.LogEvent
		header [MagicHeaderLen]byte
	)

	for budget.eventsRemaining > 0 {
		if budget.bytesRemaining <= 0 && budget.framesProcessed > 0 {
			return events, false, nil
		}

		remaining := fileSize - r.cursor.Offset
		if remaining < MagicHeaderLen {
			if isLatest {
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
			r.clearStallStateLocked()
			recovered, doneSeg, recErr := r.advanceRecoveryLocked(f, segID, fileSize, isLatest, budget)
			if recErr != nil {
				return events, false, recErr
			}
			if recovered {
				continue
			}
			return events, doneSeg, nil
		}

		frameBytes := int64(MagicHeaderLen) + int64(payloadLen)
		if remaining < frameBytes {
			if isLatest {
				// Track consecutive unchanged polls at this exact (segID, offset, fileSize).
				// Normal in-flight writes complete quickly; if the segment stays quiet across
				// partialStallPolls, probe for a CRC-validated subsequent frame so a corrupt
				// length header cannot wedge the active segment forever.
				if r.stallSegID == segID && r.stallOffset == r.cursor.Offset && r.stallFileSize == fileSize {
					r.stallCount++
				} else {
					r.stallSegID = segID
					r.stallOffset = r.cursor.Offset
					r.stallFileSize = fileSize
					r.stallCount = 1
				}
				if r.stallCount >= r.partialStallPolls {
					recovered, _, recErr := r.advanceRecoveryLocked(f, segID, fileSize, true, budget)
					if recErr != nil {
						return events, false, recErr
					}
					if recovered {
						r.corruptedFrames++
						r.clearStallStateLocked()
						continue
					}
				}
				return events, false, nil
			}
			r.corruptedFrames++
			recovered, doneSeg, recErr := r.advanceRecoveryLocked(f, segID, fileSize, false, budget)
			if recErr != nil {
				return events, false, recErr
			}
			if recovered {
				continue
			}
			return events, doneSeg, nil
		}

		// Enforce per-batch byte budget before allocating payload, allowing the over-budget
		// exception strictly before the first CRC-valid frame in the batch is processed.
		if frameBytes > budget.bytesRemaining && budget.framesProcessed > 0 {
			return events, false, nil
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
			r.clearStallStateLocked()
			recovered, doneSeg, recErr := r.advanceRecoveryLocked(f, segID, fileSize, isLatest, budget)
			if recErr != nil {
				return events, false, recErr
			}
			if recovered {
				continue
			}
			return events, doneSeg, nil
		}

		r.clearRecoveryStateLocked()
		r.clearStallStateLocked()
		r.cursor.Offset += frameBytes
		r.cursor.NextID++
		r.framesRead++
		budget.framesProcessed++
		budget.bytesRemaining -= frameBytes

		ev, parseErr := ParseRawLog(r.cursor.NextID, payload, r.maxLineLen, r.defaultService)
		if parseErr == nil {
			events = append(events, ev)
			budget.eventsRemaining--
		}
		if budget.bytesRemaining <= 0 {
			break
		}
	}

	return events, r.cursor.Offset >= fileSize && !isLatest, nil
}

// advanceRecoveryLocked shares one batch-wide recovery scan budget across ReadBatch
// for both active and sealed segments. Forward scan progress is tracked separately from
// incomplete active-segment candidates so a quiet active segment never stalls while
// incomplete candidates are still retried immediately once the file grows.
func (r *SegReader) advanceRecoveryLocked(f *os.File, segID uint64, fileSize int64, isLatest bool, budget *batchBudget) (recovered bool, doneSegment bool, err error) {
	minStart := r.cursor.Offset + 1
	if r.recoveryScanSeg != segID {
		r.recoveryScanSeg = segID
		r.recoveryScanOffset = minStart
		r.pendingCandidates = nil
	} else if r.recoveryScanOffset < minStart {
		r.recoveryScanOffset = minStart
	}

	// Recheck any previously saved incomplete candidate whose required completion size
	// is now available in fileSize — including when an active segment became sealed on
	// rotation before the next poll so a completed tail frame is never skipped.
	if len(r.pendingCandidates) > 0 {
		remaining := r.pendingCandidates[:0]
		for i, cand := range r.pendingCandidates {
			if cand.offset < minStart {
				continue
			}
			if cand.needSize > fileSize {
				remaining = append(remaining, cand)
				continue
			}
			payloadEst := cand.needSize - cand.offset - MagicHeaderLen
			if budget.recoveryRemaining <= 0 || (payloadEst > budget.recoveryChecksumRemaining && budget.recoveryChecksumsRun > 0) {
				// Budget exhausted: preserve unchecked candidates for the next poll.
				remaining = append(remaining, r.pendingCandidates[i:]...)
				r.pendingCandidates = remaining
				return false, false, nil
			}
			valid, headerBytes, hashedBytes, verifyErr := verifyCandidateFrame(f, cand.offset, fileSize)
			if verifyErr != nil {
				r.pendingCandidates = append(remaining, r.pendingCandidates[i:]...)
				return false, false, verifyErr
			}
			budget.recoveryRemaining -= headerBytes
			if budget.recoveryRemaining < 0 {
				budget.recoveryRemaining = 0
			}
			if hashedBytes > 0 {
				budget.recoveryChecksumsRun++
				budget.recoveryChecksumRemaining -= hashedBytes
				if budget.recoveryChecksumRemaining < 0 {
					budget.recoveryChecksumRemaining = 0
				}
			}
			if valid {
				r.clearRecoveryStateLocked()
				r.cursor.Offset = cand.offset
				if _, seekErr := f.Seek(cand.offset, io.SeekStart); seekErr != nil {
					return false, false, seekErr
				}
				return true, false, nil
			}
			// Invalid candidate once complete: drop permanently.
		}
		r.pendingCandidates = remaining
	}

	if budget.recoveryRemaining <= 0 || (budget.recoveryChecksumRemaining <= 0 && budget.recoveryChecksumsRun > 0) {
		return false, false, nil
	}

	scanStart := r.recoveryScanOffset
	nextOff, scannedTo, bytesScanned, found, checksumExhausted, newCandidates, scanErr := findNextValidFrame(f, scanStart, fileSize, isLatest, budget)
	if scanErr != nil {
		return false, false, scanErr
	}
	budget.recoveryRemaining -= bytesScanned
	if budget.recoveryRemaining < 0 {
		budget.recoveryRemaining = 0
	}

	if found {
		r.clearRecoveryStateLocked()
		r.cursor.Offset = nextOff
		if _, seekErr := f.Seek(nextOff, io.SeekStart); seekErr != nil {
			return false, false, seekErr
		}
		return true, false, nil
	}

	r.recoveryScanSeg = segID
	if scannedTo > r.recoveryScanOffset {
		r.recoveryScanOffset = scannedTo
	}
	if isLatest && len(newCandidates) > 0 {
		for _, c := range newCandidates {
			r.pendingCandidates = addIncompleteCandidate(r.pendingCandidates, c)
		}
	}

	if isLatest {
		if bytesScanned > 0 || checksumExhausted {
			r.recoveryStalls++
		}
		return false, false, nil
	}

	// Sealed segment: advance to next segment ONLY once incremental recovery reaches EOF
	// without pausing on checksum budget exhaustion.
	if !checksumExhausted && (scannedTo >= fileSize-MagicHeaderLen || bytesScanned == 0) {
		r.clearRecoveryStateLocked()
		return false, true, nil
	}
	r.recoveryStalls++
	return false, false, nil
}

func verifyCandidateFrame(f *os.File, offset, fileSize int64) (valid bool, headerBytes int64, hashedBytes int64, err error) {
	if offset+MagicHeaderLen >= fileSize {
		return false, 0, 0, nil
	}
	var hdr [MagicHeaderLen]byte
	if _, err := f.ReadAt(hdr[:], offset); err != nil {
		if isEOFError(err) {
			return false, MagicHeaderLen, 0, nil
		}
		return false, MagicHeaderLen, 0, fmt.Errorf("verify candidate header at %d: %w", offset, err)
	}
	pLen := binary.BigEndian.Uint32(hdr[0:4])
	wantCRC := binary.BigEndian.Uint32(hdr[4:8])
	if pLen == 0 || pLen > MaxFrameBytes || offset+MagicHeaderLen+int64(pLen) > fileSize {
		return false, MagicHeaderLen, 0, nil
	}
	payload := make([]byte, pLen)
	if _, err := f.ReadAt(payload, offset+MagicHeaderLen); err != nil {
		if isEOFError(err) {
			return false, MagicHeaderLen, 0, nil
		}
		return false, MagicHeaderLen, 0, fmt.Errorf("verify candidate payload at %d: %w", offset, err)
	}
	return crc32.ChecksumIEEE(payload) == wantCRC, MagicHeaderLen, int64(pLen), nil
}

// addIncompleteCandidate records an incomplete candidate in ascending offset order,
// evicting the candidate with the largest required completion size if at capacity so
// genuine short in-flight tail frames are not displaced by huge corrupt length headers.
func addIncompleteCandidate(cands []incompleteCandidate, cand incompleteCandidate) []incompleteCandidate {
	for _, existing := range cands {
		if existing.offset == cand.offset {
			return cands
		}
	}
	if len(cands) >= maxPendingRecoveryCandidates {
		worstIdx := -1
		worstNeed := cand.needSize
		for i, existing := range cands {
			if existing.needSize > worstNeed {
				worstNeed = existing.needSize
				worstIdx = i
			}
		}
		if worstIdx == -1 {
			return cands
		}
		cands[worstIdx] = cand
	} else {
		cands = append(cands, cand)
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].offset < cands[j].offset })
	return cands
}

// findNextValidFrame scans forward up to budget.recoveryRemaining offsets from startOff
// looking for the next byte offset whose 8-byte [len][crc32] header points to a complete
// payload within fileSize passing IEEE CRC32. Checksum payload bytes are budgeted
// separately via budget.recoveryChecksumRemaining (permitting one candidate to exceed
// budget when recoveryChecksumsRun == 0 so progress is guaranteed).
func findNextValidFrame(f *os.File, startOff, fileSize int64, isLatest bool, budget *batchBudget) (foundOff int64, nextScanOff int64, bytesScanned int64, found bool, checksumExhausted bool, incomplete []incompleteCandidate, err error) {
	maxScan := budget.recoveryRemaining
	if maxScan <= 0 || startOff+MagicHeaderLen >= fileSize {
		return 0, startOff, 0, false, false, nil, nil
	}
	limit := min(fileSize-MagicHeaderLen-1, startOff+maxScan-1)
	if limit < startOff {
		return 0, startOff, 0, false, false, nil, nil
	}
	scanWindowSize := int(min(fileSize-startOff, maxScan+MaxFrameBytes+MagicHeaderLen))
	buf := make([]byte, scanWindowSize)
	n, readErr := f.ReadAt(buf, startOff)
	if readErr != nil && !isEOFError(readErr) {
		return 0, startOff, 0, false, false, nil, fmt.Errorf("scan recovery window at %d: %w", startOff, readErr)
	}
	buf = buf[:n]

	maxRel := int(limit - startOff)
	if maxRel > len(buf)-MagicHeaderLen-1 {
		maxRel = len(buf) - MagicHeaderLen - 1
	}
	if maxRel < 0 {
		return 0, startOff, 0, false, false, nil, nil
	}

	for rel := 0; rel <= maxRel; rel++ {
		pLen := binary.BigEndian.Uint32(buf[rel : rel+4])
		if pLen == 0 || pLen > MaxFrameBytes {
			continue
		}
		end := rel + MagicHeaderLen + int(pLen)
		if end > len(buf) {
			if isLatest && startOff+int64(end) > fileSize {
				incomplete = addIncompleteCandidate(incomplete, incompleteCandidate{
					offset:   startOff + int64(rel),
					needSize: startOff + int64(end),
				})
			}
			continue
		}
		payloadBytes := int64(pLen)
		if payloadBytes > budget.recoveryChecksumRemaining && budget.recoveryChecksumsRun > 0 {
			// Pause before hashing this candidate so the next poll resumes right here.
			return 0, startOff + int64(rel), int64(rel), false, true, incomplete, nil
		}
		budget.recoveryChecksumsRun++
		budget.recoveryChecksumRemaining -= payloadBytes
		if budget.recoveryChecksumRemaining < 0 {
			budget.recoveryChecksumRemaining = 0
		}
		wantCRC := binary.BigEndian.Uint32(buf[rel+4 : rel+8])
		if crc32.ChecksumIEEE(buf[rel+MagicHeaderLen:end]) == wantCRC {
			return startOff + int64(rel), startOff + int64(rel), int64(rel) + 1, true, false, nil, nil
		}
	}

	scanned := int64(maxRel) + 1
	nextOff := startOff + scanned
	if nextOff > fileSize-MagicHeaderLen {
		nextOff = fileSize - MagicHeaderLen
	}
	if nextOff < startOff {
		nextOff = startOff
	}
	return 0, nextOff, scanned, false, false, incomplete, nil
}

func isEOFError(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
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
	r.clearRecoveryStateLocked()
	r.clearStallStateLocked()
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
		RecoveryStalls:   r.recoveryStalls,
		BurnResets:       r.burnResets,
	}
}

// WriteSegmentFrame appends a single Genesis-compatible CRC32 frame to w.
// Rejects empty payloads or payloads exceeding MaxFrameBytes before writing any bytes.
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
