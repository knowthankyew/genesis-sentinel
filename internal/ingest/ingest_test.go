package ingest

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestParseRawLogAllFormatsAndEdgeCases(t *testing.T) {
	// 1. JSON Lines (including surrounding whitespace preserving service=sentinel)
	ev, err := ParseRawLog(1, []byte(`  {"timestamp":1763996400,"service":"sentinel","level":"err","trace_id":"tr-1","msg":"alert"}   `), 0, "genesis")
	if err != nil {
		t.Fatalf("JSON whitespace parse failed: %v", err)
	}
	if ev.Service != "sentinel" || ev.Level != "ERROR" || ev.TraceID != "tr-1" || ev.Message != "alert" {
		t.Fatalf("unexpected JSON LogEvent: %+v", ev)
	}

	// 2. Oversized valid JSON (> maxLineLen) preserves service=sentinel and bounds Message
	bigMsg := strings.Repeat("A", 70000)
	bigJSON := []byte(`{"timestamp":1763996400,"service":"sentinel","level":"ERROR","message":"` + bigMsg + `"}`)
	ev, err = ParseRawLog(2, bigJSON, DefaultMaxLineLength, "genesis")
	if err != nil {
		t.Fatalf("oversized valid JSON parse failed: %v", err)
	}
	if ev.Service != "sentinel" {
		t.Fatalf("oversized JSON lost service=sentinel: got %q", ev.Service)
	}
	if len(ev.Message) > DefaultMaxLineLength {
		t.Fatalf("expected message truncated to <= %d, got %d", DefaultMaxLineLength, len(ev.Message))
	}

	// 3. Oversized truncated/malformed JSON is rejected instead of relabeled as plain text
	truncatedJSON := []byte(`{"service":"sentinel","message":"` + strings.Repeat("B", 70000))
	if _, err := ParseRawLog(3, truncatedJSON, DefaultMaxLineLength, "genesis"); !errors.Is(err, ErrOversizedLine) {
		t.Fatalf("expected ErrOversizedLine for malformed oversized JSON, got %v", err)
	}

	// 4. Syslog RFC 5424 with multiple SD elements and escaped ']' in quotes
	ev, err = ParseRawLog(4, []byte(`<35>1 2026-11-24T10:00:00Z host1 sshd 1234 msg42 [a@32473 x="1\]still"][b@32473 y="2"] failed login`), 0, "genesis")
	if err != nil {
		t.Fatalf("RFC 5424 multi-SD parse failed: %v", err)
	}
	if ev.Service != "sshd" || ev.Level != "ERROR" || ev.TraceID != "msg42" || ev.Message != "failed login" {
		t.Fatalf("unexpected RFC 5424 LogEvent: %+v", ev)
	}

	// 5. Syslog RFC 3164 (including IPv6 hostname with colons and space-delimited tag)
	ev, err = ParseRawLog(5, []byte(`<36>Nov 24 10:00:00 macbook sudo[991]: user dev : command not allowed`), 0, "genesis")
	if err != nil {
		t.Fatalf("RFC 3164 parse failed: %v", err)
	}
	if ev.Service != "sudo" || ev.Level != "WARN" || ev.Message != "user dev : command not allowed" {
		t.Fatalf("unexpected RFC 3164 LogEvent: %+v", ev)
	}
	ev, err = ParseRawLog(51, []byte(`<36>Nov 24 10:00:00 2001:db8::1 sshd: failed login`), 0, "genesis")
	if err != nil || ev.Service != "sshd" || ev.Message != "failed login" {
		t.Fatalf("RFC 3164 IPv6 hostname parse failed: ev=%+v err=%v", ev, err)
	}
	ev, err = ParseRawLog(511, []byte(`<36>Nov 24 10:00:00 2001:db8:: sentinel: alert`), 0, "genesis")
	if err != nil || ev.Service != "sentinel" || ev.Message != "alert" {
		t.Fatalf("RFC 3164 IPv6 :: hostname parse failed: ev=%+v err=%v", ev, err)
	}
	ev, err = ParseRawLog(52, []byte(`<36>Nov 24 10:00:00 host1 cronjob completed ok`), 0, "genesis")
	if err != nil || ev.Service != "cronjob" || ev.Message != "completed ok" {
		t.Fatalf("RFC 3164 space-delimited tag failed: ev=%+v err=%v", ev, err)
	}
	// Hostname-free RFC 3164 TAG with PID must preserve service=sentinel for self-alert filtering
	ev, err = ParseRawLog(521, []byte(`<36>Nov 24 10:00:00 sentinel[42] alert emitted`), 0, "genesis")
	if err != nil || ev.Service != "sentinel" || ev.Message != "alert emitted" {
		t.Fatalf("RFC 3164 hostname-free PID tag lost service=sentinel: ev=%+v err=%v", ev, err)
	}

	// 5a. Extreme float timestamp 1e20 falls back cleanly without int64 overflow UB
	ev, err = ParseRawLog(520, []byte(`{"timestamp":1e20,"service":"api","level":"INFO","msg":"overflow ts"}`), 0, "genesis")
	if err != nil || ev.Timestamp <= 0 {
		t.Fatalf("extreme float timestamp failed fallback: ev=%+v err=%v", ev, err)
	}

	// 5b. Trailing garbage after valid JSON object must NOT parse as JSON
	ev, err = ParseRawLog(53, []byte(`{"service":"sentinel","msg":"x"} trailing}`), 0, "genesis")
	if err != nil {
		t.Fatalf("trailing JSON fallback errored: %v", err)
	}
	if ev.Service == "sentinel" {
		t.Fatalf("expected JSON with trailing garbage to be rejected as JSON, got %+v", ev)
	}

	// 5c. Oversized invalid UTF-8 continuation bytes must not panic after truncation
	badUTF8 := bytes.Repeat([]byte{0x80}, DefaultMaxLineLength+16)
	if _, err := ParseRawLog(54, badUTF8, DefaultMaxLineLength, "genesis"); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("expected ErrEmptyInput for oversized invalid UTF-8 continuation bytes, got %v", err)
	}

	// 5d. Oversized Pipe record with service=sentinel must NOT be relabeled as plain text
	longTracePipe := []byte("1763996400|sentinel|ERROR|" + strings.Repeat("t", DefaultMaxLineLength+10) + "|msg")
	if _, err := ParseRawLog(55, longTracePipe, DefaultMaxLineLength, "genesis"); !errors.Is(err, ErrOversizedLine) {
		t.Fatalf("expected ErrOversizedLine for oversized pipe header, got %v", err)
	}
	longMsgPipe := []byte("1763996400|sentinel|ERROR|tr-1|" + strings.Repeat("m", DefaultMaxLineLength+100))
	ev, err = ParseRawLog(56, longMsgPipe, DefaultMaxLineLength, "genesis")
	if err != nil || ev.Service != "sentinel" || len(ev.Message) > DefaultMaxLineLength {
		t.Fatalf("expected oversized pipe message to preserve service=sentinel and truncate msg, got ev=%+v err=%v", ev, err)
	}

	// 6. Pipe format
	ev, err = ParseRawLog(6, []byte(`1763996400|nginx|WARN|req-9|GET /etc/passwd 403`), 0, "genesis")
	if err != nil {
		t.Fatalf("Pipe parse failed: %v", err)
	}
	if ev.Service != "nginx" || ev.Level != "WARN" || ev.TraceID != "req-9" || ev.Message != "GET /etc/passwd 403" {
		t.Fatalf("unexpected Pipe LogEvent: %+v", ev)
	}

	// 7. Plain text fallback
	ev, err = ParseRawLog(7, []byte(`FATAL panic: runtime error`), 0, "worker")
	if err != nil {
		t.Fatalf("Plain text parse failed: %v", err)
	}
	if ev.Service != "worker" || ev.Level != "FATAL" {
		t.Fatalf("unexpected plain text LogEvent: %+v", ev)
	}
}

func TestSegReaderRotationResumeBurnReplacementAndCRCRecovery(t *testing.T) {
	segDir := t.TempDir()
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")

	// Reject oversized fixture frames before writing a header
	var discard bytes.Buffer
	if err := WriteSegmentFrame(&discard, make([]byte, MaxFrameBytes+1)); err == nil {
		t.Fatal("expected WriteSegmentFrame to reject payload > MaxFrameBytes")
	}

	// Write 2 valid frames + 1 CRC-damaged frame + 1 valid frame into seg1
	seg1Path := filepath.Join(segDir, "00000001.seg")
	f1, err := os.Create(seg1Path)
	if err != nil {
		t.Fatalf("create seg1: %v", err)
	}
	_ = WriteSegmentFrame(f1, []byte(`{"timestamp":100,"service":"api","level":"INFO","message":"line 1"}`))
	_ = WriteSegmentFrame(f1, []byte(`{"timestamp":101,"service":"api","level":"INFO","message":"line 2"}`))
	// Write a corrupted frame (bad CRC) followed by a valid frame to test bounded forward recovery
	var badBuf bytes.Buffer
	_ = WriteSegmentFrame(&badBuf, []byte(`{"timestamp":101,"service":"api","level":"INFO","message":"corrupt"}`))
	badBytes := badBuf.Bytes()
	badBytes[len(badBytes)-2] ^= 0xff
	_, _ = f1.Write(badBytes)
	_ = WriteSegmentFrame(f1, []byte(`{"timestamp":102,"service":"api","level":"INFO","message":"recovered after crc"}`))
	_ = f1.Close()

	reader, err := NewSegReader(segDir, cursorPath, 0)
	if err != nil {
		t.Fatalf("NewSegReader: %v", err)
	}

	batch, err := reader.ReadBatch(100)
	if err != nil {
		t.Fatalf("ReadBatch 1: %v", err)
	}
	if len(batch) != 3 || batch[0].Message != "line 1" || batch[1].Message != "line 2" || batch[2].Message != "recovered after crc" {
		t.Fatalf("expected 3 recovered frames, got %+v", batch)
	}
	if reader.Stats().CorruptedFrames == 0 {
		t.Fatal("expected CorruptedFrames > 0 after CRC mismatch recovery")
	}
	if err := reader.SaveCursor(); err != nil {
		t.Fatalf("SaveCursor: %v", err)
	}

	// Simulate `genesis burn` where replacement 00000001.seg grows LARGER than saved offset before next poll!
	_ = os.Remove(seg1Path)
	fRepl, err := os.Create(seg1Path)
	if err != nil {
		t.Fatalf("create replacement seg1: %v", err)
	}
	for i := 0; i < 10; i++ {
		_ = WriteSegmentFrame(fRepl, []byte(`{"timestamp":300,"service":"api","level":"INFO","message":"brand-new-replacement-after-burn-padding-to-exceed-old-offset"}`))
	}
	_ = fRepl.Close()

	// Resume from persisted cursor on disk and verify replacement fingerprint triggers burn rewind
	reader2, err := NewSegReader(segDir, cursorPath, 0)
	if err != nil {
		t.Fatalf("NewSegReader resume: %v", err)
	}
	batchRepl, err := reader2.ReadBatch(100)
	if err != nil {
		t.Fatalf("ReadBatch replacement: %v", err)
	}
	if len(batchRepl) != 10 {
		t.Fatalf("expected all 10 replacement frames after burn fingerprint mismatch, got %d", len(batchRepl))
	}
	if reader2.Stats().BurnResets != 1 {
		t.Fatalf("expected BurnResets=1 on same-ID larger replacement file, got %d", reader2.Stats().BurnResets)
	}
}

func TestQueryPollerDeduplicationGapsSaturationBoundsAndConcurrency(t *testing.T) {
	var mu sync.Mutex
	pollNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		pollNum++
		cur := pollNum
		mu.Unlock()

		var logs []model.LogEvent
		switch cur {
		case 1:
			logs = []model.LogEvent{
				{ID: 10, Timestamp: 1000, Service: "api", Level: "INFO", Message: "m10"},
				{ID: 11, Timestamp: 1001, Service: "api", Level: "INFO", Message: "m11"},
			}
		case 2:
			logs = []model.LogEvent{
				{ID: 11, Timestamp: 1001, Service: "api", Level: "INFO", Message: "m11"},
				{ID: 12, Timestamp: 1002, Service: "api", Level: "INFO", Message: "m12"},
			}
		case 3:
			logs = []model.LogEvent{
				{ID: 20, Timestamp: 1010, Service: "api", Level: "ERROR", Message: "m20"},
			}
		}
		_ = json.NewEncoder(w).Encode(genesisQueryResponse{Count: len(logs), Logs: logs})
	}))
	defer srv.Close()

	// Limit=2 triggers SaturatedPages on poll 1 and poll 2 WITHOUT falsely inflating EvictionGaps!
	poller := NewQueryPoller(srv.URL, "tok-123", 2, false)
	ctx := context.Background()

	b1, err := poller.Poll(ctx)
	if err != nil || len(b1) != 2 {
		t.Fatalf("poll 1: len=%d err=%v", len(b1), err)
	}
	b2, err := poller.Poll(ctx)
	if err != nil || len(b2) != 1 || b2[0].ID != 12 {
		t.Fatalf("poll 2 expected deduplicated ID 12, got %+v err=%v", b2, err)
	}
	b3, err := poller.Poll(ctx)
	if err != nil || len(b3) != 1 || b3[0].ID != 20 {
		t.Fatalf("poll 3 expected ID 20, got %+v err=%v", b3, err)
	}

	st := poller.Stats()
	if st.EvictionGaps != 1 || st.EstimatedLost != 7 || st.SaturatedPages != 2 {
		t.Fatalf("expected EvictionGaps=1 EstimatedLost=7 SaturatedPages=2, got %+v", st)
	}

	// Test response byte limit
	poller.SetMaxResponseBytes(10)
	if _, err := poller.Poll(ctx); !errors.Is(err, ErrQueryResponseTooLarge) {
		t.Fatalf("expected ErrQueryResponseTooLarge, got %v", err)
	}

	// Test negative & over-limit synthetic counts do not panic
	evs, _, err := ParseLogEventsFromRaw(-5, 42)
	if err != nil || len(evs) != 0 {
		t.Fatalf("expected empty result for negative count, got len=%d err=%v", len(evs), err)
	}
	if _, _, err := ParseLogEventsFromRaw(MaxSyntheticInMemoryLines+1, 42); err == nil {
		t.Fatal("expected ParseLogEventsFromRaw to reject count > MaxSyntheticInMemoryLines")
	}
}

func TestSegReaderSegmentRotationAndIdenticalPrefixReplacement(t *testing.T) {
	segDir := t.TempDir()
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")

	// 1. Segment rotation: 00000001.seg -> 00000002.seg with cursor save & resume
	seg1 := filepath.Join(segDir, "00000001.seg")
	seg2 := filepath.Join(segDir, "00000002.seg")
	prefixLine := []byte(`{"timestamp":100,"service":"api","level":"INFO","message":"identical-prefix-padding-line-repeated-across-burn-boundary-0123456789012345678901234567890123456789"}`)

	f1, _ := os.Create(seg1)
	_ = WriteSegmentFrame(f1, prefixLine)
	_ = WriteSegmentFrame(f1, []byte(`{"timestamp":101,"service":"api","level":"INFO","message":"seg1-second"}`))
	_ = f1.Close()

	r1, err := NewSegReader(segDir, cursorPath, 0)
	if err != nil {
		t.Fatalf("NewSegReader: %v", err)
	}
	b1, err := r1.ReadBatch(10)
	if err != nil || len(b1) != 2 {
		t.Fatalf("seg1 read: len=%d err=%v", len(b1), err)
	}
	if err := r1.SaveCursor(); err != nil {
		t.Fatalf("SaveCursor seg1: %v", err)
	}

	// Rotate to 00000002.seg and resume from saved cursor
	f2, _ := os.Create(seg2)
	_ = WriteSegmentFrame(f2, []byte(`{"timestamp":102,"service":"sshd","level":"ERROR","message":"seg2-first"}`))
	_ = WriteSegmentFrame(f2, []byte(`{"timestamp":103,"service":"sshd","level":"ERROR","message":"seg2-second"}`))
	_ = f2.Close()

	r2, err := NewSegReader(segDir, cursorPath, 0)
	if err != nil {
		t.Fatalf("NewSegReader seg2: %v", err)
	}
	b2, err := r2.ReadBatch(10)
	if err != nil || len(b2) != 2 || b2[0].Message != "seg2-first" || b2[1].Message != "seg2-second" {
		t.Fatalf("expected exact seg2 delivery without repeat/skip, got %+v err=%v", b2, err)
	}

	// 2. Identical-prefix replacement test on 00000001.seg (create replacement BEFORE unlinking original so inode is guaranteed distinct!)
	if origInfo, statErr := os.Stat(seg1); statErr == nil && fileIdentity(origInfo) != "" {
		segDirB := t.TempDir()
		cursorPathB := filepath.Join(t.TempDir(), "cursorB.json")
		segB := filepath.Join(segDirB, "00000001.seg")
		fb1, _ := os.Create(segB)
		_ = WriteSegmentFrame(fb1, prefixLine)
		_ = WriteSegmentFrame(fb1, prefixLine)
		_ = fb1.Close()

		rb1, _ := NewSegReader(segDirB, cursorPathB, 0)
		if batch, err := rb1.ReadBatch(10); err != nil || len(batch) != 2 {
			t.Fatalf("rb1 read: len=%d err=%v", len(batch), err)
		}
		_ = rb1.SaveCursor()

		// Create replacement at a distinct temp path WHILE original segB still exists, then rename into place
		segBNew := filepath.Join(segDirB, "00000001.seg.new")
		fb2, _ := os.Create(segBNew)
		_ = WriteSegmentFrame(fb2, prefixLine)
		_ = WriteSegmentFrame(fb2, prefixLine)
		_ = WriteSegmentFrame(fb2, []byte(`{"timestamp":200,"service":"api","level":"WARN","message":"after-identical-prefix-replacement"}`))
		_ = fb2.Close()
		if err := os.Rename(segBNew, segB); err != nil {
			t.Fatalf("rename replacement segB: %v", err)
		}

		rb2, _ := NewSegReader(segDirB, cursorPathB, 0)
		batchRepl, err := rb2.ReadBatch(10)
		if err != nil || len(batchRepl) != 3 {
			t.Fatalf("expected identical-prefix replacement to rewind and deliver all 3 frames, got len=%d err=%v", len(batchRepl), err)
		}
		if rb2.Stats().BurnResets != 1 {
			t.Fatalf("expected BurnResets=1 for identical-prefix replacement, got %d", rb2.Stats().BurnResets)
		}
	}
}

func TestQueryPollerGapWithCursorRowPresentAndConcurrency(t *testing.T) {
	gate := make(chan struct{})
	var closeGateOnce sync.Once
	releaseGate := func() { closeGateOnce.Do(func() { close(gate) }) }

	inHandler := make(chan struct{}, 2)
	call := 0
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		call++
		c := call
		mu.Unlock()
		switch c {
		case 1:
			_ = json.NewEncoder(w).Encode(genesisQueryResponse{
				Count: 1,
				Logs:  []model.LogEvent{{ID: 10, Timestamp: 1000, Service: "api", Level: "INFO", Message: "m10"}},
			})
		case 2:
			inHandler <- struct{}{}
			<-gate
			// Page includes already-seen ID 10 plus ID 14 => IDs 11, 12, 13 were lost!
			_ = json.NewEncoder(w).Encode(genesisQueryResponse{
				Count: 2,
				Logs: []model.LogEvent{
					{ID: 10, Timestamp: 1000, Service: "api", Level: "INFO", Message: "m10"},
					{ID: 14, Timestamp: 1004, Service: "api", Level: "ERROR", Message: "m14"},
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(genesisQueryResponse{Count: 0})
		}
	}))
	// Release gate BEFORE srv.Close() so cleanup never hangs even if an assertion fails early.
	defer func() {
		releaseGate()
		srv.Close()
	}()

	poller := NewQueryPoller(srv.URL, "", 100, false)
	if _, err := poller.Poll(context.Background()); err != nil {
		t.Fatalf("poll 1: %v", err)
	}

	pollDone := make(chan error, 1)
	go func() {
		_, err := poller.Poll(context.Background())
		pollDone <- err
	}()

	select {
	case <-inHandler:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for second Poll request to enter handler")
	}

	// Verify canceled caller exits Poll queue promptly without waiting for gate (guarded by watchdog)
	cancelDone := make(chan error, 1)
	go func() {
		cancelCtx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := poller.Poll(cancelCtx)
		cancelDone <- err
	}()
	select {
	case err := <-cancelDone:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected queued canceled Poll to return DeadlineExceeded, got %v", err)
		}
	case <-time.After(2 * time.Second):
		releaseGate()
		t.Fatal("queued canceled Poll blocked instead of honoring context cancellation")
	}

	// Exercise concurrent Stats and SetMaxResponseBytes while Poll is blocked in HTTP handler (with timeout guard)
	statsDone := make(chan struct{})
	go func() {
		_ = poller.Stats()
		poller.SetMaxResponseBytes(DefaultMaxQueryResponseBytes)
		close(statsDone)
	}()
	select {
	case <-statsDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Stats/SetMaxResponseBytes deadlocked while Poll was in flight")
	}

	releaseGate()
	select {
	case err := <-pollDone:
		if err != nil {
			t.Fatalf("second poll failed: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for second Poll to finish after releasing gate")
	}

	st := poller.Stats()
	if st.EvictionGaps != 1 || st.EstimatedLost != 3 {
		t.Fatalf("cursor 10 + page [10, 14]: expected EvictionGaps=1 EstimatedLost=3, got %+v", st)
	}
}

func TestQueryPollerRejectsTrailingGarbageWithoutAdvancingCursor(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"count":1,"logs":[{"id":99,"timestamp":1000,"service":"api","level":"INFO","message":"ok"}]} trailing-garbage`))
	}))
	defer srv.Close()

	poller := NewQueryPoller(srv.URL, "", 100, false)
	if _, err := poller.Poll(context.Background()); err == nil {
		t.Fatal("expected QueryPoller to reject trailing non-whitespace garbage after JSON object")
	}
	if st := poller.Stats(); st.LastID != 0 || st.EventsRead != 0 {
		t.Fatalf("cursor advanced despite malformed response: %+v", st)
	}
}

func TestSegReaderQuietIncompleteCandidateForwardScanAndParseFailureBudget(t *testing.T) {
	// 1. Quiet active segment with a fake incomplete candidate header in the first 256 KiB
	// and a real valid frame beyond 256 KiB must still advance and recover the later frame.
	segDir := t.TempDir()
	seg1 := filepath.Join(segDir, "00000001.seg")
	buf := bytes.Repeat([]byte{0xff}, maxRecoveryScanBytes+4096)
	// Place a fake incomplete candidate header at offset 100 claiming payloadLen = 900000 (> fileSize)
	binary.BigEndian.PutUint32(buf[100:104], 900000)
	binary.BigEndian.PutUint32(buf[104:108], 0xdeadbeef)
	var validFrame bytes.Buffer
	_ = WriteSegmentFrame(&validFrame, []byte(`{"timestamp":500,"service":"api","level":"INFO","message":"beyond-scan-window"}`))
	buf = append(buf, validFrame.Bytes()...)
	if err := os.WriteFile(seg1, buf, 0600); err != nil {
		t.Fatalf("write quiet damaged seg: %v", err)
	}

	r, err := NewSegReader(segDir, filepath.Join(t.TempDir(), "c1.json"), 0)
	if err != nil {
		t.Fatalf("NewSegReader: %v", err)
	}
	b1, err := r.ReadBatch(10)
	if err != nil {
		t.Fatalf("poll 1: %v", err)
	}
	if len(b1) != 0 {
		t.Fatalf("expected 0 events on first bounded scan poll, got %d", len(b1))
	}
	b2, err := r.ReadBatch(10)
	if err != nil {
		t.Fatalf("poll 2: %v", err)
	}
	if len(b2) != 1 || b2[0].Message != "beyond-scan-window" {
		t.Fatalf("expected quiet active segment to advance past fake incomplete candidate and recover frame, got %+v", b2)
	}

	// 2. Active segment with a genuine in-flight frame after corruption recovers once file grows.
	segDir2 := t.TempDir()
	seg2 := filepath.Join(segDir2, "00000001.seg")
	var partialFull bytes.Buffer
	partialFull.Write(bytes.Repeat([]byte{0xff}, 32)) // corrupt prefix
	var targetFrame bytes.Buffer
	_ = WriteSegmentFrame(&targetFrame, []byte(`{"timestamp":600,"service":"sshd","level":"ERROR","message":"inflight-frame-completed"}`))
	fullBytes := append(partialFull.Bytes(), targetFrame.Bytes()...)
	halfCut := 32 + MagicHeaderLen + 10
	if err := os.WriteFile(seg2, fullBytes[:halfCut], 0600); err != nil {
		t.Fatalf("write partial seg2: %v", err)
	}
	r2, _ := NewSegReader(segDir2, filepath.Join(t.TempDir(), "c2.json"), 0)
	if evs, err := r2.ReadBatch(10); err != nil || len(evs) != 0 {
		t.Fatalf("expected 0 events before growth, got len=%d err=%v", len(evs), err)
	}
	// Complete the in-flight frame write
	if err := os.WriteFile(seg2, fullBytes, 0600); err != nil {
		t.Fatalf("complete seg2: %v", err)
	}
	evs, err := r2.ReadBatch(10)
	if err != nil || len(evs) != 1 || evs[0].Message != "inflight-frame-completed" {
		t.Fatalf("expected pending incomplete candidate to recover after file growth, got %+v err=%v", evs, err)
	}

	// 3. Budget must stop after one processed frame even when CRC-valid frames fail ParseRawLog.
	segDir3 := t.TempDir()
	seg3 := filepath.Join(segDir3, "00000001.seg")
	f3, err := os.Create(seg3)
	if err != nil {
		t.Fatalf("create seg3: %v", err)
	}
	for i := 0; i < 10; i++ {
		// Whitespace-only payloads pass CRC32 but fail ParseRawLog with ErrEmptyInput
		_ = WriteSegmentFrame(f3, bytes.Repeat([]byte{' '}, 64))
	}
	_ = f3.Close()

	r3, _ := NewSegReader(segDir3, filepath.Join(t.TempDir(), "c3.json"), 0)
	r3.SetMaxBatchBytes(10) // smaller than one 72-byte frame; only 1 over-budget frame allowed per call
	if _, err := r3.ReadBatch(100); err != nil {
		t.Fatalf("ReadBatch seg3: %v", err)
	}
	if st := r3.Stats(); st.FramesRead != 1 {
		t.Fatalf("expected over-budget exception limited to 1 parse-failing frame per ReadBatch, got FramesRead=%d", st.FramesRead)
	}
}
