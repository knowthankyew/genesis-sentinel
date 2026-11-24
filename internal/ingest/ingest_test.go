package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

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
	ev, err = ParseRawLog(52, []byte(`<36>Nov 24 10:00:00 host1 cronjob completed ok`), 0, "genesis")
	if err != nil || ev.Service != "cronjob" || ev.Message != "completed ok" {
		t.Fatalf("RFC 3164 space-delimited tag failed: ev=%+v err=%v", ev, err)
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

	// Test negative synthetic count doesn't panic
	evs, _, err := ParseLogEventsFromRaw(-5, 42)
	if err != nil || len(evs) != 0 {
		t.Fatalf("expected empty result for negative count, got len=%d err=%v", len(evs), err)
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

	// 2. Identical-prefix replacement test on 00000001.seg (same prefix >= 256 bytes, larger size, new inode!)
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

	// Unlink and recreate 00000001.seg with IDENTICAL first 2 frames (>=256 bytes) + 1 new third frame
	_ = os.Remove(segB)
	fb2, _ := os.Create(segB)
	_ = WriteSegmentFrame(fb2, prefixLine)
	_ = WriteSegmentFrame(fb2, prefixLine)
	_ = WriteSegmentFrame(fb2, []byte(`{"timestamp":200,"service":"api","level":"WARN","message":"after-identical-prefix-replacement"}`))
	_ = fb2.Close()

	rb2, _ := NewSegReader(segDirB, cursorPathB, 0)
	batchRepl, err := rb2.ReadBatch(10)
	if err != nil || len(batchRepl) != 3 {
		t.Fatalf("expected identical-prefix replacement to rewind and deliver all 3 frames, got len=%d err=%v", len(batchRepl), err)
	}
	if rb2.Stats().BurnResets != 1 {
		t.Fatalf("expected BurnResets=1 for identical-prefix replacement, got %d", rb2.Stats().BurnResets)
	}
}

func TestQueryPollerGapWithCursorRowPresentAndConcurrency(t *testing.T) {
	gate := make(chan struct{})
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
	defer srv.Close()

	poller := NewQueryPoller(srv.URL, "", 100, false)
	if _, err := poller.Poll(context.Background()); err != nil {
		t.Fatalf("poll 1: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = poller.Poll(context.Background())
	}()

	<-inHandler
	// Exercise concurrent Stats and SetMaxResponseBytes while Poll is blocked in HTTP handler
	_ = poller.Stats()
	poller.SetMaxResponseBytes(DefaultMaxQueryResponseBytes)
	close(gate)
	wg.Wait()

	st := poller.Stats()
	if st.EvictionGaps != 1 || st.EstimatedLost != 3 {
		t.Fatalf("cursor 10 + page [10, 14]: expected EvictionGaps=1 EstimatedLost=3, got %+v", st)
	}
}
