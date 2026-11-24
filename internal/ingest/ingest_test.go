package ingest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestParseRawLogAllFormats(t *testing.T) {
	// 1. JSON Lines
	ev, err := ParseRawLog(1, []byte(`{"timestamp":1763996400,"service":"api","level":"err","trace_id":"tr-1","msg":"db timeout","host":"node1"}`), 0, "genesis")
	if err != nil {
		t.Fatalf("JSON parse failed: %v", err)
	}
	if ev.Service != "api" || ev.Level != "ERROR" || ev.TraceID != "tr-1" || ev.Message != "db timeout" || ev.Attributes["host"] != "node1" {
		t.Fatalf("unexpected JSON LogEvent: %+v", ev)
	}

	// 2. Syslog RFC 5424 (<35> => facility 4, severity 3 => ERROR)
	ev, err = ParseRawLog(2, []byte(`<35>1 2026-11-24T10:00:00Z host1 sshd 1234 msg42 - Failed password for root`), 0, "genesis")
	if err != nil {
		t.Fatalf("RFC 5424 parse failed: %v", err)
	}
	if ev.Service != "sshd" || ev.Level != "ERROR" || ev.TraceID != "msg42" || ev.Message != "Failed password for root" {
		t.Fatalf("unexpected RFC 5424 LogEvent: %+v", ev)
	}

	// 3. Syslog RFC 3164 (<36> => severity 4 => WARN)
	ev, err = ParseRawLog(3, []byte(`<36>Nov 24 10:00:00 macbook sudo[991]: user dev : command not allowed`), 0, "genesis")
	if err != nil {
		t.Fatalf("RFC 3164 parse failed: %v", err)
	}
	if ev.Service != "sudo" || ev.Level != "WARN" || ev.Message != "user dev : command not allowed" {
		t.Fatalf("unexpected RFC 3164 LogEvent: %+v", ev)
	}

	// 4. Pipe format
	ev, err = ParseRawLog(4, []byte(`1763996400|nginx|WARN|req-9|GET /etc/passwd 403`), 0, "genesis")
	if err != nil {
		t.Fatalf("Pipe parse failed: %v", err)
	}
	if ev.Service != "nginx" || ev.Level != "WARN" || ev.TraceID != "req-9" || ev.Message != "GET /etc/passwd 403" {
		t.Fatalf("unexpected Pipe LogEvent: %+v", ev)
	}

	// 5. Plain text fallback
	ev, err = ParseRawLog(5, []byte(`FATAL panic: runtime error`), 0, "worker")
	if err != nil {
		t.Fatalf("Plain text parse failed: %v", err)
	}
	if ev.Service != "worker" || ev.Level != "FATAL" {
		t.Fatalf("unexpected plain text LogEvent: %+v", ev)
	}
}

func TestSegReaderRotationResumePartialAndBurn(t *testing.T) {
	segDir := t.TempDir()
	cursorPath := filepath.Join(t.TempDir(), "cursor.json")

	// Write 2 frames into segment 1
	seg1Path := filepath.Join(segDir, "00000001.seg")
	f1, err := os.Create(seg1Path)
	if err != nil {
		t.Fatalf("create seg1: %v", err)
	}
	_ = WriteSegmentFrame(f1, []byte(`{"timestamp":100,"service":"api","level":"INFO","message":"line 1"}`))
	_ = WriteSegmentFrame(f1, []byte(`{"timestamp":101,"service":"api","level":"INFO","message":"line 2"}`))
	// Append a partial 5-byte truncated header at tail of active segment
	_, _ = f1.Write([]byte{0x00, 0x00, 0x00, 0x10, 0xde})
	_ = f1.Close()

	reader, err := NewSegReader(segDir, cursorPath, 0)
	if err != nil {
		t.Fatalf("NewSegReader: %v", err)
	}

	// Should read the 2 valid frames and pause safely at the partial header
	batch, err := reader.ReadBatch(100)
	if err != nil {
		t.Fatalf("ReadBatch 1: %v", err)
	}
	if len(batch) != 2 || batch[0].Message != "line 1" || batch[1].Message != "line 2" {
		t.Fatalf("unexpected batch 1: %+v", batch)
	}
	if err := reader.SaveCursor(); err != nil {
		t.Fatalf("SaveCursor: %v", err)
	}

	// Simulate segment rotation to 00000002.seg (seg1 is now closed with its torn tail)
	seg2Path := filepath.Join(segDir, "00000002.seg")
	f2, err := os.Create(seg2Path)
	if err != nil {
		t.Fatalf("create seg2: %v", err)
	}
	_ = WriteSegmentFrame(f2, []byte(`{"timestamp":102,"service":"sshd","level":"ERROR","message":"line 3"}`))
	_ = f2.Close()

	// Create a fresh reader resuming from saved cursor on disk
	reader2, err := NewSegReader(segDir, cursorPath, 0)
	if err != nil {
		t.Fatalf("NewSegReader resume: %v", err)
	}
	batch2, err := reader2.ReadBatch(100)
	if err != nil {
		t.Fatalf("ReadBatch 2: %v", err)
	}
	if len(batch2) != 1 || batch2[0].Message != "line 3" || batch2[0].Service != "sshd" {
		t.Fatalf("unexpected batch 2 after rotation/resume: %+v", batch2)
	}
	st := reader2.Stats()
	if st.CorruptedFrames != 1 {
		t.Fatalf("expected 1 corrupted trailing stub counted on closed seg1, got %d", st.CorruptedFrames)
	}

	// Simulate `genesis burn`: remove all segments and recreate empty 00000001.seg with fresh data
	_ = os.Remove(seg1Path)
	_ = os.Remove(seg2Path)
	fBurn, err := os.Create(seg1Path)
	if err != nil {
		t.Fatalf("recreate seg1 after burn: %v", err)
	}
	_ = WriteSegmentFrame(fBurn, []byte(`{"timestamp":200,"service":"api","level":"INFO","message":"post-burn"}`))
	_ = fBurn.Close()

	batch3, err := reader2.ReadBatch(100)
	if err != nil {
		t.Fatalf("ReadBatch 3 after burn: %v", err)
	}
	if len(batch3) != 1 || batch3[0].Message != "post-burn" {
		t.Fatalf("unexpected post-burn batch: %+v", batch3)
	}
	if reader2.Stats().BurnResets != 1 {
		t.Fatalf("expected BurnResets=1, got %d", reader2.Stats().BurnResets)
	}
}

func TestQueryPollerDeduplicationAndEvictionGapDetection(t *testing.T) {
	pollNum := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		pollNum++
		var logs []model.LogEvent
		switch pollNum {
		case 1:
			logs = []model.LogEvent{
				{ID: 10, Timestamp: 1000, Service: "api", Level: "INFO", Message: "m10"},
				{ID: 11, Timestamp: 1001, Service: "api", Level: "INFO", Message: "m11"},
			}
		case 2:
			// Overlapping ID 11 (deduplicated) + contiguous ID 12
			logs = []model.LogEvent{
				{ID: 11, Timestamp: 1001, Service: "api", Level: "INFO", Message: "m11"},
				{ID: 12, Timestamp: 1002, Service: "api", Level: "INFO", Message: "m12"},
			}
		case 3:
			// Gap: IDs 13..19 were evicted before poll 3!
			logs = []model.LogEvent{
				{ID: 20, Timestamp: 1010, Service: "api", Level: "ERROR", Message: "m20"},
			}
		}
		_ = json.NewEncoder(w).Encode(genesisQueryResponse{Count: len(logs), Logs: logs})
	}))
	defer srv.Close()

	poller := NewQueryPoller(srv.URL, "tok-123", 100)
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
	if st.EvictionGaps != 1 || st.EstimatedLost != 7 {
		t.Fatalf("expected EvictionGaps=1 EstimatedLost=7, got %+v", st)
	}
}
