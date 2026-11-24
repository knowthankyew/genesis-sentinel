package pipeline

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/ingest"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
)

func TestPipelineEndToEnd100kSyntheticSegmentReplay(t *testing.T) {
	segDir := t.TempDir()
	dataDir := t.TempDir()

	// Write 100,000 synthetic mixed Track A logs into Genesis CRC32 .seg file(s)
	segPath := filepath.Join(segDir, "00000001.seg")
	f, err := os.Create(segPath)
	if err != nil {
		t.Fatalf("create synthetic seg: %v", err)
	}
	const totalLines = 100_000
	summary, err := ingest.GenerateSyntheticCorpus(totalLines, 42, func(raw []byte) error {
		return ingest.WriteSegmentFrame(f, raw)
	})
	_ = f.Close()
	if err != nil {
		t.Fatalf("generate synthetic corpus: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.GenesisDataDir = segDir

	ruleEng, err := rules.NewEngine(rules.DefaultRulePack())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	var alertBuf bytes.Buffer
	sink := emit.NewWriterSink(&alertBuf)

	reader, err := ingest.NewSegReader(segDir, filepath.Join(dataDir, "cursor.json"), 0)
	if err != nil {
		t.Fatalf("NewSegReader: %v", err)
	}

	pipe := New(cfg, ruleEng, sink, "segdir")
	pipe.AttachSegReader(reader)

	// Also verify loop prevention by injecting self-alerts directly
	pipe.IngestEvent(model.LogEvent{ID: 999999, Service: "sentinel", Level: "ERROR", Message: "UNION SELECT self alert"})

	for {
		batch, readErr := reader.ReadBatch(8192)
		if readErr != nil {
			t.Fatalf("ReadBatch: %v", readErr)
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			pipe.IngestEvent(ev)
		}
	}
	if err := reader.SaveCursor(); err != nil {
		t.Fatalf("SaveCursor: %v", err)
	}

	alerts := pipe.FlushWindow()
	st := pipe.Stats()

	if st.LinesRead != totalLines {
		t.Fatalf("LinesRead = %d, want %d", st.LinesRead, totalLines)
	}
	if st.LinesIgnoredSelf != 1 {
		t.Fatalf("LinesIgnoredSelf = %d, want 1", st.LinesIgnoredSelf)
	}
	if st.CollapseRatio < 1000 {
		t.Fatalf("expected huge collapse ratio (>1000x) on 100k logs, got %.2fx (%d templates)", st.CollapseRatio, st.TemplatesEmitted)
	}

	// Verify every injected synthetic threat class fired an alert!
	foundRules := make(map[string]bool)
	for _, a := range alerts {
		for _, rid := range a.RuleIDs {
			foundRules[rid] = true
		}
	}
	for _, want := range []string{"SENT-001", "SENT-002", "SENT-003", "SENT-004", "SENT-005", "SENT-006"} {
		if !foundRules[want] {
			t.Errorf("expected rule %s to fire on synthetic replay (summary=%+v), got rules=%v", want, summary, foundRules)
		}
	}
	if st.InjectionSignals < 1 {
		t.Fatalf("expected at least 1 prompt-injection signal detected, got %d", st.InjectionSignals)
	}

	// Regression check: emitted JSON must never contain unsanitized LLM control delimiters
	// or 16-digit float mantissas that collide with Genesis --redact's card pattern.
	genesisCardPattern := regexp.MustCompile(`\b(?:\d{4}[ -]?){3}\d{4}\b`)
	emittedJSON := alertBuf.String()
	if strings.Contains(emittedJSON, "<|im_") {
		t.Fatalf("unsanitized control token leaked into emitted alert JSON: %s", emittedJSON)
	}
	if match := genesisCardPattern.FindString(emittedJSON); match != "" {
		t.Fatalf("emitted alert JSON contains 16-digit sequence %q that breaks Genesis --redact JSON parsing", match)
	}

	// Verify Burn wipes persisted cursor.json cleanly
	rep, err := pipe.Burn()
	if err != nil {
		t.Fatalf("Burn failed: %v", err)
	}
	if rep.FilesRemoved < 1 {
		t.Fatalf("expected Burn to remove cursor.json, got %+v", rep)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "cursor.json")); !os.IsNotExist(err) {
		t.Fatalf("expected cursor.json to be deleted after burn")
	}
}
