package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/ingest"
	"github.com/knowthankyew/genesis-sentinel/internal/pipeline"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
)

// ScanReport is the machine-readable summary produced by `sentinel scan`.
type ScanReport struct {
	Source           string       `json:"source"`
	ElapsedMs        float64      `json:"elapsed_ms"`
	ThroughputLPS    float64      `json:"throughput_lps"`
	LinesRead        uint64       `json:"lines_read"`
	TemplatesEmitted uint64       `json:"templates_emitted"`
	CollapseRatio    float64      `json:"collapse_ratio"`
	AlertsEmitted    uint64       `json:"alerts_emitted"`
	InjectionSignals uint64       `json:"injection_signals"`
	CorruptedFrames  uint64       `json:"corrupted_frames"`
	HeapBytes        uint64       `json:"heap_bytes"`
	Alerts           []emit.Alert `json:"alerts"`
}

func runScan(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	segDir := fs.String("seg-dir", "", "Directory of Genesis .seg files to scan")
	filePath := fs.String("file", "", "Raw log or JSONL file to scan")
	syntheticN := fs.Int("synthetic", 0, "Generate and replay N Track A synthetic logs through CRC32 .seg files")
	seed := fs.Uint64("seed", 42, "Deterministic PRNG seed for --synthetic replay")
	rulesPath := fs.String("rules", "", "Optional path to custom JSON rules.json pack")
	asJSON := fs.Bool("json", false, "Emit full ScanReport as JSON")
	emitGenesis := fs.Bool("emit-genesis", false, "Also emit detected alerts to Genesis TCP ingest")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *rulesPath != "" {
		cfg.RulesPath = *rulesPath
	}

	if *segDir == "" && *filePath == "" && *syntheticN <= 0 {
		return fmt.Errorf("scan requires one of --seg-dir, --file, or --synthetic <N>")
	}

	ruleEng, err := rules.LoadEngine(cfg.RulesPath)
	if err != nil {
		return err
	}

	var sink emit.Sink = emit.NopSink{}
	if *emitGenesis {
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("config validation failed for --emit-genesis: %w", err)
		}
		tcpSink := emit.NewGenesisTCPSink(cfg.GenesisTCPAddr, 2*time.Second)
		defer func() { _ = tcpSink.Close() }()
		sink = tcpSink
	}

	var (
		sourceLabel string
		pipe        *pipeline.Pipeline
		startTime   time.Time
		alerts      []emit.Alert
	)

	switch {
	case *syntheticN > 0:
		tmpDir, mkErr := os.MkdirTemp("", "sentinel-synthetic-*")
		if mkErr != nil {
			return fmt.Errorf("create temp synthetic dir: %w", mkErr)
		}
		defer func() { _ = os.RemoveAll(tmpDir) }()

		segFile := filepath.Join(tmpDir, "00000001.seg")
		f, createErr := os.Create(segFile)
		if createErr != nil {
			return createErr
		}
		if _, genErr := ingest.GenerateSyntheticCorpus(*syntheticN, *seed, func(raw []byte) error {
			return ingest.WriteSegmentFrame(f, raw)
		}); genErr != nil {
			_ = f.Close()
			return genErr
		}
		if closeErr := f.Close(); closeErr != nil {
			return closeErr
		}

		sourceLabel = fmt.Sprintf("synthetic-seg (%d lines, seed=%d)", *syntheticN, *seed)
		startTime = time.Now()
		pipe, alerts, err = scanSegDirectory(cfg, ruleEng, sink, tmpDir)
		if err != nil {
			return err
		}

	case *segDir != "":
		sourceLabel = "segdir:" + *segDir
		startTime = time.Now()
		pipe, alerts, err = scanSegDirectory(cfg, ruleEng, sink, *segDir)
		if err != nil {
			return err
		}

	case *filePath != "":
		sourceLabel = "file:" + *filePath
		startTime = time.Now()
		pipe, alerts, err = scanLogFile(cfg, ruleEng, sink, *filePath)
		if err != nil {
			return err
		}
	}

	elapsed := time.Since(startTime)
	st := pipe.Stats()
	elapsedSec := elapsed.Seconds()
	var lps float64
	if elapsedSec > 0 {
		lps = float64(st.LinesRead) / elapsedSec
	}

	report := ScanReport{
		Source:           sourceLabel,
		ElapsedMs:        float64(elapsed.Microseconds()) / 1000.0,
		ThroughputLPS:    lps,
		LinesRead:        st.LinesRead,
		TemplatesEmitted: st.TemplatesEmitted,
		CollapseRatio:    st.CollapseRatio,
		AlertsEmitted:    st.AlertsEmitted,
		InjectionSignals: st.InjectionSignals,
		CorruptedFrames:  st.CorruptedFrames,
		HeapBytes:        st.HeapBytes,
		Alerts:           alerts,
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	_, _ = fmt.Fprintf(stdout, "Genesis Sentinel Scan Complete\n")
	_, _ = fmt.Fprintf(stdout, "  Source          : %s\n", report.Source)
	_, _ = fmt.Fprintf(stdout, "  Lines Read      : %d\n", report.LinesRead)
	_, _ = fmt.Fprintf(stdout, "  Templates       : %d (collapse ratio: %.1fx)\n", report.TemplatesEmitted, report.CollapseRatio)
	_, _ = fmt.Fprintf(stdout, "  Elapsed         : %.2f ms (%.0f lines/sec)\n", report.ElapsedMs, report.ThroughputLPS)
	_, _ = fmt.Fprintf(stdout, "  Heap Alloc      : %.2f MB\n", float64(report.HeapBytes)/(1024*1024))
	_, _ = fmt.Fprintf(stdout, "  Alerts Emitted  : %d (prompt-injection signals: %d)\n", report.AlertsEmitted, report.InjectionSignals)
	if len(alerts) > 0 {
		_, _ = fmt.Fprintf(stdout, "\nAlerts:\n")
		for _, a := range alerts {
			_, _ = fmt.Fprintf(stdout, "  [%s] %s\n", a.Severity, a.Message)
		}
	}
	return nil
}

func scanSegDirectory(cfg *config.Config, ruleEng *rules.Engine, sink emit.Sink, segDir string) (*pipeline.Pipeline, []emit.Alert, error) {
	reader, err := ingest.NewSegReader(segDir, "", 0)
	if err != nil {
		return nil, nil, err
	}
	pipe := pipeline.New(cfg, ruleEng, sink, "segdir")
	pipe.AttachSegReader(reader)

	for {
		batch, readErr := reader.ReadBatch(8192)
		if readErr != nil {
			return nil, nil, readErr
		}
		if len(batch) == 0 {
			break
		}
		for _, ev := range batch {
			pipe.IngestEvent(ev)
		}
	}
	alerts := pipe.FlushWindow()
	return pipe, alerts, nil
}

func scanLogFile(cfg *config.Config, ruleEng *rules.Engine, sink emit.Sink, path string) (*pipeline.Pipeline, []emit.Alert, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open log file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	pipe := pipeline.New(cfg, ruleEng, sink, "file")
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	var id uint64
	for scanner.Scan() {
		id++
		ev, parseErr := ingest.ParseRawLog(id, scanner.Bytes(), 0, filepath.Base(path))
		if parseErr != nil {
			continue
		}
		pipe.IngestEvent(ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("scan log file %q: %w", path, err)
	}

	alerts := pipe.FlushWindow()
	return pipe, alerts, nil
}
