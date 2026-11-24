package cli

import (
	"bufio"
	"encoding/json"
	"errors"
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
	Source                   string       `json:"source"`
	ElapsedMs                float64      `json:"elapsed_ms"`
	ThroughputLPS            float64      `json:"throughput_lps"`
	LinesRead                uint64       `json:"lines_read"`
	OversizedLines           uint64       `json:"oversized_lines"`
	TemplatesEmitted         uint64       `json:"templates_emitted"`
	CollapseRatio            float64      `json:"collapse_ratio"`
	AlertsEmitted            uint64       `json:"alerts_emitted"`
	SinkErrors               uint64       `json:"sink_errors"`
	InjectionSignals         uint64       `json:"injection_signals"`
	SurprisalMode            string       `json:"surprisal_mode"`
	SurprisalScored          uint64       `json:"surprisal_scored"`
	SurprisalAnomalies       uint64       `json:"surprisal_anomalies"`
	SurprisalBaselineCases   int          `json:"surprisal_baseline_cases"`
	SurprisalMaxNats         float64      `json:"surprisal_max_nats"`
	TriageMode               string       `json:"triage_mode"`
	TriageEvaluated          uint64       `json:"triage_evaluated"`
	TriageFallbacks          uint64       `json:"triage_fallbacks"`
	TriageInjectionOverrides uint64       `json:"triage_injection_overrides"`
	CorruptedFrames          uint64       `json:"corrupted_frames"`
	HeapBytes                uint64       `json:"heap_bytes"`
	Alerts                   []emit.Alert `json:"alerts"`
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
	baselinePath := fs.String("baseline", "", "Optional path to a saved baseline.json snapshot for Tier 1 surprisal scoring")
	surprisalMode := fs.String("surprisal-mode", "", "Tier 1 surprisal mode: inprocess | http | hybrid")
	surprisalThreshold := fs.Float64("surprisal-threshold", 0, "Tier 1 surprisal anomaly threshold in nats")
	triageMode := fs.String("triage-mode", "", "Tier 2 local LoRA triage mode: off | http")
	inferenceHTTP := fs.String("inference-http", "", "Loopback URL for ml/src/FtaaSService.Inference (:8000)")
	baseModel := fs.String("base-model", "", "Allowlisted Tier 2 base model (default SmolLM2-135M-Instruct)")
	adapterPath := fs.String("adapter-path", "", "Relative LoRA adapter path under ml/data/artifacts/")
	windowEvents := fs.Int("window-events", 0, "Optional event batch size per window flush during offline replay (0 = single flush)")
	asJSON := fs.Bool("json", false, "Emit full ScanReport as JSON")
	emitGenesis := fs.Bool("emit-genesis", false, "Also emit detected alerts to Genesis TCP ingest")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *windowEvents < 0 {
		return fmt.Errorf("invalid --window-events %d: must be >= 0", *windowEvents)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "rules":
			cfg.RulesPath = *rulesPath
		case "surprisal-mode":
			cfg.SurprisalMode = *surprisalMode
		case "surprisal-threshold":
			cfg.SurprisalThreshold = *surprisalThreshold
		case "triage-mode":
			cfg.TriageMode = *triageMode
		case "inference-http":
			cfg.InferenceAddr = *inferenceHTTP
		case "base-model":
			cfg.BaseModel = *baseModel
		case "adapter-path":
			cfg.AdapterPath = *adapterPath
		}
	})
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	if *segDir == "" && *filePath == "" && *syntheticN <= 0 {
		return fmt.Errorf("scan requires one of --seg-dir, --file, or --synthetic <N>")
	}

	if *baselinePath != "" {
		if _, statErr := os.Stat(*baselinePath); statErr != nil {
			return fmt.Errorf("baseline file %q: %w", *baselinePath, statErr)
		}
	}

	ruleEng, err := rules.LoadEngine(cfg.RulesPath)
	if err != nil {
		return err
	}

	var sink emit.Sink = emit.NopSink{}
	if *emitGenesis {
		tcpSink := emit.NewGenesisTCPSink(cfg.GenesisTCPAddr, 2*time.Second)
		defer func() { _ = tcpSink.Close() }()
		sink = tcpSink
	}

	var (
		sourceLabel    string
		pipe           *pipeline.Pipeline
		startTime      time.Time
		alerts         []emit.Alert
		oversizedLines uint64
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
		pipe, alerts, err = scanSegDirectory(cfg, ruleEng, sink, tmpDir, *baselinePath, *windowEvents)
		if err != nil {
			return err
		}

	case *segDir != "":
		sourceLabel = "segdir:" + *segDir
		startTime = time.Now()
		pipe, alerts, err = scanSegDirectory(cfg, ruleEng, sink, *segDir, *baselinePath, *windowEvents)
		if err != nil {
			return err
		}

	case *filePath != "":
		sourceLabel = "file:" + *filePath
		startTime = time.Now()
		pipe, alerts, oversizedLines, err = scanLogFile(cfg, ruleEng, sink, *filePath, *baselinePath, *windowEvents)
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
		Source:                   sourceLabel,
		ElapsedMs:                float64(elapsed.Microseconds()) / 1000.0,
		ThroughputLPS:            lps,
		LinesRead:                st.LinesRead,
		OversizedLines:           oversizedLines,
		TemplatesEmitted:         st.TemplatesEmitted,
		CollapseRatio:            st.CollapseRatio,
		AlertsEmitted:            st.AlertsEmitted,
		SinkErrors:               st.SinkErrors,
		InjectionSignals:         st.InjectionSignals,
		SurprisalMode:            st.SurprisalMode,
		SurprisalScored:          st.SurprisalScored,
		SurprisalAnomalies:       st.SurprisalAnomalies,
		SurprisalBaselineCases:   st.SurprisalBaselineCases,
		SurprisalMaxNats:         st.SurprisalMaxNats,
		TriageMode:               st.TriageMode,
		TriageEvaluated:          st.TriageEvaluated,
		TriageFallbacks:          st.TriageFallbacks,
		TriageInjectionOverrides: st.TriageInjectionOverrides,
		CorruptedFrames:          st.CorruptedFrames,
		HeapBytes:                st.HeapBytes,
		Alerts:                   alerts,
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	writef := func(format string, a ...any) error {
		_, wErr := fmt.Fprintf(stdout, format, a...)
		return wErr
	}
	for _, fn := range []func() error{
		func() error { return writef("Genesis Sentinel Scan Complete\n") },
		func() error { return writef("  Source          : %s\n", report.Source) },
		func() error {
			return writef("  Lines Read      : %d (oversized skipped: %d)\n", report.LinesRead, report.OversizedLines)
		},
		func() error {
			return writef("  Templates       : %d (collapse ratio: %.1fx)\n", report.TemplatesEmitted, report.CollapseRatio)
		},
		func() error {
			return writef("  Tier 1 Surprisal: mode=%s scored=%d anomalies=%d max=%.2fnats baseline=%d\n",
				report.SurprisalMode, report.SurprisalScored, report.SurprisalAnomalies, report.SurprisalMaxNats, report.SurprisalBaselineCases)
		},
		func() error {
			return writef("  Tier 2 Triage   : mode=%s evaluated=%d fallbacks=%d injection_overrides=%d\n",
				report.TriageMode, report.TriageEvaluated, report.TriageFallbacks, report.TriageInjectionOverrides)
		},
		func() error {
			return writef("  Elapsed         : %.2f ms (%.0f lines/sec)\n", report.ElapsedMs, report.ThroughputLPS)
		},
		func() error {
			return writef("  Heap Alloc      : %.2f MB\n", float64(report.HeapBytes)/(1024*1024))
		},
		func() error {
			return writef("  Alerts Emitted  : %d (sink errors: %d, prompt-injection signals: %d)\n", report.AlertsEmitted, report.SinkErrors, report.InjectionSignals)
		},
	} {
		if wErr := fn(); wErr != nil {
			return fmt.Errorf("write scan report: %w", wErr)
		}
	}
	if len(alerts) > 0 {
		if wErr := writef("\nAlerts:\n"); wErr != nil {
			return fmt.Errorf("write scan report: %w", wErr)
		}
		for _, a := range alerts {
			if wErr := writef("  [%s] %s\n", a.Severity, a.Message); wErr != nil {
				return fmt.Errorf("write scan report: %w", wErr)
			}
		}
	}
	return nil
}

func scanSegDirectory(cfg *config.Config, ruleEng *rules.Engine, sink emit.Sink, segDir, baselinePath string, windowEvents int) (*pipeline.Pipeline, []emit.Alert, error) {
	reader, err := ingest.NewSegReader(segDir, "", 0)
	if err != nil {
		return nil, nil, err
	}
	pipe := pipeline.New(cfg, ruleEng, sink, "segdir")
	pipe.AttachSegReader(reader)
	if baselinePath != "" {
		if _, loadErr := pipe.SurprisalEngine().LoadFromFile(baselinePath); loadErr != nil {
			return nil, nil, fmt.Errorf("load baseline %q: %w", baselinePath, loadErr)
		}
	}

	var (
		allAlerts []emit.Alert
		inWindow  int
	)
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
			if windowEvents > 0 {
				inWindow++
				if inWindow >= windowEvents {
					emitted, _ := pipe.FlushWindow()
					allAlerts = append(allAlerts, emitted...)
					inWindow = 0
				}
			}
		}
	}
	emitted, _ := pipe.FlushWindow()
	allAlerts = append(allAlerts, emitted...)
	return pipe, allAlerts, nil
}

// scanLogFile streams lines with a bounded bufio.Reader so an adversarial >1 MiB
// line is drained through its newline, counted as oversized, and never aborts
// scanning of subsequent valid records.
func scanLogFile(cfg *config.Config, ruleEng *rules.Engine, sink emit.Sink, path, baselinePath string, windowEvents int) (*pipeline.Pipeline, []emit.Alert, uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open log file %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	pipe := pipeline.New(cfg, ruleEng, sink, "file")
	if baselinePath != "" {
		if _, loadErr := pipe.SurprisalEngine().LoadFromFile(baselinePath); loadErr != nil {
			return nil, nil, 0, fmt.Errorf("load baseline %q: %w", baselinePath, loadErr)
		}
	}
	reader := bufio.NewReaderSize(f, 64*1024)
	defaultSvc := filepath.Base(path)

	var (
		id        uint64
		oversized uint64
		acc       []byte
		skipping  bool
		allAlerts []emit.Alert
		inWindow  int
	)

	// Allow up to MaxFrameBytes of payload plus up to 2 bytes for CRLF line ending.
	const maxRawLineWithCRLF = ingest.MaxFrameBytes + 2

	for {
		chunk, readErr := reader.ReadSlice('\n')
		if errors.Is(readErr, bufio.ErrBufferFull) {
			if !skipping {
				if len(acc)+len(chunk) > maxRawLineWithCRLF {
					skipping = true
					acc = acc[:0]
					oversized++
				} else {
					acc = append(acc, chunk...)
				}
			}
			continue
		}

		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return nil, nil, oversized, fmt.Errorf("read log file %q: %w", path, readErr)
		}

		if skipping {
			// Reached terminating newline (or EOF) of the oversized line; resume on next line.
			skipping = false
			acc = acc[:0]
			if errors.Is(readErr, io.EOF) {
				break
			}
			continue
		}

		var line []byte
		if len(acc) > 0 {
			if len(acc)+len(chunk) > maxRawLineWithCRLF {
				oversized++
				acc = acc[:0]
				if errors.Is(readErr, io.EOF) {
					break
				}
				continue
			}
			acc = append(acc, chunk...)
			line = acc
		} else {
			line = chunk
		}

		// Strip trailing LF / CRLF before enforcing MaxFrameBytes on payload bytes.
		payload := trimLineEnding(line)
		if len(payload) > ingest.MaxFrameBytes {
			oversized++
		} else if len(payload) > 0 {
			id++
			ev, parseErr := ingest.ParseRawLog(id, payload, 0, defaultSvc)
			if parseErr == nil {
				pipe.IngestEvent(ev)
				if windowEvents > 0 {
					inWindow++
					if inWindow >= windowEvents {
						emitted, _ := pipe.FlushWindow()
						allAlerts = append(allAlerts, emitted...)
						inWindow = 0
					}
				}
			} else if errors.Is(parseErr, ingest.ErrOversizedLine) {
				oversized++
			}
		}
		acc = acc[:0]

		if errors.Is(readErr, io.EOF) {
			break
		}
	}

	emitted, _ := pipe.FlushWindow()
	allAlerts = append(allAlerts, emitted...)
	return pipe, allAlerts, oversized, nil
}

func trimLineEnding(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1] == '\r' {
		b = b[:len(b)-1]
	}
	return b
}
