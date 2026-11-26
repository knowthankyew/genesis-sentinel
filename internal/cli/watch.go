package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/ingest"
	"github.com/knowthankyew/genesis-sentinel/internal/pipeline"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/train"
)

func runWatch(args []string, stdout, stderr io.Writer) error {
	// Parse CLI flags once so repeated flags (e.g. --config=/missing --config=)
	// honor standard flag-parser last-value-wins semantics, then apply only explicitly
	// supplied flag overrides on top of LoadConfig(configPath).
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		configPath              string
		genesisDataDir          string
		genesisHTTP             string
		genesisTCP              string
		httpAddr                string
		dataDir                 string
		windowStr               string
		rulesPath               string
		surprisalMode           string
		surprisalHTTP           string
		surprisalThreshold      float64
		baselineSize            int
		triageMode              string
		inferenceHTTP           string
		baseModel               string
		adapterPath             string
		triageTimeout           int
		escalationMode          string
		escalationInferenceHTTP string
		escalationBaseModel     string
		escalationAdapterPath   string
		escalationPolicy        string
		escalationTimeout       int
		autoReloadAdapter       bool
		pollInterval            time.Duration
		dryRun                  bool
		stdoutAlerts            bool
	)

	fs.StringVar(&configPath, "config", "", "Path to sentinel.json config file")
	fs.StringVar(&genesisDataDir, "genesis-data-dir", "", "Genesis --data-dir path for lossless .seg tailing (primary)")
	fs.StringVar(&genesisHTTP, "genesis-http", "", "Genesis HTTP base URL for /query fallback")
	fs.StringVar(&genesisTCP, "genesis-tcp", "", "Genesis TCP ingest address for alert emission")
	fs.StringVar(&httpAddr, "http", "", "Sentinel HTTP stats/health/burn listen address")
	fs.StringVar(&dataDir, "data-dir", "", "Sentinel local state directory (cursors, baselines, feedback)")
	fs.StringVar(&windowStr, "window", "", "Tier 0 template collapse flush window (e.g. 10s)")
	fs.StringVar(&rulesPath, "rules", "", "Optional path to custom JSON rules.json pack")
	fs.StringVar(&surprisalMode, "surprisal-mode", "", "Tier 1 surprisal mode: inprocess | http | hybrid")
	fs.StringVar(&surprisalHTTP, "surprisal-http", "", "Loopback URL for ml/src/surprisal-service (:5200)")
	fs.Float64Var(&surprisalThreshold, "surprisal-threshold", 0, "Tier 1 surprisal anomaly threshold in nats (default 5.0)")
	fs.IntVar(&baselineSize, "baseline-size", 0, "Tier 1 rolling baseline capacity (default 2000)")
	fs.StringVar(&triageMode, "triage-mode", "", "Tier 2 local LoRA triage mode: off | http")
	fs.StringVar(&inferenceHTTP, "inference-http", "", "Loopback URL for ml/src/FtaaSService.Inference (:8000)")
	fs.StringVar(&baseModel, "base-model", "", "Allowlisted Tier 2 base model (default SmolLM2-135M-Instruct)")
	fs.StringVar(&adapterPath, "adapter-path", "", "Relative LoRA adapter path under ml/data/artifacts/")
	fs.IntVar(&triageTimeout, "triage-timeout", 0, "Tier 2 flush-wide inference budget in seconds (5-300, default 45)")
	fs.StringVar(&escalationMode, "escalation-mode", "", "Phase 5 escalation inference mode: off | http")
	fs.StringVar(&escalationInferenceHTTP, "escalation-inference-http", "", "Loopback URL for Gemma 2 2B IT escalation inference (:8001)")
	fs.StringVar(&escalationBaseModel, "escalation-base-model", "", "Allowlisted escalation base model (default google/gemma-2-2b-it)")
	fs.StringVar(&escalationAdapterPath, "escalation-adapter-path", "", "Relative LoRA adapter path for escalation slot")
	fs.StringVar(&escalationPolicy, "escalation-policy", "", "Escalation policy: high_critical | strict | always")
	fs.IntVar(&escalationTimeout, "escalation-timeout", 0, "Escalation flush-wide inference budget in seconds (5-300, default 90)")
	fs.BoolVar(&autoReloadAdapter, "auto-reload-adapter", true, "Automatically hot-reload active-adapter.json changes on disk during watch")
	fs.DurationVar(&pollInterval, "poll-interval", 250*time.Millisecond, "Polling interval for new .seg frames or /query windows")
	fs.BoolVar(&dryRun, "dry-run", false, "Print alerts to stdout instead of emitting to Genesis TCP")
	fs.BoolVar(&stdoutAlerts, "stdout-alerts", false, "Mirror emitted alerts to stdout in addition to Genesis TCP")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if pollInterval <= 0 {
		return fmt.Errorf("invalid -poll-interval %v: must be positive", pollInterval)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	adapterPathExplicit := false
	baseModelExplicit := false
	escalationAdapterExplicit := false
	escalationModelExplicit := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "genesis-data-dir":
			cfg.GenesisDataDir = genesisDataDir
		case "genesis-http":
			cfg.GenesisHTTPAddr = genesisHTTP
		case "genesis-tcp":
			cfg.GenesisTCPAddr = genesisTCP
		case "http":
			cfg.HTTPAddr = httpAddr
		case "data-dir":
			cfg.DataDir = dataDir
		case "window":
			cfg.WindowStr = windowStr
		case "rules":
			cfg.RulesPath = rulesPath
		case "surprisal-mode":
			cfg.SurprisalMode = surprisalMode
		case "surprisal-http":
			cfg.SurprisalHTTPAddr = surprisalHTTP
		case "surprisal-threshold":
			cfg.SurprisalThreshold = surprisalThreshold
		case "baseline-size":
			cfg.BaselineWindowSize = baselineSize
		case "triage-mode":
			cfg.TriageMode = triageMode
		case "inference-http":
			cfg.InferenceAddr = inferenceHTTP
		case "base-model":
			cfg.BaseModel = baseModel
			baseModelExplicit = true
		case "adapter-path":
			cfg.AdapterPath = adapterPath
			adapterPathExplicit = true
		case "triage-timeout":
			if triageTimeout > 0 {
				cfg.TriageTimeoutSec = triageTimeout
			}
		case "escalation-mode":
			cfg.EscalationMode = escalationMode
		case "escalation-inference-http":
			cfg.EscalationInferenceAddr = escalationInferenceHTTP
		case "escalation-base-model":
			cfg.EscalationBaseModel = escalationBaseModel
			escalationModelExplicit = true
		case "escalation-adapter-path":
			cfg.EscalationAdapterPath = escalationAdapterPath
			escalationAdapterExplicit = true
		case "escalation-policy":
			cfg.EscalationPolicy = escalationPolicy
		case "escalation-timeout":
			if escalationTimeout > 0 {
				cfg.EscalationTimeoutSec = escalationTimeout
			}
		case "auto-reload-adapter":
			cfg.AutoReloadAdapter = autoReloadAdapter
		}
	})

	// Auto-load persisted active LoRA adapter manifest for primary and/or escalation slots when
	// omitted in flags/config, declining mismatched model pairs cleanly.
	var adapterManifestLoadErr error
	var adapterManifestMismatchMsg string
	var startupManifestHash [32]byte
	var hasStartupManifest bool
	var primaryLoadedFromDisk bool
	var escalationLoadedFromDisk bool
	if cfg.DataDir != "" {
		active, diskHash, exists, loadErr := train.LoadActiveAdapterWithHash(cfg.DataDir)
		if loadErr != nil {
			adapterManifestLoadErr = loadErr
		} else if exists {
			startupManifestHash = diskHash
			hasStartupManifest = true
			if !adapterPathExplicit && cfg.AdapterPath == "" && active.AdapterPath != "" {
				if baseModelExplicit && active.BaseModel != "" && !strings.EqualFold(active.BaseModel, cfg.BaseModel) {
					adapterManifestMismatchMsg = fmt.Sprintf("skipping persisted adapter %q trained for %s because --base-model=%s was explicitly requested",
						active.AdapterPath, active.BaseModel, cfg.BaseModel)
				} else {
					cfg.AdapterPath = active.AdapterPath
					primaryLoadedFromDisk = true
					if !baseModelExplicit && active.BaseModel != "" {
						cfg.BaseModel = active.BaseModel
					}
				}
			}
			if !escalationAdapterExplicit && cfg.EscalationAdapterPath == "" && active.Escalation != nil {
				if escalationModelExplicit && active.Escalation.BaseModel != "" && !strings.EqualFold(active.Escalation.BaseModel, cfg.EscalationBaseModel) {
					adapterManifestMismatchMsg = strings.TrimSpace(adapterManifestMismatchMsg + fmt.Sprintf(" skipping persisted escalation adapter %q trained for %s because --escalation-base-model=%s was explicitly requested",
						active.Escalation.AdapterPath, active.Escalation.BaseModel, cfg.EscalationBaseModel))
				} else {
					cfg.EscalationAdapterPath = active.Escalation.AdapterPath
					escalationLoadedFromDisk = true
					if !escalationModelExplicit && active.Escalation.BaseModel != "" {
						cfg.EscalationBaseModel = active.Escalation.BaseModel
					}
				}
			}
		}
	}

	if d, parseErr := time.ParseDuration(cfg.WindowStr); parseErr != nil || d <= 0 {
		return fmt.Errorf("invalid -window duration %q", cfg.WindowStr)
	} else {
		cfg.WindowDuration = d
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	debug.SetMemoryLimit(cfg.MaxMemMB * 1024 * 1024)

	ruleEng, err := rules.LoadEngine(cfg.RulesPath)
	if err != nil {
		return err
	}

	// Bind HTTP listener synchronously before opening ingestion or starting loops so bind errors fail fast.
	ln, err := net.Listen("tcp", cfg.HTTPAddr)
	if err != nil {
		return fmt.Errorf("bind sentinel HTTP listener on %s: %w", cfg.HTTPAddr, err)
	}
	defer func() { _ = ln.Close() }()

	var sink emit.Sink
	if dryRun {
		sink = emit.NewWriterSink(stdout)
	} else if stdoutAlerts {
		sink = emit.NewMultiSink(
			emit.NewGenesisTCPSinkWithPolicy(cfg.GenesisTCPAddr, 2*time.Second, cfg.AllowRemoteEndpoints),
			emit.NewWriterSink(stdout),
		)
	} else {
		sink = emit.NewGenesisTCPSinkWithPolicy(cfg.GenesisTCPAddr, 2*time.Second, cfg.AllowRemoteEndpoints)
	}
	defer func() { _ = sink.Close() }()

	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("create sentinel data dir %q: %w", cfg.DataDir, err)
	}

	var (
		segReader    *ingest.SegReader
		queryPoller  *ingest.QueryPoller
		activeSource string
		cursorPath   string
	)

	if cfg.GenesisDataDir != "" {
		activeSource = "segdir"
		cursorPath = filepath.Join(cfg.DataDir, "cursor.json")
		segReader, err = ingest.NewSegReader(cfg.GenesisDataDir, cursorPath, 0)
		if err != nil {
			return fmt.Errorf("initialize segment reader: %w", err)
		}
	} else {
		activeSource = "query_fallback"
		queryPoller = ingest.NewQueryPoller(cfg.GenesisHTTPAddr, cfg.GenesisAuthToken, 10000, cfg.AllowRemoteEndpoints)
	}

	pipe := pipeline.New(cfg, ruleEng, sink, activeSource)
	pipe.ConfigureAdapterSyncPolicy(hasStartupManifest, startupManifestHash, adapterPathExplicit, escalationAdapterExplicit, primaryLoadedFromDisk, escalationLoadedFromDisk)
	pinPrimary, pinEsc := "", ""
	if baseModelExplicit {
		pinPrimary = cfg.BaseModel
	}
	if escalationModelExplicit {
		pinEsc = cfg.EscalationBaseModel
	}
	pipe.SetExplicitBaseModels(pinPrimary, pinEsc)
	pipe.EnableAsyncTriage(0)
	defer pipe.Close()
	pipe.AttachSegReader(segReader)
	pipe.AttachQueryPoller(queryPoller)
	if cfg.DataDir != "" {
		pipe.AttachAlertJournal(feedback.NewAlertJournalWithRedaction(cfg.DataDir, cfg.RequireRedaction))
	}

	// Hydrate persisted Tier 1 rolling baseline snapshot if present.
	baselinePath := filepath.Join(cfg.DataDir, "baseline.json")
	loadedBaseline := 0
	logger := log.New(stderr, "", log.LstdFlags)
	if adapterManifestLoadErr != nil {
		logger.Printf("[Tier2] Warning: ignoring unreadable active adapter manifest %s: %v",
			filepath.Join(cfg.DataDir, train.ActiveAdapterFilename), adapterManifestLoadErr)
	}
	if adapterManifestMismatchMsg != "" {
		logger.Printf("[Tier2] Warning: %s", adapterManifestMismatchMsg)
	}
	if surpEng := pipe.SurprisalEngine(); surpEng != nil {
		n, loadErr := surpEng.LoadFromFile(baselinePath)
		if loadErr != nil {
			logger.Printf("[Tier1] Warning: ignoring unreadable baseline snapshot %s: %v", baselinePath, loadErr)
		} else {
			loadedBaseline = n
		}
	}

	// Surface active disk paths prominently on startup (ADR-4 transparency).
	logger.Println("==========================================================")
	logger.Printf("  GENESIS SENTINEL %s (Tier 0 Rules + Tier 1 Surprisal + Tier 2 LoRA)", Version)
	logger.Println("==========================================================")
	logger.Printf("[Disk]   Sentinel Data Dir : %s (open via `sentinel data open`)", cfg.DataDir)
	logger.Printf("[Tier1]  Laplace-LK Mode   : %s | Threshold: %.2f nats | Baseline: %d/%d (%s)",
		cfg.SurprisalMode, cfg.SurprisalThreshold, loadedBaseline, cfg.BaselineWindowSize, baselinePath)
	if cfg.TriageMode == "http" {
		logger.Printf("[Tier2]  LoRA Triage Mode  : http-async (%s) | Model: %s | Adapter: %q",
			cfg.InferenceAddr, cfg.BaseModel, cfg.AdapterPath)
	} else {
		logger.Printf("[Tier2]  LoRA Triage Mode  : off (enable via --triage-mode http; default model %s)", cfg.BaseModel)
	}
	if cfg.EscalationMode == "http" {
		logger.Printf("[Tier2+] Escalation Mode   : http (%s) | Model: %s | Adapter: %q | Policy: %s",
			cfg.EscalationInferenceAddr, cfg.EscalationBaseModel, cfg.EscalationAdapterPath, cfg.EscalationPolicy)
	} else {
		logger.Printf("[Tier2+] Escalation Mode   : off (enable via --escalation-mode http; default model %s)", cfg.EscalationBaseModel)
	}
	if activeSource == "segdir" {
		logger.Printf("[Source] Lossless .seg Dir : %s (cursor: %s)", cfg.GenesisDataDir, cursorPath)
	} else {
		logger.Printf("[Source] Volatile /query   : %s (tip: pass --genesis-data-dir for lossless .seg tailing)", cfg.GenesisHTTPAddr)
	}
	if dryRun {
		logger.Println("[Sink]   Dry-Run Mode      : Alerts printed to stdout only")
	} else {
		logger.Printf("[Sink]   Genesis TCP Alert : %s (service=%s)", cfg.GenesisTCPAddr, cfg.AlertServiceName)
	}
	logger.Printf("[Window] Flush Interval    : %v | Poll Interval: %v | Auto-Reload Adapter: %v", cfg.WindowDuration, pollInterval, cfg.AutoReloadAdapter)

	writeTimeout := 15 * time.Second
	if cfg.TriageMode == "http" && cfg.TriageTimeoutSec > 0 {
		if want := time.Duration(cfg.TriageTimeoutSec+5) * time.Second; want > writeTimeout {
			writeTimeout = want
		}
	}
	if cfg.EscalationMode == "http" && cfg.EscalationTimeoutSec > 0 {
		if want := time.Duration(cfg.EscalationTimeoutSec+5) * time.Second; want > writeTimeout {
			writeTimeout = want
		}
	}
	httpSrv := &http.Server{
		Handler:           newWatchHTTPHandler(pipe, cfg.AuthToken),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Printf("[HTTP]   Stats & Health    : http://%s (/healthz, /stats, POST /adapter, DELETE /burn)", ln.Addr().String())
		if serveErr := httpSrv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Printf("[HTTP]   Server error: %v", serveErr)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pollTicker := time.NewTicker(pollInterval)
	defer pollTicker.Stop()

	flushTicker := time.NewTicker(cfg.WindowDuration)
	defer flushTicker.Stop()

	adapterReloadTicker := time.NewTicker(time.Second)
	defer adapterReloadTicker.Stop()

	// Track unsaved cursor progress so transient SaveCursor errors retry on subsequent idle polls.
	cursorDirty := false

	for {
		select {
		case <-ctx.Done():
			logger.Println("[Shutdown] Flushing final Tier 0+1 window and saving state...")
			emitted, failed := pipe.FlushWindow()
			if len(emitted) > 0 || len(failed) > 0 {
				logger.Printf("[Shutdown] Emitted %d final alert(s) (%d sink failure(s)).", len(emitted), len(failed))
			}

			var finalSaveErr error
			if segReader != nil {
				if saveErr := segReader.SaveCursor(); saveErr != nil {
					logger.Printf("[Shutdown] Final cursor save failed: %v", saveErr)
					finalSaveErr = fmt.Errorf("final cursor save failed: %w", saveErr)
				}
			}
			if saveErr := pipe.SaveBaseline(baselinePath, false); saveErr != nil {
				logger.Printf("[Shutdown] Final baseline save failed: %v", saveErr)
				finalSaveErr = errors.Join(finalSaveErr, fmt.Errorf("final baseline save failed: %w", saveErr))
			}

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			shutdownErr := httpSrv.Shutdown(shutdownCtx)
			cancel()
			if shutdownErr != nil {
				logger.Printf("[Shutdown] HTTP graceful shutdown incomplete (%v); forcing server close.", shutdownErr)
				if closeErr := httpSrv.Close(); closeErr != nil {
					shutdownErr = errors.Join(shutdownErr, closeErr)
				}
			}
			pipe.Close()
			return errors.Join(finalSaveErr, shutdownErr)

		case <-pollTicker.C:
			if segReader != nil {
				batch, readErr := segReader.ReadBatch(4096)
				if readErr != nil {
					logger.Printf("[Ingest] segment read error: %v", readErr)
					continue
				}
				for _, ev := range batch {
					pipe.IngestEvent(ev)
				}
				if len(batch) > 0 {
					cursorDirty = true
				}
				if cursorDirty {
					if saveErr := segReader.SaveCursor(); saveErr != nil {
						logger.Printf("[Cursor] save error (will retry on next poll): %v", saveErr)
					} else {
						cursorDirty = false
					}
				}
			} else if queryPoller != nil {
				batch, pollErr := queryPoller.Poll(ctx)
				if pollErr != nil {
					if ctx.Err() == nil {
						logger.Printf("[Ingest] /query poll error: %v", pollErr)
					}
					continue
				}
				for _, ev := range batch {
					pipe.IngestEvent(ev)
				}
			}

		case <-flushTicker.C:
			emitted, failed := pipe.FlushWindow()
			if len(emitted) > 0 || len(failed) > 0 {
				st := pipe.Stats()
				logger.Printf("[Tier0+1] Emitted %d alert(s), %d sink failure(s), %d journal error(s) (total_lines=%d, surprisal_anomalies=%d, baseline=%d)",
					len(emitted), len(failed), st.JournalErrors, st.LinesRead, st.SurprisalAnomalies, st.SurprisalBaselineCases)
			}
			if saveErr := pipe.SaveBaseline(baselinePath, false); saveErr != nil {
				logger.Printf("[Tier1] baseline save error (will retry on next flush): %v", saveErr)
			}

		case <-adapterReloadTicker.C:
			if !cfg.AutoReloadAdapter {
				continue
			}
			if reloaded, reloadErr := pipe.SyncActiveAdapterFromDisk(); reloadErr != nil {
				logger.Printf("[Adapter] Warning: failed auto-reloading active-adapter.json: %v", reloadErr)
			} else if reloaded {
				st := pipe.Stats()
				logger.Printf("[Adapter] Auto-reloaded manifest on disk (primary=%q escalation=%q swaps=%d)",
					st.TriageAdapter, st.EscalationAdapter, st.AdapterSwapsTotal)
			}
		}
	}
}

func newWatchHTTPHandler(pipe *pipeline.Pipeline, authToken string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", pipe.HandleHealthz)
	mux.HandleFunc("/stats", pipe.HandleStats)
	mux.HandleFunc("/burn", pipe.HandleBurn)
	mux.HandleFunc("/adapter", pipe.HandleAdapter)
	return security.AuthMiddleware(authToken, mux)
}
