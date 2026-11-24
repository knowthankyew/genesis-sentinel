package cli

import (
	"context"
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
	"syscall"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/ingest"
	"github.com/knowthankyew/genesis-sentinel/internal/pipeline"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

func runWatch(args []string, stdout, stderr io.Writer) error {
	// Pre-scan for -config / --config matching Genesis's flag precedence
	var configPath string
	for i, arg := range args {
		if (arg == "-config" || arg == "--config") && i+1 < len(args) {
			configPath = args[i+1]
		} else if len(arg) > 8 && arg[:8] == "-config=" {
			configPath = arg[8:]
		} else if len(arg) > 9 && arg[:9] == "--config=" {
			configPath = arg[9:]
		}
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&configPath, "config", configPath, "Path to sentinel.json config file")
	genesisDataDir := fs.String("genesis-data-dir", cfg.GenesisDataDir, "Genesis --data-dir path for lossless .seg tailing (primary)")
	genesisHTTP := fs.String("genesis-http", cfg.GenesisHTTPAddr, "Genesis HTTP base URL for /query fallback")
	genesisTCP := fs.String("genesis-tcp", cfg.GenesisTCPAddr, "Genesis TCP ingest address for alert emission")
	httpAddr := fs.String("http", cfg.HTTPAddr, "Sentinel HTTP stats/health/burn listen address")
	dataDir := fs.String("data-dir", cfg.DataDir, "Sentinel local state directory (cursors, baselines, feedback)")
	windowStr := fs.String("window", cfg.WindowStr, "Tier 0 template collapse flush window (e.g. 10s)")
	rulesPath := fs.String("rules", cfg.RulesPath, "Optional path to custom JSON rules.json pack")
	pollInterval := fs.Duration("poll-interval", 250*time.Millisecond, "Polling interval for new .seg frames or /query windows")
	dryRun := fs.Bool("dry-run", false, "Print alerts to stdout instead of emitting to Genesis TCP")
	stdoutAlerts := fs.Bool("stdout-alerts", false, "Mirror emitted alerts to stdout in addition to Genesis TCP")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *pollInterval <= 0 {
		return fmt.Errorf("invalid -poll-interval %v: must be positive", *pollInterval)
	}

	cfg.GenesisDataDir = *genesisDataDir
	cfg.GenesisHTTPAddr = *genesisHTTP
	cfg.GenesisTCPAddr = *genesisTCP
	cfg.HTTPAddr = *httpAddr
	cfg.DataDir = *dataDir
	cfg.WindowStr = *windowStr
	cfg.RulesPath = *rulesPath

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
	if *dryRun {
		sink = emit.NewWriterSink(stdout)
	} else if *stdoutAlerts {
		sink = emit.NewMultiSink(
			emit.NewGenesisTCPSink(cfg.GenesisTCPAddr, 2*time.Second),
			emit.NewWriterSink(stdout),
		)
	} else {
		sink = emit.NewGenesisTCPSink(cfg.GenesisTCPAddr, 2*time.Second)
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
	pipe.AttachSegReader(segReader)
	pipe.AttachQueryPoller(queryPoller)

	// Surface active disk paths prominently on startup (ADR-4 transparency).
	logger := log.New(stderr, "", log.LstdFlags)
	logger.Println("==========================================================")
	logger.Printf("  GENESIS SENTINEL %s (Tier 0 Deterministic Engine)", Version)
	logger.Println("==========================================================")
	logger.Printf("[Disk]   Sentinel Data Dir : %s (open via `sentinel data open`)", cfg.DataDir)
	if activeSource == "segdir" {
		logger.Printf("[Source] Lossless .seg Dir : %s (cursor: %s)", cfg.GenesisDataDir, cursorPath)
	} else {
		logger.Printf("[Source] Volatile /query   : %s (tip: pass --genesis-data-dir for lossless .seg tailing)", cfg.GenesisHTTPAddr)
	}
	if *dryRun {
		logger.Println("[Sink]   Dry-Run Mode      : Alerts printed to stdout only")
	} else {
		logger.Printf("[Sink]   Genesis TCP Alert : %s (service=%s)", cfg.GenesisTCPAddr, cfg.AlertServiceName)
	}
	logger.Printf("[Window] Flush Interval    : %v | Poll Interval: %v", cfg.WindowDuration, *pollInterval)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", pipe.HandleHealthz)
	mux.HandleFunc("/stats", pipe.HandleStats)
	mux.HandleFunc("/burn", pipe.HandleBurn)

	httpSrv := &http.Server{
		Handler:           security.AuthMiddleware(cfg.AuthToken, mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Printf("[HTTP]   Stats & Health    : http://%s (/healthz, /stats, DELETE /burn)", ln.Addr().String())
		if serveErr := httpSrv.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			logger.Printf("[HTTP]   Server error: %v", serveErr)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pollTicker := time.NewTicker(*pollInterval)
	defer pollTicker.Stop()

	flushTicker := time.NewTicker(cfg.WindowDuration)
	defer flushTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Println("[Shutdown] Flushing final Tier 0 window and saving cursor...")
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
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = httpSrv.Shutdown(shutdownCtx)
			cancel()
			return finalSaveErr

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
					if saveErr := segReader.SaveCursor(); saveErr != nil {
						logger.Printf("[Cursor] save error (will retry next batch): %v", saveErr)
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
				logger.Printf("[Tier0] Emitted %d alert(s), %d sink failure(s) (total_lines=%d)", len(emitted), len(failed), pipe.Stats().LinesRead)
			}
		}
	}
}
