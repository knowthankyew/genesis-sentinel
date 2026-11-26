package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
)

// Version identifies the current Genesis Sentinel release stage.
const Version = "0.6.0-phase5"

// openDirFn launches the OS file manager for `sentinel data open` (overridable in tests).
var openDirFn = openDirectoryOS

// Execute routes CLI subcommands following Genesis's single-binary dispatch style.
func Execute(args []string) error {
	return ExecuteWithOutput(args, os.Stdout, os.Stderr)
}

// ExecuteWithOutput executes CLI subcommands writing to explicit stdout/stderr writers.
func ExecuteWithOutput(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		PrintUsage(stdout)
		return nil
	}

	cmd := args[0]
	switch cmd {
	case "watch":
		return runWatch(args[1:], stdout, stderr)
	case "scan":
		return runScan(args[1:], stdout, stderr)
	case "feedback":
		return runFeedback(args[1:], stdout, stderr)
	case "train":
		return runTrain(args[1:], stdout, stderr)
	case "adapter":
		return runAdapter(args[1:], stdout, stderr)
	case "stats":
		return runStats(args[1:], stdout, stderr)
	case "burn":
		return runBurn(args[1:], stdout, stderr)
	case "data":
		return runData(args[1:], stdout, stderr)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "version", "-v", "--version":
		_, _ = fmt.Fprintf(stdout, "genesis-sentinel %s\n", Version)
		return nil
	case "help", "-h", "--help":
		PrintUsage(stdout)
		return nil
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command: %s\n\n", cmd)
		PrintUsage(stderr)
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func runConfig(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	// Redact sensitive tokens before printing resolved config.
	safeCopy := *cfg
	if safeCopy.AuthToken != "" {
		safeCopy.AuthToken = "[REDACTED]"
	}
	if safeCopy.GenesisAuthToken != "" {
		safeCopy.GenesisAuthToken = "[REDACTED]"
	}
	if safeCopy.FTaaSAPIKey != "" {
		safeCopy.FTaaSAPIKey = "[REDACTED]"
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(safeCopy)
}

func runData(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("data", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}

	action := "status"
	if fs.NArg() > 0 {
		action = fs.Arg(0)
	}

	switch action {
	case "path":
		_, _ = fmt.Fprintln(stdout, cfg.DataDir)
		return nil
	case "status":
		status := inspectDataDir(cfg.DataDir, cfg.FeedbackDir, cfg.GenesisDataDir)
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(status)
	case "open":
		if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
			return fmt.Errorf("failed to initialize data directory %q: %w", cfg.DataDir, err)
		}
		if err := openDirFn(cfg.DataDir); err != nil {
			return fmt.Errorf("failed to open %q in file manager: %w", cfg.DataDir, err)
		}
		_, _ = fmt.Fprintf(stdout, "Opened Sentinel data directory: %s\n", cfg.DataDir)
		return nil
	default:
		return fmt.Errorf("unknown data subcommand %q (expected: path, status, or open)", action)
	}
}

type dataDirStatus struct {
	DataDir        string `json:"data_dir"`
	FeedbackDir    string `json:"feedback_dir"`
	GenesisDataDir string `json:"genesis_data_dir,omitempty"`
	Exists         bool   `json:"exists"`
	FileCount      int    `json:"file_count"`
	TotalBytes     int64  `json:"total_bytes"`
}

func inspectDataDir(dataDir, feedbackDir, genesisDataDir string) dataDirStatus {
	st := dataDirStatus{
		DataDir:        dataDir,
		FeedbackDir:    feedbackDir,
		GenesisDataDir: genesisDataDir,
	}
	info, err := os.Stat(dataDir)
	if err != nil || !info.IsDir() {
		return st
	}
	st.Exists = true
	_ = filepath.WalkDir(dataDir, func(_ string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		st.FileCount++
		if fi, err := d.Info(); err == nil {
			st.TotalBytes += fi.Size()
		}
		return nil
	})
	return st
}

func openDirectoryOS(dir string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", dir).Run()
	case "linux":
		return exec.Command("xdg-open", dir).Run()
	case "windows":
		return exec.Command("explorer", dir).Run()
	default:
		return fmt.Errorf("unsupported OS %q for graphical folder open; inspect path manually: %s", runtime.GOOS, dir)
	}
}

// PrintUsage writes the Genesis Sentinel CLI usage help text.
func PrintUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Genesis Sentinel - Local-First Tiered Log Triage & Anomaly Sidecar

Usage:
  sentinel [command] [flags]

Commands:
  watch     Watch Genesis .seg files (or /query windows) through Tier 0 -> 1 -> 2
  scan      Run an offline scan over Genesis .seg files, raw log files, or synthetic replay
  feedback  Label alerts as true/false positives, seed starter data, and export redacted JSONL
  train     Audit/submit redacted feedback datasets to local FTaaS and activate LoRA adapters
  adapter   Inspect, hot-swap, verify, roll back, or deactivate live Tier 2 LoRA adapters
  stats     Display live pipeline throughput, surprisal, triage, and alert metrics
  burn      Purge Sentinel disk state, baselines, alert journals, and unexported feedback queues
  data      Inspect or open Sentinel's local data directory (path | status | open)
  config    Validate and print the resolved Sentinel configuration
  version   Print the Genesis Sentinel version
  help      Show help for Genesis Sentinel

See docs/ROADMAP.md and docs/DECISIONS.md for architecture and execution phases.`)
}
