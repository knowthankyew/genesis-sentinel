package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
)

// Version identifies the current Genesis Sentinel release stage.
const Version = "0.1.0-scaffold"

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
		return notImplemented("watch", "Phase 1 (Genesis Bridge & Tier 0 Deterministic Engine)")
	case "scan":
		return notImplemented("scan", "Phase 1/2 (Batch Segment Scan & Laplace-LK Surprisal)")
	case "feedback":
		return notImplemented("feedback", "Phase 3 (Redacted Feedback Curation for FTaaS)")
	case "train":
		return notImplemented("train", "Phase 3 (Async SmolLM2 LoRA Job Submission to FTaaS)")
	case "stats":
		return notImplemented("stats", "Phase 1 (Sentinel Pipeline Metrics)")
	case "burn":
		return notImplemented("burn", "Phase 1 (Amnesiac State & Feedback Purge)")
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

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(safeCopy)
}

func notImplemented(cmd, roadmapPhase string) error {
	return fmt.Errorf("%q is scheduled for %s — see docs/ROADMAP.md", cmd, roadmapPhase)
}

// PrintUsage writes the Genesis Sentinel CLI usage help text.
func PrintUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Genesis Sentinel - Local-First Tiered Log Triage & Anomaly Sidecar

Usage:
  sentinel [command] [flags]

Commands:
  watch     Watch Genesis segments or query windows through Tier 0 -> 1 -> 2 (Phase 1+)
  scan      Run an offline scan over Genesis .seg files or JSONL exports (Phase 1+)
  feedback  Label alerts as true/false positives and export redacted JSONL (Phase 3)
  train     Submit a redacted feedback dataset to local FTaaS (SmolLM2) (Phase 3)
  stats     Display live pipeline throughput, surprisal, and alert metrics (Phase 1+)
  burn      Purge Sentinel in-memory baselines and unexported local queues (Phase 1+)
  config    Validate and print the resolved Sentinel configuration
  version   Print the Genesis Sentinel version
  help      Show help for Genesis Sentinel

See docs/ROADMAP.md and docs/DECISIONS.md for architecture and execution phases.`)
}
