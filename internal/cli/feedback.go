package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

func runFeedback(args []string, stdout, stderr io.Writer) error {
	action := "add"
	subArgs := args
	if len(args) > 0 {
		first := strings.ToLower(strings.TrimSpace(args[0]))
		if first == "-h" || first == "--help" || !strings.HasPrefix(args[0], "-") {
			action = first
			subArgs = args[1:]
		}
	}

	switch action {
	case "add":
		return runFeedbackAdd(subArgs, stdout, stderr)
	case "seed":
		return runFeedbackSeed(subArgs, stdout, stderr)
	case "export":
		return runFeedbackExport(subArgs, stdout, stderr)
	case "stats":
		return runFeedbackStats(subArgs, stdout, stderr)
	case "alerts":
		return runFeedbackAlerts(subArgs, stdout, stderr)
	case "help", "-h", "--help":
		printFeedbackUsage(stdout)
		return nil
	default:
		printFeedbackUsage(stderr)
		return fmt.Errorf("unknown feedback subcommand %q (expected: add, seed, export, stats, or alerts)", action)
	}
}

func printFeedbackUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  sentinel feedback [add] --alert-id <ID> --label <tp|fp|CLASS> [--note "..."] [--weight 1.0]
  sentinel feedback [add] --service <svc> --level <lvl> --sample "<log>" --label <CLASS>
  sentinel feedback seed [--per-class 10] [--val-per-class 2] [--name seed] [--seed 42]
  sentinel feedback export [--out <path>] [--name <slug>] [--include-seed 0]
  sentinel feedback stats [--name <slug>]
  sentinel feedback alerts [--limit 20]

Canonical Classes (enforced fail-closed by live Tier 2 parser):
  BENIGN-NOISE, RECON-SCAN, AUTH-BRUTEFORCE, INJECTION-ATTEMPT,
  EXFIL-SUSPECT, PRIV-ESC, POLICY-ANOMALY, NEEDS-REVIEW
  (custom [A-Z0-9-] tags are permitted for dataset curation; live Tier 2 defaults unknown tags to NEEDS-REVIEW)`)
}

func applyDirOverrides(cfg *config.Config, dataDir, feedbackDir string) {
	if dataDir != "" {
		cfg.DataDir = dataDir
		if feedbackDir == "" {
			cfg.FeedbackDir = filepath.Join(dataDir, "feedback")
		}
	}
	if feedbackDir != "" {
		cfg.FeedbackDir = feedbackDir
	}
}

func runFeedbackAdd(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("feedback add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	feedbackDir := fs.String("feedback-dir", "", "Override Sentinel feedback directory")
	name := fs.String("name", "", "Optional dataset slug (writes sentinel-feedback-<name>.jsonl)")
	alertID := fs.String("alert-id", "", "Alert ID from local alerts.jsonl journal to label")
	service := fs.String("service", "", "Source service name (when labeling manually without --alert-id)")
	level := fs.String("level", "INFO", "Source log level (when labeling manually)")
	tmpl := fs.String("template", "", "Log template pattern (optional; defaults to sample)")
	sample := fs.String("sample", "", "Log sample line (when labeling manually without --alert-id)")
	label := fs.String("label", "", "Operator verdict label: tp | fp | BENIGN-NOISE | AUTH-BRUTEFORCE | custom tag")
	note := fs.String("note", "", "Optional 1-sentence explanation for the fine-tuning target")
	weight := fs.Float64("weight", 1.0, "Optional FTaaS probability mass sample weight (> 0)")
	noRedact := fs.Bool("no-redact", false, "Explicitly disable mandatory PII/secret redaction (NOT recommended)")
	asJSON := fs.Bool("json", false, "Emit JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --alert-id, --label, --sample)", fs.Arg(0))
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyDirOverrides(cfg, *dataDir, *feedbackDir)
	if *noRedact {
		cfg.RequireRedaction = false
	}

	if strings.TrimSpace(*label) == "" {
		return fmt.Errorf("feedback add requires --label (e.g. tp, fp, BENIGN-NOISE, AUTH-BRUTEFORCE)")
	}

	var alert emit.Alert
	if strings.TrimSpace(*alertID) != "" {
		journal := feedback.NewAlertJournal(cfg.DataDir)
		foundAlert, ok, findErr := journal.FindByID(*alertID)
		if findErr != nil {
			return fmt.Errorf("lookup alert %q: %w", *alertID, findErr)
		}
		if !ok {
			return fmt.Errorf("alert_id %q not found in %s (run `sentinel feedback alerts` to list recent alerts)", *alertID, journal.Path())
		}
		alert = foundAlert
	} else {
		if strings.TrimSpace(*sample) == "" && strings.TrimSpace(*tmpl) == "" {
			return fmt.Errorf("feedback add requires either --alert-id or --sample / --template")
		}
		svc := strings.TrimSpace(*service)
		if svc == "" {
			svc = "unknown"
		}
		sampleStr := *sample
		tmplStr := *tmpl
		if tmplStr == "" {
			tmplStr = sampleStr
		}
		if sampleStr == "" {
			sampleStr = tmplStr
		}
		alert = emit.Alert{
			AlertID:         "manual",
			SourceService:   svc,
			SourceLevel:     strings.ToUpper(strings.TrimSpace(*level)),
			TemplateID:      "manual",
			Template:        tmplStr,
			Count:           1,
			SanitizedSample: sampleStr,
		}
	}

	rec, redactedKinds, err := feedback.RecordFromAlert(alert, *label, *note, *weight, cfg.MaxPromptByte, cfg.RequireRedaction)
	if err != nil {
		return err
	}

	filename, err := feedback.NamedFilename(*name)
	if err != nil {
		return err
	}
	store := feedback.NewStore(cfg.FeedbackDir, cfg.RequireRedaction)
	total, err := store.Append(filename, rec)
	if err != nil {
		return err
	}
	outPath, _ := store.PathFor(filename)

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"status":         "recorded",
			"path":           outPath,
			"label":          rec.Label,
			"redacted":       rec.Redacted,
			"redacted_kinds": redactedKinds,
			"total_records":  total,
		})
	}
	_, err = fmt.Fprintf(stdout, "Recorded feedback [%s] -> %s (total records: %d, redacted: %v)\n",
		rec.Label, outPath, total, rec.Redacted)
	return err
}

func runFeedbackSeed(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("feedback seed", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	feedbackDir := fs.String("feedback-dir", "", "Override Sentinel feedback directory")
	name := fs.String("name", "seed", "Dataset slug (writes sentinel-feedback-<name>.jsonl)")
	perClass := fs.Int("per-class", 10, "Number of synthetic examples generated per security taxonomy class")
	valPerClass := fs.Int("val-per-class", 0, "Optional holdout validation examples per class (writes sentinel-feedback-<name>-val.jsonl)")
	seed := fs.Uint64("seed", 42, "Deterministic PRNG seed")
	asJSON := fs.Bool("json", false, "Emit JSON summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --alert-id, --label, --sample)", fs.Arg(0))
	}
	if *perClass <= 0 {
		return fmt.Errorf("--per-class must be positive, got %d", *perClass)
	}
	if *valPerClass < 0 {
		return fmt.Errorf("--val-per-class must be >= 0, got %d", *valPerClass)
	}
	maxPerClass := config.DefaultMaxTrainingRecords / len(triage.AllClasses())
	if *perClass > maxPerClass {
		return fmt.Errorf("--per-class %d exceeds FTaaS %d-record ceiling (%d max per class across %d classes)",
			*perClass, config.DefaultMaxTrainingRecords, maxPerClass, len(triage.AllClasses()))
	}
	if *valPerClass > maxPerClass {
		return fmt.Errorf("--val-per-class %d exceeds FTaaS %d-record ceiling (%d max per class across %d classes)",
			*valPerClass, config.DefaultMaxTrainingRecords, maxPerClass, len(triage.AllClasses()))
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyDirOverrides(cfg, *dataDir, *feedbackDir)

	trainName, err := feedback.NamedFilename(*name)
	if err != nil {
		return err
	}
	store := feedback.NewStore(cfg.FeedbackDir, cfg.RequireRedaction)
	trainPath, err := store.PathFor(trainName)
	if err != nil {
		return err
	}

	trainRecs, valRecs := feedback.GenerateSeedSplit(*perClass, *valPerClass, *seed)
	trainSum, err := feedback.WriteFTaaSDataset(trainPath, trainRecs, cfg.RequireRedaction)
	if err != nil {
		return err
	}

	var valSum *feedback.ExportSummary
	if len(valRecs) > 0 {
		valSlug := strings.TrimSpace(*name)
		if valSlug == "" {
			valSlug = "val"
		} else {
			valSlug = valSlug + "-val"
		}
		valName, err := feedback.NamedFilename(valSlug)
		if err != nil {
			return err
		}
		valPath, err := store.PathFor(valName)
		if err != nil {
			return err
		}
		vs, err := feedback.WriteFTaaSDataset(valPath, valRecs, cfg.RequireRedaction)
		if err != nil {
			return err
		}
		valSum = &vs
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"train":      trainSum,
			"validation": valSum,
			"classes":    triage.AllClasses(),
		})
	}
	if _, err := fmt.Fprintf(stdout, "Generated synthetic seed dataset: %s (%d records across %d classes, %d bytes, sha256=%s)\n",
		trainSum.Path, trainSum.RecordCount, len(trainSum.ClassCounts), trainSum.ByteSize, trainSum.SHA256[:12]); err != nil {
		return err
	}
	if valSum != nil {
		_, err = fmt.Fprintf(stdout, "Generated companion validation split: %s (%d records, %d bytes, sha256=%s)\n",
			valSum.Path, valSum.RecordCount, valSum.ByteSize, valSum.SHA256[:12])
		return err
	}
	return nil
}

func runFeedbackExport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("feedback export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	feedbackDir := fs.String("feedback-dir", "", "Override Sentinel feedback directory")
	name := fs.String("name", "", "Source dataset slug (default sentinel-feedback.jsonl)")
	outPath := fs.String("out", "", "Destination FTaaS JSONL path (default <feedback_dir>/sentinel-feedback-export.jsonl)")
	includeSeed := fs.Int("include-seed", 0, "Optional synthetic seed examples per class to blend with curated feedback")
	seed := fs.Uint64("seed", 42, "Deterministic seed when --include-seed > 0")
	asJSON := fs.Bool("json", false, "Emit JSON summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --alert-id, --label, --sample)", fs.Arg(0))
	}
	if *includeSeed < 0 {
		return fmt.Errorf("--include-seed must be >= 0, got %d", *includeSeed)
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyDirOverrides(cfg, *dataDir, *feedbackDir)

	srcName, err := feedback.NamedFilename(*name)
	if err != nil {
		return err
	}
	dest := strings.TrimSpace(*outPath)
	if dest == "" {
		dest = filepath.Join(cfg.FeedbackDir, "sentinel-feedback-export.jsonl")
	}

	store := feedback.NewStore(cfg.FeedbackDir, cfg.RequireRedaction)
	sum, err := store.ExportFTaaS(srcName, dest, *includeSeed, *seed)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(sum)
	}
	_, err = fmt.Fprintf(stdout, "Exported FTaaS JSONL dataset: %s (%d records, %d bytes, sha256=%s)\n",
		sum.Path, sum.RecordCount, sum.ByteSize, sum.SHA256[:12])
	return err
}

func runFeedbackStats(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("feedback stats", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	feedbackDir := fs.String("feedback-dir", "", "Override Sentinel feedback directory")
	name := fs.String("name", "", "Optional dataset slug")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --alert-id, --label, --sample)", fs.Arg(0))
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyDirOverrides(cfg, *dataDir, *feedbackDir)

	filename, err := feedback.NamedFilename(*name)
	if err != nil {
		return err
	}
	store := feedback.NewStore(cfg.FeedbackDir, cfg.RequireRedaction)
	st, err := store.Stats(filename)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(st)
}

func runFeedbackAlerts(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("feedback alerts", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	limit := fs.Int("limit", 20, "Maximum number of recent alerts to list")
	asJSON := fs.Bool("json", false, "Emit JSON array")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --alert-id, --label, --sample)", fs.Arg(0))
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyDirOverrides(cfg, *dataDir, "")

	journal := feedback.NewAlertJournal(cfg.DataDir)
	alerts, err := journal.Recent(*limit)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(alerts)
	}
	if len(alerts) == 0 {
		_, err = fmt.Fprintf(stdout, "No alerts recorded in %s yet.\n", journal.Path())
		return err
	}
	for _, a := range alerts {
		cls := a.TriageClass
		if cls == "" {
			cls = "-"
		}
		if _, err := fmt.Fprintf(stdout, "%s  [%s] tier=%s service=%s triage=%s  %s\n",
			escapeForTerminal(a.AlertID), escapeForTerminal(a.Severity), escapeForTerminal(a.Tier),
			escapeForTerminal(a.SourceService), escapeForTerminal(cls), escapeForTerminal(a.Template)); err != nil {
			return err
		}
	}
	return nil
}
