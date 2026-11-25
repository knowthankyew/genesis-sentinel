package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/train"
)

func runTrain(args []string, stdout, stderr io.Writer) error {
	action := "submit"
	subArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = strings.ToLower(strings.TrimSpace(args[0]))
		subArgs = args[1:]
	}

	switch action {
	case "submit":
		return runTrainSubmit(subArgs, stdout, stderr)
	case "status":
		return runTrainStatus(subArgs, stdout, stderr)
	case "list":
		return runTrainList(subArgs, stdout, stderr)
	case "activate":
		return runTrainActivate(subArgs, stdout, stderr)
	case "help", "-h", "--help":
		printTrainUsage(stdout)
		return nil
	default:
		printTrainUsage(stderr)
		return fmt.Errorf("unknown train subcommand %q (expected: submit, status, list, or activate)", action)
	}
}

func printTrainUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  sentinel train [submit] [--dataset <file.jsonl>] [--base-model HuggingFaceTB/SmolLM2-135M-Instruct] [--preflight=true] [--wait] [--activate]
  sentinel train [submit] --audit-only --dataset <file.jsonl>
  sentinel train status --job-id <id>
  sentinel train list [--limit 20]
  sentinel train activate --adapter-path artifacts/<jobId>/model_adapters [--sentinel-http http://127.0.0.1:8090]`)
}

func runTrainSubmit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("train submit", flag.ContinueOnError)
	fs.SetOutput(stderr)

	defHP := train.DefaultHyperparameters()
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	feedbackDir := fs.String("feedback-dir", "", "Override Sentinel feedback directory")
	ftaasHTTP := fs.String("ftaas-http", "", "Loopback FTaaS API URL (default http://127.0.0.1:5100)")
	apiKey := fs.String("api-key", "", "Optional FTaaS API key (or SENTINEL_FTAAS_API_KEY)")
	datasetPath := fs.String("dataset", "", "Path to redacted FTaaS JSONL dataset (if omitted, exports curated feedback)")
	seedPerClass := fs.Int("seed-per-class", 0, "Optional synthetic seed examples per class to blend when exporting feedback")
	seed := fs.Uint64("seed", 42, "Deterministic seed when --seed-per-class > 0")
	jobName := fs.String("job-name", "", "FTaaS training job name")
	baseModel := fs.String("base-model", "", "Allowlisted base model (default HuggingFaceTB/SmolLM2-135M-Instruct)")
	epochs := fs.Int("epochs", defHP.Epochs, "LoRA training epochs (1-20)")
	batchSize := fs.Int("batch-size", defHP.BatchSize, "LoRA batch size (1-64)")
	lr := fs.Float64("lr", defHP.LearningRate, "LoRA learning rate ((0, 0.1])")
	loraRank := fs.Int("lora-rank", defHP.LoraRank, "LoRA rank r (1-128)")
	loraAlpha := fs.Int("lora-alpha", defHP.LoraAlpha, "LoRA alpha (1-512)")
	loraDropout := fs.Float64("lora-dropout", defHP.LoraDropout, "LoRA dropout ([0, 1))")
	maxLength := fs.Int("max-length", defHP.MaxLength, "Tokenization max sequence length for FTaaS worker (64-2048, default 512)")
	preflight := fs.Bool("preflight", true, "Enable FTaaS surprisal preflight redundancy ablation & anomaly audit")
	auditOnly := fs.Bool("audit-only", false, "Run POST /api/v1/jobs/audit preflight dry-run without queuing training")
	ablationThreshold := fs.Float64("ablation-threshold", 0.15, "Audit ablation threshold in nats (with --audit-only)")
	anomalyThreshold := fs.Float64("anomaly-threshold", 5.0, "Audit anomaly threshold in nats (with --audit-only)")
	wait := fs.Bool("wait", false, "Poll FTaaS until training job completes")
	pollInterval := fs.Duration("poll-interval", 3*time.Second, "Polling interval when --wait is enabled")
	activate := fs.Bool("activate", false, "Persist active-adapter.json once --wait completes (and hot-reload daemon if --sentinel-http is set)")
	sentinelHTTP := fs.String("sentinel-http", "", "Optional running Sentinel HTTP URL for live POST /adapter hot-swap")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback FTaaS/Sentinel endpoints")
	asJSON := fs.Bool("json", false, "Emit JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *activate && !*wait {
		return fmt.Errorf("--activate requires --wait (pass both --wait --activate, or activate later via `sentinel train activate`)")
	}
	if *auditOnly && (*wait || *activate) {
		return fmt.Errorf("--audit-only cannot be combined with --wait or --activate")
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	applyDirOverrides(cfg, *dataDir, *feedbackDir)
	if *ftaasHTTP != "" {
		cfg.FTaaSAPIAddr = *ftaasHTTP
	}
	if *apiKey != "" {
		cfg.FTaaSAPIKey = *apiKey
	}
	if *baseModel != "" {
		cfg.BaseModel = *baseModel
	}
	if *allowRemote {
		cfg.AllowRemoteEndpoints = true
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	resolvedDataset := strings.TrimSpace(*datasetPath)
	if resolvedDataset == "" {
		exportDest := filepath.Join(cfg.FeedbackDir, "sentinel-feedback-train.jsonl")
		store := feedback.NewStore(cfg.FeedbackDir, cfg.RequireRedaction)
		sum, exportErr := store.ExportFTaaS(feedback.DefaultFeedbackFilename, exportDest, *seedPerClass, *seed)
		if exportErr != nil {
			return fmt.Errorf("prepare training dataset: %w (hint: pass --dataset or --seed-per-class 10)", exportErr)
		}
		resolvedDataset = sum.Path
	}

	client, err := train.NewFTaaSClient(cfg.FTaaSAPIAddr, cfg.FTaaSAPIKey, 2*time.Minute, cfg.AllowRemoteEndpoints)
	if err != nil {
		return err
	}

	ctx := context.Background()
	if *auditOnly {
		res, auditErr := client.AuditDataset(ctx, resolvedDataset, *ablationThreshold, *anomalyThreshold, cfg.RequireRedaction)
		if auditErr != nil {
			return auditErr
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	hp := train.Hyperparameters{
		Epochs:       *epochs,
		BatchSize:    *batchSize,
		LearningRate: *lr,
		LoraRank:     *loraRank,
		LoraAlpha:    *loraAlpha,
		LoraDropout:  *loraDropout,
		MaxLength:    *maxLength,
	}

	subRes, err := client.SubmitJob(ctx, train.SubmitRequest{
		JobName:                  *jobName,
		BaseModel:                cfg.BaseModel,
		DatasetPath:              resolvedDataset,
		Hyperparameters:          hp,
		EnableSurprisalPreflight: *preflight,
		RequireRedaction:         cfg.RequireRedaction,
	})
	if err != nil {
		return err
	}

	if !*wait {
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(subRes)
		}
		_, err = fmt.Fprintf(stdout, "Submitted FTaaS LoRA job %s (%s) on %s | status=%s preflight=%s\n",
			subRes.JobID, subRes.JobName, subRes.BaseModel, subRes.Status, subRes.SurprisalPreflightStatus)
		return err
	}

	finalJob, err := client.WaitForJob(ctx, subRes.JobID, *pollInterval, func(d train.JobDetail) {
		if !*asJSON {
			_, _ = fmt.Fprintf(stderr, "[FTaaS] job=%s status=%s progress=%.1f%% step=%d/%d\n",
				d.JobID, d.Status, d.ProgressPercent, d.CurrentStep, d.TotalSteps)
		}
	})
	if err != nil {
		return err
	}

	var activatedState *train.ActiveAdapter
	finalStatus := strings.ToLower(strings.TrimSpace(finalJob.Status))
	if finalStatus != "succeeded" && finalStatus != "completed" {
		return fmt.Errorf("FTaaS job %s did not succeed (status=%q)", finalJob.JobID, finalJob.Status)
	}
	if *activate {
		if strings.TrimSpace(finalJob.AdapterPath) == "" {
			return fmt.Errorf("FTaaS job %s completed (%s) but returned an empty adapterPath; cannot activate", finalJob.JobID, finalJob.Status)
		}
		state := train.ActiveAdapter{
			JobID:       finalJob.JobID,
			BaseModel:   finalJob.BaseModel,
			AdapterPath: finalJob.AdapterPath,
			DatasetHash: finalJob.DatasetHash,
			ActivatedAt: time.Now().UTC(),
		}
		// Notify a running daemon BEFORE updating any local manifest so a 401/rejection never
		// writes an unactivated adapter, and skip redundant unserialized local writes when the
		// daemon already persisted active-adapter.json under its exclusive activation lock.
		daemonSavedSameDir := false
		if strings.TrimSpace(*sentinelHTTP) != "" {
			token := *authToken
			if token == "" {
				token = cfg.AuthToken
			}
			daemonDir, err := train.NotifyDaemonAdapter(ctx, *sentinelHTTP, token, state, cfg.AllowRemoteEndpoints)
			if err != nil {
				return fmt.Errorf("notify running Sentinel daemon: %w", err)
			}
			daemonSavedSameDir = sameCleanDir(daemonDir, cfg.DataDir)
		}
		if !daemonSavedSameDir {
			if err := train.SaveActiveAdapter(cfg.DataDir, state); err != nil {
				return fmt.Errorf("save active adapter: %w", err)
			}
		}
		activatedState = &state
	}

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"submission": subRes,
			"job":        finalJob,
			"activated":  activatedState,
		})
	}
	_, err = fmt.Fprintf(stdout, "FTaaS job %s completed: status=%s adapter=%s activated=%v\n",
		finalJob.JobID, finalJob.Status, finalJob.AdapterPath, activatedState != nil)
	return err
}

func runTrainStatus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("train status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	ftaasHTTP := fs.String("ftaas-http", "", "Loopback FTaaS API URL")
	apiKey := fs.String("api-key", "", "Optional FTaaS API key")
	jobID := fs.String("job-id", "", "FTaaS training job ID")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback FTaaS endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*jobID) == "" {
		return fmt.Errorf("train status requires --job-id")
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *ftaasHTTP != "" {
		cfg.FTaaSAPIAddr = *ftaasHTTP
	}
	if *apiKey != "" {
		cfg.FTaaSAPIKey = *apiKey
	}
	remote := *allowRemote || cfg.AllowRemoteEndpoints

	client, err := train.NewFTaaSClient(cfg.FTaaSAPIAddr, cfg.FTaaSAPIKey, 15*time.Second, remote)
	if err != nil {
		return err
	}
	detail, err := client.GetJob(context.Background(), *jobID)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(detail)
}

func runTrainList(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("train list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	ftaasHTTP := fs.String("ftaas-http", "", "Loopback FTaaS API URL")
	apiKey := fs.String("api-key", "", "Optional FTaaS API key")
	limit := fs.Int("limit", 20, "Maximum number of jobs to return")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback FTaaS endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *ftaasHTTP != "" {
		cfg.FTaaSAPIAddr = *ftaasHTTP
	}
	if *apiKey != "" {
		cfg.FTaaSAPIKey = *apiKey
	}
	remote := *allowRemote || cfg.AllowRemoteEndpoints

	client, err := train.NewFTaaSClient(cfg.FTaaSAPIAddr, cfg.FTaaSAPIKey, 15*time.Second, remote)
	if err != nil {
		return err
	}
	jobs, err := client.ListJobs(context.Background(), *limit)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jobs)
}

func runTrainActivate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("train activate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	adapterPath := fs.String("adapter-path", "", "Relative LoRA adapter path under ml/data/artifacts/")
	baseModel := fs.String("base-model", "", "Allowlisted base model matching the adapter")
	jobID := fs.String("job-id", "", "Optional originating FTaaS job ID")
	sentinelHTTP := fs.String("sentinel-http", "", "Optional running Sentinel HTTP URL for live POST /adapter hot-swap")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback Sentinel endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	if *baseModel != "" {
		cfg.BaseModel = *baseModel
	}
	remote := *allowRemote || cfg.AllowRemoteEndpoints

	state := train.ActiveAdapter{
		JobID:       strings.TrimSpace(*jobID),
		BaseModel:   cfg.BaseModel,
		AdapterPath: strings.TrimSpace(*adapterPath),
		ActivatedAt: time.Now().UTC(),
	}
	daemonSavedSameDir := false
	if strings.TrimSpace(*sentinelHTTP) != "" {
		token := *authToken
		if token == "" {
			token = cfg.AuthToken
		}
		daemonDir, err := train.NotifyDaemonAdapter(context.Background(), *sentinelHTTP, token, state, remote)
		if err != nil {
			return err
		}
		daemonSavedSameDir = sameCleanDir(daemonDir, cfg.DataDir)
	}
	if !daemonSavedSameDir {
		if err := train.SaveActiveAdapter(cfg.DataDir, state); err != nil {
			return err
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(state)
}

func sameCleanDir(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	absA, errA := filepath.Abs(a)
	absB, errB := filepath.Abs(b)
	if errA == nil && errB == nil {
		if evalA, err := filepath.EvalSymlinks(absA); err == nil {
			absA = evalA
		}
		if evalB, err := filepath.EvalSymlinks(absB); err == nil {
			absB = evalB
		}
		return filepath.Clean(absA) == filepath.Clean(absB)
	}
	return filepath.Clean(a) == filepath.Clean(b)
}
