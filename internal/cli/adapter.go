package cli

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/train"
)

func runAdapter(args []string, stdout, stderr io.Writer) error {
	action := "status"
	subArgs := args
	if len(args) > 0 {
		first := strings.ToLower(strings.TrimSpace(args[0]))
		if first == "-h" || first == "--help" || !strings.HasPrefix(args[0], "-") {
			action = first
			subArgs = args[1:]
		}
	}

	switch action {
	case "status":
		return runAdapterStatus(subArgs, stdout, stderr)
	case "swap", "activate":
		return runAdapterSwap(subArgs, stdout, stderr)
	case "rollback":
		return runAdapterRollback(subArgs, stdout, stderr)
	case "deactivate":
		return runAdapterDeactivate(subArgs, stdout, stderr)
	case "history":
		return runAdapterHistory(subArgs, stdout, stderr)
	case "help", "-h", "--help":
		printAdapterUsage(stdout)
		return nil
	default:
		printAdapterUsage(stderr)
		return fmt.Errorf("unknown adapter subcommand %q (expected: status, swap, rollback, deactivate, or history)", action)
	}
}

func printAdapterUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, `Usage:
  sentinel adapter status [--sentinel-http http://127.0.0.1:8090] [--data-dir dir]
  sentinel adapter swap --adapter-path artifacts/<jobId>/model_adapters [--slot primary|escalation] [--base-model <id>] [--verify] [--enable] [--sentinel-http http://127.0.0.1:8090]
  sentinel adapter rollback [--slot primary|escalation] [--verify] [--enable] [--sentinel-http http://127.0.0.1:8090]
  sentinel adapter deactivate [--slot primary|escalation|all] [--sentinel-http http://127.0.0.1:8090]
  sentinel adapter history [--sentinel-http http://127.0.0.1:8090]`)
}

func resolveDaemonURL(explicit, cfgHTTPAddr string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return s
	}
	addr := strings.TrimSpace(cfgHTTPAddr)
	if addr == "" {
		return ""
	}
	if !strings.Contains(addr, "://") {
		return "http://" + addr
	}
	return addr
}

func resolveAuthToken(explicit, cfgToken string) string {
	if explicit != "" {
		return explicit
	}
	return cfgToken
}

func runAdapterStatus(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("adapter status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	sentinelHTTP := fs.String("sentinel-http", "", "Optional running Sentinel HTTP URL to inspect live runtime slots")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow querying non-loopback Sentinel endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q", fs.Arg(0))
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	remote := *allowRemote || cfg.AllowRemoteEndpoints

	if strings.TrimSpace(*sentinelHTTP) != "" {
		resp, err := train.QueryDaemonAdapterStatus(context.Background(), *sentinelHTTP, resolveAuthToken(*authToken, cfg.AuthToken), remote)
		if err != nil {
			return err
		}
		return writeIndentedJSON(stdout, resp)
	}

	manifest, exists, err := train.LoadActiveAdapter(cfg.DataDir)
	if err != nil && exists {
		return err
	}
	out := map[string]any{
		"source":                    "disk",
		"data_dir":                  cfg.DataDir,
		"manifest_present":          exists,
		"auto_reload_adapter":       cfg.AutoReloadAdapter,
		"triage_mode":               cfg.TriageMode,
		"inference_http":            cfg.InferenceAddr,
		"escalation_mode":           cfg.EscalationMode,
		"escalation_inference_http": cfg.EscalationInferenceAddr,
		"escalation_policy":         cfg.EscalationPolicy,
		"manifest":                  manifest,
	}
	return writeIndentedJSON(stdout, out)
}

func runAdapterHistory(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("adapter history", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	sentinelHTTP := fs.String("sentinel-http", "", "Running Sentinel HTTP URL (defaults to http://<config.http>)")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow querying non-loopback Sentinel endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q", fs.Arg(0))
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	target := resolveDaemonURL(*sentinelHTTP, cfg.HTTPAddr)
	resp, err := train.QueryDaemonAdapterStatus(
		context.Background(),
		target,
		resolveAuthToken(*authToken, cfg.AuthToken),
		*allowRemote || cfg.AllowRemoteEndpoints,
	)
	if err != nil {
		return err
	}
	return writeIndentedJSON(stdout, map[string]any{
		"adapter_swaps_total": resp.AdapterSwapsTotal,
		"recent_swaps":        resp.RecentSwaps,
	})
}

func runAdapterSwap(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("adapter swap", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	slot := fs.String("slot", train.SlotPrimary, "Target adapter slot: primary | escalation")
	adapterPath := fs.String("adapter-path", "", "Relative LoRA adapter path under ml/data/artifacts/")
	baseModel := fs.String("base-model", "", "Allowlisted base model matching the adapter")
	jobID := fs.String("job-id", "", "Optional originating FTaaS job ID")
	datasetHash := fs.String("dataset-hash", "", "Optional training dataset SHA-256")
	sentinelHTTP := fs.String("sentinel-http", "", "Optional running Sentinel HTTP URL for live POST /adapter hot-swap")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback Sentinel endpoint")
	verify := fs.Bool("verify", false, "Verify inference /healthz and base model match before live swap")
	enable := fs.Bool("enable", false, "Enable slot inference client dynamically if it started off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --adapter-path)", fs.Arg(0))
	}

	normSlot, err := train.NormalizeSlot(*slot, false)
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	resolvedModel := strings.TrimSpace(*baseModel)
	if resolvedModel == "" {
		if normSlot == train.SlotEscalation {
			resolvedModel = cfg.EscalationBaseModel
		} else {
			resolvedModel = cfg.BaseModel
		}
	}
	if _, err := model.ValidateBaseModel(resolvedModel); err != nil {
		return err
	}
	cleanAdapter, err := model.ValidateAdapterPath(*adapterPath)
	if err != nil {
		return err
	}
	if cleanAdapter == "" {
		return fmt.Errorf("--adapter-path is required")
	}

	remote := *allowRemote || cfg.AllowRemoteEndpoints
	slotState := train.AdapterSlot{
		JobID:       strings.TrimSpace(*jobID),
		BaseModel:   resolvedModel,
		AdapterPath: cleanAdapter,
		DatasetHash: strings.TrimSpace(*datasetHash),
		ActivatedAt: time.Now().UTC(),
	}
	out, err := activateSlotWithOptionalDaemon(
		context.Background(),
		cfg.DataDir,
		*dataDir != "",
		normSlot,
		slotState,
		strings.TrimSpace(*sentinelHTTP),
		resolveAuthToken(*authToken, cfg.AuthToken),
		remote,
		*verify,
		*enable,
	)
	if err != nil {
		return err
	}
	return writeIndentedJSON(stdout, out)
}

func runAdapterRollback(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("adapter rollback", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	slot := fs.String("slot", train.SlotPrimary, "Target adapter slot: primary | escalation")
	sentinelHTTP := fs.String("sentinel-http", "", "Optional running Sentinel HTTP URL for live rollback")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback Sentinel endpoint")
	verify := fs.Bool("verify", false, "Verify inference /healthz before restoring previous adapter")
	enable := fs.Bool("enable", false, "Enable slot inference client dynamically if it started off")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --slot)", fs.Arg(0))
	}
	normSlot, err := train.NormalizeSlot(*slot, false)
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	remote := *allowRemote || cfg.AllowRemoteEndpoints

	daemonSavedSameDir := false
	daemonRolledBack := false
	var daemonResp train.AdapterStatusResponse
	if strings.TrimSpace(*sentinelHTTP) != "" {
		resp, err := train.DaemonAdapterAction(context.Background(), *sentinelHTTP, resolveAuthToken(*authToken, cfg.AuthToken), train.AdapterSwapRequest{
			Slot:   normSlot,
			Action: train.ActionRollback,
			Verify: *verify,
			Enable: *enable,
		}, remote)
		if err != nil {
			return err
		}
		daemonRolledBack = true
		daemonResp = resp
		daemonSavedSameDir = shouldSkipLocalManifestMirror(*sentinelHTTP, resp.DataDir, *dataDir != "")
	}

	var manifest train.ActiveAdapter
	if !daemonSavedSameDir {
		if daemonRolledBack {
			if daemonResp.Truncated {
				return fmt.Errorf("running daemon already rolled back %s slot (do NOT re-run 'sentinel adapter rollback', as the daemon already swapped previous; inspect with 'sentinel adapter status'), but slot metadata exceeded 64 KiB wire limit (truncated=true); synchronize local manifest in %q manually", normSlot, cfg.DataDir)
			}
			slotStatus := daemonResp.Primary
			if normSlot == train.SlotEscalation {
				slotStatus = daemonResp.Escalation
			}
			updated, syncErr := train.MirrorDaemonSlotToManifest(
				cfg.DataDir,
				normSlot,
				slotStatus,
				daemonResp.BaseModel,
				daemonResp.AdapterPath,
				daemonResp.JobID,
			)
			if syncErr != nil {
				return fmt.Errorf("running daemon already rolled back %s slot (do NOT re-run 'sentinel adapter rollback', as the daemon already swapped previous; inspect with 'sentinel adapter status'), but synchronizing local manifest failed: %w", normSlot, syncErr)
			}
			manifest = updated
		} else {
			updated, _, rbErr := train.RollbackActiveAdapterSlot(cfg.DataDir, normSlot)
			if rbErr != nil {
				return rbErr
			}
			manifest = updated
		}
	}
	if daemonRolledBack {
		return writeIndentedJSON(stdout, daemonResp)
	}
	return writeIndentedJSON(stdout, manifest)
}

func runAdapterDeactivate(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("adapter deactivate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", "", "Path to sentinel.json configuration file")
	dataDir := fs.String("data-dir", "", "Override Sentinel data directory")
	slot := fs.String("slot", train.SlotPrimary, "Target adapter slot: primary | escalation | all")
	sentinelHTTP := fs.String("sentinel-http", "", "Optional running Sentinel HTTP URL for live deactivation")
	authToken := fs.String("auth-token", "", "Optional Bearer token for running Sentinel HTTP API")
	allowRemote := fs.Bool("allow-remote", false, "Allow non-loopback Sentinel endpoint")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional argument %q (use flags such as --slot)", fs.Arg(0))
	}
	normSlot, err := train.NormalizeSlot(*slot, true)
	if err != nil {
		return err
	}
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if *dataDir != "" {
		cfg.DataDir = *dataDir
	}
	remote := *allowRemote || cfg.AllowRemoteEndpoints

	daemonSavedSameDir := false
	var daemonResp train.AdapterStatusResponse
	daemonCalled := false
	if strings.TrimSpace(*sentinelHTTP) != "" {
		resp, err := train.DeactivateDaemonAdapter(context.Background(), *sentinelHTTP, resolveAuthToken(*authToken, cfg.AuthToken), normSlot, remote)
		if err != nil {
			return err
		}
		daemonCalled = true
		daemonResp = resp
		daemonSavedSameDir = shouldSkipLocalManifestMirror(*sentinelHTTP, resp.DataDir, *dataDir != "")
	}
	if !daemonSavedSameDir {
		updated, changed, err := train.DeactivateActiveAdapterSlot(cfg.DataDir, normSlot)
		if err != nil {
			if daemonCalled {
				return fmt.Errorf("running daemon deactivated %s slot, but updating local manifest failed: %w", normSlot, err)
			}
			return err
		}
		if daemonCalled {
			return writeIndentedJSON(stdout, daemonResp)
		}
		return writeIndentedJSON(stdout, map[string]any{
			"status":   "deactivated",
			"slot":     normSlot,
			"changed":  changed,
			"manifest": updated,
		})
	}
	return writeIndentedJSON(stdout, daemonResp)
}

func shouldSkipLocalManifestMirror(sentinelHTTP, daemonDataDir string, dataDirExplicit bool) bool {
	if security.IsLoopbackEndpoint(sentinelHTTP) && strings.TrimSpace(daemonDataDir) != "" {
		return true
	}
	return !security.IsLoopbackEndpoint(sentinelHTTP) && !dataDirExplicit
}

func activateSlotWithOptionalDaemon(
	ctx context.Context,
	dataDir string,
	dataDirExplicit bool,
	slot string,
	slotState train.AdapterSlot,
	sentinelHTTP, authToken string,
	allowRemote, verify, enable bool,
) (any, error) {
	normSlot, err := train.NormalizeSlot(slot, false)
	if err != nil {
		return nil, err
	}
	daemonSavedSameDir := false
	daemonActivated := false
	var daemonResp train.AdapterStatusResponse

	if sentinelHTTP != "" {
		if normSlot == train.SlotPrimary && !verify && !enable {
			daemonDir, notifyErr := train.NotifyDaemonAdapter(ctx, sentinelHTTP, authToken, train.ActiveAdapter{
				JobID:       slotState.JobID,
				BaseModel:   slotState.BaseModel,
				AdapterPath: slotState.AdapterPath,
				DatasetHash: slotState.DatasetHash,
				ActivatedAt: slotState.ActivatedAt,
			}, allowRemote)
			if notifyErr != nil {
				return nil, notifyErr
			}
			daemonActivated = true
			daemonResp = train.AdapterStatusResponse{
				Status:      "activated",
				Slot:        normSlot,
				JobID:       slotState.JobID,
				BaseModel:   slotState.BaseModel,
				AdapterPath: slotState.AdapterPath,
				DataDir:     daemonDir,
			}
		} else {
			resp, notifyErr := train.DaemonAdapterAction(ctx, sentinelHTTP, authToken, train.AdapterSwapRequest{
				Slot:        normSlot,
				Action:      train.ActionActivate,
				JobID:       slotState.JobID,
				BaseModel:   slotState.BaseModel,
				AdapterPath: slotState.AdapterPath,
				DatasetHash: slotState.DatasetHash,
				Verify:      verify,
				Enable:      enable,
			}, allowRemote)
			if notifyErr != nil {
				return nil, notifyErr
			}
			daemonActivated = true
			daemonResp = resp
		}
		daemonSavedSameDir = shouldSkipLocalManifestMirror(sentinelHTTP, daemonResp.DataDir, dataDirExplicit)
	}

	if !daemonSavedSameDir {
		var (
			updated train.ActiveAdapter
			err     error
		)
		if daemonActivated {
			if daemonResp.Truncated {
				return nil, fmt.Errorf("running Sentinel daemon already activated adapter %q (job %s), but response metadata exceeded 64 KiB wire limit (truncated=true); inspect with 'sentinel adapter status' and synchronize %q manually",
					slotState.AdapterPath, slotState.JobID, dataDir)
			}
			slotStatus := daemonResp.Primary
			if normSlot == train.SlotEscalation {
				slotStatus = daemonResp.Escalation
			}
			if slotStatus == nil {
				slotStatus = &train.SlotStatus{
					Slot:        normSlot,
					JobID:       slotState.JobID,
					BaseModel:   slotState.BaseModel,
					AdapterPath: slotState.AdapterPath,
					DatasetHash: slotState.DatasetHash,
					SwappedAt:   slotState.ActivatedAt,
				}
			}
			updated, err = train.MirrorDaemonSlotToManifest(dataDir, normSlot, slotStatus, slotState.BaseModel, slotState.AdapterPath, slotState.JobID)
		} else {
			updated, err = train.UpdateActiveAdapterSlot(dataDir, normSlot, slotState)
		}
		if err != nil {
			if daemonActivated {
				return nil, fmt.Errorf("running Sentinel daemon already activated adapter %q (job %s), but saving local manifest to %q failed: %w",
					slotState.AdapterPath, slotState.JobID, dataDir, err)
			}
			return nil, err
		}
		if daemonActivated {
			return daemonResp, nil
		}
		return updated, nil
	}
	return daemonResp, nil
}

func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
