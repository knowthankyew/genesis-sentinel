package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/pipeline"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
	"github.com/knowthankyew/genesis-sentinel/internal/train"
)

func TestExecuteAdapterCLICommandsEndToEnd(t *testing.T) {
	dataDir := t.TempDir()

	gemmaHealthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/healthz" {
			_, _ = w.Write([]byte(`{"status":"Healthy","baseModel":"google/gemma-2-2b-it","baseModelLoaded":true,"backend":"pytorch-peft"}`))
			return
		}
		_, _ = w.Write([]byte(`{"baseModel":"google/gemma-2-2b-it","completion":"[RECON-SCAN] severity=HIGH mitre=TA0043 explanation=ok"}`))
	}))
	defer gemmaHealthSrv.Close()

	ruleEng, err := rules.NewEngine(rules.DefaultRulePack())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.TriageMode = "http"
	cfg.InferenceAddr = gemmaHealthSrv.URL
	cfg.EscalationMode = "off"
	cfg.EscalationInferenceAddr = gemmaHealthSrv.URL
	cfg.EscalationBaseModel = model.ModelGemma22BIT

	pipe := pipeline.New(cfg, ruleEng, emit.NopSink{}, "file")
	daemonSrv := httptest.NewServer(newWatchHTTPHandler(pipe, "cli-secret"))
	defer daemonSrv.Close()

	var out, errBuf bytes.Buffer
	// 1. Live swap on escalation slot with --verify and --enable
	if err := ExecuteWithOutput([]string{
		"adapter", "swap",
		"--data-dir", dataDir,
		"--slot", "escalation",
		"--adapter-path", "artifacts/gemma-1/model_adapters",
		"--job-id", "job-g1",
		"--verify",
		"--enable",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "cli-secret",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter swap v1 failed: %v stderr=%s", err, errBuf.String())
	}

	// 2. Live swap v2 on escalation slot
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "swap",
		"--data-dir", dataDir,
		"--slot", "escalation",
		"--adapter-path", "artifacts/gemma-2/model_adapters",
		"--job-id", "job-g2",
		"--verify",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "cli-secret",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter swap v2 failed: %v stderr=%s", err, errBuf.String())
	}

	// 3. Query status + history
	out.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "status",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "cli-secret",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter status failed: %v", err)
	}
	var statusResp train.AdapterStatusResponse
	if err := json.Unmarshal(out.Bytes(), &statusResp); err != nil {
		t.Fatalf("decode adapter status JSON: %v", err)
	}
	if !statusResp.EscalationEnabled || statusResp.Escalation == nil ||
		statusResp.Escalation.AdapterPath != "artifacts/gemma-2/model_adapters" || !statusResp.Escalation.HasRollback {
		t.Fatalf("unexpected live adapter status: %+v", statusResp)
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "history",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "cli-secret",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter history failed: %v", err)
	}
	if !strings.Contains(out.String(), "artifacts/gemma-2/model_adapters") {
		t.Fatalf("expected swap history output to contain gemma-2, got %s", out.String())
	}

	// 4. Live rollback restores gemma-1 cleanly
	out.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "rollback",
		"--data-dir", dataDir,
		"--slot", "escalation",
		"--verify",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "cli-secret",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter rollback failed: %v stderr=%s", err, errBuf.String())
	}
	if st := pipe.Stats(); st.EscalationAdapter != "artifacts/gemma-1/model_adapters" {
		t.Fatalf("expected rollback to restore gemma-1, got %q", st.EscalationAdapter)
	}

	// 5. Deactivate escalation cleanly via CLI
	out.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "deactivate",
		"--data-dir", dataDir,
		"--slot", "escalation",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "cli-secret",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter deactivate failed: %v stderr=%s", err, errBuf.String())
	}
	if st := pipe.Stats(); st.EscalationAdapter != "" {
		t.Fatalf("expected deactivate to clear escalation adapter, got %q", st.EscalationAdapter)
	}

	// 6. Offline status inspects manifest cleanly
	out.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "status",
		"--data-dir", dataDir,
	}, &out, &errBuf); err != nil {
		t.Fatalf("offline adapter status failed: %v", err)
	}
	if !strings.Contains(out.String(), filepath.Base(dataDir)) && !strings.Contains(out.String(), "manifest_present") {
		t.Fatalf("unexpected offline adapter status: %s", out.String())
	}
}

func TestExecuteScanWithDualTierEscalationFlags(t *testing.T) {
	smolSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","completion":"[NEEDS-REVIEW] severity=MEDIUM mitre=NONE explanation=uncertain scan"}`))
	}))
	defer smolSrv.Close()

	gemmaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"baseModel":"google/gemma-2-2b-it","adapterPath":"artifacts/gemma-test/model_adapters","completion":"[AUTH-BRUTEFORCE] severity=CRITICAL mitre=TA0006 explanation=repeated SSH failures confirmed by Gemma"}`))
	}))
	defer gemmaSrv.Close()

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{
		"scan",
		"--synthetic", "50",
		"--seed", "42",
		"--triage-mode", "http",
		"--inference-http", smolSrv.URL,
		"--escalation-mode", "http",
		"--escalation-inference-http", gemmaSrv.URL,
		"--escalation-adapter-path", "artifacts/gemma-test/model_adapters",
		"--escalation-policy", "always",
		"--json",
	}, &out, &errBuf); err != nil {
		t.Fatalf("scan with escalation flags failed: %v stderr=%s", err, errBuf.String())
	}
	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode ScanReport JSON: %v", err)
	}
	if rep.EscalationMode != "http" || rep.EscalationsTriggered == 0 || rep.EscalationEvaluated == 0 {
		t.Fatalf("expected active escalation metrics in ScanReport, got %+v", rep)
	}
}

func TestExecuteTrainSubmitSelectsEscalationModelAndRollbackMirrorsDaemon(t *testing.T) {
	// 1. Verify `train submit --slot escalation` defaults baseModel to cfg.EscalationBaseModel
	// and preserves existing primary manifest entries on activation.
	dataDir := t.TempDir()
	if _, err := train.UpdateActiveAdapterSlot(dataDir, train.SlotPrimary, train.AdapterSlot{
		JobID:       "existing-primary",
		BaseModel:   model.ModelSmolLM2135MInstruct,
		AdapterPath: "artifacts/existing-primary/model_adapters",
	}); err != nil {
		t.Fatalf("seed primary slot: %v", err)
	}

	var seenBaseModel string
	ftaasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				t.Errorf("ParseMultipartForm: %v", err)
			}
			seenBaseModel = r.FormValue("baseModel")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"jobId":"job-esc-9","jobName":"esc","baseModel":"` + seenBaseModel + `","status":"queued","surprisalPreflightStatus":"skipped"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job-esc-9":
			_, _ = w.Write([]byte(`{"jobId":"job-esc-9","status":"completed","baseModel":"` + seenBaseModel + `","adapterPath":"artifacts/job-esc-9/model_adapters","datasetHash":"sha256:abc"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ftaasSrv.Close()

	fbDir := t.TempDir()
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{
		"train", "submit",
		"--data-dir", dataDir,
		"--feedback-dir", fbDir,
		"--ftaas-http", ftaasSrv.URL,
		"--seed-per-class", "1",
		"--preflight=false",
		"--wait",
		"--activate",
		"--slot", "escalation",
		"--poll-interval", "10ms",
		"--json",
	}, &out, &errBuf); err != nil {
		t.Fatalf("train submit --slot escalation failed: %v stderr=%s", err, errBuf.String())
	}
	if seenBaseModel != model.ModelGemma22BIT {
		t.Fatalf("expected escalation training submission to select %s, got %q", model.ModelGemma22BIT, seenBaseModel)
	}
	loaded, exists, err := train.LoadActiveAdapter(dataDir)
	if err != nil || !exists || loaded.AdapterPath != "artifacts/existing-primary/model_adapters" ||
		loaded.Escalation == nil || loaded.Escalation.AdapterPath != "artifacts/job-esc-9/model_adapters" {
		t.Fatalf("expected both primary and escalation slots preserved, got %+v err=%v", loaded, err)
	}

	// 2. Verify `adapter rollback` against a loopback daemon reporting its own daemonDir
	// rolls back daemonDir cleanly WITHOUT mutating an unrelated localDivergedDir ([6]).
	daemonDir := t.TempDir()
	localDivergedDir := t.TempDir()
	for _, path := range []string{"artifacts/d-1/model_adapters", "artifacts/d-2/model_adapters"} {
		if _, err := train.UpdateActiveAdapterSlot(daemonDir, train.SlotPrimary, train.AdapterSlot{
			BaseModel:   model.ModelSmolLM2135MInstruct,
			AdapterPath: path,
		}); err != nil {
			t.Fatalf("seed daemon dir: %v", err)
		}
	}
	if _, err := train.UpdateActiveAdapterSlot(localDivergedDir, train.SlotPrimary, train.AdapterSlot{
		BaseModel:   model.ModelSmolLM2135MInstruct,
		AdapterPath: "artifacts/local-only/model_adapters",
	}); err != nil {
		t.Fatalf("seed local dir: %v", err)
	}

	ruleEng, _ := rules.NewEngine(rules.DefaultRulePack())
	dCfg := config.DefaultConfig()
	dCfg.DataDir = daemonDir
	dCfg.TriageMode = "off"
	dPipe := pipeline.New(dCfg, ruleEng, emit.NopSink{}, "file")
	daemonSrv := httptest.NewServer(newWatchHTTPHandler(dPipe, "tok"))
	defer daemonSrv.Close()

	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "rollback",
		"--data-dir", localDivergedDir,
		"--slot", "primary",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "tok",
	}, &out, &errBuf); err != nil {
		t.Fatalf("daemon rollback failed: %v stderr=%s", err, errBuf.String())
	}
	daemonLoaded, _, err := train.LoadActiveAdapter(daemonDir)
	if err != nil || daemonLoaded.AdapterPath != "artifacts/d-1/model_adapters" {
		t.Fatalf("expected daemonDir rolled back to d-1, got %+v err=%v", daemonLoaded, err)
	}
	untouchedLocal, _, err := train.LoadActiveAdapter(localDivergedDir)
	if err != nil || untouchedLocal.AdapterPath != "artifacts/local-only/model_adapters" {
		t.Fatalf("expected unrelated localDivergedDir untouched at local-only, got %+v err=%v", untouchedLocal, err)
	}
}

func TestExecuteAdapterPositionalArgsAndIsolatedLocalManifest(t *testing.T) {
	var out, errBuf bytes.Buffer
	for _, args := range [][]string{
		{"adapter", "rollback", "escalation"},
		{"adapter", "deactivate", "escalation"},
		{"adapter", "history", "extra"},
	} {
		out.Reset()
		errBuf.Reset()
		err := ExecuteWithOutput(args, &out, &errBuf)
		if err == nil || !strings.Contains(err.Error(), "unexpected positional argument") {
			t.Fatalf("expected positional argument rejection for %v, got %v", args, err)
		}
	}

	daemonDir := t.TempDir()
	otherLocalDir := t.TempDir()
	if _, err := train.UpdateActiveAdapterSlot(otherLocalDir, train.SlotPrimary, train.AdapterSlot{
		BaseModel:   model.ModelSmolLM2135MInstruct,
		AdapterPath: "artifacts/other-instance/model_adapters",
	}); err != nil {
		t.Fatalf("seed otherLocalDir: %v", err)
	}

	ruleEng, _ := rules.NewEngine(rules.DefaultRulePack())
	dCfg := config.DefaultConfig()
	dCfg.DataDir = daemonDir
	dCfg.TriageMode = "off"
	dPipe := pipeline.New(dCfg, ruleEng, emit.NopSink{}, "file")
	daemonSrv := httptest.NewServer(newWatchHTTPHandler(dPipe, "tok"))
	defer daemonSrv.Close()

	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"adapter", "swap",
		"--data-dir", otherLocalDir,
		"--slot", "primary",
		"--adapter-path", "artifacts/daemon-v2/model_adapters",
		"--sentinel-http", daemonSrv.URL,
		"--auth-token", "tok",
	}, &out, &errBuf); err != nil {
		t.Fatalf("adapter swap against loopback daemon failed: %v stderr=%s", err, errBuf.String())
	}
	daemonLoaded, _, err := train.LoadActiveAdapter(daemonDir)
	if err != nil || daemonLoaded.AdapterPath != "artifacts/daemon-v2/model_adapters" {
		t.Fatalf("expected daemonDir updated to daemon-v2, got %+v err=%v", daemonLoaded, err)
	}
	localLoaded, _, err := train.LoadActiveAdapter(otherLocalDir)
	if err != nil || localLoaded.AdapterPath != "artifacts/other-instance/model_adapters" {
		t.Fatalf("expected unrelated otherLocalDir untouched by loopback daemon swap, got %+v err=%v", localLoaded, err)
	}

	// Remote daemon rollback & deactivate with omitted --data-dir must leave the default local
	// manifest intact rather than silently mutating local state ([3]).
	defaultDataDir := t.TempDir()
	cfgFile := filepath.Join(t.TempDir(), "sentinel.json")
	if err := os.WriteFile(cfgFile, []byte(`{"data_dir":`+strconv.Quote(defaultDataDir)+`,"allow_remote_endpoints":true}`), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := train.SaveActiveAdapter(defaultDataDir, train.ActiveAdapter{
		BaseModel: model.ModelSmolLM2135MInstruct, AdapterPath: "artifacts/local-keep/model_adapters",
	}); err != nil {
		t.Fatalf("seed defaultDataDir: %v", err)
	}
	if !shouldSkipLocalManifestMirror("https://remote-daemon.example.com:9090", "", false) {
		t.Fatal("expected remote daemon operation with omitted --data-dir to skip mutating local manifest")
	}
	if shouldSkipLocalManifestMirror("https://remote-daemon.example.com:9090", "", true) {
		t.Fatal("expected remote daemon operation with explicit --data-dir to update explicit local manifest")
	}
	keptLocal, _, err := train.LoadActiveAdapter(defaultDataDir)
	if err != nil || keptLocal.AdapterPath != "artifacts/local-keep/model_adapters" {
		t.Fatalf("expected defaultDataDir preserved, got %+v err=%v", keptLocal, err)
	}
}

func TestExecuteAdapterRollbackMirrorFailureAndTruncatedResponse(t *testing.T) {
	// 1. Daemon rollback succeeds on server, local mirror fails -> operator error must warn NOT to re-run rollback ([2]).
	rbSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"rolled_back","slot":"primary","action":"rollback","job_id":"rb-1","base_model":"SmolLM2-135M-Instruct","adapter_path":"artifacts/rb-1/model_adapters","triage_enabled":true,"escalation_enabled":false,"primary":{"slot":"primary","mode":"http","enabled":true,"base_model":"SmolLM2-135M-Instruct","adapter_path":"artifacts/rb-1/model_adapters","job_id":"rb-1","op_seq":2,"history_id":"h-1"}}` + "\n"))
	}))
	defer rbSrv.Close()

	blockerFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blockerFile, []byte("file"), 0600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}
	var out, errBuf bytes.Buffer
	err := ExecuteWithOutput([]string{
		"adapter", "rollback",
		"--slot", "primary",
		"--data-dir", blockerFile,
		"--sentinel-http", rbSrv.URL,
	}, &out, &errBuf)
	if err == nil || !strings.Contains(err.Error(), "do NOT re-run 'sentinel adapter rollback'") {
		t.Fatalf("expected non-retry warning when daemon rollback succeeded but local mirror failed, got: %v", err)
	}

	// 2. Truncated daemon rollback response (Truncated: true) must NOT overwrite or corrupt local manifest ([13]).
	truncSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"rolled_back","slot":"primary","action":"rollback","truncated":true,"triage_enabled":true,"escalation_enabled":false}` + "\n"))
	}))
	defer truncSrv.Close()

	localDir := t.TempDir()
	if err := train.SaveActiveAdapter(localDir, train.ActiveAdapter{
		JobID:       "before-trunc",
		BaseModel:   model.ModelSmolLM2135MInstruct,
		AdapterPath: "artifacts/before-trunc/model_adapters",
	}); err != nil {
		t.Fatalf("seed localDir: %v", err)
	}
	out.Reset()
	errBuf.Reset()
	err = ExecuteWithOutput([]string{
		"adapter", "rollback",
		"--slot", "primary",
		"--data-dir", localDir,
		"--sentinel-http", truncSrv.URL,
	}, &out, &errBuf)
	if err == nil || !strings.Contains(err.Error(), "truncated=true") || !strings.Contains(err.Error(), "do NOT re-run 'sentinel adapter rollback'") {
		t.Fatalf("expected truncated wire error with no-retry guidance, got: %v", err)
	}
	after, _, loadErr := train.LoadActiveAdapter(localDir)
	if loadErr != nil || after.AdapterPath != "artifacts/before-trunc/model_adapters" {
		t.Fatalf("expected localDir preserved untouched on truncated response, got %+v err=%v", after, loadErr)
	}
}
