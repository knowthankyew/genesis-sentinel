package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
