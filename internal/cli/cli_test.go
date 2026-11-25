package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/pipeline"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
	"github.com/knowthankyew/genesis-sentinel/internal/surprisal"
)

func TestExecuteVersionAndHelp(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"version"}, &out, &errBuf); err != nil {
		t.Fatalf("version command failed: %v", err)
	}
	if !strings.Contains(out.String(), Version) {
		t.Fatalf("expected version %q in output, got %q", Version, out.String())
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{"help"}, &out, &errBuf); err != nil {
		t.Fatalf("help command failed: %v", err)
	}
	if !strings.Contains(out.String(), "Genesis Sentinel") {
		t.Fatalf("unexpected help output: %q", out.String())
	}
}

func TestExecuteConfigRedactsTokens(t *testing.T) {
	t.Setenv("SENTINEL_AUTH_TOKEN", "super-secret-sentinel-token")
	t.Setenv("SENTINEL_GENESIS_AUTH_TOKEN", "super-secret-genesis-token")
	t.Setenv("SENTINEL_FTAAS_API_KEY", "super-secret-ftaas-key")

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"config"}, &out, &errBuf); err != nil {
		t.Fatalf("config command failed: %v", err)
	}

	if strings.Contains(out.String(), "super-secret") {
		t.Fatal("config output leaked raw auth token")
	}

	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("config output is not valid JSON: %v", err)
	}
	if decoded["auth_token"] != "[REDACTED]" || decoded["genesis_auth_token"] != "[REDACTED]" || decoded["ftaas_api_key"] != "[REDACTED]" {
		t.Fatalf("expected tokens to be redacted, got auth_token=%v genesis_auth_token=%v ftaas_api_key=%v",
			decoded["auth_token"], decoded["genesis_auth_token"], decoded["ftaas_api_key"])
	}
}

func TestExecuteUnknownCommandAndRequiredFlags(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"bogus"}, &out, &errBuf); err == nil {
		t.Fatal("expected error for unknown command")
	}
	// Bare `feedback` without --label fails validation cleanly.
	if err := ExecuteWithOutput([]string{"feedback"}, &out, &errBuf); err == nil {
		t.Fatal("expected validation error for feedback without --label")
	}
	// Bare `train` with empty data dir fails cleanly when no dataset/feedback exists.
	if err := ExecuteWithOutput([]string{"train", "--data-dir", t.TempDir()}, &out, &errBuf); err == nil {
		t.Fatal("expected validation error for train without dataset or curated feedback")
	}
}

func TestExecuteScanSyntheticJSON(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--synthetic", "5000", "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan --synthetic failed: %v (stderr=%s)", err, errBuf.String())
	}

	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.LinesRead != 5000 {
		t.Fatalf("LinesRead = %d, want 5000", rep.LinesRead)
	}
	if rep.AlertsEmitted < 6 {
		t.Fatalf("expected >= 6 alerts covering all starter classes, got %d", rep.AlertsEmitted)
	}
	if rep.CollapseRatio < 100 {
		t.Fatalf("expected strong collapse ratio (>100x), got %.2f", rep.CollapseRatio)
	}
}

func TestExecuteScanFileContinuesPastOversizedLine(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "mixed.log")
	oversized := strings.Repeat("X", 1024*1024+128) + "\n"
	content := `{"timestamp":1763996400,"service":"api","level":"INFO","message":"before oversized"}` + "\n" +
		oversized +
		`{"timestamp":1763996401,"service":"nginx","level":"WARN","message":"GET /../../etc/passwd HTTP/1.1 403"}` + "\n"
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("write mixed.log: %v", err)
	}

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--file", tmpFile, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan --file failed: %v", err)
	}
	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.OversizedLines != 1 || rep.LinesRead != 2 || rep.AlertsEmitted != 1 {
		t.Fatalf("expected OversizedLines=1 LinesRead=2 AlertsEmitted=1, got %+v", rep)
	}
}

func TestExecuteScanFileExactMaxFramePayloadBoundaries(t *testing.T) {
	// Verify exact 1 MiB payload passes with LF, CRLF, and EOF, while 1 MiB + 1 byte is skipped.
	prefix := `{"timestamp":1763996400,"service":"api","level":"INFO","message":"`
	suffix := `"}`
	padLen := 1024*1024 - len(prefix) - len(suffix)
	exactPayload := prefix + strings.Repeat("a", padLen) + suffix
	overPayload := prefix + strings.Repeat("b", padLen+1) + suffix

	tmpFile := filepath.Join(t.TempDir(), "bounds.log")
	content := exactPayload + "\n" + exactPayload + "\r\n" + overPayload + "\n" + exactPayload
	if err := os.WriteFile(tmpFile, []byte(content), 0600); err != nil {
		t.Fatalf("write bounds.log: %v", err)
	}

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--file", tmpFile, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan bounds.log failed: %v", err)
	}
	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.LinesRead != 3 || rep.OversizedLines != 1 {
		t.Fatalf("expected 3 exact-limit payloads read (LF, CRLF, EOF) and 1 oversized skipped, got %+v", rep)
	}
}

func TestExecuteStatsEscapesControlBytes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("raw \x1b[31mred\x1b[0m text"))
	}))
	defer srv.Close()

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"stats", "--http", srv.URL}, &out, &errBuf); err != nil {
		t.Fatalf("stats non-JSON failed: %v", err)
	}
	if strings.ContainsRune(out.String(), '\x1b') {
		t.Fatalf("stats output leaked raw terminal ESC byte: %q", out.String())
	}
}

func TestExecuteWatchRejectsNonPositivePollInterval(t *testing.T) {
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"watch", "--poll-interval", "0s"}, &out, &errBuf); err == nil {
		t.Fatal("expected watch --poll-interval=0s to return error")
	}
}

func TestExecuteStatsAndBurn(t *testing.T) {
	// Test `sentinel stats` against loopback httptest server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stats" && r.Header.Get("Authorization") == "Bearer tok-stat" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"lines_read":1234,"alerts_emitted":2}`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"stats", "--http", srv.URL, "--auth-token", "tok-stat"}, &out, &errBuf); err != nil {
		t.Fatalf("stats command failed: %v", err)
	}
	if !strings.Contains(out.String(), `"lines_read": 1234`) {
		t.Fatalf("unexpected stats output: %s", out.String())
	}

	// Test `sentinel burn` requires -y, then purges local state cleanly
	tmp := filepath.Join(t.TempDir(), ".genesis-sentinel")
	t.Setenv("SENTINEL_DATA_DIR", tmp)
	if err := os.MkdirAll(tmp, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "cursor.json"), []byte(`{"segment_id":2}`), 0600); err != nil {
		t.Fatalf("write cursor: %v", err)
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn"}, &out, &errBuf); err == nil {
		t.Fatal("expected burn without -y to fail")
	}

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn", "-y"}, &out, &errBuf); err != nil {
		t.Fatalf("burn -y failed: %v", err)
	}
	if !strings.Contains(out.String(), `"status": "burned"`) {
		t.Fatalf("unexpected burn output: %s", out.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, "cursor.json")); !os.IsNotExist(err) {
		t.Fatal("cursor.json survived burn -y")
	}

	// Plain-text OR non-burned HTTP 200 responses from --http burn endpoint must return an error.
	badBurnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK plain text not a burn report"))
	}))
	defer badBurnSrv.Close()

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn", "-y", "--http", badBurnSrv.URL}, &out, &errBuf); err == nil {
		t.Fatal("expected burn --http to fail on non-JSON BurnReport response")
	}

	okStatusSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer okStatusSrv.Close()

	out.Reset()
	if err := ExecuteWithOutput([]string{"burn", "-y", "--http", okStatusSrv.URL}, &out, &errBuf); err == nil {
		t.Fatal("expected burn --http to fail when status != 'burned' or required BurnReport fields are missing")
	}
}

func TestExecuteDataSubcommands(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), ".genesis-sentinel")
	t.Setenv("SENTINEL_DATA_DIR", tmp)

	// 1. `sentinel data path`
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"data", "path"}, &out, &errBuf); err != nil {
		t.Fatalf("data path failed: %v", err)
	}
	if strings.TrimSpace(out.String()) != tmp {
		t.Fatalf("data path = %q, want %q", strings.TrimSpace(out.String()), tmp)
	}

	// 2. `sentinel data status` before creation
	out.Reset()
	if err := ExecuteWithOutput([]string{"data", "status"}, &out, &errBuf); err != nil {
		t.Fatalf("data status failed: %v", err)
	}
	var st dataDirStatus
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if st.Exists || st.FileCount != 0 {
		t.Fatalf("expected non-existent empty dir, got %+v", st)
	}

	// 3. `sentinel data open` uses injectable opener and creates dir cleanly
	var opened string
	origOpen := openDirFn
	openDirFn = func(dir string) error {
		opened = dir
		return nil
	}
	defer func() { openDirFn = origOpen }()

	out.Reset()
	if err := ExecuteWithOutput([]string{"data", "open"}, &out, &errBuf); err != nil {
		t.Fatalf("data open failed: %v", err)
	}
	if opened != tmp {
		t.Fatalf("openDirFn called with %q, want %q", opened, tmp)
	}

	// 4. Write a sample file and verify `sentinel data status` counts bytes accurately
	if err := os.WriteFile(filepath.Join(tmp, "cursor.json"), []byte(`{"seg":1}`), 0600); err != nil {
		t.Fatalf("failed writing sample file: %v", err)
	}
	out.Reset()
	if err := ExecuteWithOutput([]string{"data", "status"}, &out, &errBuf); err != nil {
		t.Fatalf("data status failed: %v", err)
	}
	st = dataDirStatus{}
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("invalid status JSON: %v", err)
	}
	if !st.Exists || st.FileCount != 1 || st.TotalBytes != 9 {
		t.Fatalf("unexpected data status after write: %+v", st)
	}
}

func TestExecuteScanWithPreloadedBaselineSurfacesTier1Anomaly(t *testing.T) {
	dir := t.TempDir()
	baselinePath := filepath.Join(dir, "baseline.json")

	// Preload 25 benign baseline windows into baseline.json.
	eng := surprisal.NewEngine(surprisal.Options{BaselineWindowSize: 100, WarmupMinCases: 20})
	for i := 0; i < 25; i++ {
		eng.LearnBaseline(model.TemplateWindow{
			TemplateID:    "tmpl-health",
			Template:      "GET /healthz HTTP/1.1 200 <DUR>",
			Service:       "api",
			Level:         "INFO",
			Count:         10,
			FirstSeenUnix: 1763996000,
			LastSeenUnix:  1763996010,
			SampleLine:    "GET /healthz HTTP/1.1 200 4ms",
		})
	}
	if err := eng.SaveToFile(baselinePath, true); err != nil {
		t.Fatalf("SaveToFile baseline: %v", err)
	}

	// Write a log file containing a normal-entropy novel unseen anomaly that matches ZERO Tier 0 static rules.
	logPath := filepath.Join(dir, "novel.log")
	logLine := `{"timestamp":1763996500,"service":"unseen-daemon","level":"ERROR","message":"unexpected outbound relay connection reset by peer during background archive sync retry"}` + "\n"
	if err := os.WriteFile(logPath, []byte(logLine), 0600); err != nil {
		t.Fatalf("write novel.log: %v", err)
	}

	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"scan", "--file", logPath, "--baseline", baselinePath, "--json"}, &out, &errBuf); err != nil {
		t.Fatalf("scan --baseline failed: %v (stderr=%s)", err, errBuf.String())
	}

	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if rep.SurprisalAnomalies < 1 || rep.AlertsEmitted < 1 {
		t.Fatalf("expected Tier 1 surprisal anomaly alert with preloaded baseline, got %+v", rep)
	}
	foundTier1 := false
	for _, a := range rep.Alerts {
		if a.Tier == "tier1" && a.SurprisalNats >= 5.0 {
			foundTier1 = true
		}
	}
	if !foundTier1 {
		t.Fatalf("expected a tier1 alert with surprisal_nats >= 5.0, got alerts=%+v", rep.Alerts)
	}

	// Explicitly requesting a nonexistent --baseline file must fail closed.
	out.Reset()
	errBuf.Reset()
	missingPath := filepath.Join(dir, "does-not-exist.json")
	if err := ExecuteWithOutput([]string{"scan", "--file", logPath, "--baseline", missingPath}, &out, &errBuf); err == nil {
		t.Fatal("expected scan --baseline <missing> to return an error")
	}
}

func TestExecutePhase3FeedbackTrainAndTier2ScanEndToEnd(t *testing.T) {
	dataDir := t.TempDir()
	var out, errBuf bytes.Buffer

	// 1. Seed starter dataset + companion validation split.
	if err := ExecuteWithOutput([]string{
		"feedback", "seed",
		"--data-dir", dataDir,
		"--name", "starter",
		"--per-class", "2",
		"--val-per-class", "1",
		"--json",
	}, &out, &errBuf); err != nil {
		t.Fatalf("feedback seed failed: %v (stderr=%s)", err, errBuf.String())
	}
	seedPath := filepath.Join(dataDir, "feedback", "sentinel-feedback-starter.jsonl")
	valPath := filepath.Join(dataDir, "feedback", "sentinel-feedback-starter-val.jsonl")
	if _, err := os.Stat(seedPath); err != nil {
		t.Fatalf("expected seed dataset at %s: %v", seedPath, err)
	}
	if _, err := os.Stat(valPath); err != nil {
		t.Fatalf("expected validation split at %s: %v", valPath, err)
	}

	// 2. Add operator feedback containing PII (SSN) -> automatically scrubbed before persistence.
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"feedback", "add",
		"--data-dir", dataDir,
		"--service", "nginx",
		"--level", "WARN",
		"--sample", "GET /healthz user=alice@example.com ssn=123-45-6789 200",
		"--label", "fp",
		"--json",
	}, &out, &errBuf); err != nil {
		t.Fatalf("feedback add failed: %v (stderr=%s)", err, errBuf.String())
	}
	rawQueue, err := os.ReadFile(filepath.Join(dataDir, "feedback", "sentinel-feedback.jsonl"))
	if err != nil {
		t.Fatalf("read sentinel-feedback.jsonl: %v", err)
	}
	if strings.Contains(string(rawQueue), "123-45-6789") || strings.Contains(string(rawQueue), "alice@example.com") {
		t.Fatalf("PII leaked into sentinel-feedback.jsonl: %s", string(rawQueue))
	}

	// 3. Mock local FTaaS API server for --audit-only and submit --wait --activate.
	ftaasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs/audit":
			_, _ = w.Write([]byte(`{"isValid":true,"cleanedRecordCount":16,"summary":{"original_count":17,"cleaned_count":16,"ablated_count":1,"anomalous_count":0}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"jobId":"job-smol-01","jobName":"sentinel-e2e","status":"Queued","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","datasetPath":"datasets/job-smol-01.jsonl","datasetHash":"abcd1234","surprisalPreflightStatus":"Completed"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job-smol-01":
			_, _ = w.Write([]byte(`{"jobId":"job-smol-01","jobName":"sentinel-e2e","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","datasetHash":"abcd1234","progressPercent":100,"currentStep":10,"totalSteps":10,"adapterPath":"artifacts/job-smol-01/model_adapters"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ftaasSrv.Close()

	// 3a. Dry-run preflight audit.
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"train", "submit",
		"--data-dir", dataDir,
		"--ftaas-http", ftaasSrv.URL,
		"--seed-per-class", "2",
		"--audit-only",
	}, &out, &errBuf); err != nil {
		t.Fatalf("train --audit-only failed: %v (stderr=%s)", err, errBuf.String())
	}
	if !strings.Contains(out.String(), `"cleanedRecordCount": 16`) {
		t.Fatalf("unexpected audit-only output: %s", out.String())
	}

	// 3b. Submit + wait + activate -> writes active-adapter.json.
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"train", "submit",
		"--data-dir", dataDir,
		"--ftaas-http", ftaasSrv.URL,
		"--dataset", seedPath,
		"--job-name", "sentinel-e2e",
		"--wait",
		"--poll-interval", "5ms",
		"--activate",
		"--json",
	}, &out, &errBuf); err != nil {
		t.Fatalf("train submit --wait --activate failed: %v (stderr=%s)", err, errBuf.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "active-adapter.json")); err != nil {
		t.Fatalf("expected active-adapter.json after --activate: %v", err)
	}

	// 4. Mock local Inference server + run `sentinel scan --triage-mode http`, verifying adapter & model forwarding.
	var inferHits atomic.Int32
	inferSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			BaseModel   string `json:"baseModel"`
			AdapterPath string `json:"adapterPath"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.BaseModel != model.ModelSmolLM2135MInstruct || req.AdapterPath != "artifacts/job-smol-01/model_adapters" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		inferHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","adapterPath":"artifacts/job-smol-01/model_adapters","completion":"[INJECTION-ATTEMPT] severity=CRITICAL mitre=TA0001 explanation=Path traversal attack detected.","latencyMs":21.0}`))
	}))
	defer inferSrv.Close()

	logPath := filepath.Join(dataDir, "attack.log")
	if err := os.WriteFile(logPath, []byte(`{"timestamp":1763997100,"service":"nginx","level":"WARN","message":"GET /../../../../etc/passwd HTTP/1.1 403"}`+"\n"), 0600); err != nil {
		t.Fatalf("write attack.log: %v", err)
	}

	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"scan",
		"--file", logPath,
		"--triage-mode", "http",
		"--inference-http", inferSrv.URL,
		"--adapter-path", "artifacts/job-smol-01/model_adapters",
		"--json",
	}, &out, &errBuf); err != nil {
		t.Fatalf("scan --triage-mode http failed: %v (stderr=%s)", err, errBuf.String())
	}
	var rep ScanReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("decode scan JSON: %v", err)
	}
	if inferHits.Load() != 1 || rep.TriageEvaluated != 1 || len(rep.Alerts) != 1 || rep.Alerts[0].TriageClass != "INJECTION-ATTEMPT" || rep.Alerts[0].Tier != "tier0+tier2" {
		t.Fatalf("unexpected Tier 2 scan report (inferHits=%d): %+v", inferHits.Load(), rep)
	}

	// 5. `sentinel burn -y` cleans feedback files AND active-adapter.json cleanly!
	out.Reset()
	errBuf.Reset()
	t.Setenv("SENTINEL_DATA_DIR", dataDir)
	if err := ExecuteWithOutput([]string{"burn", "-y"}, &out, &errBuf); err != nil {
		t.Fatalf("burn -y failed: %v (stderr=%s)", err, errBuf.String())
	}
	for _, gone := range []string{
		filepath.Join(dataDir, "active-adapter.json"),
		seedPath,
		valPath,
		filepath.Join(dataDir, "feedback", "sentinel-feedback.jsonl"),
	} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be wiped by sentinel burn -y", gone)
		}
	}
}

func TestWatchHTTPHandlerRequiresAuthBeforeAdapterMutation(t *testing.T) {
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.DataDir = dataDir
	cfg.TriageMode = "http"
	cfg.InferenceAddr = "http://127.0.0.1:8000"
	cfg.AdapterPath = "artifacts/original/model_adapters"
	ruleEng, err := rules.NewEngine(rules.DefaultRulePack())
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	pipe := pipeline.New(cfg, ruleEng, emit.NopSink{}, "file")
	handler := newWatchHTTPHandler(pipe, "daemon-auth-secret")

	// Unauthenticated POST /adapter must fail with 401 before mutating client or writing active-adapter.json.
	unauthRec := httptest.NewRecorder()
	unauthReq := httptest.NewRequest(http.MethodPost, "/adapter", strings.NewReader(`{"adapter_path":"artifacts/hijack/model_adapters"}`))
	handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated POST /adapter, got %d", unauthRec.Code)
	}
	if st := pipe.Stats(); st.TriageAdapter != "artifacts/original/model_adapters" {
		t.Fatalf("unauthenticated request mutated adapter: %q", st.TriageAdapter)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "active-adapter.json")); !os.IsNotExist(err) {
		t.Fatal("unauthenticated request wrote active-adapter.json")
	}

	// Authenticated POST /adapter succeeds and writes active-adapter.json.
	authRec := httptest.NewRecorder()
	authReq := httptest.NewRequest(http.MethodPost, "/adapter", strings.NewReader(`{"adapter_path":"artifacts/verified/model_adapters"}`))
	authReq.Header.Set("Authorization", "Bearer daemon-auth-secret")
	handler.ServeHTTP(authRec, authReq)
	if authRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for authenticated POST /adapter, got %d: %s", authRec.Code, authRec.Body.String())
	}
	if st := pipe.Stats(); st.TriageAdapter != "artifacts/verified/model_adapters" {
		t.Fatalf("authenticated POST /adapter did not update client: %q", st.TriageAdapter)
	}
}

func TestExecuteTrainSubmitFailedJobDoesNotActivateAdapter(t *testing.T) {
	dataDir := t.TempDir()
	var out, errBuf bytes.Buffer
	if err := ExecuteWithOutput([]string{"feedback", "seed", "--data-dir", dataDir, "--name", "s", "--per-class", "1"}, &out, &errBuf); err != nil {
		t.Fatalf("seed failed: %v", err)
	}
	seedPath := filepath.Join(dataDir, "feedback", "sentinel-feedback-s.jsonl")

	ftaasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"jobId":"job-fail-1","jobName":"fail-test","status":"Queued","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job-fail-1":
			_, _ = w.Write([]byte(`{"jobId":"job-fail-1","status":"Failed","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","adapterPath":"artifacts/job-fail-1/model_adapters","errorMessage":"oom"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ftaasSrv.Close()

	out.Reset()
	errBuf.Reset()
	err := ExecuteWithOutput([]string{
		"train", "submit",
		"--data-dir", dataDir,
		"--ftaas-http", ftaasSrv.URL,
		"--dataset", seedPath,
		"--wait",
		"--poll-interval", "5ms",
		"--activate",
	}, &out, &errBuf)
	if err == nil {
		t.Fatal("expected train submit --wait --activate to return error for Failed job")
	}
	if _, statErr := os.Stat(filepath.Join(dataDir, "active-adapter.json")); !os.IsNotExist(statErr) {
		t.Fatal("Failed job with nonempty adapterPath wrote active-adapter.json")
	}

	// Reject --activate without --wait before submitting any job.
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"train", "submit",
		"--data-dir", dataDir,
		"--ftaas-http", ftaasSrv.URL,
		"--dataset", seedPath,
		"--activate",
	}, &out, &errBuf); err == nil {
		t.Fatal("expected --activate without --wait to be rejected")
	}

	// Reject --wait --activate when Succeeded job returns empty adapterPath.
	emptyAdapterSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"jobId":"job-empty-1","status":"Queued","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job-empty-1":
			_, _ = w.Write([]byte(`{"jobId":"job-empty-1","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","adapterPath":""}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer emptyAdapterSrv.Close()
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"train", "submit",
		"--data-dir", dataDir,
		"--ftaas-http", emptyAdapterSrv.URL,
		"--dataset", seedPath,
		"--wait", "--poll-interval", "5ms", "--activate",
	}, &out, &errBuf); err == nil {
		t.Fatal("expected --wait --activate with empty adapterPath to return an error")
	}

	// train activate with rejecting daemon (401) must leave previous active-adapter.json untouched.
	prevManifest := `{"base_model":"HuggingFaceTB/SmolLM2-135M-Instruct","adapter_path":"artifacts/prev/model_adapters"}`
	manifestPath := filepath.Join(dataDir, "active-adapter.json")
	if err := os.WriteFile(manifestPath, []byte(prevManifest), 0600); err != nil {
		t.Fatalf("seed previous active-adapter.json: %v", err)
	}
	rejectDaemon := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer rejectDaemon.Close()
	out.Reset()
	errBuf.Reset()
	if err := ExecuteWithOutput([]string{
		"train", "activate",
		"--data-dir", dataDir,
		"--adapter-path", "artifacts/new/model_adapters",
		"--sentinel-http", rejectDaemon.URL,
	}, &out, &errBuf); err == nil {
		t.Fatal("expected train activate against 401 daemon to fail")
	}
	rawAfter, _ := os.ReadFile(manifestPath)
	if string(rawAfter) != prevManifest {
		t.Fatalf("401 daemon activation mutated active-adapter.json: got %s", string(rawAfter))
	}
}
