package train

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestFTaaSClientSubmitAuditWaitAndActivate(t *testing.T) {
	tmp := t.TempDir()
	dsPath := filepath.Join(tmp, "sentinel-feedback-seed.jsonl")
	recs := feedback.GenerateSeedDataset(2, 42)
	if _, err := feedback.WriteFTaaSDataset(dsPath, recs, true); err != nil {
		t.Fatalf("WriteFTaaSDataset: %v", err)
	}

	dsBytes, err := os.ReadFile(dsPath)
	if err != nil {
		t.Fatalf("read dsPath: %v", err)
	}

	type submitCapture struct {
		baseModel string
		jobName   string
		preflight string
		fileBytes []byte
	}
	type auditCapture struct {
		ablation  string
		anomaly   string
		fileBytes []byte
	}
	submitCh := make(chan submitCapture, 1)
	auditCh := make(chan auditCapture, 1)

	var pollCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs/audit":
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f, _, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			gotFile, _ := io.ReadAll(f)
			_ = f.Close()
			select {
			case auditCh <- auditCapture{
				ablation:  r.FormValue("ablationThreshold"),
				anomaly:   r.FormValue("anomalyThreshold"),
				fileBytes: gotFile,
			}:
			default:
				t.Errorf("unexpected duplicate audit request")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"isValid":true,"cleanedRecordCount":14,"summary":{"original_count":16,"cleaned_count":14,"ablated_count":2,"anomalous_count":0}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f, _, err := r.FormFile("file")
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			gotFile, _ := io.ReadAll(f)
			_ = f.Close()
			bm := r.FormValue("baseModel")
			jn := r.FormValue("jobName")
			pf := r.FormValue("enableSurprisalPreflight")
			select {
			case submitCh <- submitCapture{baseModel: bm, jobName: jn, preflight: pf, fileBytes: gotFile}:
			default:
				t.Errorf("unexpected duplicate submit request")
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"jobId":"job_abc123","jobName":"` + jn + `","status":"Queued","baseModel":"` + bm + `","datasetPath":"datasets/job_abc123.jsonl","datasetHash":"deadbeef","surprisalPreflightStatus":"Completed"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job_abc123":
			n := pollCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			switch n {
			case 1:
				// Transient 503 should be retried cleanly by WaitForJob without aborting wait.
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"error":"temporary overload"}`))
			case 2:
				_, _ = w.Write([]byte(`{"jobId":"job_abc123","jobName":"sentinel-test","status":"Running","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","progressPercent":50.0,"currentStep":6,"totalSteps":12}`))
			default:
				_, _ = w.Write([]byte(`{"jobId":"job_abc123","jobName":"sentinel-test","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","datasetHash":"deadbeef","progressPercent":100.0,"currentStep":12,"totalSteps":12,"adapterPath":"artifacts/job_abc123/model_adapters"}`))
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job_failed":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jobId":"job_failed","status":"Failed","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","adapterPath":"artifacts/job_failed/model_adapters","errorMessage":"worker OOM"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job_mismatch":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jobId":"job_other","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","adapterPath":"artifacts/job_other/model_adapters"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"jobId":"job_abc123","jobName":"sentinel-test","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// Append trailing '?' to verify ForceQuery is cleared before routing.
	client, err := NewFTaaSClient(srv.URL+"?", "", 5*time.Second, false)
	if err != nil {
		t.Fatalf("NewFTaaSClient: %v", err)
	}

	auditRes, err := client.AuditDataset(context.Background(), dsPath, 0.00001, 5.0, true)
	if err != nil || !auditRes.IsValid || auditRes.CleanedRecordCount != 14 {
		t.Fatalf("AuditDataset unexpected: %+v err=%v", auditRes, err)
	}
	var gotAudit auditCapture
	select {
	case gotAudit = <-auditCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mock audit handler to receive upload")
	}
	if gotAudit.ablation != "0.00001" || gotAudit.anomaly != "5" || !bytes.Equal(gotAudit.fileBytes, dsBytes) {
		t.Fatalf("AuditDataset mismatch: ablation=%q anomaly=%q fileLen=%d wantLen=%d", gotAudit.ablation, gotAudit.anomaly, len(gotAudit.fileBytes), len(dsBytes))
	}

	subRes, err := client.SubmitJob(context.Background(), SubmitRequest{
		JobName:                  "sentinel-test",
		BaseModel:                model.ModelSmolLM2135MInstruct,
		DatasetPath:              dsPath,
		Hyperparameters:          DefaultHyperparameters(),
		EnableSurprisalPreflight: true,
		RequireRedaction:         true,
	})
	if err != nil {
		t.Fatalf("SubmitJob unexpected error: %v", err)
	}
	var gotSub submitCapture
	select {
	case gotSub = <-submitCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mock submit handler to receive upload")
	}
	if subRes.JobID != "job_abc123" || gotSub.preflight != "true" || gotSub.baseModel != model.ModelSmolLM2135MInstruct || gotSub.jobName != "sentinel-test" || !bytes.Equal(gotSub.fileBytes, dsBytes) {
		t.Fatalf("SubmitJob unexpected: res=%+v fileMatch=%v", subRes, bytes.Equal(gotSub.fileBytes, dsBytes))
	}

	// Mismatched jobId from GET /api/v1/jobs/{id} MUST fail closed.
	if _, err := client.GetJob(context.Background(), "job_mismatch"); err == nil {
		t.Fatal("expected GetJob to reject mismatched jobId response")
	}

	var updates int
	finalJob, err := client.WaitForJob(context.Background(), subRes.JobID, 10*time.Millisecond, func(JobDetail) {
		updates++
	})
	if err != nil || finalJob.Status != "Succeeded" || finalJob.AdapterPath != "artifacts/job_abc123/model_adapters" || updates != 2 {
		t.Fatalf("WaitForJob unexpected: %+v updates=%d err=%v", finalJob, updates, err)
	}

	// Failed job with non-empty adapterPath MUST return the polled terminal detail AND a non-nil error.
	failedJob, err := client.WaitForJob(context.Background(), "job_failed", 10*time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "worker OOM") || failedJob.JobID != "job_failed" || failedJob.Status != "Failed" || failedJob.AdapterPath == "" {
		t.Fatalf("expected WaitForJob to return failed detail with worker OOM error, got job=%+v err=%v", failedJob, err)
	}

	jobs, err := client.ListJobs(context.Background(), 5)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("ListJobs unexpected: %+v err=%v", jobs, err)
	}

	// Persist and reload active adapter manifest cleanly.
	state := ActiveAdapter{
		JobID:       finalJob.JobID,
		BaseModel:   finalJob.BaseModel,
		AdapterPath: finalJob.AdapterPath,
		DatasetHash: finalJob.DatasetHash,
	}
	if err := SaveActiveAdapter(tmp, state); err != nil {
		t.Fatalf("SaveActiveAdapter: %v", err)
	}
	loaded, exists, err := LoadActiveAdapter(tmp)
	if err != nil || !exists || loaded.JobID != state.JobID || loaded.BaseModel != state.BaseModel || loaded.AdapterPath != state.AdapterPath || loaded.DatasetHash != state.DatasetHash {
		t.Fatalf("LoadActiveAdapter: got=%+v want=%+v exists=%v err=%v", loaded, state, exists, err)
	}

	// Reject an existing manifest with an empty adapter_path while preserving exists=true.
	emptyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(emptyDir, ActiveAdapterFilename), []byte(`{"base_model":"HuggingFaceTB/SmolLM2-135M-Instruct","adapter_path":""}`), 0600); err != nil {
		t.Fatalf("write empty adapter manifest: %v", err)
	}
	if _, exists, err := LoadActiveAdapter(emptyDir); !exists || err == nil {
		t.Fatalf("expected LoadActiveAdapter to reject empty adapter_path with exists=true, got exists=%v err=%v", exists, err)
	}
	// Reject oversized manifest exceeding maxActiveAdapterBytes before writing to disk.
	oversizedState := state
	oversizedState.JobID = strings.Repeat("J", maxActiveAdapterBytes)
	if err := SaveActiveAdapter(tmp, oversizedState); err == nil {
		t.Fatal("expected SaveActiveAdapter to reject oversized manifest exceeding maxActiveAdapterBytes")
	}
}

func TestFTaaSClientRejectsBitNetNonLoopbackBadURLAndUnredactedPIIWithoutUpload(t *testing.T) {
	if _, err := NewFTaaSClient("https://remote.example.com:5100", "", time.Second, false); err == nil {
		t.Fatal("expected non-loopback FTaaS URL to be rejected")
	}
	if _, err := NewFTaaSClient("http://user:topsecretpass@127.0.0.1:notaport", "", time.Second, false); err == nil || strings.Contains(err.Error(), "topsecretpass") {
		t.Fatalf("expected generic URL parse error without leaking credentials, got %v", err)
	}

	var serverHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHits.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	client, err := NewFTaaSClient(srv.URL, "", time.Second, false)
	if err != nil {
		t.Fatalf("NewFTaaSClient: %v", err)
	}

	tmp := t.TempDir()
	goodPath := filepath.Join(tmp, "good.jsonl")
	if _, err := feedback.WriteFTaaSDataset(goodPath, feedback.GenerateSeedDataset(1, 1), true); err != nil {
		t.Fatalf("WriteFTaaSDataset: %v", err)
	}
	if _, err := client.SubmitJob(context.Background(), SubmitRequest{
		BaseModel:       "microsoft/BitNet-b1.58-2B-4T",
		DatasetPath:     goodPath,
		Hyperparameters: DefaultHyperparameters(),
	}); !errors.Is(err, model.ErrExperimentalModelExcluded) {
		t.Fatalf("expected BitNet exclusion error, got %v", err)
	}

	piiPath := filepath.Join(tmp, "pii.jsonl")
	if err := os.WriteFile(piiPath, []byte(`{"prompt":"login user 123-45-6789 failed","completion":"[AUTH-BRUTEFORCE]"}`+"\n"), 0600); err != nil {
		t.Fatalf("write pii.jsonl: %v", err)
	}
	_, err = client.SubmitJob(context.Background(), SubmitRequest{
		BaseModel:        model.ModelSmolLM2135MInstruct,
		DatasetPath:      piiPath,
		Hyperparameters:  DefaultHyperparameters(),
		RequireRedaction: true,
	})
	if err == nil || !strings.Contains(err.Error(), "pre-upload PII/secret check") {
		t.Fatalf("expected pre-upload PII validation error, got %v", err)
	}
	if serverHits.Load() != 0 {
		t.Fatalf("expected 0 HTTP uploads to mock FTaaS server on PII rejection, got %d", serverHits.Load())
	}
}

func TestNotifyDaemonAdapterRedactsEchoedCredentialsInErrorBody(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		// Echo both labeled Bearer token AND unlabeled opaque configured token!
		_, _ = w.Write([]byte(`{"error":"rejected Authorization: Bearer leaked-daemon-secret-9999 and raw opaque-token-xyz987"}`))
	}))
	defer srv.Close()

	_, err := NotifyDaemonAdapter(context.Background(), srv.URL+"?", "opaque-token-xyz987", ActiveAdapter{
		BaseModel:   model.ModelSmolLM2135MInstruct,
		AdapterPath: "artifacts/job1/model_adapters",
	}, false)
	if err == nil {
		t.Fatal("expected HTTP 500 error from NotifyDaemonAdapter")
	}
	if hits.Load() != 1 || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("expected request to reach HTTP 500 handler, hits=%d err=%v", hits.Load(), err)
	}
	if strings.Contains(err.Error(), "leaked-daemon-secret-9999") || strings.Contains(err.Error(), "opaque-token-xyz987") {
		t.Fatalf("NotifyDaemonAdapter leaked credential in error output: %v", err)
	}
	if _, err := NotifyDaemonAdapter(context.Background(), "http://u:secretpass@127.0.0.1:notaport", "", ActiveAdapter{}, false); err == nil || strings.Contains(err.Error(), "secretpass") {
		t.Fatalf("NotifyDaemonAdapter leaked URL credentials on parse failure: %v", err)
	}
	// Wrapped transport *url.Error must strip URL username as well as password.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NotifyDaemonAdapter(cancelCtx, "http://secretuser:secretpass@127.0.0.1:1", "", ActiveAdapter{
		BaseModel:   model.ModelSmolLM2135MInstruct,
		AdapterPath: "artifacts/job1/model_adapters",
	}, false); err == nil || strings.Contains(err.Error(), "secretuser") || strings.Contains(err.Error(), "secretpass") || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected sanitized url.Error preserving context.Canceled without username/password, got %v", err)
	}
}
