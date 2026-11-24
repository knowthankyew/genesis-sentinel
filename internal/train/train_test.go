package train

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

	var pollCount atomic.Int32
	var gotBaseModel, gotJobName, gotPreflight string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs/audit":
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"isValid":true,"cleanedRecordCount":14,"summary":{"original_count":16,"cleaned_count":14,"ablated_count":2,"anomalous_count":0}}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/jobs":
			if err := r.ParseMultipartForm(4 << 20); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			gotBaseModel = r.FormValue("baseModel")
			gotJobName = r.FormValue("jobName")
			gotPreflight = r.FormValue("enableSurprisalPreflight")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"jobId":"job_abc123","jobName":"` + gotJobName + `","status":"Queued","baseModel":"` + gotBaseModel + `","datasetPath":"datasets/job_abc123.jsonl","datasetHash":"deadbeef","surprisalPreflightStatus":"Completed"}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs/job_abc123":
			n := pollCount.Add(1)
			w.Header().Set("Content-Type", "application/json")
			if n == 1 {
				_, _ = w.Write([]byte(`{"jobId":"job_abc123","jobName":"sentinel-test","status":"Running","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","progressPercent":50.0,"currentStep":6,"totalSteps":12}`))
			} else {
				_, _ = w.Write([]byte(`{"jobId":"job_abc123","jobName":"sentinel-test","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct","datasetHash":"deadbeef","progressPercent":100.0,"currentStep":12,"totalSteps":12,"adapterPath":"artifacts/job_abc123/model_adapters"}`))
			}
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/jobs":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"jobId":"job_abc123","jobName":"sentinel-test","status":"Succeeded","baseModel":"HuggingFaceTB/SmolLM2-135M-Instruct"}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := NewFTaaSClient(srv.URL, "", 5*time.Second, false)
	if err != nil {
		t.Fatalf("NewFTaaSClient: %v", err)
	}

	auditRes, err := client.AuditDataset(context.Background(), dsPath, 0.15, 5.0, true)
	if err != nil || !auditRes.IsValid || auditRes.CleanedRecordCount != 14 {
		t.Fatalf("AuditDataset unexpected: %+v err=%v", auditRes, err)
	}

	subRes, err := client.SubmitJob(context.Background(), SubmitRequest{
		JobName:                  "sentinel-test",
		BaseModel:                model.ModelSmolLM2135MInstruct,
		DatasetPath:              dsPath,
		Hyperparameters:          DefaultHyperparameters(),
		EnableSurprisalPreflight: true,
		RequireRedaction:         true,
	})
	if err != nil || subRes.JobID != "job_abc123" || gotPreflight != "true" || gotBaseModel != model.ModelSmolLM2135MInstruct {
		t.Fatalf("SubmitJob unexpected: %+v err=%v", subRes, err)
	}

	var updates int
	finalJob, err := client.WaitForJob(context.Background(), subRes.JobID, 10*time.Millisecond, func(JobDetail) {
		updates++
	})
	if err != nil || finalJob.Status != "Succeeded" || finalJob.AdapterPath != "artifacts/job_abc123/model_adapters" || updates != 2 {
		t.Fatalf("WaitForJob unexpected: %+v updates=%d err=%v", finalJob, updates, err)
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
	if err != nil || !exists || loaded.AdapterPath != state.AdapterPath {
		t.Fatalf("LoadActiveAdapter: %+v exists=%v err=%v", loaded, exists, err)
	}
}

func TestFTaaSClientRejectsBitNetNonLoopbackAndUnredactedPII(t *testing.T) {
	if _, err := NewFTaaSClient("https://remote.example.com:5100", "", time.Second, false); err == nil {
		t.Fatal("expected non-loopback FTaaS URL to be rejected")
	}

	client, err := NewFTaaSClient("http://127.0.0.1:5100", "", time.Second, false)
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
	if _, err := client.SubmitJob(context.Background(), SubmitRequest{
		BaseModel:        model.ModelSmolLM2135MInstruct,
		DatasetPath:      piiPath,
		Hyperparameters:  DefaultHyperparameters(),
		RequireRedaction: true,
	}); err == nil {
		t.Fatal("expected unredacted SSN dataset to be rejected before upload")
	}
}
