package train

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

const (
	defaultFTaaSTimeout   = 120 * time.Second
	maxFTaaSResponseBytes = 2 * 1024 * 1024 // 2 MiB response body ceiling
)

var validJobIDRe = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Hyperparameters mirrors ml/src/FtaaSService.Api/Domain/Hyperparameters.cs.
type Hyperparameters struct {
	Epochs       int     `json:"epochs"`
	BatchSize    int     `json:"batchSize"`
	LearningRate float64 `json:"learningRate"`
	LoraRank     int     `json:"loraRank"`
	LoraAlpha    int     `json:"loraAlpha"`
	LoraDropout  float64 `json:"loraDropout"`
	MaxLength    int     `json:"maxLength,omitempty"`
}

// DefaultHyperparameters returns safe SmolLM2-Instruct LoRA defaults matching FTaaS
// with MaxLength=512 so framed Tier 2 security telemetry windows fit without truncation.
func DefaultHyperparameters() Hyperparameters {
	return Hyperparameters{
		Epochs:       3,
		BatchSize:    4,
		LearningRate: 0.0002,
		LoraRank:     8,
		LoraAlpha:    32,
		LoraDropout:  0.05,
		MaxLength:    512,
	}
}

// Validate enforces the exact hyperparameter bounds verified by FTaaS JobEndpoints.cs.
func (h Hyperparameters) Validate() error {
	if h.Epochs < 1 || h.Epochs > 20 {
		return fmt.Errorf("epochs must be in [1, 20], got %d", h.Epochs)
	}
	if h.BatchSize < 1 || h.BatchSize > 64 {
		return fmt.Errorf("batchSize must be in [1, 64], got %d", h.BatchSize)
	}
	if math.IsNaN(h.LearningRate) || math.IsInf(h.LearningRate, 0) || h.LearningRate <= 0 || h.LearningRate > 0.1 {
		return fmt.Errorf("learningRate must be in (0, 0.1], got %v", h.LearningRate)
	}
	if h.LoraRank < 1 || h.LoraRank > 128 {
		return fmt.Errorf("loraRank must be in [1, 128], got %d", h.LoraRank)
	}
	if h.LoraAlpha < 1 || h.LoraAlpha > 512 {
		return fmt.Errorf("loraAlpha must be in [1, 512], got %d", h.LoraAlpha)
	}
	if math.IsNaN(h.LoraDropout) || math.IsInf(h.LoraDropout, 0) || h.LoraDropout < 0 || h.LoraDropout >= 1 {
		return fmt.Errorf("loraDropout must be in [0, 1), got %v", h.LoraDropout)
	}
	if h.MaxLength != 0 && (h.MaxLength < 64 || h.MaxLength > 2048) {
		return fmt.Errorf("maxLength must be in [64, 2048], got %d", h.MaxLength)
	}
	return nil
}

// SubmitRequest configures a multipart FTaaS LoRA training job submission.
type SubmitRequest struct {
	JobName                  string
	BaseModel                string
	DatasetPath              string
	Hyperparameters          Hyperparameters
	EnableSurprisalPreflight bool
	RequireRedaction         bool
}

// SurprisalAuditSummary captures preflight redundancy/anomaly statistics from FTaaS.
type SurprisalAuditSummary struct {
	OriginalCount  int                `json:"original_count"`
	CleanedCount   int                `json:"cleaned_count"`
	AblatedCount   int                `json:"ablated_count"`
	AnomalousCount int                `json:"anomalous_count"`
	Deviations     map[string]float64 `json:"measured_deviations,omitempty"`
}

// SubmitResponse decodes POST /api/v1/jobs (HTTP 202 Accepted).
type SubmitResponse struct {
	JobID                    string                 `json:"jobId"`
	JobName                  string                 `json:"jobName"`
	Status                   string                 `json:"status"`
	BaseModel                string                 `json:"baseModel"`
	DatasetPath              string                 `json:"datasetPath"`
	DatasetHash              string                 `json:"datasetHash"`
	CreatedAt                string                 `json:"createdAt"`
	SurprisalPreflightStatus string                 `json:"surprisalPreflightStatus,omitempty"`
	SurprisalAudit           *SurprisalAuditSummary `json:"surprisalAudit,omitempty"`
}

// DatasetAuditResponse decodes POST /api/v1/jobs/audit dry-run preflight responses.
type DatasetAuditResponse struct {
	IsValid            bool                   `json:"isValid"`
	ErrorMessage       string                 `json:"errorMessage,omitempty"`
	CleanedRecordCount int                    `json:"cleanedRecordCount"`
	Summary            *SurprisalAuditSummary `json:"summary,omitempty"`
}

// JobDetail decodes GET /api/v1/jobs/{id} and list items.
type JobDetail struct {
	JobID              string          `json:"jobId"`
	JobName            string          `json:"jobName"`
	Status             string          `json:"status"`
	BaseModel          string          `json:"baseModel"`
	DatasetPath        string          `json:"datasetPath"`
	DatasetHash        string          `json:"datasetHash"`
	Hyperparameters    Hyperparameters `json:"hyperparameters"`
	ProgressPercent    float64         `json:"progressPercent"`
	CurrentStep        int             `json:"currentStep"`
	TotalSteps         int             `json:"totalSteps"`
	CurrentLoss        *float64        `json:"currentLoss,omitempty"`
	MlflowExperimentID string          `json:"mlflowExperimentId,omitempty"`
	MlflowRunID        string          `json:"mlflowRunId,omitempty"`
	AdapterPath        string          `json:"adapterPath,omitempty"`
	ErrorMessage       string          `json:"errorMessage,omitempty"`
	CreatedAt          string          `json:"createdAt,omitempty"`
	UpdatedAt          string          `json:"updatedAt,omitempty"`
}

// FTaaSClient communicates with local ml/src/FtaaSService.Api over loopback HTTP.
type FTaaSClient struct {
	baseURL     string
	redactedURL string
	apiKey      string
	httpClient  *http.Client
}

// NewFTaaSClient constructs a loopback-enforced FTaaS API client.
func NewFTaaSClient(rawURL, apiKey string, timeout time.Duration, allowRemote bool) (*FTaaSClient, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		trimmed = "http://127.0.0.1:5100"
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid FTaaS API URL: failed to parse host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported FTaaS API URL scheme %q (expected http or https)", u.Scheme)
	}
	if !allowRemote && !security.IsLoopbackEndpoint(trimmed) {
		return nil, fmt.Errorf("refusing non-loopback FTaaS endpoint %q without allow_remote_endpoints=true", u.Host)
	}
	if timeout <= 0 {
		timeout = defaultFTaaSTimeout
	}

	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	fullBase := strings.TrimRight(u.String(), "/")
	redactedU := *u
	redactedU.User = nil
	redactedBase := strings.TrimRight(redactedU.String(), "/")

	return &FTaaSClient{
		baseURL:     fullBase,
		redactedURL: redactedBase,
		apiKey:      strings.TrimSpace(apiKey),
		httpClient:  security.NewLoopbackHTTPClient(timeout, allowRemote, true),
	}, nil
}

// AuditDataset uploads a redacted JSONL file to POST /api/v1/jobs/audit for dry-run
// surprisal preflight evaluation without queuing a LoRA training job.
func (c *FTaaSClient) AuditDataset(
	ctx context.Context,
	datasetPath string,
	ablationThreshold float64,
	anomalyThreshold float64,
	requireRedaction bool,
) (DatasetAuditResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if math.IsNaN(ablationThreshold) || math.IsInf(ablationThreshold, 0) || ablationThreshold < 0 {
		return DatasetAuditResponse{}, fmt.Errorf("ablationThreshold must be a non-negative finite float")
	}
	if math.IsNaN(anomalyThreshold) || math.IsInf(anomalyThreshold, 0) || anomalyThreshold < 0 {
		return DatasetAuditResponse{}, fmt.Errorf("anomalyThreshold must be a non-negative finite float")
	}
	snapshot, _, err := feedback.ReadAndValidateJSONLFile(datasetPath, requireRedaction)
	if err != nil {
		return DatasetAuditResponse{}, err
	}

	fields := map[string]string{
		"ablationThreshold": strconv.FormatFloat(ablationThreshold, 'f', -1, 64),
		"anomalyThreshold":  strconv.FormatFloat(anomalyThreshold, 'f', -1, 64),
	}
	body, contentType, err := buildMultipartUploadFromBytes(filepath.Base(datasetPath), snapshot, fields)
	if err != nil {
		return DatasetAuditResponse{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/jobs/audit", body)
	if err != nil {
		return DatasetAuditResponse{}, err
	}
	req.Header.Set("Content-Type", contentType)
	c.applyAuth(req)

	respBody, statusCode, err := c.doBounded(req)
	if err != nil {
		return DatasetAuditResponse{}, fmt.Errorf("POST %s/api/v1/jobs/audit: %w", c.redactedURL, err)
	}
	if statusCode != http.StatusOK {
		return DatasetAuditResponse{}, fmt.Errorf("FTaaS /api/v1/jobs/audit returned HTTP %d: %s", statusCode, compactErrBody(respBody))
	}
	var out DatasetAuditResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return DatasetAuditResponse{}, fmt.Errorf("decode FTaaS audit response: %w", err)
	}
	return out, nil
}

// SubmitJob validates baseModel, hyperparameters, and dataset compliance, then uploads
// the redacted JSONL file to POST /api/v1/jobs on local FTaaS.
func (c *FTaaSClient) SubmitJob(ctx context.Context, req SubmitRequest) (SubmitResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	baseModel := strings.TrimSpace(req.BaseModel)
	if baseModel == "" {
		baseModel = model.ModelSmolLM2135MInstruct
	}
	if _, err := model.ValidateBaseModel(baseModel); err != nil {
		return SubmitResponse{}, fmt.Errorf("train base_model: %w", err)
	}
	if err := req.Hyperparameters.Validate(); err != nil {
		return SubmitResponse{}, fmt.Errorf("invalid hyperparameters: %w", err)
	}
	snapshot, _, err := feedback.ReadAndValidateJSONLFile(req.DatasetPath, req.RequireRedaction)
	if err != nil {
		return SubmitResponse{}, err
	}

	jobName := strings.TrimSpace(req.JobName)
	if jobName == "" {
		jobName = "sentinel-triage-" + time.Now().UTC().Format("20060102-150405")
	}
	hpBytes, err := json.Marshal(req.Hyperparameters)
	if err != nil {
		return SubmitResponse{}, err
	}

	fields := map[string]string{
		"jobName":                  jobName,
		"baseModel":                baseModel,
		"enableSurprisalPreflight": strconv.FormatBool(req.EnableSurprisalPreflight),
		"hyperparameters":          string(hpBytes),
	}
	body, contentType, err := buildMultipartUploadFromBytes(filepath.Base(req.DatasetPath), snapshot, fields)
	if err != nil {
		return SubmitResponse{}, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/jobs", body)
	if err != nil {
		return SubmitResponse{}, err
	}
	httpReq.Header.Set("Content-Type", contentType)
	c.applyAuth(httpReq)

	respBody, statusCode, err := c.doBounded(httpReq)
	if err != nil {
		return SubmitResponse{}, fmt.Errorf("POST %s/api/v1/jobs (jobName=%q) failed (run `sentinel train list` to verify whether FTaaS already queued this job before retrying): %w", c.redactedURL, jobName, err)
	}
	if statusCode != http.StatusAccepted && statusCode != http.StatusOK {
		return SubmitResponse{}, fmt.Errorf("FTaaS /api/v1/jobs returned HTTP %d: %s", statusCode, compactErrBody(respBody))
	}

	var out SubmitResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return SubmitResponse{}, fmt.Errorf("decode FTaaS submit response for jobName=%q (FTaaS accepted HTTP %d; run `sentinel train list` to locate the queued job before retrying): %w", jobName, statusCode, err)
	}
	if !validJobIDRe.MatchString(out.JobID) {
		return SubmitResponse{}, fmt.Errorf("FTaaS returned invalid jobId %q for jobName=%q (FTaaS accepted HTTP %d; run `sentinel train list` to locate the queued job before retrying)", out.JobID, jobName, statusCode)
	}
	return out, nil
}

// GetJob fetches live progress and adapter status for jobID from GET /api/v1/jobs/{id}.
func (c *FTaaSClient) GetJob(ctx context.Context, jobID string) (JobDetail, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	jobID = strings.TrimSpace(jobID)
	if !validJobIDRe.MatchString(jobID) {
		return JobDetail{}, fmt.Errorf("invalid job ID %q", jobID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/jobs/"+url.PathEscape(jobID), nil)
	if err != nil {
		return JobDetail{}, err
	}
	c.applyAuth(req)

	respBody, statusCode, err := c.doBounded(req)
	if err != nil {
		return JobDetail{}, fmt.Errorf("GET %s/api/v1/jobs/%s: %w", c.redactedURL, jobID, err)
	}
	if statusCode != http.StatusOK {
		return JobDetail{}, fmt.Errorf("FTaaS GET /api/v1/jobs/%s returned HTTP %d: %s", jobID, statusCode, compactErrBody(respBody))
	}
	var detail JobDetail
	if err := json.Unmarshal(respBody, &detail); err != nil {
		return JobDetail{}, fmt.Errorf("decode FTaaS job detail: %w", err)
	}
	if strings.TrimSpace(detail.JobID) == "" || strings.TrimSpace(detail.JobID) != jobID {
		return JobDetail{}, fmt.Errorf("FTaaS job detail mismatch: requested jobId %q, received %q", jobID, detail.JobID)
	}
	return detail, nil
}

// ListJobs retrieves recent training jobs from GET /api/v1/jobs?limit=N.
func (c *FTaaSClient) ListJobs(ctx context.Context, limit int) ([]JobDetail, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/api/v1/jobs?limit=%d", c.baseURL, limit), nil)
	if err != nil {
		return nil, err
	}
	c.applyAuth(req)

	respBody, statusCode, err := c.doBounded(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s/api/v1/jobs: %w", c.redactedURL, err)
	}
	if statusCode != http.StatusOK {
		return nil, fmt.Errorf("FTaaS GET /api/v1/jobs returned HTTP %d: %s", statusCode, compactErrBody(respBody))
	}
	var jobs []JobDetail
	if err := json.Unmarshal(respBody, &jobs); err != nil {
		return nil, fmt.Errorf("decode FTaaS job list: %w", err)
	}
	return jobs, nil
}

// WaitForJob polls GET /api/v1/jobs/{id} until a terminal status (Succeeded, Failed, Cancelled)
// is reached or ctx expires.
func (c *FTaaSClient) WaitForJob(
	ctx context.Context,
	jobID string,
	pollInterval time.Duration,
	onProgress func(JobDetail),
) (JobDetail, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		detail, err := c.GetJob(ctx, jobID)
		if err != nil {
			return JobDetail{}, err
		}
		if onProgress != nil {
			onProgress(detail)
		}
		switch strings.ToLower(strings.TrimSpace(detail.Status)) {
		case "succeeded", "completed":
			return detail, nil
		case "failed", "cancelled", "canceled", "error", "aborted", "timed_out", "timeout":
			msg := strings.TrimSpace(detail.ErrorMessage)
			if msg == "" {
				msg = "training job terminated with status " + detail.Status
			}
			return detail, fmt.Errorf("FTaaS job %s %s: %s", jobID, detail.Status, compactErrBody([]byte(msg)))
		}
		select {
		case <-ctx.Done():
			return detail, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *FTaaSClient) applyAuth(req *http.Request) {
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("X-API-Key", c.apiKey)
	}
}

func (c *FTaaSClient) doBounded(req *http.Request) ([]byte, int, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, security.SanitizeURLError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFTaaSResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(body) > maxFTaaSResponseBytes {
		return nil, resp.StatusCode, fmt.Errorf("response exceeded %d-byte limit", maxFTaaSResponseBytes)
	}
	return body, resp.StatusCode, nil
}

func buildMultipartUploadFromBytes(fileName string, content []byte, fields map[string]string) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)

	for k, v := range fields {
		if err := mw.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	part, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(content); err != nil {
		return nil, "", err
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	return &buf, mw.FormDataContentType(), nil
}

func compactErrBody(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 4096 {
		s = s[:4096]
	}
	// Redact any echoed Authorization credentials, JWTs, API keys, or PII before error output.
	s, _ = feedback.RedactText(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return ' '
		}
		return r
	}, s)
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
