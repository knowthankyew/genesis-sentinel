package surprisal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

const (
	maxHTTPResponseBytes  = 1024 * 1024 // 1 MiB response ceiling
	maxHTTPReferenceCases = 64          // cap reference payload size sent over loopback
	defaultHTTPTimeout    = 2 * time.Second
)

// HTTPClient communicates over loopback with the companion ml/src/surprisal-service
// (`:5200`) for optional `surprisal_mode=http` or `hybrid` cross-checks (ADR-7).
type HTTPClient struct {
	baseURL     string
	allowRemote bool
	client      *http.Client
}

// NewHTTPClient creates a loopback-enforced client targeting baseURL (e.g. http://127.0.0.1:5200).
func NewHTTPClient(baseURL string, timeout time.Duration, allowRemote bool) (*HTTPClient, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if trimmed == "" {
		return nil, fmt.Errorf("surprisal HTTP base URL is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	if !allowRemote && !security.IsLoopbackEndpoint(trimmed) {
		return nil, fmt.Errorf("refusing non-loopback surprisal-service URL %q without allow_remote_endpoints=true", trimmed)
	}
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &HTTPClient{
		baseURL:     trimmed,
		allowRemote: allowRemote,
		client:      security.NewLoopbackHTTPClient(timeout, allowRemote, false),
	}, nil
}

type datasetRecordPayload struct {
	Prompt     string  `json:"prompt"`
	Completion string  `json:"completion"`
	Weight     float64 `json:"weight"`
}

type verifyRequestPayload struct {
	ReferenceRecords      []datasetRecordPayload `json:"reference_records"`
	Prompt                string                 `json:"prompt"`
	CandidateCompletion   string                 `json:"candidate_completion"`
	MaxTolerableSurprisal float64                `json:"max_tolerable_surprisal"`
}

// VerifyResponse mirrors ml/src/surprisal-service/service.py VerifyResponse.
type VerifyResponse struct {
	IsConforming          bool    `json:"is_conforming"`
	MeasuredSurprisalNats float64 `json:"measured_surprisal_nats"`
	PredictedTag          string  `json:"predicted_tag"`
	CandidateTag          string  `json:"candidate_tag"`
	Explanation           string  `json:"explanation"`
}

// Health checks GET /health on surprisal-service.
func (c *HTTPClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("surprisal-service health request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPResponseBytes))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("surprisal-service health returned status %d", resp.StatusCode)
	}
	return nil
}

// VerifyWindow posts a sanitized log window summary and bounded baseline references
// to POST /v1/verify/completion on the local surprisal-service sidecar.
func (c *HTTPClient) VerifyWindow(
	ctx context.Context,
	w model.TemplateWindow,
	references []LogFeatures,
	thresholdNats float64,
) (VerifyResponse, error) {
	if len(references) == 0 {
		return VerifyResponse{}, fmt.Errorf("cannot verify window with empty reference baseline")
	}

	selected := selectStrided(references, maxHTTPReferenceCases)
	refPayload := make([]datasetRecordPayload, 0, len(selected))
	for _, rf := range selected {
		refPayload = append(refPayload, datasetRecordPayload{
			Prompt:     formatFeatureSummaryPrompt(rf),
			Completion: "[" + sanitizeTag(rf.Nominal[1]) + "] baseline",
			Weight:     1.0,
		})
	}

	candFeat := ExtractFeatures(w)
	cleanSample, _ := security.SanitizeUntrustedLogText(w.SampleLine, 256)
	payload := verifyRequestPayload{
		ReferenceRecords:      refPayload,
		Prompt:                formatFeatureSummaryPrompt(candFeat) + " sample=" + cleanSample,
		CandidateCompletion:   "[" + sanitizeTag(candFeat.Nominal[1]) + "] window",
		MaxTolerableSurprisal: thresholdNats,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("marshal surprisal verify request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/verify/completion", bytes.NewReader(bodyBytes))
	if err != nil {
		return VerifyResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("post %s/v1/verify/completion: %w", c.baseURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("read surprisal response: %w", err)
	}
	if len(respBytes) > maxHTTPResponseBytes {
		return VerifyResponse{}, fmt.Errorf("surprisal response exceeded %d-byte limit", maxHTTPResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return VerifyResponse{}, fmt.Errorf("surprisal-service returned status %d", resp.StatusCode)
	}

	var out VerifyResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return VerifyResponse{}, fmt.Errorf("decode surprisal response: %w", err)
	}
	return out, nil
}

func formatFeatureSummaryPrompt(f LogFeatures) string {
	return fmt.Sprintf("svc=%s lvl=%s tmpl=%s proto=%s tok=%.2f len=%.2f ent=%.2f sym=%.2f cnt=%.2f",
		f.Nominal[0], f.Nominal[1], f.Nominal[2], f.Nominal[3],
		f.Continuous[0], f.Continuous[1], f.Continuous[2], f.Continuous[3], f.Continuous[4],
	)
}

func sanitizeTag(raw string) string {
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return "INFO"
	}
	return b.String()
}
