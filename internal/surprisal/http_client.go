package surprisal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
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
	baseURL     *url.URL
	allowRemote bool
	client      *http.Client
}

// NewHTTPClient creates a loopback-enforced client targeting baseURL (e.g. http://127.0.0.1:5200).
// Base URLs containing query strings or fragments are rejected fail-closed so appended
// endpoint paths (/health, /v1/verify/completion) always target explicit URL paths.
func NewHTTPClient(baseURL string, timeout time.Duration, allowRemote bool) (*HTTPClient, error) {
	trimmed := strings.TrimSpace(baseURL)
	if trimmed == "" {
		return nil, fmt.Errorf("surprisal HTTP base URL is empty")
	}
	if !strings.Contains(trimmed, "://") {
		trimmed = "http://" + trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		// Never echo the raw URL or wrapped *url.Error since malformed input may contain credentials.
		return nil, fmt.Errorf("parse surprisal-service URL: invalid URL syntax")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("surprisal-service base URL must not contain embedded userinfo or credentials")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported surprisal-service URL scheme %q (expected http or https)", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("surprisal-service URL is missing host")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("surprisal-service base URL must not include query parameters or fragments")
	}
	if !allowRemote && !security.IsLoopbackEndpoint(parsed.String()) {
		return nil, fmt.Errorf("refusing non-loopback surprisal-service URL %q without allow_remote_endpoints=true", parsed.Redacted())
	}
	// Trim literal trailing '/' on the escaped path BEFORE decoding so trailing
	// percent-encoded slashes (e.g. /tenant%2F/) are preserved accurately.
	escapedBase := strings.TrimRight(parsed.EscapedPath(), "/")
	decodedBase, unescErr := url.PathUnescape(escapedBase)
	if unescErr != nil {
		return nil, fmt.Errorf("parse surprisal-service URL: invalid escaped path")
	}
	parsed.Path = decodedBase
	if escapedBase != decodedBase {
		parsed.RawPath = escapedBase
	} else {
		parsed.RawPath = ""
	}
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &HTTPClient{
		baseURL:     parsed,
		allowRemote: allowRemote,
		client:      security.NewLoopbackHTTPClient(timeout, allowRemote, false),
	}, nil
}

func (c *HTTPClient) endpointURL(suffix string) string {
	u := *c.baseURL
	u.Path = c.baseURL.Path + suffix
	if c.baseURL.RawPath != "" {
		u.RawPath = c.baseURL.RawPath + suffix
	}
	return u.String()
}

func (c *HTTPClient) redactedEndpointURL(suffix string) string {
	u := *c.baseURL
	u.User = nil
	u.Path = c.baseURL.Path + suffix
	if c.baseURL.RawPath != "" {
		u.RawPath = c.baseURL.RawPath + suffix
	}
	return u.String()
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

// Health checks GET /health on surprisal-service and verifies response body readability.
func (c *HTTPClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpointURL("/health"), nil)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("surprisal-service health request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("surprisal-service health returned status %d", resp.StatusCode)
	}
	n, copyErr := io.Copy(io.Discard, io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if copyErr != nil {
		return fmt.Errorf("read surprisal-service health response: %w", copyErr)
	}
	if n > maxHTTPResponseBytes {
		return fmt.Errorf("surprisal-service health response exceeded %d-byte limit", maxHTTPResponseBytes)
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
			Completion: "[" + sanitizeTag(rf.Nominal[1]) + "] log_window",
			Weight:     1.0,
		})
	}

	// Send the exact same structural feature summary format for the candidate as for
	// reference records (and omit raw log sample text) so identical benign windows score
	// 0.0 nats against ml/src/surprisal-service and raw log contents never leave local RAM.
	candFeat := ExtractFeatures(w)
	payload := verifyRequestPayload{
		ReferenceRecords:      refPayload,
		Prompt:                formatFeatureSummaryPrompt(candFeat),
		CandidateCompletion:   "[" + sanitizeTag(candFeat.Nominal[1]) + "] log_window",
		MaxTolerableSurprisal: thresholdNats,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("marshal surprisal verify request: %w", err)
	}

	verifyURL := c.endpointURL("/v1/verify/completion")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return VerifyResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("post %s: %w", c.redactedEndpointURL("/v1/verify/completion"), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return VerifyResponse{}, fmt.Errorf("surprisal-service returned status %d", resp.StatusCode)
	}

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return VerifyResponse{}, fmt.Errorf("read surprisal response: %w", err)
	}
	if len(respBytes) > maxHTTPResponseBytes {
		return VerifyResponse{}, fmt.Errorf("surprisal response exceeded %d-byte limit", maxHTTPResponseBytes)
	}

	var raw struct {
		IsConforming          *bool    `json:"is_conforming"`
		MeasuredSurprisalNats *float64 `json:"measured_surprisal_nats"`
		PredictedTag          string   `json:"predicted_tag"`
		CandidateTag          string   `json:"candidate_tag"`
		Explanation           string   `json:"explanation"`
	}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return VerifyResponse{}, fmt.Errorf("decode surprisal response: %w", err)
	}
	if raw.IsConforming == nil {
		return VerifyResponse{}, fmt.Errorf("surprisal response missing required field 'is_conforming'")
	}
	if raw.MeasuredSurprisalNats == nil {
		return VerifyResponse{}, fmt.Errorf("surprisal response missing required field 'measured_surprisal_nats'")
	}
	measured := *raw.MeasuredSurprisalNats
	if math.IsNaN(measured) || math.IsInf(measured, 0) || measured < 0 {
		return VerifyResponse{}, fmt.Errorf("surprisal response has invalid measured_surprisal_nats %v", measured)
	}
	return VerifyResponse{
		IsConforming:          *raw.IsConforming,
		MeasuredSurprisalNats: measured,
		PredictedTag:          raw.PredictedTag,
		CandidateTag:          raw.CandidateTag,
		Explanation:           raw.Explanation,
	}, nil
}

func formatFeatureSummaryPrompt(f LogFeatures) string {
	cleanSvc, _ := security.SanitizeUntrustedLogText(f.Nominal[0], maxServiceFeatureBytes)
	cleanLvl, _ := security.SanitizeUntrustedLogText(f.Nominal[1], maxLevelFeatureBytes)
	cleanTmpl, _ := security.SanitizeUntrustedLogText(f.Nominal[2], maxTemplateFeatureBytes)
	cleanProto, _ := security.SanitizeUntrustedLogText(f.Nominal[3], maxProtoFeatureBytes)
	return fmt.Sprintf("svc=%s lvl=%s tmpl=%s proto=%s tok=%.2f len=%.2f ent=%.2f sym=%.2f cnt=%.2f",
		cleanSvc, cleanLvl, cleanTmpl, cleanProto,
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
