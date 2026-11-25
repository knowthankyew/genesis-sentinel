package triage

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

const (
	defaultInferenceTimeout   = 10 * time.Second
	defaultCircuitCooldown    = 30 * time.Second
	maxInferenceResponseBytes = 256 * 1024 // 256 KiB cap on local inference response bodies
)

// ClientOptions configures the loopback Tier 2 inference client targeting
// ml/src/FtaaSService.Inference (/api/v1/inference/generate).
type ClientOptions struct {
	BaseURL        string
	BaseModel      string
	AdapterPath    string
	APIKey         string
	Timeout        time.Duration
	Cooldown       time.Duration
	MaxTokens      int
	Temperature    float64
	MaxPromptBytes int
	AllowRemote    bool
}

// ClientStats exposes live diagnostics for Tier 2 local inference calls.
type ClientStats struct {
	BaseModel          string `json:"base_model"`
	AdapterPath        string `json:"adapter_path,omitempty"`
	EvaluatedTotal     uint64 `json:"evaluated_total"`
	FallbacksTotal     uint64 `json:"fallbacks_total"`
	InjectionOverrides uint64 `json:"injection_overrides"`
	CircuitOpen        bool   `json:"circuit_open"`
}

// HealthStatus summarizes GET /healthz from the local FTaaS inference server.
type HealthStatus struct {
	Status             string `json:"status"`
	Device             string `json:"device"`
	BaseModel          string `json:"baseModel"`
	BaseModelLoaded    bool   `json:"baseModelLoaded"`
	Backend            string `json:"backend"`
	CachedAdapterCount int    `json:"cachedAdapterCount"`
	ChatTemplate       string `json:"chatTemplate"`
}

type generateRequest struct {
	BaseModel         string  `json:"baseModel,omitempty"`
	AdapterPath       string  `json:"adapterPath,omitempty"`
	Prompt            string  `json:"prompt"`
	MaxTokens         int     `json:"maxTokens"`
	Temperature       float64 `json:"temperature"`
	ApplyChatTemplate bool    `json:"applyChatTemplate"`
}

type generateResponse struct {
	BaseModel   *string `json:"baseModel"`
	AdapterPath *string `json:"adapterPath"`
	Completion  string  `json:"completion"`
	LatencyMs   float64 `json:"latencyMs"`
}

// Client invokes the local FTaaS PyTorch/PEFT inference server over loopback HTTP,
// enforcing model allowlist governance, prompt sanitization, bounded retries via a
// generation-tracked circuit breaker, and fail-closed verdict parsing.
type Client struct {
	baseURL        string
	redactedURL    string
	apiKey         string
	maxTokens      int
	temperature    float64
	maxPromptBytes int
	cooldown       time.Duration
	httpClient     *http.Client
	nowFn          func() time.Time

	mu                 sync.Mutex
	baseModel          string
	adapterPath        string
	openUntil          time.Time
	circuitGen         uint64
	evaluatedTotal     uint64
	fallbacksTotal     uint64
	injectionOverrides uint64
}

// ValidateAdapterPath checks that a LoRA adapter path conforms to FTaaS's relative path
// confinement rule (no absolute paths, no ".." traversal segments, no control characters).
func ValidateAdapterPath(rel string) (string, error) {
	trimmed := strings.TrimSpace(rel)
	if trimmed == "" {
		return "", nil
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", fmt.Errorf("invalid adapter path: contains control characters")
		}
	}
	// Reject Windows drive prefixes or backslashes that could confuse cross-platform path resolution.
	if strings.ContainsRune(trimmed, '\\') || (len(trimmed) >= 2 && trimmed[1] == ':') {
		return "", fmt.Errorf("invalid adapter path %q: must use relative forward-slash segments", rel)
	}
	if strings.HasPrefix(trimmed, "/") {
		return "", fmt.Errorf("invalid adapter path %q: must be relative under artifacts/", rel)
	}
	for _, seg := range strings.Split(trimmed, "/") {
		if seg == ".." {
			return "", fmt.Errorf("invalid adapter path %q: path traversal is prohibited", rel)
		}
	}
	cleaned := path.Clean(trimmed)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || strings.HasPrefix(cleaned, "/") || (len(cleaned) >= 2 && cleaned[1] == ':') {
		return "", fmt.Errorf("invalid adapter path %q: escapes artifacts directory", rel)
	}
	return cleaned, nil
}

// NewClient constructs a validated Tier 2 inference client.
func NewClient(opts ClientOptions) (*Client, error) {
	baseModel := strings.TrimSpace(opts.BaseModel)
	if baseModel == "" {
		baseModel = model.ModelSmolLM2135MInstruct
	}
	if _, err := model.ValidateBaseModel(baseModel); err != nil {
		return nil, fmt.Errorf("triage client base_model: %w", err)
	}

	adapterPath, err := ValidateAdapterPath(opts.AdapterPath)
	if err != nil {
		return nil, err
	}

	rawURL := strings.TrimSpace(opts.BaseURL)
	if rawURL == "" {
		rawURL = "http://127.0.0.1:8000"
	}
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid inference URL: failed to parse host")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported inference URL scheme %q (expected http or https)", u.Scheme)
	}
	if !opts.AllowRemote && !security.IsLoopbackEndpoint(rawURL) {
		return nil, fmt.Errorf("refusing non-loopback inference endpoint %q without allow_remote_endpoints=true", u.Host)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultInferenceTimeout
	}
	cooldown := opts.Cooldown
	if cooldown <= 0 {
		cooldown = defaultCircuitCooldown
	}
	maxTokens := opts.MaxTokens
	if maxTokens <= 0 {
		maxTokens = DefaultMaxTokens
	}
	if maxTokens < MinMaxTokens {
		maxTokens = MinMaxTokens
	}
	if maxTokens > MaxAllowedTokens {
		maxTokens = MaxAllowedTokens
	}
	temp := opts.Temperature
	if math.IsNaN(temp) || math.IsInf(temp, 0) || temp < 0 {
		temp = DefaultTemperature
	}
	if temp > 1.0 {
		temp = 1.0
	}
	maxPrompt := opts.MaxPromptBytes
	if maxPrompt <= 0 {
		maxPrompt = config.DefaultMaxPromptBytes
	}
	if maxPrompt < MinPromptBytes {
		return nil, fmt.Errorf("triage max_prompt_bytes %d is too small to fit required prompt framing (minimum %d)", maxPrompt, MinPromptBytes)
	}

	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	u.Path = strings.TrimRight(u.Path, "/")
	fullBase := strings.TrimRight(u.String(), "/")
	redactedU := *u
	redactedU.User = nil
	redactedBase := strings.TrimRight(redactedU.String(), "/")

	return &Client{
		baseURL:        fullBase,
		redactedURL:    redactedBase,
		apiKey:         strings.TrimSpace(opts.APIKey),
		maxTokens:      maxTokens,
		temperature:    temp,
		maxPromptBytes: maxPrompt,
		cooldown:       cooldown,
		httpClient:     security.NewLoopbackHTTPClient(timeout, opts.AllowRemote, true),
		nowFn:          time.Now,
		baseModel:      baseModel,
		adapterPath:    adapterPath,
	}, nil
}

// SetAdapterPath hot-swaps the active LoRA adapter relative path after validation.
func (c *Client) SetAdapterPath(relPath string) error {
	clean, err := ValidateAdapterPath(relPath)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.adapterPath = clean
	c.openUntil = time.Time{}
	c.circuitGen++
	c.mu.Unlock()
	return nil
}

// SetBaseModel updates the active base model after verifying it against the model allowlist.
func (c *Client) SetBaseModel(baseModel string) error {
	if _, err := model.ValidateBaseModel(baseModel); err != nil {
		return err
	}
	c.mu.Lock()
	c.baseModel = strings.TrimSpace(baseModel)
	c.openUntil = time.Time{}
	c.circuitGen++
	c.mu.Unlock()
	return nil
}

// AdapterPath returns the currently active LoRA adapter relative path.
func (c *Client) AdapterPath() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.adapterPath
}

// BaseModel returns the currently configured allowlisted base model ID.
func (c *Client) BaseModel() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.baseModel
}

// SetModelAndAdapter atomically validates and hot-swaps both the active base model and
// LoRA adapter path under a single lock so concurrent readers never observe a torn pair.
func (c *Client) SetModelAndAdapter(baseModel, relPath string) error {
	if _, err := model.ValidateBaseModel(baseModel); err != nil {
		return err
	}
	clean, err := ValidateAdapterPath(relPath)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.baseModel = strings.TrimSpace(baseModel)
	c.adapterPath = clean
	c.openUntil = time.Time{}
	c.circuitGen++
	c.mu.Unlock()
	return nil
}

// ResetAdapter deactivates any hot-swapped LoRA adapter (reverting to base-model-only
// inference) and clears the circuit breaker. Used by Pipeline.Burn().
func (c *Client) ResetAdapter() {
	c.mu.Lock()
	c.adapterPath = ""
	c.openUntil = time.Time{}
	c.circuitGen++
	c.mu.Unlock()
}

// ResetCircuit clears the circuit breaker and bumps circuitGen so older in-flight failures
// cannot re-open a freshly reset breaker.
func (c *Client) ResetCircuit() {
	c.mu.Lock()
	c.openUntil = time.Time{}
	c.circuitGen++
	c.mu.Unlock()
}

func (c *Client) now() time.Time {
	if c.nowFn != nil {
		return c.nowFn()
	}
	return time.Now()
}

// Stats returns a thread-safe snapshot of Tier 2 inference counters.
func (c *Client) Stats() ClientStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return ClientStats{
		BaseModel:          c.baseModel,
		AdapterPath:        c.adapterPath,
		EvaluatedTotal:     c.evaluatedTotal,
		FallbacksTotal:     c.fallbacksTotal,
		InjectionOverrides: c.injectionOverrides,
		CircuitOpen:        !c.openUntil.IsZero() && c.now().Before(c.openUntil),
	}
}

// Health checks GET /healthz on the local FTaaS inference service.
func (c *Client) Health(ctx context.Context) (HealthStatus, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return HealthStatus{}, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return HealthStatus{}, fmt.Errorf("inference health check at %s: %w", c.redactedURL, security.SanitizeURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInferenceResponseBytes+1))
	if err != nil {
		return HealthStatus{}, fmt.Errorf("read inference /healthz body: %w", err)
	}
	if len(body) > maxInferenceResponseBytes {
		return HealthStatus{}, fmt.Errorf("inference /healthz body exceeded %d bytes", maxInferenceResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return HealthStatus{}, fmt.Errorf("inference /healthz returned HTTP %d", resp.StatusCode)
	}
	var st HealthStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return HealthStatus{}, fmt.Errorf("decode inference /healthz: %w", err)
	}
	return st, nil
}

// TriageWindow sends a sanitized, framed Tier 0+1 window prompt to local inference and
// returns a fail-closed model.TriageVerdict plus whether an injection override occurred.
func (c *Client) TriageWindow(ctx context.Context, in PromptInput) (model.TriageVerdict, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	c.mu.Lock()
	now := c.now()
	if !c.openUntil.IsZero() && now.Before(c.openUntil) {
		until := c.openUntil
		c.fallbacksTotal++
		c.mu.Unlock()
		return model.TriageVerdict{}, false, fmt.Errorf("tier2 inference circuit open until %s", until.Format(time.RFC3339))
	}
	if ctx.Err() != nil {
		c.fallbacksTotal++
		c.mu.Unlock()
		return model.TriageVerdict{}, false, ctx.Err()
	}
	baseModel := c.baseModel
	adapterPath := c.adapterPath
	circuitGen := c.circuitGen
	c.mu.Unlock()

	prompt, injSuspected, injSignals := BuildTriagePrompt(in, c.maxPromptBytes)

	payload := generateRequest{
		BaseModel:         baseModel,
		AdapterPath:       adapterPath,
		Prompt:            prompt,
		MaxTokens:         c.maxTokens,
		Temperature:       c.temperature,
		ApplyChatTemplate: true,
	}
	rawBody, err := json.Marshal(payload)
	if err != nil {
		return model.TriageVerdict{}, false, fmt.Errorf("marshal generate request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/inference/generate", bytes.NewReader(rawBody))
	if err != nil {
		return model.TriageVerdict{}, false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// Distinguish explicit caller cancellation (shutdown/abort -> keep breaker closed) from
		// dispatched request timeouts or transport failures (including exhausting a flush budget
		// while the server hangs -> trip breaker so subsequent flushes do not stall repeatedly).
		explicitCancel := errors.Is(ctx.Err(), context.Canceled) && errors.Is(err, context.Canceled)
		c.recordFailure(circuitGen, !explicitCancel)
		return model.TriageVerdict{}, false, fmt.Errorf("post %s/api/v1/inference/generate: %w", c.redactedURL, security.SanitizeURLError(err))
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxInferenceResponseBytes+1))
	if err != nil {
		explicitCancel := errors.Is(ctx.Err(), context.Canceled) && errors.Is(err, context.Canceled)
		c.recordFailure(circuitGen, !explicitCancel)
		return model.TriageVerdict{}, false, fmt.Errorf("read inference response: %w", security.SanitizeURLError(err))
	}
	if len(respBody) > maxInferenceResponseBytes {
		c.recordFailure(circuitGen, true)
		return model.TriageVerdict{}, false, fmt.Errorf("inference response exceeded %d bytes", maxInferenceResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		// Open circuit on 5xx/409/422 server or model-mismatch errors so we don't hammer
		// an unhealthy or mismatched local inference server on every alert window.
		c.recordFailure(circuitGen, resp.StatusCode >= 500 || resp.StatusCode == http.StatusConflict || resp.StatusCode == http.StatusUnprocessableEntity)
		return model.TriageVerdict{}, false, fmt.Errorf("inference endpoint returned HTTP %d: %s",
			resp.StatusCode, redactErrSnippet(string(respBody)))
	}

	var genResp generateResponse
	if err := json.Unmarshal(respBody, &genResp); err != nil {
		c.recordFailure(circuitGen, true)
		return model.TriageVerdict{}, false, fmt.Errorf("decode inference response: %w", err)
	}
	if strings.TrimSpace(genResp.Completion) == "" {
		c.recordFailure(circuitGen, false)
		return model.TriageVerdict{}, false, fmt.Errorf("inference returned empty completion")
	}
	// Fail closed if the server explicitly reports a different (or explicitly empty) runtime
	// model or adapter than requested, while keeping omitted optional response fields compatible.
	if genResp.BaseModel != nil {
		if respModel := strings.TrimSpace(*genResp.BaseModel); respModel != baseModel {
			c.recordFailure(circuitGen, true)
			return model.TriageVerdict{}, false, fmt.Errorf("inference baseModel mismatch: requested %q, server used %q", baseModel, respModel)
		}
	}
	if genResp.AdapterPath != nil {
		if respAdapter := strings.TrimSpace(*genResp.AdapterPath); respAdapter != adapterPath {
			c.recordFailure(circuitGen, true)
			return model.TriageVerdict{}, false, fmt.Errorf("inference adapterPath mismatch: requested %q, server used %q", adapterPath, respAdapter)
		}
	}

	verdict, overridden := ParseCompletion(
		genResp.Completion,
		baseModel,
		adapterPath,
		in.TemplateID,
		injSuspected,
		injSignals,
	)

	c.mu.Lock()
	c.evaluatedTotal++
	if overridden {
		c.injectionOverrides++
	}
	if !c.openUntil.IsZero() && c.circuitGen == circuitGen {
		c.openUntil = time.Time{}
	}
	c.mu.Unlock()

	return verdict, overridden, nil
}

func (c *Client) recordFailure(circuitGen uint64, tripBreaker bool) {
	c.mu.Lock()
	c.fallbacksTotal++
	if tripBreaker && c.circuitGen == circuitGen {
		c.openUntil = c.now().Add(c.cooldown)
		c.circuitGen++
	}
	c.mu.Unlock()
}

var (
	diagAuthCredRe = regexp.MustCompile(`(?i)\b((?:Bearer|Basic)\s+)[A-Za-z0-9._~+/=-]{6,}`)
	diagJWTRe      = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)
	diagCredKVRe   = regexp.MustCompile(`(?i)(["']?)(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)(["']?\s*[=:]\s*)("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}]+)`)
)

func redactErrSnippet(raw string) string {
	s := sanitizeSingleLine(raw, 240)
	s = diagJWTRe.ReplaceAllString(s, "[REDACTED_JWT]")
	s = diagAuthCredRe.ReplaceAllString(s, "${1}[REDACTED_TOKEN]")
	s = diagCredKVRe.ReplaceAllString(s, "${1}${2}${3}[REDACTED_SECRET]")
	return s
}
