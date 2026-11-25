package config

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

// Default operational ceilings and tuning bounds for Genesis Sentinel.
const (
	DefaultMaxMemMB             = 256
	DefaultWindowSec            = 10
	DefaultSurprisalThreshold   = 5.0
	MinMaxPromptBytes           = 512
	DefaultMaxPromptBytes       = 2048
	DefaultMaxTrainingRecords   = 50000
	DefaultMaxTrainingFileBytes = 25 * 1024 * 1024
	MaxBaselineWindowSize       = 10000
	DefaultTriageMaxTokens      = 64
	DefaultTriageTemperature    = 0.1
	DefaultTriageTimeoutSec     = 45
)

// Config represents all operational configuration options for Genesis Sentinel.
// Loaded via Defaults -> sentinel.json -> SENTINEL_* environment variables -> CLI flags.
type Config struct {
	// Sidecar HTTP API & Health Surface
	HTTPAddr           string `json:"http"`
	AllowAllInterfaces bool   `json:"allow_all_interfaces"`
	AuthToken          string `json:"auth_token"`

	// Upstream Genesis Source & Alert Sink (loopback-only by default)
	GenesisHTTPAddr  string `json:"genesis_http"`
	GenesisTCPAddr   string `json:"genesis_tcp"`
	GenesisAuthToken string `json:"genesis_auth_token"`
	GenesisDataDir   string `json:"genesis_data_dir"`
	AlertServiceName string `json:"alert_service_name"`

	// Tier 0: Template Collapse & Deterministic Rules
	WindowDuration time.Duration `json:"-"`
	WindowStr      string        `json:"window"`
	RulesPath      string        `json:"rules_path"`

	// Tier 1: Laplace-LK Surprisal Engine
	SurprisalMode      string  `json:"surprisal_mode"` // "inprocess" | "http" | "hybrid"
	SurprisalHTTPAddr  string  `json:"surprisal_http"`
	SurprisalThreshold float64 `json:"surprisal_threshold_nats"`
	BaselineWindowSize int     `json:"baseline_window_size"`

	// Tier 2: FTaaS Training & Local LoRA Inference (Smol-first; Gemma Phase 5; BitNet excluded)
	TriageMode        string  `json:"triage_mode"` // "off" (default) | "http"
	TriageMaxTokens   int     `json:"triage_max_tokens"`
	TriageTemperature float64 `json:"triage_temperature"`
	TriageTimeoutSec  int     `json:"triage_timeout_sec"`
	BaseModel         string  `json:"base_model"`
	AdapterPath       string  `json:"adapter_path"`
	FTaaSAPIAddr      string  `json:"ftaas_api_http"`
	FTaaSAPIKey       string  `json:"ftaas_api_key"`
	InferenceAddr     string  `json:"inference_http"`
	MaxPromptByte     int     `json:"max_prompt_bytes"`

	// Local Disk State & Privacy Guardrails (intentional Pillar 1 variance; see ADR-4)
	DataDir              string `json:"data_dir"`
	FeedbackDir          string `json:"feedback_dir"`
	RequireRedaction     bool   `json:"require_redaction"`
	AllowRemoteEndpoints bool   `json:"allow_remote_endpoints"`
	MaxMemMB             int64  `json:"max_mem_mb"`
}

// DefaultDataDir resolves Sentinel's default local state directory (~/.genesis-sentinel).
// Operators can inspect or open this folder without memorizing hidden paths via
// `sentinel data path`, `sentinel data status`, and `sentinel data open`.
func DefaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ".genesis-sentinel"
	}
	return filepath.Join(home, ".genesis-sentinel")
}

// DefaultConfig returns safe local-first defaults matching Sentinel ADRs 1-7.
func DefaultConfig() *Config {
	dataDir := DefaultDataDir()
	return &Config{
		HTTPAddr:             "127.0.0.1:8090",
		AllowAllInterfaces:   false,
		AuthToken:            "",
		GenesisHTTPAddr:      "http://127.0.0.1:8080",
		GenesisTCPAddr:       "127.0.0.1:9000",
		GenesisAuthToken:     "",
		GenesisDataDir:       "",
		AlertServiceName:     "sentinel",
		WindowDuration:       DefaultWindowSec * time.Second,
		WindowStr:            "10s",
		RulesPath:            "",
		SurprisalMode:        "inprocess",
		SurprisalHTTPAddr:    "http://127.0.0.1:5200",
		SurprisalThreshold:   DefaultSurprisalThreshold,
		BaselineWindowSize:   2000,
		TriageMode:           "off",
		TriageMaxTokens:      DefaultTriageMaxTokens,
		TriageTemperature:    DefaultTriageTemperature,
		TriageTimeoutSec:     DefaultTriageTimeoutSec,
		BaseModel:            model.ModelSmolLM2135MInstruct,
		AdapterPath:          "",
		FTaaSAPIAddr:         "http://127.0.0.1:5100",
		FTaaSAPIKey:          "",
		InferenceAddr:        "http://127.0.0.1:8000",
		MaxPromptByte:        DefaultMaxPromptBytes,
		DataDir:              dataDir,
		FeedbackDir:          "",
		RequireRedaction:     true,
		AllowRemoteEndpoints: false,
		MaxMemMB:             DefaultMaxMemMB,
	}
}

// LoadConfig merges Defaults -> Config File -> SENTINEL_* Environment Variables.
func LoadConfig(configPath string) (*Config, error) {
	cfg := DefaultConfig()

	if configPath != "" {
		if err := loadFromFile(cfg, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config file %q: %w", configPath, err)
		}
	} else if _, err := os.Stat("sentinel.json"); err == nil {
		if err := loadFromFile(cfg, "sentinel.json"); err != nil {
			return nil, fmt.Errorf("failed to load sentinel.json: %w", err)
		}
	}

	loadFromEnv(cfg)

	if cfg.FeedbackDir == "" && cfg.DataDir != "" {
		cfg.FeedbackDir = filepath.Join(cfg.DataDir, "feedback")
	}

	if cfg.WindowStr != "" {
		d, err := time.ParseDuration(cfg.WindowStr)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("invalid window duration %q", cfg.WindowStr)
		}
		cfg.WindowDuration = d
	}

	return cfg, nil
}

// Validate enforces Sentinel's architectural invariants (zero-egress loopback defaults,
// model allowlist excluding experimental BitNet, and sane operational bounds).
func (c *Config) Validate() error {
	if _, err := model.ValidateBaseModel(c.BaseModel); err != nil {
		return fmt.Errorf("invalid base_model: %w", err)
	}

	switch c.SurprisalMode {
	case "inprocess", "http", "hybrid":
	default:
		return fmt.Errorf("invalid surprisal_mode %q: must be inprocess, http, or hybrid", c.SurprisalMode)
	}

	if math.IsNaN(c.SurprisalThreshold) || math.IsInf(c.SurprisalThreshold, 0) || c.SurprisalThreshold <= 0 {
		return fmt.Errorf("surprisal_threshold_nats must be a positive finite number, got %v", c.SurprisalThreshold)
	}
	if c.BaselineWindowSize <= 0 || c.BaselineWindowSize > MaxBaselineWindowSize {
		return fmt.Errorf("baseline_window_size must be between 1 and %d, got %d", MaxBaselineWindowSize, c.BaselineWindowSize)
	}
	if c.MaxPromptByte < MinMaxPromptBytes {
		return fmt.Errorf("max_prompt_bytes must be at least %d to fit required prompt framing, got %d", MinMaxPromptBytes, c.MaxPromptByte)
	}
	if c.MaxMemMB <= 0 {
		return fmt.Errorf("max_mem_mb must be positive, got %d", c.MaxMemMB)
	}

	switch strings.ToLower(strings.TrimSpace(c.TriageMode)) {
	case "", "off":
		c.TriageMode = "off"
	case "http":
		c.TriageMode = "http"
	default:
		return fmt.Errorf("invalid triage_mode %q: must be off or http", c.TriageMode)
	}
	if c.TriageMaxTokens < 16 || c.TriageMaxTokens > 256 {
		return fmt.Errorf("triage_max_tokens must be between 16 and 256, got %d", c.TriageMaxTokens)
	}
	if math.IsNaN(c.TriageTemperature) || math.IsInf(c.TriageTemperature, 0) || c.TriageTemperature < 0 || c.TriageTemperature > 1.0 {
		return fmt.Errorf("triage_temperature must be finite and in [0.0, 1.0], got %v", c.TriageTemperature)
	}
	if c.TriageTimeoutSec < 5 || c.TriageTimeoutSec > 300 {
		return fmt.Errorf("triage_timeout_sec must be between 5 and 300, got %d", c.TriageTimeoutSec)
	}
	c.AdapterPath = strings.TrimSpace(c.AdapterPath)
	if trimmedAdapter := c.AdapterPath; trimmedAdapter != "" {
		for _, r := range trimmedAdapter {
			if unicode.IsControl(r) {
				return fmt.Errorf("adapter_path %q must not contain control characters", c.AdapterPath)
			}
		}
		if strings.HasPrefix(trimmedAdapter, "/") || strings.ContainsRune(trimmedAdapter, '\\') ||
			(len(trimmedAdapter) >= 2 && trimmedAdapter[1] == ':') {
			return fmt.Errorf("adapter_path %q must be a relative forward-slash path under artifacts/", c.AdapterPath)
		}
		for _, seg := range strings.Split(trimmedAdapter, "/") {
			if seg == ".." {
				return fmt.Errorf("adapter_path %q must not contain path traversal segments", c.AdapterPath)
			}
		}
		cleanedAdapter := path.Clean(trimmedAdapter)
		if cleanedAdapter == "." || cleanedAdapter == ".." || strings.HasPrefix(cleanedAdapter, "../") ||
			strings.HasPrefix(cleanedAdapter, "/") || (len(cleanedAdapter) >= 2 && cleanedAdapter[1] == ':') {
			return fmt.Errorf("adapter_path %q must be a relative forward-slash path under artifacts/", c.AdapterPath)
		}
	}

	if !c.AllowAllInterfaces && security.IsBindingAllInterfaces(c.HTTPAddr) {
		return fmt.Errorf("http listen address %q binds all interfaces without allow_all_interfaces=true", c.HTTPAddr)
	}

	if !c.AllowRemoteEndpoints {
		endpoints := map[string]string{
			"genesis_http":   c.GenesisHTTPAddr,
			"genesis_tcp":    c.GenesisTCPAddr,
			"surprisal_http": c.SurprisalHTTPAddr,
			"ftaas_api_http": c.FTaaSAPIAddr,
			"inference_http": c.InferenceAddr,
		}
		for name, addr := range endpoints {
			if addr != "" && !security.IsLoopbackEndpoint(addr) {
				return fmt.Errorf("%s (%q) must target loopback unless allow_remote_endpoints=true", name, addr)
			}
		}
	}

	return nil
}

func loadFromFile(cfg *Config, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, cfg)
}

func loadFromEnv(cfg *Config) {
	if v := os.Getenv("SENTINEL_HTTP"); v != "" {
		cfg.HTTPAddr = v
	}
	if v := os.Getenv("SENTINEL_ALLOW_ALL_INTERFACES"); v != "" {
		cfg.AllowAllInterfaces = parseBool(v)
	}
	if v := os.Getenv("SENTINEL_AUTH_TOKEN"); v != "" {
		cfg.AuthToken = v
	}
	if v := os.Getenv("SENTINEL_GENESIS_HTTP"); v != "" {
		cfg.GenesisHTTPAddr = v
	}
	if v := os.Getenv("SENTINEL_GENESIS_TCP"); v != "" {
		cfg.GenesisTCPAddr = v
	}
	if v := os.Getenv("SENTINEL_GENESIS_AUTH_TOKEN"); v != "" {
		cfg.GenesisAuthToken = v
	}
	if v := os.Getenv("SENTINEL_GENESIS_DATA_DIR"); v != "" {
		cfg.GenesisDataDir = v
	}
	if v := os.Getenv("SENTINEL_ALERT_SERVICE"); v != "" {
		cfg.AlertServiceName = v
	}
	if v := os.Getenv("SENTINEL_WINDOW"); v != "" {
		cfg.WindowStr = v
	}
	if v := os.Getenv("SENTINEL_RULES_PATH"); v != "" {
		cfg.RulesPath = v
	}
	if v := os.Getenv("SENTINEL_SURPRISAL_MODE"); v != "" {
		cfg.SurprisalMode = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("SENTINEL_SURPRISAL_HTTP"); v != "" {
		cfg.SurprisalHTTPAddr = v
	}
	if v := os.Getenv("SENTINEL_SURPRISAL_THRESHOLD"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.SurprisalThreshold = f
		}
	}
	if v := os.Getenv("SENTINEL_BASELINE_WINDOW_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.BaselineWindowSize = n
		}
	}
	if v := os.Getenv("SENTINEL_TRIAGE_MODE"); v != "" {
		cfg.TriageMode = strings.ToLower(strings.TrimSpace(v))
	}
	if v := os.Getenv("SENTINEL_TRIAGE_MAX_TOKENS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TriageMaxTokens = n
		}
	}
	if v := os.Getenv("SENTINEL_TRIAGE_TEMPERATURE"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.TriageTemperature = f
		}
	}
	if v := os.Getenv("SENTINEL_TRIAGE_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.TriageTimeoutSec = n
		}
	}
	if v := os.Getenv("SENTINEL_BASE_MODEL"); v != "" {
		cfg.BaseModel = v
	}
	if v := os.Getenv("SENTINEL_ADAPTER_PATH"); v != "" {
		cfg.AdapterPath = v
	}
	if v := os.Getenv("SENTINEL_FTAAS_API_HTTP"); v != "" {
		cfg.FTaaSAPIAddr = v
	}
	if v := os.Getenv("SENTINEL_FTAAS_API_KEY"); v != "" {
		cfg.FTaaSAPIKey = v
	}
	if v := os.Getenv("SENTINEL_INFERENCE_HTTP"); v != "" {
		cfg.InferenceAddr = v
	}
	if v := os.Getenv("SENTINEL_MAX_PROMPT_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxPromptByte = n
		}
	}
	if v := os.Getenv("SENTINEL_DATA_DIR"); v != "" {
		cfg.DataDir = v
	}
	if v := os.Getenv("SENTINEL_FEEDBACK_DIR"); v != "" {
		cfg.FeedbackDir = v
	}
	if v := os.Getenv("SENTINEL_REQUIRE_REDACTION"); v != "" {
		cfg.RequireRedaction = parseBool(v)
	}
	if v := os.Getenv("SENTINEL_ALLOW_REMOTE_ENDPOINTS"); v != "" {
		cfg.AllowRemoteEndpoints = parseBool(v)
	}
	if v := os.Getenv("SENTINEL_MAX_MEM_MB"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.MaxMemMB = n
		}
	}
}

func parseBool(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "true" || s == "1" || s == "yes" || s == "on"
}
