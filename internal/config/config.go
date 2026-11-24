package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
)

// Default operational ceilings and tuning bounds for Genesis Sentinel.
const (
	DefaultMaxMemMB             = 256
	DefaultWindowSec            = 10
	DefaultSurprisalThreshold   = 5.0
	DefaultMaxPromptBytes       = 2048
	DefaultMaxTrainingRecords   = 50000
	DefaultMaxTrainingFileBytes = 25 * 1024 * 1024
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
	BaseModel     string `json:"base_model"`
	AdapterPath   string `json:"adapter_path"`
	FTaaSAPIAddr  string `json:"ftaas_api_http"`
	InferenceAddr string `json:"inference_http"`
	MaxPromptByte int    `json:"max_prompt_bytes"`

	// Feedback & Privacy Guardrails
	FeedbackDir          string `json:"feedback_dir"`
	RequireRedaction     bool   `json:"require_redaction"`
	AllowRemoteEndpoints bool   `json:"allow_remote_endpoints"`
	MaxMemMB             int64  `json:"max_mem_mb"`
}

// DefaultConfig returns safe local-first defaults matching Genesis privacy invariants.
func DefaultConfig() *Config {
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
		BaseModel:            model.ModelSmolLM2135M,
		AdapterPath:          "",
		FTaaSAPIAddr:         "http://127.0.0.1:5100",
		InferenceAddr:        "http://127.0.0.1:8000",
		MaxPromptByte:        DefaultMaxPromptBytes,
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

	if c.SurprisalThreshold <= 0 {
		return fmt.Errorf("surprisal_threshold_nats must be positive, got %v", c.SurprisalThreshold)
	}
	if c.BaselineWindowSize <= 0 {
		return fmt.Errorf("baseline_window_size must be positive, got %d", c.BaselineWindowSize)
	}
	if c.MaxPromptByte <= 0 {
		return fmt.Errorf("max_prompt_bytes must be positive, got %d", c.MaxPromptByte)
	}
	if c.MaxMemMB <= 0 {
		return fmt.Errorf("max_mem_mb must be positive, got %d", c.MaxMemMB)
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
	if v := os.Getenv("SENTINEL_BASE_MODEL"); v != "" {
		cfg.BaseModel = v
	}
	if v := os.Getenv("SENTINEL_ADAPTER_PATH"); v != "" {
		cfg.AdapterPath = v
	}
	if v := os.Getenv("SENTINEL_FTAAS_API_HTTP"); v != "" {
		cfg.FTaaSAPIAddr = v
	}
	if v := os.Getenv("SENTINEL_INFERENCE_HTTP"); v != "" {
		cfg.InferenceAddr = v
	}
	if v := os.Getenv("SENTINEL_MAX_PROMPT_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.MaxPromptByte = n
		}
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
