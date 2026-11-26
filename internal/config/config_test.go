package config

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestDefaultConfigValidates(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() failed: %v", err)
	}
	if cfg.BaseModel != model.ModelSmolLM2135MInstruct {
		t.Fatalf("expected default base model %q, got %q", model.ModelSmolLM2135MInstruct, cfg.BaseModel)
	}
	if cfg.SurprisalMode != "inprocess" {
		t.Fatalf("expected default surprisal mode %q, got %q", "inprocess", cfg.SurprisalMode)
	}
	if cfg.DataDir == "" {
		t.Fatalf("expected non-empty default DataDir, got %q", cfg.DataDir)
	}
	if !cfg.RequireRedaction {
		t.Fatal("expected RequireRedaction to default to true")
	}
}

func TestConfigRejectsBitNetAndNonLoopback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BaseModel = "microsoft/BitNet-b1.58-2B-4T"
	if err := cfg.Validate(); !errors.Is(err, model.ErrExperimentalModelExcluded) {
		t.Fatalf("expected ErrExperimentalModelExcluded for BitNet, got %v", err)
	}

	cfg = DefaultConfig()
	cfg.FTaaSAPIAddr = "https://external.example.com:5100"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-loopback FTaaS endpoint to fail validation by default")
	}

	cfg.AllowRemoteEndpoints = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected AllowRemoteEndpoints=true to permit explicit remote address, got %v", err)
	}

	cfg = DefaultConfig()
	cfg.BaselineWindowSize = MaxBaselineWindowSize
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected BaselineWindowSize=%d to validate, got %v", MaxBaselineWindowSize, err)
	}
	cfg.BaselineWindowSize = MaxBaselineWindowSize + 1
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected BaselineWindowSize=%d to fail validation", MaxBaselineWindowSize+1)
	}

	for _, badThresh := range []float64{math.NaN(), math.Inf(1), math.Inf(-1), 0, -1.5} {
		cfg = DefaultConfig()
		cfg.SurprisalThreshold = badThresh
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected SurprisalThreshold=%v to fail validation", badThresh)
		}
	}

	cfg = DefaultConfig()
	cfg.TriageMode = "invalid"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected invalid triage_mode to fail validation")
	}
	cfg = DefaultConfig()
	cfg.AdapterPath = "../escape"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected traversal adapter_path to fail validation")
	}
	cfg = DefaultConfig()
	cfg.AdapterPath = "artifacts/job\t1/model_adapters"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected control-character adapter_path to fail validation")
	}
	cfg = DefaultConfig()
	cfg.AdapterPath = "  artifacts/job-1/model_adapters\n"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected leading/trailing whitespace around adapter_path to normalize cleanly, got %v", err)
	}
	if cfg.AdapterPath != "artifacts/job-1/model_adapters" {
		t.Fatalf("expected Validate() to normalize AdapterPath, got %q", cfg.AdapterPath)
	}
	// With triage_mode=off, small positive max_prompt_bytes (e.g. 256) remains valid while <=0 fails.
	cfg = DefaultConfig()
	cfg.TriageMode = "off"
	cfg.MaxPromptByte = 256
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected max_prompt_bytes=256 to validate when triage_mode=off, got %v", err)
	}
	cfg.MaxPromptByte = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected non-positive max_prompt_bytes to fail validation")
	}
	// With triage_mode=http, require both framing-sized max_prompt_bytes AND non-empty inference_http.
	cfg = DefaultConfig()
	cfg.TriageMode = "http"
	cfg.MaxPromptByte = 64
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected sub-framing max_prompt_bytes to fail validation when triage_mode=http")
	}
	cfg = DefaultConfig()
	cfg.TriageMode = "http"
	cfg.InferenceAddr = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected empty inference_http to fail validation when triage_mode=http")
	}
	cfg = DefaultConfig()
	cfg.TriageMaxTokens = 999
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected out-of-range triage_max_tokens to fail validation")
	}
	cfg = DefaultConfig()
	cfg.TriageTemperature = math.NaN()
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected NaN triage_temperature to fail validation")
	}
	cfg = DefaultConfig()
	cfg.TriageTimeoutSec = 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected triage_timeout_sec < 5 to fail validation")
	}
	cfg.TriageTimeoutSec = 301
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected triage_timeout_sec > 300 to fail validation")
	}
}

func TestLoadConfigFileAndEnvPrecedence(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "sentinel.json")
	raw := `{"base_model":"HuggingFaceTB/SmolLM2-135M-Instruct","surprisal_threshold_nats":4.25,"window":"15s","triage_timeout_sec":60,"triage_max_tokens":96}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatalf("failed writing temp config: %v", err)
	}

	t.Setenv("SENTINEL_SURPRISAL_THRESHOLD", "6.5")
	t.Setenv("SENTINEL_TRIAGE_TIMEOUT_SEC", "0")
	t.Setenv("SENTINEL_TRIAGE_MAX_TOKENS", "0")
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	if cfg.BaseModel != model.ModelSmolLM2135MInstruct {
		t.Fatalf("expected file base model, got %q", cfg.BaseModel)
	}
	if cfg.SurprisalThreshold != 6.5 {
		t.Fatalf("expected env override 6.5, got %v", cfg.SurprisalThreshold)
	}
	if cfg.WindowDuration.Seconds() != 15 {
		t.Fatalf("expected 15s window duration, got %v", cfg.WindowDuration)
	}
	if cfg.TriageTimeoutSec != 60 || cfg.TriageMaxTokens != 96 {
		t.Fatalf("expected nonpositive env overrides to preserve file values (60, 96), got (%d, %d)", cfg.TriageTimeoutSec, cfg.TriageMaxTokens)
	}
}

func TestConfigPhase5EscalationValidationAndEnv(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.EscalationMode != "off" || cfg.EscalationBaseModel != model.ModelGemma22BIT ||
		cfg.EscalationPolicy != EscalationPolicyHighCritical || !cfg.AutoReloadAdapter {
		t.Fatalf("unexpected Phase 5 default escalation config: %+v", cfg)
	}

	// Valid Gemma 2 2B IT escalation configuration
	cfg.EscalationMode = "http"
	cfg.EscalationPolicy = EscalationPolicyStrict
	cfg.EscalationAdapterPath = "  artifacts/gemma-job/model_adapters\n"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid escalation config, got %v", err)
	}
	if cfg.EscalationAdapterPath != "artifacts/gemma-job/model_adapters" {
		t.Fatalf("expected normalized EscalationAdapterPath, got %q", cfg.EscalationAdapterPath)
	}

	// Reject BitNet in escalation_base_model (ADR-5)
	bad := DefaultConfig()
	bad.EscalationBaseModel = "microsoft/BitNet-b1.58-2B-4T"
	if err := bad.Validate(); err == nil {
		t.Fatal("expected BitNet escalation_base_model to fail validation")
	}

	// Reject bad escalation_mode, escalation_policy, non-loopback inference URL, traversal adapter path
	for _, tc := range []struct {
		name string
		mut  func(*Config)
	}{
		{"BadMode", func(c *Config) { c.EscalationMode = "grpc" }},
		{"BadPolicy", func(c *Config) { c.EscalationPolicy = "yolo" }},
		{"BadRemoteAddr", func(c *Config) { c.EscalationInferenceAddr = "http://10.0.0.42:8001" }},
		{"TraversalAdapter", func(c *Config) { c.EscalationAdapterPath = "../escape" }},
		{"SmallPromptHTTP", func(c *Config) { c.EscalationMode = "http"; c.MaxPromptByte = 64 }},
		{"BadTokens", func(c *Config) { c.EscalationMaxTokens = 5 }},
		{"BadTimeout", func(c *Config) { c.EscalationTimeoutSec = 500 }},
		{"BadFloor", func(c *Config) { c.EscalationConfidenceFloor = 1.5 }},
	} {
		c := DefaultConfig()
		tc.mut(c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}

	// Environment variable overrides
	t.Setenv("SENTINEL_ESCALATION_MODE", "http")
	t.Setenv("SENTINEL_ESCALATION_INFERENCE_HTTP", "http://127.0.0.1:8101")
	t.Setenv("SENTINEL_ESCALATION_BASE_MODEL", model.ModelGemma22BIT)
	t.Setenv("SENTINEL_ESCALATION_ADAPTER_PATH", "artifacts/gemma-1/model_adapters")
	t.Setenv("SENTINEL_ESCALATION_POLICY", "always")
	t.Setenv("SENTINEL_ESCALATION_MAX_TOKENS", "128")
	t.Setenv("SENTINEL_ESCALATION_TIMEOUT_SEC", "120")
	t.Setenv("SENTINEL_ESCALATION_CONFIDENCE_FLOOR", "0.85")
	t.Setenv("SENTINEL_AUTO_RELOAD_ADAPTER", "false")

	loaded, err := LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if loaded.EscalationMode != "http" || loaded.EscalationInferenceAddr != "http://127.0.0.1:8101" ||
		loaded.EscalationPolicy != EscalationPolicyAlways || loaded.EscalationMaxTokens != 128 ||
		loaded.EscalationTimeoutSec != 120 || loaded.EscalationConfidenceFloor != 0.85 ||
		loaded.AutoReloadAdapter {
		t.Fatalf("unexpected Phase 5 env overrides: %+v", loaded)
	}
}
