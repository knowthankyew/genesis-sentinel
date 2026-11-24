package config

import (
	"errors"
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
}

func TestLoadConfigFileAndEnvPrecedence(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "sentinel.json")
	raw := `{"base_model":"HuggingFaceTB/SmolLM2-135M-Instruct","surprisal_threshold_nats":4.25,"window":"15s"}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0600); err != nil {
		t.Fatalf("failed writing temp config: %v", err)
	}

	t.Setenv("SENTINEL_SURPRISAL_THRESHOLD", "6.5")
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
}
