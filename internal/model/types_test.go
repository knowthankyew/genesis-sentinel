package model

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestValidateBaseModel(t *testing.T) {
	tests := []struct {
		name     string
		modelID  string
		wantTier ModelTier
		wantErr  error
	}{
		{
			name:     "smol base local default",
			modelID:  ModelSmolLM2135M,
			wantTier: TierSmol,
		},
		{
			name:     "smol 135m instruct",
			modelID:  ModelSmolLM2135MInstruct,
			wantTier: TierSmol,
		},
		{
			name:     "smol 360m instruct",
			modelID:  ModelSmolLM2360MInstruct,
			wantTier: TierSmol,
		},
		{
			name:     "gemma 2b phase 5 tier",
			modelID:  ModelGemma22BIT,
			wantTier: TierGemma,
		},
		{
			name:    "bitnet explicitly excluded",
			modelID: "microsoft/BitNet-b1.58-2B-4T",
			wantErr: ErrExperimentalModelExcluded,
		},
		{
			name:    "bitnet embedding explicitly excluded",
			modelID: "microsoft/bitnet-embedding-270m",
			wantErr: ErrExperimentalModelExcluded,
		},
		{
			name:    "empty model rejected",
			modelID: "   ",
			wantErr: ErrUnsupportedModel,
		},
		{
			name:    "unknown model rejected",
			modelID: "org/unknown-7b",
			wantErr: ErrUnsupportedModel,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := ValidateBaseModel(tc.modelID)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("ValidateBaseModel(%q) error = %v, want %v", tc.modelID, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateBaseModel(%q) unexpected error: %v", tc.modelID, err)
			}
			if spec.Tier != tc.wantTier {
				t.Fatalf("ValidateBaseModel(%q) tier = %q, want %q", tc.modelID, spec.Tier, tc.wantTier)
			}
		})
	}
}

func TestLogEventJSONMatchesGenesisContract(t *testing.T) {
	raw := `{"id":42,"timestamp":1763996400,"service":"sshd","level":"ERROR","trace_id":"t-1","message":"Failed password for invalid user admin","attributes":{"src_ip":"192.0.2.10"},"size_bytes":412}`

	var ev LogEvent
	if err := json.Unmarshal([]byte(raw), &ev); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if ev.ID != 42 || ev.Service != "sshd" || ev.Level != "ERROR" || ev.TraceID != "t-1" {
		t.Fatalf("unexpected decoded LogEvent: %+v", ev)
	}
	if ev.Attributes["src_ip"] != "192.0.2.10" {
		t.Fatalf("expected attributes.src_ip=192.0.2.10, got %q", ev.Attributes["src_ip"])
	}
}
