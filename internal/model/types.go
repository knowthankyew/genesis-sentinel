package model

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Supported base model identifiers for the Genesis Sentinel LoRA pipeline.
// SmolLM2 is the active development and edge triage tier (Phases 0-4).
// Gemma 2 2B IT is scheduled as the Phase 5 reasoning-tier upgrade.
// Experimental BitNet models are explicitly excluded pending upstream toolchain maturity.
const (
	ModelSmolLM2135M         = "HuggingFaceTB/SmolLM2-135M"
	ModelSmolLM2135MInstruct = "HuggingFaceTB/SmolLM2-135M-Instruct"
	ModelSmolLM2360MInstruct = "HuggingFaceTB/SmolLM2-360M-Instruct"
	ModelGemma22BIT          = "google/gemma-2-2b-it"
)

// ModelTier classifies the intended operational tier of a base model.
type ModelTier string

const (
	TierSmol  ModelTier = "smol"
	TierGemma ModelTier = "gemma"
)

// ModelSpec defines static metadata for an allowlisted base model.
type ModelSpec struct {
	ID            string    `json:"id"`
	Tier          ModelTier `json:"tier"`
	InstructTuned bool      `json:"instruct_tuned"`
	RoadmapPhase  int       `json:"roadmap_phase"`
}

var (
	// ErrUnsupportedModel is returned when a model ID is not in the Sentinel allowlist.
	ErrUnsupportedModel = errors.New("unsupported base model")
	// ErrExperimentalModelExcluded is returned when an excluded experimental family (e.g. BitNet) is requested.
	ErrExperimentalModelExcluded = errors.New("experimental model family excluded by ADR-5")
)

var allowedModels = map[string]ModelSpec{
	ModelSmolLM2135M: {
		ID:            ModelSmolLM2135M,
		Tier:          TierSmol,
		InstructTuned: false,
		RoadmapPhase:  3,
	},
	ModelSmolLM2135MInstruct: {
		ID:            ModelSmolLM2135MInstruct,
		Tier:          TierSmol,
		InstructTuned: true,
		RoadmapPhase:  3,
	},
	ModelSmolLM2360MInstruct: {
		ID:            ModelSmolLM2360MInstruct,
		Tier:          TierSmol,
		InstructTuned: true,
		RoadmapPhase:  3,
	},
	ModelGemma22BIT: {
		ID:            ModelGemma22BIT,
		Tier:          TierGemma,
		InstructTuned: true,
		RoadmapPhase:  5,
	},
}

// ValidateBaseModel verifies that modelID is in the active Sentinel allowlist
// and explicitly rejects excluded experimental model families such as BitNet.
func ValidateBaseModel(modelID string) (ModelSpec, error) {
	trimmed := strings.TrimSpace(modelID)
	if trimmed == "" {
		return ModelSpec{}, fmt.Errorf("%w: empty model identifier", ErrUnsupportedModel)
	}
	if strings.Contains(strings.ToLower(trimmed), "bitnet") {
		return ModelSpec{}, fmt.Errorf("%w: %q is not permitted in genesis-sentinel", ErrExperimentalModelExcluded, trimmed)
	}
	spec, ok := allowedModels[trimmed]
	if !ok {
		return ModelSpec{}, fmt.Errorf("%w: %q", ErrUnsupportedModel, trimmed)
	}
	return spec, nil
}

// LogEvent mirrors Genesis's parser.LogEntry wire contract over /query and /tail.
type LogEvent struct {
	ID         uint64            `json:"id"`
	Timestamp  int64             `json:"timestamp"`
	Service    string            `json:"service"`
	Level      string            `json:"level"`
	TraceID    string            `json:"trace_id"`
	Message    string            `json:"message"`
	Attributes map[string]string `json:"attributes,omitempty"`
	SizeBytes  int               `json:"size_bytes"`
}

// RuleHit records a deterministic Tier 0 signature, IOC, or rate-limit match.
type RuleHit struct {
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// TemplateWindow represents a collapsed batch of structurally identical log lines
// produced by Tier 0 template mining over a bounded time window.
type TemplateWindow struct {
	TemplateID                 string    `json:"template_id"`
	Template                   string    `json:"template"`
	Service                    string    `json:"service"`
	ServiceTruncated           bool      `json:"service_truncated,omitempty"`
	Level                      string    `json:"level"`
	HasIdentityHash            bool      `json:"-"`
	ServiceHash                [32]byte  `json:"-"`
	ServiceLowerHash           [32]byte  `json:"-"`
	LevelHash                  [32]byte  `json:"-"`
	Count                      uint64    `json:"count"`
	FirstSeenUnix              int64     `json:"first_seen_unix"`
	LastSeenUnix               int64     `json:"last_seen_unix"`
	SampleLine                 string    `json:"sample_line"`
	SampleTruncated            bool      `json:"sample_truncated,omitempty"`
	SampleEntropy              float64   `json:"sample_entropy"`
	AdditionalSamples          []string  `json:"additional_samples,omitempty"`
	AdditionalSamplesTruncated []bool    `json:"additional_samples_truncated,omitempty"`
	RuleHits                   []RuleHit `json:"rule_hits,omitempty"`
}

// SurprisalScore captures Tier 1 Laplace-LK information-theoretic novelty output
// derived from Hazard et al. (arXiv:2510.22809) equations.
type SurprisalScore struct {
	TemplateID        string             `json:"template_id"`
	TotalNats         float64            `json:"total_nats"`
	ThresholdNats     float64            `json:"threshold_nats"`
	Anomalous         bool               `json:"anomalous"`
	FeatureContribs   map[string]float64 `json:"feature_contribs,omitempty"`
	BaselineCaseCount int                `json:"baseline_case_count"`
}

// TriageVerdict represents a structured Tier 2 LoRA adapter classification result.
// Sentinel operates in alert-only mode; verdicts never execute destructive host actions.
type TriageVerdict struct {
	VerdictID          string    `json:"verdict_id"`
	TemplateID         string    `json:"template_id"`
	Label              string    `json:"label"`
	Severity           string    `json:"severity"`
	Confidence         float64   `json:"confidence"`
	MitreTactic        string    `json:"mitre_tactic,omitempty"`
	Explanation        string    `json:"explanation"`
	ModelID            string    `json:"model_id"`
	AdapterID          string    `json:"adapter_id,omitempty"`
	InjectionSuspected bool      `json:"injection_suspected"`
	InjectionSignals   []string  `json:"injection_signals,omitempty"`
	EvaluatedAt        time.Time `json:"evaluated_at"`
}

// FeedbackRecord is a redacted, operator-curated training record formatted for
// FTaaS JSONL ingestion (prompt, completion, weight).
type FeedbackRecord struct {
	Prompt     string    `json:"prompt"`
	Completion string    `json:"completion"`
	Weight     float64   `json:"weight"`
	Label      string    `json:"label,omitempty"`
	Redacted   bool      `json:"redacted"`
	ReviewedAt time.Time `json:"reviewed_at"`
}
