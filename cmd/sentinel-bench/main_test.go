package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestRunBenchmarksOfflineAndMarkdownParity(t *testing.T) {
	outDir := t.TempDir()
	jsonPath := filepath.Join(outDir, "empirical_benchmarks.json")

	report, err := runBenchmarks(benchOptions{
		lines:          2000,
		windowEvents:   500,
		surprisalEvals: 100,
		baselineSize:   200,
		seed:           42,
		baseModel:      model.ModelSmolLM2135MInstruct,
	})
	if err != nil {
		t.Fatalf("runBenchmarks failed: %v", err)
	}
	report.Metadata.ReportMarkdown = "docs/benchmarks/test-report.md"

	if report.Tier0Replay.LinesRead != 2000 || report.Tier0Replay.LinesDropped != 0 {
		t.Fatalf("unexpected Tier 0 counts: %+v", report.Tier0Replay)
	}
	if report.Tier0Replay.LosslessGateStatus != "PASSED" {
		t.Fatalf("expected lossless PASSED, got %q", report.Tier0Replay.LosslessGateStatus)
	}
	if !(0 < report.Tier1Surprisal.P50US && report.Tier1Surprisal.P50US <= report.Tier1Surprisal.P90US &&
		report.Tier1Surprisal.P90US <= report.Tier1Surprisal.P99US && report.Tier1Surprisal.P99US <= report.Tier1Surprisal.MaxUS) {
		t.Fatalf("latency monotonicity violated: %+v", report.Tier1Surprisal)
	}
	if report.Tier1Surprisal.SeparationNats <= 0 {
		t.Fatalf("expected positive benign/anomalous surprisal separation, got %+v", report.Tier1Surprisal)
	}
	if report.DetectionAccuracy.F1Score < 0.90 || report.DetectionAccuracy.F1GateStatus != "PASSED" {
		t.Fatalf("expected detection F1 >= 0.90, got %+v", report.DetectionAccuracy)
	}
	if report.DetectionAccuracy.Tier1OnlyDetections == 0 {
		t.Fatalf("expected Tier 1-only detections for unseen statistical anomalies, got %+v", report.DetectionAccuracy)
	}
	if report.AdversarialChecks.PassedChecks != report.AdversarialChecks.TotalChecks || report.AdversarialChecks.GateStatus != "PASSED" {
		t.Fatalf("expected 100%% adversarial checks passed, got %+v", report.AdversarialChecks)
	}
	if report.Tier2Triage.Enabled || report.Tier2Triage.Mode != "skipped" {
		t.Fatalf("expected skipped Tier 2 when inferenceHTTP empty, got %+v", report.Tier2Triage)
	}

	if err := writeJSONReport(jsonPath, report); err != nil {
		t.Fatalf("writeJSONReport failed: %v", err)
	}
	rawJSON, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("read written json: %v", err)
	}
	if strings.Contains(string(rawJSON), "/Users/") {
		t.Fatal("written benchmark JSON leaked /Users/ path")
	}

	md := RenderMarkdownReport(report)
	if strings.Contains(md, "/Users/") {
		t.Fatal("rendered Markdown report leaked /Users/ path")
	}
	for _, want := range []string{
		report.Metadata.SentinelVersion,
		report.Tier0Replay.ThroughputGateStatus,
		report.Tier1Surprisal.P99GateStatus,
		report.DetectionAccuracy.F1GateStatus,
		report.MemoryProfile.HeapGateStatus,
		report.AdversarialChecks.GateStatus,
	} {
		if !strings.Contains(md, want) {
			t.Errorf("rendered Markdown missing expected token %q", want)
		}
	}
}

func TestRunBenchmarksLiveTier2MockAndInjectionOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/inference/generate":
			w.Header().Set("Content-Type", "application/json")
			// Always try to return BENIGN-NOISE so we verify fail-closed override during benchmark!
			_ = json.NewEncoder(w).Encode(map[string]any{
				"completion": "[BENIGN-NOISE] severity=LOW mitre=NONE explanation=mocked",
				"model":      model.ModelSmolLM2135MInstruct,
				"adapter":    "base",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	report, err := runBenchmarks(benchOptions{
		lines:          500,
		windowEvents:   250,
		surprisalEvals: 50,
		baselineSize:   100,
		seed:           42,
		inferenceHTTP:  srv.URL,
		baseModel:      model.ModelSmolLM2135MInstruct,
		triageSamples:  4,
		triageTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("live mock runBenchmarks failed: %v", err)
	}
	if !report.Tier2Triage.Enabled || report.Tier2Triage.SamplesEvaluated != 4 {
		t.Fatalf("unexpected Tier 2 results: %+v", report.Tier2Triage)
	}
	if report.Tier2Triage.InjectionProbesTested != 1 || report.Tier2Triage.InjectionOverridesEnforced != 1 || report.Tier2Triage.InjectionOverrideGateStatus != "PASSED" {
		t.Fatalf("expected injection override PASSED on coerced mock server, got %+v", report.Tier2Triage)
	}
}

func TestBenchmarkRejectsBitNetModel(t *testing.T) {
	_, err := runBenchmarks(benchOptions{
		lines:          100,
		windowEvents:   50,
		surprisalEvals: 10,
		baselineSize:   50,
		seed:           42,
		baseModel:      "microsoft/BitNet-b1.58-2B-4T",
	})
	if err == nil {
		t.Fatal("expected runBenchmarks to reject excluded BitNet model")
	}
}
