package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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

	if report.Tier0Replay.LinesRead != 2000 || report.Tier0Replay.LinesDropped != 0 || !report.Tier0Replay.ContentDigestMatched {
		t.Fatalf("unexpected Tier 0 lossless result: %+v", report.Tier0Replay)
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

	var decoded BenchmarkReport
	if err := json.Unmarshal(rawJSON, &decoded); err != nil {
		t.Fatalf("decode written JSON: %v", err)
	}

	md := RenderMarkdownReport(decoded)
	if strings.Contains(md, "/Users/") {
		t.Fatal("rendered Markdown report leaked /Users/ path")
	}

	// Verify row-level parity between decoded JSON fields and their labeled Markdown rows
	// (distinct values prevent swapped metrics or mismatched gates from passing).
	wantRows := []string{
		fmt.Sprintf("| **Lines Written / Read** | `%d` written / `%d` read (`%d` dropped, digest matched=`%t`) | `%s` |",
			decoded.Tier0Replay.LinesWritten, decoded.Tier0Replay.LinesRead, decoded.Tier0Replay.LinesDropped, decoded.Tier0Replay.ContentDigestMatched, decoded.Tier0Replay.LosslessGateStatus),
		fmt.Sprintf("| **Tier 0+1 Throughput** | `%.2f lines/sec` (target >= %.0f lines/sec) | `%s` |",
			decoded.Tier0Replay.ThroughputLPS, decoded.AcceptanceGates.ThroughputTargetLPS, decoded.Tier0Replay.ThroughputGateStatus),
		fmt.Sprintf("| **Latency P50 / P90 / P99 / Max** | `%.3f us` / `%.3f us` / `%.3f us` / `%.3f us` | `%s` |",
			decoded.Tier1Surprisal.P50US, decoded.Tier1Surprisal.P90US, decoded.Tier1Surprisal.P99US, decoded.Tier1Surprisal.MaxUS, decoded.Tier1Surprisal.P99GateStatus),
		fmt.Sprintf("| **Precision / Recall / F1** | `%.4f` / `%.4f` / `%.4f` (target F1 >= %.2f) | `%s` |",
			decoded.DetectionAccuracy.Precision, decoded.DetectionAccuracy.Recall, decoded.DetectionAccuracy.F1Score, decoded.AcceptanceGates.DetectionF1Target, decoded.DetectionAccuracy.F1GateStatus),
		fmt.Sprintf("| **Sampled Go Heap Plateau / Peak** | `%.2f MB` plateau / `%.2f MB` sampled peak (ceiling `%.0f MB`, method=`%s`) | `%s` |",
			decoded.MemoryProfile.HeapAllocPlateauMB, decoded.MemoryProfile.HeapAllocPeakMB, decoded.AcceptanceGates.MemoryCeilingMB, decoded.MemoryProfile.HeapSamplingMethod, decoded.MemoryProfile.HeapGateStatus),
		fmt.Sprintf("| **Adversarial Hostile-Log Self-Checks** | `%d/%d` passed (`%.2f%%`) | `%s` |",
			decoded.AdversarialChecks.PassedChecks, decoded.AdversarialChecks.TotalChecks, decoded.AdversarialChecks.PassRatePct, decoded.AdversarialChecks.GateStatus),
	}
	for _, row := range wantRows {
		if !strings.Contains(md, row) {
			t.Errorf("Markdown row parity mismatch; expected exact row:\n  %s", row)
		}
	}

	// Verify unrounded confusion-matrix F1 calculation on a rounding-sensitive case (TP=81, FP=11, FN=19 -> 162/192 = 0.8438).
	prec, rec, f1 := computeConfusionMetrics(81, 11, 19)
	if prec != 0.8804 || rec != 0.81 || f1 != 0.8438 {
		t.Fatalf("computeConfusionMetrics(81,11,19) = (%.4f, %.4f, %.4f), want (0.8804, 0.8100, 0.8438)", prec, rec, f1)
	}
}

func TestRunBenchmarksLiveTier2OverrideAccountingAndFailedProbeGate(t *testing.T) {
	// 1. Coerced BENIGN-NOISE server: must record 1 actual override and 1 safe verdict -> PASSED.
	coercedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/inference/generate":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"completion": "[BENIGN-NOISE] severity=LOW mitre=NONE explanation=mocked",
				"model":      model.ModelSmolLM2135MInstruct,
				"adapter":    "base",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer coercedSrv.Close()

	repCoerced, err := runBenchmarks(benchOptions{
		lines:          500,
		windowEvents:   250,
		surprisalEvals: 50,
		baselineSize:   100,
		seed:           42,
		inferenceHTTP:  coercedSrv.URL,
		baseModel:      model.ModelSmolLM2135MInstruct,
		triageSamples:  4,
		triageTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("coerced live mock failed: %v", err)
	}
	if repCoerced.Tier2Triage.InjectionProbesAttempted != 1 || repCoerced.Tier2Triage.InjectionProbesSafe != 1 ||
		repCoerced.Tier2Triage.InjectionOverridesActual != 1 || repCoerced.Tier2Triage.InjectionOverrideGateStatus != "PASSED" {
		t.Fatalf("unexpected coerced override accounting: %+v", repCoerced.Tier2Triage)
	}

	// 2. Non-benign model server: safe verdict without actual override (actual=0, safe=1, gate=PASSED).
	nonBenignSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/inference/generate":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"completion": "[INJECTION-ATTEMPT] severity=CRITICAL mitre=TA0001 explanation=detected",
				"model":      model.ModelSmolLM2135MInstruct,
				"adapter":    "base",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer nonBenignSrv.Close()

	repNonBenign, err := runBenchmarks(benchOptions{
		lines:          200,
		windowEvents:   100,
		surprisalEvals: 20,
		baselineSize:   50,
		seed:           42,
		inferenceHTTP:  nonBenignSrv.URL,
		baseModel:      model.ModelSmolLM2135MInstruct,
		triageSamples:  4,
		triageTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("non-benign live mock failed: %v", err)
	}
	if repNonBenign.Tier2Triage.InjectionProbesAttempted != 1 || repNonBenign.Tier2Triage.InjectionProbesSafe != 1 ||
		repNonBenign.Tier2Triage.InjectionOverridesActual != 0 || repNonBenign.Tier2Triage.InjectionOverrideGateStatus != "PASSED" {
		t.Fatalf("expected actual=0 and safe=1 on non-benign response, got %+v", repNonBenign.Tier2Triage)
	}

	// 3. Failing injection probe: the second injection probe (9th call including warmup, after the first
	// injection probe succeeded) returns HTTP 500 -> gate must be INCOMPLETE (not 1/1 PASSED)!
	var callNum atomic.Int32
	flakySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/healthz":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/api/v1/inference/generate":
			n := callNum.Add(1)
			if n == 9 { // warmup=1, samples 0..6 = calls 2..8, sample 7 (2nd injection probe) = call 9
				http.Error(w, "simulated timeout/error", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"completion": "[INJECTION-ATTEMPT] severity=HIGH mitre=TA0001 explanation=ok",
				"model":      model.ModelSmolLM2135MInstruct,
				"adapter":    "base",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer flakySrv.Close()

	repFlaky, err := runBenchmarks(benchOptions{
		lines:          200,
		windowEvents:   100,
		surprisalEvals: 20,
		baselineSize:   50,
		seed:           42,
		inferenceHTTP:  flakySrv.URL,
		baseModel:      model.ModelSmolLM2135MInstruct,
		triageSamples:  8,
		triageTimeout:  5 * time.Second,
	})
	if err != nil {
		t.Fatalf("flaky live mock failed: %v", err)
	}
	if repFlaky.Tier2Triage.InjectionProbesAttempted != 2 || repFlaky.Tier2Triage.InjectionProbesSafe != 1 ||
		repFlaky.Tier2Triage.InjectionProbesFailed != 1 || repFlaky.Tier2Triage.InjectionOverrideGateStatus != "INCOMPLETE" {
		t.Fatalf("expected INCOMPLETE gate (attempted=2, safe=1, failed=1), got %+v", repFlaky.Tier2Triage)
	}
}

func TestBenchmarkRejectsBitNetModelAndExternalReportPath(t *testing.T) {
	_, err := runBenchmarks(benchOptions{
		lines:          100,
		windowEvents:   50,
		surprisalEvals: 10,
		baselineSize:   50,
		seed:           42,
		baseModel:      "microsoft/BitNet-b1.58-2B-4T",
	})
	if !errors.Is(err, model.ErrExperimentalModelExcluded) {
		t.Fatalf("expected ErrExperimentalModelExcluded for BitNet model, got %v", err)
	}

	// Reject --surprisal-evals 1 so separation is never computed with an empty benign cohort.
	if _, err := runBenchmarks(benchOptions{
		lines:          100,
		windowEvents:   50,
		surprisalEvals: 1,
		baselineSize:   50,
		seed:           42,
	}); err == nil {
		t.Fatal("expected runBenchmarks to reject --surprisal-evals 1")
	}

	// Keep outside-path and symlink-escape tests independent of TMPDIR using t.Chdir.
	tmpRoot := t.TempDir()
	workDir := filepath.Join(tmpRoot, "workspace")
	siblingDir := filepath.Join(tmpRoot, "outside")
	if err := os.MkdirAll(filepath.Join(workDir, "docs"), 0755); err != nil {
		t.Fatalf("mkdir workDir: %v", err)
	}
	if err := os.MkdirAll(siblingDir, 0755); err != nil {
		t.Fatalf("mkdir siblingDir: %v", err)
	}
	t.Chdir(workDir)

	extPath := filepath.Join(siblingDir, "outside.md")
	if _, relErr := resolveReportMarkdownPath(extPath, true); relErr == nil {
		t.Fatalf("expected external --out-md %q to be rejected when publishing JSON", extPath)
	}
	symOutDir := filepath.Join(workDir, "docs", "out-link")
	if err := os.Symlink(siblingDir, symOutDir); err == nil {
		if _, relErr := resolveReportMarkdownPath(filepath.Join("docs", "out-link", "report.md"), true); relErr == nil {
			t.Fatal("expected symlinked directory escaping workspace to be rejected by resolveReportMarkdownPath")
		}
	}
	// New in-workspace subdirectory must still resolve cleanly.
	if relOK, relErr := resolveReportMarkdownPath(filepath.Join("docs", "newdir", "report.md"), true); relErr != nil || relOK != "docs/newdir/report.md" {
		t.Fatalf("expected new in-workspace path to resolve cleanly, got %q err=%v", relOK, relErr)
	}

	// Verify publishReportPair preserves prior Markdown if JSON publication fails (e.g. target is a directory).
	pairDir := t.TempDir()
	mdPath := filepath.Join(pairDir, "report.md")
	origMD := []byte("# prior report\n")
	if err := os.WriteFile(mdPath, origMD, 0644); err != nil {
		t.Fatalf("write prior md: %v", err)
	}
	badJSONTarget := filepath.Join(pairDir, "dir-not-file")
	if err := os.MkdirAll(badJSONTarget, 0755); err != nil {
		t.Fatalf("mkdir bad target: %v", err)
	}
	if err := publishReportPair(mdPath, badJSONTarget, []byte("# new report\n"), BenchmarkReport{}); err == nil {
		t.Fatal("expected publishReportPair to fail when JSON target is a directory")
	}
	gotMD, err := os.ReadFile(mdPath)
	if err != nil || string(gotMD) != string(origMD) {
		t.Fatalf("expected prior Markdown to be preserved after failed JSON publish, got %q (err=%v)", string(gotMD), err)
	}

	// Reject matching Markdown and JSON destinations (including equivalent relative/cleaned paths).
	sameAlias := filepath.Join(pairDir, ".", "report.md")
	if err := publishReportPair(mdPath, sameAlias, []byte("# collision\n"), BenchmarkReport{}); err == nil {
		t.Fatal("expected publishReportPair to reject matching Markdown and JSON destinations")
	}
	gotAfterCollision, err := os.ReadFile(mdPath)
	if err != nil || string(gotAfterCollision) != string(origMD) {
		t.Fatalf("expected prior Markdown untouched after destination collision rejection, got %q (err=%v)", string(gotAfterCollision), err)
	}

	// Fail closed if existing Markdown destination is not a regular file or cannot be backed up.
	if err := publishReportPair(badJSONTarget, filepath.Join(pairDir, "out.json"), []byte("# new\n"), BenchmarkReport{}); err == nil {
		t.Fatal("expected publishReportPair to reject non-regular existing Markdown destination")
	}
	if os.Geteuid() != 0 {
		unreadableMD := filepath.Join(pairDir, "unreadable.md")
		if err := os.WriteFile(unreadableMD, []byte("# secret\n"), 0000); err != nil {
			t.Fatalf("write unreadable md: %v", err)
		}
		defer func() { _ = os.Chmod(unreadableMD, 0644) }()
		if err := publishReportPair(unreadableMD, filepath.Join(pairDir, "out2.json"), []byte("# replacement\n"), BenchmarkReport{}); err == nil {
			t.Fatal("expected publishReportPair to fail closed when existing Markdown cannot be read for backup")
		}
		if _, statErr := os.Stat(unreadableMD); statErr != nil {
			t.Fatalf("unreadable prior Markdown was unexpectedly removed: %v", statErr)
		}
	}

	// Reject symlink destination and preserve symlink target intact.
	symTarget := filepath.Join(pairDir, "real-target.md")
	if err := os.WriteFile(symTarget, []byte("# original target\n"), 0644); err != nil {
		t.Fatalf("write symTarget: %v", err)
	}
	symLink := filepath.Join(pairDir, "link-report.md")
	if err := os.Symlink(symTarget, symLink); err == nil {
		if err := publishReportPair(symLink, filepath.Join(pairDir, "sym-out.json"), []byte("# overwrite\n"), BenchmarkReport{}); err == nil {
			t.Fatal("expected publishReportPair to reject symlink Markdown destination")
		}
		if fi, lerr := os.Lstat(symLink); lerr != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("symlink destination was damaged: fi=%v err=%v", fi, lerr)
		}
	}

	// On case-insensitive filesystems (e.g. macOS APFS), fresh paths differing only by case must be rejected.
	if isCaseInsensitiveDir(pairDir) {
		if err := publishReportPair(filepath.Join(pairDir, "casecheck.md"), filepath.Join(pairDir, "CASECHECK.MD"), []byte("# case\n"), BenchmarkReport{}); err == nil {
			t.Fatal("expected publishReportPair to reject fresh case-insensitive collision paths")
		}
	}

	// Fresh distinct destinations must publish cleanly.
	freshMD := filepath.Join(pairDir, "fresh.md")
	freshJSON := filepath.Join(pairDir, "fresh.json")
	if err := publishReportPair(freshMD, freshJSON, []byte("# fresh\n"), BenchmarkReport{}); err != nil {
		t.Fatalf("expected publishReportPair to succeed for distinct fresh paths: %v", err)
	}
	if b, err := os.ReadFile(freshMD); err != nil || string(b) != "# fresh\n" {
		t.Fatalf("fresh Markdown mismatch: %q (err=%v)", string(b), err)
	}
	if _, err := os.Stat(freshJSON); err != nil {
		t.Fatalf("fresh JSON not created: %v", err)
	}
}
