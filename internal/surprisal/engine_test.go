package surprisal

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestExtractFeaturesProtocolAndScaling(t *testing.T) {
	httpWin := model.TemplateWindow{
		TemplateID:    "tmpl-http-200",
		Template:      "GET /api/v1/items/<NUM> HTTP/1.1 200 <DUR>",
		Service:       "  API-Gateway ",
		Level:         "info",
		Count:         50,
		FirstSeenUnix: 1763996400,
		LastSeenUnix:  1763996410,
		SampleLine:    "GET /api/v1/items/42 HTTP/1.1 200 12ms",
	}
	f := ExtractFeatures(httpWin)
	if f.Nominal[0] != "api-gateway" || f.Nominal[1] != "INFO" || f.Nominal[2] != "tmpl-http-200" || f.Nominal[3] != "http_2xx" {
		t.Fatalf("unexpected HTTP nominal features: %+v", f.Nominal)
	}
	if f.Continuous[2] <= 0 || f.Continuous[2] > 8 {
		t.Fatalf("expected bounded Shannon entropy, got %v", f.Continuous[2])
	}
	for i, v := range f.Continuous {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			t.Fatalf("continuous feature %d is non-finite: %v", i, v)
		}
	}

	syslogWin := model.TemplateWindow{
		TemplateID: "tmpl-sys",
		Template:   "Accepted publickey for <STR> from <IP>",
		Service:    "sshd",
		Level:      "INFO",
		Count:      1,
		SampleLine: "<34>Nov 24 12:00:00 host sshd[100]: Accepted publickey for alice from 10.0.0.5",
	}
	sf := ExtractFeatures(syslogWin)
	// PRI=34 -> facility = 34 >> 3 = 4 (auth)
	if sf.Nominal[3] != "syslog_fac_4" {
		t.Fatalf("expected syslog_fac_4, got %q", sf.Nominal[3])
	}

	http403 := ExtractFeatures(model.TemplateWindow{
		TemplateID: "tmpl-403",
		Service:    "nginx",
		Level:      "WARN",
		SampleLine: "GET /admin/config 403",
	})
	if http403.Nominal[3] != "http_4xx" {
		t.Fatalf("expected http_4xx, got %q", http403.Nominal[3])
	}
}

func TestEngineWarmupSeparationAndPoisoningDefense(t *testing.T) {
	eng := NewEngine(Options{
		Mode:               "inprocess",
		ThresholdNats:      5.0,
		BaselineWindowSize: 500,
		WarmupMinCases:     20,
	})
	ctx := context.Background()

	normalTemplates := []model.TemplateWindow{
		{
			TemplateID:    "t-nginx-ok",
			Template:      "GET /healthz HTTP/1.1 200 <DUR>",
			Service:       "nginx",
			Level:         "INFO",
			Count:         40,
			FirstSeenUnix: 1763996000,
			LastSeenUnix:  1763996010,
			SampleLine:    "GET /healthz HTTP/1.1 200 3ms",
		},
		{
			TemplateID:    "t-api-ok",
			Template:      "POST /api/v1/orders HTTP/1.1 200 <DUR>",
			Service:       "api",
			Level:         "INFO",
			Count:         25,
			FirstSeenUnix: 1763996000,
			LastSeenUnix:  1763996010,
			SampleLine:    "POST /api/v1/orders HTTP/1.1 200 18ms",
		},
		{
			TemplateID:    "t-cron-ok",
			Template:      "cron job <STR> finished rc=0 in <DUR>",
			Service:       "cron",
			Level:         "INFO",
			Count:         5,
			FirstSeenUnix: 1763996000,
			LastSeenUnix:  1763996010,
			SampleLine:    "cron job nightly-vacuum finished rc=0 in 140ms",
		},
		{
			TemplateID:    "t-sshd-ok",
			Template:      "Accepted publickey for ops from <IP>",
			Service:       "sshd",
			Level:         "INFO",
			Count:         3,
			FirstSeenUnix: 1763996000,
			LastSeenUnix:  1763996010,
			SampleLine:    "Accepted publickey for ops from 10.0.1.12",
		},
	}

	// 1. Cold-start warmup: first 20 normal windows must NEVER fire anomalies.
	for i := 0; i < 20; i++ {
		w := normalTemplates[i%len(normalTemplates)]
		w.Count += uint64(i % 4)
		sc := eng.Evaluate(ctx, w, false)
		if sc.Anomalous {
			t.Fatalf("cold-start warmup window %d unexpectedly flagged anomalous: %+v", i, sc)
		}
	}
	if !eng.Stats().WarmupComplete {
		t.Fatalf("expected WarmupComplete=true after 20 windows")
	}

	// 2. Feed 60 more holdout normal windows -> expect 0 false positives!
	var maxNormalNats float64
	for i := 0; i < 60; i++ {
		w := normalTemplates[i%len(normalTemplates)]
		w.Count += uint64((i % 5) + 1)
		sc := eng.Evaluate(ctx, w, false)
		if sc.TotalNats > maxNormalNats {
			maxNormalNats = sc.TotalNats
		}
		if sc.Anomalous {
			t.Fatalf("normal holdout window %d (%s) triggered false positive: %+v", i, w.TemplateID, sc)
		}
	}

	// 3. Inject novel unseen anomalies (none matching static rules!) -> expect high surprisal separation!
	anomalies := []model.TemplateWindow{
		{
			TemplateID:    "t-unseen-exfil",
			Template:      "outbound tunnel payload <HEX>",
			Service:       "exfil-daemon",
			Level:         "WARN",
			Count:         1200,
			FirstSeenUnix: 1763996500,
			LastSeenUnix:  1763996501,
			SampleLine:    "POST /v2/upload HTTP/1.1 502 aZ9xK2mQ8pL4vN7wR1yT6bC3dF5gH0jM9sU8eI2oP4qW7zX1cV6nB3mK5jH8gF2dS4aL9pO0iU7yT6rE5wQ2",
		},
		{
			TemplateID:    "t-unseen-api-500-burst",
			Template:      "INTERNAL PANIC stack trace dump <HEX> <STR> <STR>",
			Service:       "api",
			Level:         "ERROR",
			Count:         900,
			FirstSeenUnix: 1763996510,
			LastSeenUnix:  1763996511,
			SampleLine:    "POST /api/v1/debug?q=!!!@@@###$$$%%%^^^&&&***((())) HTTP/1.1 500 PANIC_OVERFLOW_0xDEADBEEF_STACK_DUMP_AABBCCDD",
		},
		{
			TemplateID:    "t-unseen-kernel-priv",
			Template:      "unrecognized binary execve uid=0 <STR>",
			Service:       "auditd-unknown",
			Level:         "CRITICAL",
			Count:         45,
			FirstSeenUnix: 1763996520,
			LastSeenUnix:  1763996521,
			SampleLine:    "EXECVE /tmp/.hidden_dropper --stealth --dump=/etc/shadow;curl|sh 2>&1 >/dev/null",
		},
	}

	baseCasesBefore := eng.Stats().BaselineCases
	for _, anom := range anomalies {
		sc := eng.Evaluate(ctx, anom, false)
		if !sc.Anomalous {
			t.Errorf("expected unseen anomaly %s to be flagged anomalous, got %+v (maxNormal=%.3f)",
				anom.TemplateID, sc, maxNormalNats)
		}
		if sc.TotalNats <= maxNormalNats+3.0 {
			t.Errorf("insufficient separation for %s: anom=%.3f vs maxNormal=%.3f",
				anom.TemplateID, sc.TotalNats, maxNormalNats)
		}
		top := TopFeatures(sc.FeatureContribs, 3)
		if len(top) == 0 {
			t.Errorf("expected non-empty TopFeatures for anomaly %s", anom.TemplateID)
		}
	}

	// 4. Poisoning defense: flooding 40 identical anomalous windows must NOT be absorbed into the baseline!
	for i := 0; i < 40; i++ {
		sc := eng.Evaluate(ctx, anomalies[0], false)
		if !sc.Anomalous {
			t.Fatalf("poisoning attack succeeded on iteration %d: anomaly stopped firing (%+v)", i, sc)
		}
	}
	// Tier 0 rule-flagged windows must also never pollute the baseline.
	eng.Evaluate(ctx, normalTemplates[0], true)

	if got := eng.Stats().BaselineCases; got != baseCasesBefore {
		t.Fatalf("baseline poisoned: cases grew from %d to %d despite only anomalous/Tier0 windows", baseCasesBefore, got)
	}
}

func TestSameServicePeersSurviveHighVolumeNeighborService(t *testing.T) {
	eng := NewEngine(Options{
		Mode:               "inprocess",
		ThresholdNats:      5.0,
		BaselineWindowSize: 1000,
		WarmupMinCases:     20,
		MaxCandidateCases:  120,
	})
	ctx := context.Background()

	// Seed 5 rare benign cron windows first, followed by 900 high-volume nginx windows.
	cronWin := model.TemplateWindow{
		TemplateID:    "t-cron-rare",
		Template:      "cron backup complete files=<NUM>",
		Service:       "cron",
		Level:         "INFO",
		Count:         2,
		FirstSeenUnix: 1763996000,
		LastSeenUnix:  1763996010,
		SampleLine:    "cron backup complete files=14",
	}
	for i := 0; i < 5; i++ {
		eng.LearnBaseline(cronWin)
	}
	nginxWin := model.TemplateWindow{
		TemplateID:    "t-nginx-bulk",
		Template:      "GET /static/app.js HTTP/1.1 200 <DUR>",
		Service:       "nginx",
		Level:         "INFO",
		Count:         500,
		FirstSeenUnix: 1763996000,
		LastSeenUnix:  1763996010,
		SampleLine:    "GET /static/app.js HTTP/1.1 200 1ms",
	}
	for i := 0; i < 900; i++ {
		eng.LearnBaseline(nginxWin)
	}

	// Same-service neighborhood selection guarantees rare cron still matches its 5 peers cleanly.
	sc := eng.Evaluate(ctx, cronWin, false)
	if sc.Anomalous || sc.TotalNats > 1.0 {
		t.Fatalf("rare benign cron service falsely flagged behind 900 nginx windows: %+v", sc)
	}
}

func TestBaselinePersistenceAndCorruptSnapshotHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	eng := NewEngine(Options{BaselineWindowSize: 50, WarmupMinCases: 5})
	for i := 0; i < 12; i++ {
		eng.LearnBaseline(model.TemplateWindow{
			TemplateID: fmt.Sprintf("t-%d", i%3),
			Template:   "GET /ok HTTP/1.1 200",
			Service:    "api",
			Level:      "INFO",
			Count:      uint64(10 + i),
			SampleLine: "GET /ok HTTP/1.1 200 5ms",
		})
	}
	if !eng.Dirty() {
		t.Fatal("expected Dirty()=true after LearnBaseline")
	}
	if err := eng.SaveToFile(path, false); err != nil {
		t.Fatalf("SaveToFile failed: %v", err)
	}
	if eng.Dirty() {
		t.Fatal("expected Dirty()=false right after SaveToFile")
	}

	eng2 := NewEngine(Options{BaselineWindowSize: 50, WarmupMinCases: 5})
	loaded, err := eng2.LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}
	if loaded != 12 || eng2.Stats().BaselineCases != 12 || eng2.Dirty() {
		t.Fatalf("unexpected loaded state: loaded=%d stats=%+v dirty=%v", loaded, eng2.Stats(), eng2.Dirty())
	}

	// Reset clears baseline and dirty flag cleanly.
	eng2.Reset()
	if eng2.Stats().BaselineCases != 0 || eng2.Dirty() {
		t.Fatalf("expected empty clean state after Reset, got %+v", eng2.Stats())
	}

	// Corrupt JSON must return an error cleanly.
	badPath := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(badPath, []byte("{not-json"), 0600); err != nil {
		t.Fatalf("write bad.json: %v", err)
	}
	if _, err := eng2.LoadFromFile(badPath); err == nil {
		t.Fatal("expected error loading corrupt baseline JSON")
	}
}

func TestHTTPParityClientModesAndLoopbackGuard(t *testing.T) {
	// Reject non-loopback endpoint by default.
	if _, err := NewHTTPClient("https://example.com:5200", time.Second, false); err == nil {
		t.Fatal("expected NewHTTPClient to reject non-loopback URL when allowRemote=false")
	}

	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
			return
		}
		if r.URL.Path == "/v1/verify/completion" {
			calls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(VerifyResponse{
				IsConforming:          false,
				MeasuredSurprisalNats: 9.75,
				PredictedTag:          "INFO",
				CandidateTag:          "ERROR",
				Explanation:           "mock sidecar anomaly",
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	client, err := NewHTTPClient(srv.URL, 2*time.Second, false)
	if err != nil {
		t.Fatalf("NewHTTPClient loopback failed: %v", err)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health failed: %v", err)
	}

	eng := NewEngine(Options{
		Mode:               "http",
		ThresholdNats:      5.0,
		BaselineWindowSize: 50,
		WarmupMinCases:     5,
		HTTPClient:         client,
	})
	for i := 0; i < 6; i++ {
		eng.LearnBaseline(model.TemplateWindow{
			TemplateID: "t-norm",
			Template:   "GET /ok 200",
			Service:    "api",
			Level:      "INFO",
			Count:      10,
			SampleLine: "GET /ok 200",
		})
	}
	sc := eng.Evaluate(context.Background(), model.TemplateWindow{
		TemplateID: "t-weird",
		Template:   "ERR unexpected",
		Service:    "api",
		Level:      "ERROR",
		Count:      10,
		SampleLine: "ERR unexpected",
	}, false)
	if !sc.Anomalous || sc.TotalNats != 9.75 || calls != 1 {
		t.Fatalf("expected HTTP mode to use sidecar score 9.75 (calls=%d), got %+v", calls, sc)
	}

	// Verify graceful fallback when sidecar goes down.
	srv.Close()
	scFallback := eng.Evaluate(context.Background(), model.TemplateWindow{
		TemplateID: "t-weird-2",
		Template:   "ERR unexpected 2",
		Service:    "unknown-svc",
		Level:      "FATAL",
		Count:      500,
		SampleLine: "FATAL !!!@@@###$$$%%% " + strings.Repeat("Z9xQ", 40),
	}, false)
	st := eng.Stats()
	if st.HTTPFallbacks != 1 || !scFallback.Anomalous {
		t.Fatalf("expected graceful fallback to in-process anomaly detection, stats=%+v score=%+v", st, scFallback)
	}
}

func TestEngineConcurrentEvaluateSaveResetRaceFree(t *testing.T) {
	eng := NewEngine(Options{
		Mode:               "inprocess",
		ThresholdNats:      5.0,
		BaselineWindowSize: 100,
		WarmupMinCases:     10,
	})
	path := filepath.Join(t.TempDir(), "baseline.json")

	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				eng.Evaluate(context.Background(), model.TemplateWindow{
					TemplateID: fmt.Sprintf("t-%d-%d", worker, i%5),
					Template:   "GET /item/<NUM> HTTP/1.1 200",
					Service:    "api",
					Level:      "INFO",
					Count:      uint64(10 + i),
					SampleLine: "GET /item/123 HTTP/1.1 200 4ms",
				}, false)
				_ = eng.Stats()
				if i%15 == 0 {
					_ = eng.SaveToFile(path, false)
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(5 * time.Millisecond)
		eng.Reset()
	}()
	wg.Wait()
}
