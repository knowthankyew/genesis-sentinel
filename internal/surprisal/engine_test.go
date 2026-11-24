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
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

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

	// Field boundary check: previous_status=500 must NOT shadow standalone status=200.
	boundaryWin := ExtractFeatures(model.TemplateWindow{
		TemplateID: "tmpl-boundary",
		Service:    "api",
		Level:      "INFO",
		SampleLine: "backup previous_status=500 status=200 ok",
	})
	if boundaryWin.Nominal[3] != "http_2xx" {
		t.Fatalf("expected boundary-aware http_2xx, got %q", boundaryWin.Nominal[3])
	}

	// Millisecond timestamps 1 second apart must produce the exact same inter-arrival
	// feature as Unix-second timestamps 1 second apart.
	secFeat := ExtractFeatures(model.TemplateWindow{
		TemplateID:    "tmpl-ts",
		Service:       "api",
		Level:         "INFO",
		Count:         2,
		FirstSeenUnix: 1763996400,
		LastSeenUnix:  1763996401,
		SampleLine:    "ok",
	})
	msFeat := ExtractFeatures(model.TemplateWindow{
		TemplateID:    "tmpl-ts",
		Service:       "api",
		Level:         "INFO",
		Count:         2,
		FirstSeenUnix: 1763996400000,
		LastSeenUnix:  1763996401000,
		SampleLine:    "ok",
	})
	if !(math.Abs(secFeat.Continuous[5]-msFeat.Continuous[5]) <= 1e-9) {
		t.Fatalf("timestamp unit normalization mismatch: sec=%v vs ms=%v", secFeat.Continuous[5], msFeat.Continuous[5])
	}

	// UTF-8 boundary clamping: 127 ASCII bytes + 2-byte 'é' must truncate cleanly without invalid UTF-8.
	utf8Svc := strings.Repeat("a", 127) + "é"
	utf8Feat := ExtractFeatures(model.TemplateWindow{
		TemplateID: "tmpl-utf8",
		Service:    utf8Svc,
		Level:      "INFO",
		SampleLine: "ok",
	})
	if !utf8.ValidString(utf8Feat.Nominal[0]) || len(utf8Feat.Nominal[0]) != 127 {
		t.Fatalf("expected valid 127-byte UTF-8 clamped service, got len=%d valid=%v", len(utf8Feat.Nominal[0]), utf8.ValidString(utf8Feat.Nominal[0]))
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
	// Reject non-loopback endpoint and base URLs with query strings or fragments.
	if _, err := NewHTTPClient("https://example.com:5200", time.Second, false); err == nil {
		t.Fatal("expected NewHTTPClient to reject non-loopback URL when allowRemote=false")
	}
	if _, err := NewHTTPClient("http://127.0.0.1:5200?tenant=local", time.Second, false); err == nil {
		t.Fatal("expected NewHTTPClient to reject base URL with query parameters")
	}
	if _, err := NewHTTPClient("http://127.0.0.1:5200#frag", time.Second, false); err == nil {
		t.Fatal("expected NewHTTPClient to reject base URL with fragment")
	}

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
			return
		}
		if r.URL.Path == "/v1/verify/completion" {
			calls.Add(1)
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
		HTTPCooldown:       time.Minute,
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
	if !sc.Anomalous || sc.TotalNats != 9.75 || calls.Load() != 1 {
		t.Fatalf("expected HTTP mode to use sidecar score 9.75 (calls=%d), got %+v", calls.Load(), sc)
	}
	if sc.FeatureContribs != nil {
		t.Fatalf("expected local FeatureContribs to be cleared on sidecar override, got %+v", sc.FeatureContribs)
	}

	// Verify graceful fallback AND circuit breaker when sidecar goes down:
	// first failure opens circuit, next 100 windows fall back immediately without hanging.
	srv.Close()
	start := time.Now()
	scFallback := eng.Evaluate(context.Background(), model.TemplateWindow{
		TemplateID: "t-weird-2",
		Template:   "ERR unexpected 2",
		Service:    "unknown-svc",
		Level:      "FATAL",
		Count:      500,
		SampleLine: "FATAL !!!@@@###$$$%%% " + strings.Repeat("Z9xQ", 40),
	}, false)
	for i := 0; i < 100; i++ {
		eng.Evaluate(context.Background(), model.TemplateWindow{
			TemplateID: "t-norm",
			Template:   "GET /ok 200",
			Service:    "api",
			Level:      "INFO",
			Count:      10,
			SampleLine: "GET /ok 200",
		}, false)
	}
	elapsed := time.Since(start)
	st := eng.Stats()
	if st.HTTPFallbacks < 101 || !scFallback.Anomalous || elapsed > 2*time.Second {
		t.Fatalf("expected circuit-breaker fast fallback (elapsed=%v), stats=%+v score=%+v", elapsed, st, scFallback)
	}
}

func TestHTTPClientRejectsIncompleteVerdictAndOffLoopbackRedirect(t *testing.T) {
	// 1. Missing required JSON fields or negative measurement must fail closed.
	badPayloads := []string{
		`{"is_conforming":true}`,
		`{"measured_surprisal_nats":1.2}`,
		`{"is_conforming":true,"measured_surprisal_nats":-0.5}`,
	}
	for _, payload := range badPayloads {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(payload))
		}))
		c, err := NewHTTPClient(srv.URL, time.Second, false)
		if err != nil {
			srv.Close()
			t.Fatalf("NewHTTPClient: %v", err)
		}
		_, err = c.VerifyWindow(context.Background(), model.TemplateWindow{Service: "api", Level: "INFO", SampleLine: "ok"},
			[]LogFeatures{ExtractFeatures(model.TemplateWindow{Service: "api", Level: "INFO", SampleLine: "ok"})}, 5.0)
		srv.Close()
		if err == nil {
			t.Fatalf("expected VerifyWindow to reject incomplete/invalid payload %s", payload)
		}
	}

	// 2. 307 redirect from loopback sidecar to external host must be rejected before forwarding POST body.
	redirSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/steal", http.StatusTemporaryRedirect)
	}))
	defer redirSrv.Close()
	c, err := NewHTTPClient(redirSrv.URL, time.Second, false)
	if err != nil {
		t.Fatalf("NewHTTPClient: %v", err)
	}
	if _, err := c.VerifyWindow(context.Background(), model.TemplateWindow{Service: "api", Level: "INFO", SampleLine: "secret"},
		[]LogFeatures{ExtractFeatures(model.TemplateWindow{Service: "api", Level: "INFO", SampleLine: "ok"})}, 5.0); err == nil {
		t.Fatal("expected VerifyWindow to reject 307 redirect to non-loopback host")
	}

	// 3. HTTP mode fail-closed poisoning defense: sidecar claiming conforming on a local burst anomaly
	// must NOT let the burst enter the rolling baseline or suppress local detection.
	permissiveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"is_conforming":true,"measured_surprisal_nats":0.1}`))
	}))
	defer permissiveSrv.Close()
	pc, _ := NewHTTPClient(permissiveSrv.URL, time.Second, false)
	eng := NewEngine(Options{Mode: "http", ThresholdNats: 5.0, BaselineWindowSize: 50, WarmupMinCases: 5, HTTPClient: pc})
	for i := 0; i < 6; i++ {
		eng.LearnBaseline(model.TemplateWindow{
			TemplateID: "t-ok", Template: "GET /ok 200", Service: "api", Level: "INFO", Count: 5, SampleLine: "GET /ok 200",
		})
	}
	before := eng.Stats().BaselineCases
	burstSc := eng.Evaluate(context.Background(), model.TemplateWindow{
		TemplateID: "t-burst-weird",
		Template:   "POST /v9/dump <HEX>",
		Service:    "api",
		Level:      "INFO",
		Count:      50000,
		SampleLine: "POST /v9/dump?x=!!!@@@###$$$%%%^^^&&&*** 503 " + strings.Repeat("Z9xQ", 30),
	}, false)
	if !burstSc.Anomalous || eng.Stats().BaselineCases != before {
		t.Fatalf("expected HTTP mode to fail closed on local burst anomaly without poisoning baseline: score=%+v cases=%d->%d",
			burstSc, before, eng.Stats().BaselineCases)
	}

	// 4. Mid-request Reset() must discard pre-reset counters and baseline updates.
	started := make(chan struct{})
	release := make(chan struct{})
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"is_conforming":true,"measured_surprisal_nats":0.2}`))
	}))
	defer slowSrv.Close()
	scClient, _ := NewHTTPClient(slowSrv.URL, 5*time.Second, false)
	engReset := NewEngine(Options{Mode: "http", ThresholdNats: 5.0, BaselineWindowSize: 50, WarmupMinCases: 3, HTTPClient: scClient})
	for i := 0; i < 4; i++ {
		engReset.LearnBaseline(model.TemplateWindow{TemplateID: "t-ok", Service: "api", Level: "INFO", Count: 5, SampleLine: "GET /ok 200"})
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		engReset.Evaluate(context.Background(), model.TemplateWindow{TemplateID: "t-ok", Service: "api", Level: "INFO", Count: 5, SampleLine: "GET /ok 200"}, false)
	}()
	<-started
	engReset.Reset()
	close(release)
	<-done
	if st := engReset.Stats(); st.BaselineCases != 0 || st.ScoredTotal != 0 || st.AnomaliesTotal != 0 || st.HTTPChecks != 0 {
		t.Fatalf("expected mid-request Reset() to discard pre-reset updates, got stats=%+v", st)
	}
}

func TestWrappedRingChronologicalParityAcrossSaveAndRestore(t *testing.T) {
	// Capacity 4, candidate cap 2: appending A..E wraps ring in-place to [E, B, C, D],
	// whereas chronological order is [B, C, D, E]. Scoring must match identically before & after restore.
	eng := NewEngine(Options{
		Mode:               "inprocess",
		ThresholdNats:      5.0,
		BaselineWindowSize: 4,
		WarmupMinCases:     4,
		KNeighbors:         1,
		MaxCandidateCases:  2,
	})
	windows := []model.TemplateWindow{
		{TemplateID: "t-A", Service: "svcA", Level: "INFO", Count: 1, SampleLine: "alpha"},
		{TemplateID: "t-B", Service: "svcB", Level: "WARN", Count: 5, SampleLine: "bravo 404"},
		{TemplateID: "t-C", Service: "svcC", Level: "ERROR", Count: 20, SampleLine: "charlie 500"},
		{TemplateID: "t-D", Service: "svcD", Level: "DEBUG", Count: 2, SampleLine: "delta 302"},
		{TemplateID: "t-E", Service: "svcE", Level: "INFO", Count: 100, SampleLine: "echo 200"},
	}
	for _, w := range windows {
		eng.LearnBaseline(w)
	}

	path := filepath.Join(t.TempDir(), "wrapped.json")
	if err := eng.SaveToFile(path, true); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}
	engRestored := NewEngine(Options{
		Mode:               "inprocess",
		ThresholdNats:      5.0,
		BaselineWindowSize: 4,
		WarmupMinCases:     4,
		KNeighbors:         1,
		MaxCandidateCases:  2,
	})
	if _, err := engRestored.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	query := windows[4]
	before := eng.Evaluate(context.Background(), query, true)
	after := engRestored.Evaluate(context.Background(), query, true)
	if before.TotalNats != after.TotalNats {
		t.Fatalf("wrapped ring score drifted across save/restore: before=%v after=%v", before.TotalNats, after.TotalNats)
	}

	// Large finite float must stay finite after round4 (no overflow to +Inf).
	huge := round4(1e308)
	if math.IsInf(huge, 0) || math.IsNaN(huge) || huge != 1e308 {
		t.Fatalf("round4(1e308) overflowed or corrupted value: %v", huge)
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
