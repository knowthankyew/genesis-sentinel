package template

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestAggregatorCollapsesRepetitiveNoiseAndKeepsStableClusterID(t *testing.T) {
	agg := NewAggregator(DefaultMaxClusters)

	for i := 0; i < 1000; i++ {
		agg.Add(model.LogEvent{
			ID:        uint64(i + 1),
			Timestamp: int64(1700000000 + i),
			Service:   "web",
			Level:     "INFO",
			Message:   fmt.Sprintf("GET /api/v1/orders/%d 200 %dms client=10.0.2.%d", 1000+i, 5+(i%40), (i%250)+1),
		})
	}
	// 4 lines for "admin" + 1 line for "root" generalizes the cluster; must remain ONE window with count=5!
	for i := 0; i < 4; i++ {
		agg.Add(model.LogEvent{
			ID:        uint64(2000 + i),
			Timestamp: 1700002000,
			Service:   "sshd",
			Level:     "ERROR",
			Message:   fmt.Sprintf("Failed password for invalid user admin from 198.51.100.42 port %d ssh2", 50000+i),
		})
	}
	agg.Add(model.LogEvent{
		ID:        2005,
		Timestamp: 1700002001,
		Service:   "sshd",
		Level:     "ERROR",
		Message:   "Failed password for invalid user root from 198.51.100.42 port 50099 ssh2",
	})

	windows := agg.Flush()
	if len(windows) != 2 {
		t.Fatalf("expected 1005 lines to collapse into 2 templates, got %d: %+v", len(windows), windows)
	}
	if windows[0].Service != "web" || windows[0].Count != 1000 {
		t.Fatalf("expected web template count=1000, got %+v", windows[0])
	}
	if windows[0].Template != "GET /api/v1/orders/<NUM> <NUM> <NUM> client=<IP>" {
		t.Fatalf("unexpected web template: %q", windows[0].Template)
	}
	if windows[1].Service != "sshd" || windows[1].Count != 5 {
		t.Fatalf("expected generalized sshd cluster to merge into count=5, got %+v", windows[1])
	}
}

func TestTemplateHashAndRootsAvoidDelimiterCollisions(t *testing.T) {
	// Direct hash framing check without cluster ordinals
	if TemplateHash("svc|edge", "WARN", "connection reset") == TemplateHash("svc", "edge|WARN", "connection reset") {
		t.Fatal("TemplateHash collided across delimiter-ambiguous service/level pairs")
	}

	agg := NewAggregator(DefaultMaxClusters)
	agg.Add(model.LogEvent{ID: 1, Timestamp: 100, Service: "svc|edge", Level: "WARN", Message: "connection reset"})
	agg.Add(model.LogEvent{ID: 2, Timestamp: 100, Service: "svc", Level: "edge|WARN", Message: "connection reset"})

	windows := agg.Flush()
	if len(windows) != 2 {
		t.Fatalf("expected distinct windows for delimiter-colliding service/level, got %d: %+v", len(windows), windows)
	}
}

func TestAggregatorPreservesSignatureEvidenceSeparatelyFromHighEntropySample(t *testing.T) {
	agg := NewAggregator(DefaultMaxClusters)
	highEntMsg := "GET /proxy target=/static/Q7xK9mP2vL4nR8tW1zB5yC3fH6jM0qS9uE4gA2kN HTTP/1.1 404"
	lfiMsg := "GET /proxy target=/static/../../../../etc/passwd HTTP/1.1 403"

	agg.Add(model.LogEvent{ID: 1, Timestamp: 100, Service: "nginx", Level: "WARN", Message: highEntMsg})
	agg.Add(model.LogEvent{ID: 2, Timestamp: 101, Service: "nginx", Level: "WARN", Message: lfiMsg})

	windows := agg.Flush()
	if len(windows) != 1 {
		t.Fatalf("expected 1 collapsed window, got %d", len(windows))
	}
	if windows[0].SampleLine != highEntMsg {
		t.Fatalf("expected primary SampleLine to remain highest-entropy message, got %q", windows[0].SampleLine)
	}
	foundInAdditional := false
	for _, s := range windows[0].AdditionalSamples {
		if s == lfiMsg {
			foundInAdditional = true
		}
	}
	if !foundInAdditional {
		t.Fatalf("expected LFI message in AdditionalSamples, got %+v", windows[0].AdditionalSamples)
	}
}

func TestPeakShannonEntropySeparatesBenignFromExfil(t *testing.T) {
	benign := "GET /healthz 200 1.2ms from 10.0.1.4"
	exfil := "TXT query Q7xK9mP2vL4nR8tW1zB5yC3fH6jM0qS9uE4gA2kN7pV8xZ1cT5wY3rD6bF0hJ4mL.tunnel.invalid NXDOMAIN"

	benignEnt := PeakShannonEntropy(benign)
	exfilEnt := PeakShannonEntropy(exfil)

	if benignEnt >= 4.7 {
		t.Fatalf("expected benign entropy < 4.7, got %.3f", benignEnt)
	}
	if exfilEnt < 5.2 {
		t.Fatalf("expected exfil peak entropy >= 5.2, got %.3f", exfilEnt)
	}
}

func TestDrainAndAggregatorRespectClusterAndWindowBounds(t *testing.T) {
	agg := NewAggregator(16)
	for i := 0; i < 500; i++ {
		agg.Add(model.LogEvent{
			ID:        uint64(i + 1),
			Timestamp: 1700000000,
			Service:   fmt.Sprintf("svc-%d", i),
			Level:     "INFO",
			Message:   fmt.Sprintf("unique token alpha_%d beta_%d", i, i*7),
		})
	}
	if agg.ClusterCount() > 16 {
		t.Fatalf("expected cluster count <= 16, got %d", agg.ClusterCount())
	}
	windows := agg.Flush()
	// Max 16 learned clusters + bounded overflow buckets (well below 500)
	if len(windows) >= 300 {
		t.Fatalf("expected bounded window count under random flood, got %d", len(windows))
	}
}

func TestAggregatorPreservesOverflowMarkerOnRepeatedEmptyMessages(t *testing.T) {
	agg := NewAggregator(1)
	agg.Add(model.LogEvent{ID: 1, Timestamp: 100, Service: "api", Level: "INFO", Message: "alpha"})
	agg.Add(model.LogEvent{ID: 2, Timestamp: 101, Service: "api", Level: "INFO", Message: ""})
	agg.Add(model.LogEvent{ID: 3, Timestamp: 102, Service: "api", Level: "INFO", Message: ""})

	windows := agg.Flush()
	if len(windows) != 2 {
		t.Fatalf("expected 2 windows (1 cluster + 1 overflow), got %d: %+v", len(windows), windows)
	}
	foundOverflow := false
	for _, w := range windows {
		if strings.HasPrefix(w.TemplateID, "overflow:") {
			foundOverflow = true
			if w.Template != "<OVERFLOW>" {
				t.Fatalf("expected overflow window Template=<OVERFLOW>, got %q", w.Template)
			}
			if w.Count != 2 {
				t.Fatalf("expected overflow window Count=2, got %d", w.Count)
			}
		}
	}
	if !foundOverflow {
		t.Fatalf("expected overflow window in %+v", windows)
	}
}

func TestAggregatorReservesDedicatedSlotAndEnforcesByteBudgets(t *testing.T) {
	// 1. Dedicated slot reservation: learn api/INFO: ready, flush, then send unknown overflow FIRST.
	agg := NewAggregator(1)
	agg.Add(model.LogEvent{ID: 1, Timestamp: 100, Service: "api", Level: "INFO", Message: "ready"})
	_ = agg.Flush()

	agg.Add(model.LogEvent{ID: 2, Timestamp: 101, Service: "unknown", Level: "INFO", Message: "unrecognized flood"})
	agg.Add(model.LogEvent{ID: 3, Timestamp: 102, Service: "api", Level: "INFO", Message: "ready"})

	windows := agg.Flush()
	if len(windows) != 2 {
		t.Fatalf("expected 2 windows (1 overflow + 1 dedicated api/INFO), got %d: %+v", len(windows), windows)
	}
	foundDedicated := false
	for _, w := range windows {
		if w.Service == "api" && w.Template == "ready" && !strings.HasPrefix(w.TemplateID, "overflow:") {
			foundDedicated = true
		}
	}
	if !foundDedicated {
		t.Fatalf("known template api/INFO: ready lost its dedicated window to earlier overflow: %+v", windows)
	}

	// 2. Overflow bucket count stays bounded across hundreds of distinct unknown services.
	for i := 0; i < 300; i++ {
		agg.Add(model.LogEvent{ID: uint64(10 + i), Timestamp: 200, Service: fmt.Sprintf("u-%d", i), Level: "INFO", Message: "flood"})
	}
	ovWins := agg.Flush()
	if len(ovWins) > maxOverflowBuckets+1 {
		t.Fatalf("expected overflow windows <= %d, got %d", maxOverflowBuckets+1, len(ovWins))
	}

	// 3. Retained sample byte budget and cluster byte budget stay strictly bounded under 64 KiB floods.
	aggBytes := NewAggregator(64)
	if err := aggBytes.SetMaxClusterBytes(4096); err != nil {
		t.Fatalf("SetMaxClusterBytes(4096): %v", err)
	}
	if err := aggBytes.SetSampleByteLimits(8192, 2048, 512); err != nil {
		t.Fatalf("SetSampleByteLimits: %v", err)
	}
	bigLine := strings.Repeat("A", 65536)
	for i := 0; i < 100; i++ {
		aggBytes.Add(model.LogEvent{
			ID:        uint64(i + 1),
			Timestamp: 300,
			Service:   fmt.Sprintf("svc-%d", i%20),
			Level:     "WARN",
			Message:   fmt.Sprintf("prefix_%d %s", i, bigLine),
		})
	}
	if got := aggBytes.RetainedSampleBytes(); got > 8192 {
		t.Fatalf("RetainedSampleBytes() = %d, exceeds budget 8192", got)
	}
	if got := aggBytes.ClusterBytes(); got > 4096 {
		t.Fatalf("ClusterBytes() = %d, exceeds budget 4096", got)
	}
	flushed := aggBytes.Flush()
	totalFlushedBytes := 0
	for _, w := range flushed {
		if len(w.SampleLine) > 512 {
			t.Fatalf("SampleLine length %d exceeds single-sample cap 512", len(w.SampleLine))
		}
		if w.SampleLine != "" && !w.SampleTruncated {
			t.Fatalf("expected 64 KiB preview sample to be marked SampleTruncated=true")
		}
		totalFlushedBytes += len(w.SampleLine)
		for _, s := range w.AdditionalSamples {
			totalFlushedBytes += len(s)
		}
	}
	if totalFlushedBytes > 8192 {
		t.Fatalf("flushed retained sample bytes %d exceeds budget 8192", totalFlushedBytes)
	}

	// 4. NaN similarity threshold falls back to DefaultSimilarityThreshold (identical messages merge).
	nanMiner := NewDrainMiner(2, math.NaN())
	id1, _, ov1 := nanMiner.ExtractTemplate("api", "INFO", "ready")
	id2, _, ov2 := nanMiner.ExtractTemplate("api", "INFO", "ready")
	if ov1 || ov2 || id1 != id2 || nanMiner.ClusterCount() != 1 {
		t.Fatalf("NaN threshold failed to merge identical messages: id1=%s id2=%s count=%d", id1, id2, nanMiner.ClusterCount())
	}
	// Reject lowering maxClusterBytes below current usage without Reset().
	if err := nanMiner.SetMaxClusterBytes(4); err == nil {
		t.Fatalf("expected SetMaxClusterBytes(4) to fail when ClusterBytes()=%d", nanMiner.ClusterBytes())
	}

	// 5. Rejected cluster rolls back newly created tree keys & bytes so subsequent small messages still fit
	// (cluster cost includes the 16-byte cluster ID, so "a" needs 1 key + 1 token + 16 ID = 18 bytes).
	rbMiner := NewDrainMiner(4, DefaultSimilarityThreshold)
	if err := rbMiner.SetMaxClusterBytes(24); err != nil {
		t.Fatalf("SetMaxClusterBytes(24): %v", err)
	}
	_, _, rejectedOv := rbMiner.ExtractTemplate("", "", "abcdefgh xyz")
	if !rejectedOv || rbMiner.ClusterBytes() != 0 {
		t.Fatalf("expected rejected cluster to roll back tree bytes to 0, got ov=%v bytes=%d", rejectedOv, rbMiner.ClusterBytes())
	}
	_, _, smallOv := rbMiner.ExtractTemplate("", "", "a")
	if smallOv || rbMiner.ClusterCount() != 1 || rbMiner.ClusterBytes() != 18 {
		t.Fatalf("small message failed after rolled-back cluster rejection: ov=%v count=%d bytes=%d", smallOv, rbMiner.ClusterCount(), rbMiner.ClusterBytes())
	}

	// 6. Generalization checks byte cap BEFORE mutating cluster tokens (2 keys + 4 tokens + 16 ID = 22 bytes).
	genMiner := NewDrainMiner(4, DefaultSimilarityThreshold)
	if err := genMiner.SetMaxClusterBytes(22); err != nil {
		t.Fatalf("SetMaxClusterBytes(22): %v", err)
	}
	_, _, g1Ov := genMiner.ExtractTemplate("", "", "x y a b")
	if g1Ov || genMiner.ClusterBytes() != 22 {
		t.Fatalf("expected initial cluster to fit in 22 bytes (incl. 16-byte ID), got ov=%v bytes=%d", g1Ov, genMiner.ClusterBytes())
	}
	_, _, g2Ov := genMiner.ExtractTemplate("", "", "x y c d")
	if !g2Ov || genMiner.ClusterBytes() != 22 {
		t.Fatalf("expected generalization exceeding 22-byte cap to overflow without mutating cluster, got ov=%v bytes=%d", g2Ov, genMiner.ClusterBytes())
	}

	// 7. Promoted preview preserves complete metadata when an equal clipped preview is promoted,
	// rejects incompatible SetSampleByteLimits reductions, and bounds window display Service/Level.
	promoAgg := NewAggregator(8)
	if err := promoAgg.SetSampleByteLimits(1024, 1024, 6); err != nil {
		t.Fatalf("SetSampleByteLimits: %v", err)
	}
	longSvc := strings.Repeat("S", 1024)
	longLvl := strings.Repeat("L", 512)
	promoAgg.Add(model.LogEvent{ID: 1, Timestamp: 1, Service: longSvc, Level: longLvl, Message: "k v x1y2z3w4"}) // mid entropy -> SampleLine="k v x1"
	promoAgg.Add(model.LogEvent{ID: 2, Timestamp: 2, Service: longSvc, Level: longLvl, Message: "k v ab"})       // complete -> AdditionalSamples=["k v ab"]
	promoAgg.Add(model.LogEvent{ID: 3, Timestamp: 3, Service: longSvc, Level: longLvl, Message: "k v ab0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"})
	if err := promoAgg.SetSampleByteLimits(2, 2, 2); err == nil {
		t.Fatal("expected SetSampleByteLimits(2, 2, 2) to fail while active window retains 12 bytes")
	}
	if got := promoAgg.RetainedSampleBytes(); got != 12 {
		t.Fatalf("expected RetainedSampleBytes=12 after promotion dedup (6+6), got %d", got)
	}
	promoWins := promoAgg.Flush()
	if len(promoWins) != 1 {
		t.Fatalf("expected 1 window, got %d", len(promoWins))
	}
	if len(promoWins[0].Service) > maxWindowServiceBytes || len(promoWins[0].Level) > maxWindowLevelBytes || !promoWins[0].ServiceTruncated {
		t.Fatalf("window display Service/Level caps or ServiceTruncated wrong: len(svc)=%d len(lvl)=%d trunc=%v", len(promoWins[0].Service), len(promoWins[0].Level), promoWins[0].ServiceTruncated)
	}
	if promoWins[0].SampleLine != "k v ab" || promoWins[0].SampleTruncated {
		t.Fatalf("expected promoted complete SampleLine=%q with SampleTruncated=false, got %q trunc=%v", "k v ab", promoWins[0].SampleLine, promoWins[0].SampleTruncated)
	}
	for _, extra := range promoWins[0].AdditionalSamples {
		if extra == "k v ab" {
			t.Fatalf("promoted preview %q duplicated in AdditionalSamples: %+v", "k v ab", promoWins[0].AdditionalSamples)
		}
	}
}

func TestDrainLeafCapPreservesExistingMatchesAndOverflowsExcess(t *testing.T) {
	miner := NewDrainMiner(DefaultMaxClusters, 0.75)
	// Fill one single prefix-tree leaf (same service, level, tokenCount=8, same first two tokens)
	// up to maxLeafClusters (128) with mutually distinct remaining 6 tokens.
	var firstID string
	for i := 0; i < maxLeafClusters; i++ {
		msg := fmt.Sprintf("prefixA prefixB t%da t%db t%dc t%dd t%de t%df", i, i, i, i, i, i)
		id, _, ov := miner.ExtractTemplate("svc", "INFO", msg)
		if ov {
			t.Fatalf("unexpected overflow at leaf cluster %d", i)
		}
		if i == 0 {
			firstID = id
		}
	}
	if miner.ClusterCount() != maxLeafClusters {
		t.Fatalf("expected %d clusters in leaf, got %d", maxLeafClusters, miner.ClusterCount())
	}

	// Existing cluster in the saturated leaf must still match cleanly without overflowing.
	matchID, _, matchOv := miner.ExtractTemplate("svc", "INFO", "prefixA prefixB t0a t0b t0c t0d t0e t0f")
	if matchOv || matchID != firstID {
		t.Fatalf("existing cluster failed to match after leaf filled: id=%s want=%s ov=%v", matchID, firstID, matchOv)
	}

	// Non-matching new messages into the saturated leaf must overflow without exceeding maxLeafClusters.
	_, tmpl1, ov1 := miner.ExtractTemplate("svc", "INFO", "prefixA prefixB x1a x1b x1c x1d x1e x1f")
	_, tmpl2, ov2 := miner.ExtractTemplate("svc", "INFO", "prefixA prefixB x2a x2b x2c x2d x2e x2f")
	if !ov1 || !ov2 || tmpl1 != "<OVERFLOW>" || tmpl2 != "<OVERFLOW>" {
		t.Fatalf("expected overflow on saturated leaf excess messages: ov=(%v,%v) tmpl=(%q,%q)", ov1, ov2, tmpl1, tmpl2)
	}
	if miner.ClusterCount() != maxLeafClusters {
		t.Fatalf("cluster count grew past leaf cap: got %d want %d", miner.ClusterCount(), maxLeafClusters)
	}
}
