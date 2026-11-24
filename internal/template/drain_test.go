package template

import (
	"fmt"
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
