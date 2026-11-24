package template

import (
	"fmt"
	"testing"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

func TestAggregatorCollapsesRepetitiveNoise(t *testing.T) {
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
	agg.Add(model.LogEvent{
		ID:        1001,
		Timestamp: 1700002000,
		Service:   "sshd",
		Level:     "ERROR",
		Message:   "Failed password for invalid user admin from 198.51.100.42 port 51922 ssh2",
	})

	windows := agg.Flush()
	if len(windows) != 2 {
		t.Fatalf("expected 1001 lines to collapse into 2 templates, got %d: %+v", len(windows), windows)
	}
	if windows[0].Service != "web" || windows[0].Count != 1000 {
		t.Fatalf("expected web template count=1000, got %+v", windows[0])
	}
	if windows[0].Template != "GET /api/v1/orders/<NUM> <NUM> <NUM> client=<IP>" {
		t.Fatalf("unexpected web template: %q", windows[0].Template)
	}
	if windows[1].Service != "sshd" || windows[1].Count != 1 {
		t.Fatalf("expected sshd template count=1, got %+v", windows[1])
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
	if exfilEnt < 5.0 {
		t.Fatalf("expected exfil peak entropy >= 5.0, got %.3f", exfilEnt)
	}
}

func TestDrainRespectsMaxClusterBound(t *testing.T) {
	agg := NewAggregator(16)
	for i := 0; i < 200; i++ {
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
}
