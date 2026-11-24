package emit

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

// Alert is the structured JSON telemetry event emitted by Sentinel back into Genesis
// (under service=sentinel) or local stdout/JSONL output. Top-level fields match
// Genesis's JSON Lines parser so alerts index cleanly and appear live in the Web UI.
type Alert struct {
	Timestamp            int64              `json:"timestamp"`
	Service              string             `json:"service"`
	Level                string             `json:"level"`
	TraceID              string             `json:"trace_id"`
	Message              string             `json:"message"`
	AlertID              string             `json:"alert_id"`
	Tier                 string             `json:"tier"`
	SourceService        string             `json:"source_service"`
	SourceLevel          string             `json:"source_level"`
	TemplateID           string             `json:"template_id"`
	Template             string             `json:"template"`
	Count                uint64             `json:"count"`
	SampleEntropy        float64            `json:"sample_entropy"`
	SurprisalNats        float64            `json:"surprisal_nats,omitempty"`
	SurprisalThreshold   float64            `json:"surprisal_threshold,omitempty"`
	TopSurprisalFeatures map[string]float64 `json:"top_surprisal_features,omitempty"`
	RuleIDs              []string           `json:"rule_ids"`
	Categories           []string           `json:"categories"`
	Severity             string             `json:"severity"`
	InjectionSuspected   bool               `json:"injection_suspected"`
	InjectionSignals     []string           `json:"injection_signals,omitempty"`
	SanitizedSample      string             `json:"sanitized_sample"`
}

// Sink receives structured Sentinel alerts.
type Sink interface {
	Emit(alert Alert) error
	Close() error
}

// ReservedAlertService is always ignored on ingest for loop prevention, even if
// the operator configures an alternate alert_service_name.
const ReservedAlertService = "sentinel"

// ShouldIgnoreEvent enforces strict loop prevention so Sentinel never ingests
// and re-evaluates its own alerts (either the reserved "sentinel" service or
// any custom configured alertService).
func ShouldIgnoreEvent(ev model.LogEvent, alertService string) bool {
	svc := strings.TrimSpace(ev.Service)
	if strings.EqualFold(svc, ReservedAlertService) {
		return true
	}
	trimmedAlert := strings.TrimSpace(alertService)
	return trimmedAlert != "" && strings.EqualFold(svc, trimmedAlert)
}

// MapSeverityToGenesisLevel maps Sentinel alert severity to Genesis log levels.
// CRITICAL -> FATAL and HIGH -> ERROR route directly into Genesis's priority QoS lane.
func MapSeverityToGenesisLevel(severity string) string {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return "FATAL"
	case "HIGH":
		return "ERROR"
	case "MEDIUM":
		return "WARN"
	default:
		return "INFO"
	}
}

// HigherSeverity returns whichever of a or b has the higher severity rank.
func HigherSeverity(a, b string) string {
	rank := func(s string) int {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	if rank(b) > rank(a) {
		return strings.ToUpper(strings.TrimSpace(b))
	}
	if rank(a) > 0 {
		return strings.ToUpper(strings.TrimSpace(a))
	}
	return "INFO"
}

// HighestSeverity returns the highest severity label among hits.
func HighestSeverity(hits []model.RuleHit) string {
	rank := func(s string) int {
		switch strings.ToUpper(strings.TrimSpace(s)) {
		case "CRITICAL":
			return 4
		case "HIGH":
			return 3
		case "MEDIUM":
			return 2
		case "LOW":
			return 1
		default:
			return 0
		}
	}
	best := "INFO"
	bestRank := 0
	for _, h := range hits {
		if r := rank(h.Severity); r > bestRank {
			bestRank = r
			best = strings.ToUpper(strings.TrimSpace(h.Severity))
		}
	}
	return best
}

// GenesisTCPSink streams newline-delimited JSON alerts to Genesis's TCP ingestion listener.
type GenesisTCPSink struct {
	mu      sync.Mutex
	addr    string
	timeout time.Duration
	conn    net.Conn
}

// NewGenesisTCPSink creates a loopback TCP alert sink targeting Genesis (e.g. 127.0.0.1:9000).
func NewGenesisTCPSink(addr string, timeout time.Duration) *GenesisTCPSink {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return &GenesisTCPSink{
		addr:    addr,
		timeout: timeout,
	}
}

// Emit encodes alert as single-line JSON and writes it over TCP, reconnecting once on stale socket error.
func (s *GenesisTCPSink) Emit(alert Alert) error {
	payload, err := json.Marshal(alert)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}
	payload = append(payload, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.writeLocked(payload); err == nil {
		return nil
	}
	// Reconnect once if the prior TCP connection was closed by Genesis.
	s.closeLocked()
	if err := s.writeLocked(payload); err != nil {
		// Clear the failed socket so a partial write never corrupts the next Emit.
		s.closeLocked()
		return err
	}
	return nil
}

func (s *GenesisTCPSink) writeLocked(payload []byte) error {
	if s.conn == nil {
		conn, err := net.DialTimeout("tcp", s.addr, s.timeout)
		if err != nil {
			return fmt.Errorf("dial genesis tcp %s: %w", s.addr, err)
		}
		s.conn = conn
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.timeout))
	_, err := s.conn.Write(payload)
	return err
}

func (s *GenesisTCPSink) closeLocked() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}

// Close closes the underlying TCP socket.
func (s *GenesisTCPSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeLocked()
	return nil
}

// WriterSink writes newline-delimited JSON alerts to an io.Writer (stdout or test buffer).
type WriterSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriterSink creates a JSONL alert sink backed by w.
func NewWriterSink(w io.Writer) *WriterSink {
	return &WriterSink{w: w}
}

// Emit writes alert as single-line JSON to w.
func (s *WriterSink) Emit(alert Alert) error {
	if s == nil || s.w == nil {
		return nil
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(payload)
	return err
}

// Close is a no-op for WriterSink.
func (s *WriterSink) Close() error { return nil }

// NopSink discards alerts (useful for dry-run benchmarks).
type NopSink struct{}

// Emit discards alert without error.
func (NopSink) Emit(Alert) error { return nil }

// Close is a no-op.
func (NopSink) Close() error { return nil }

// MultiSink fans alerts out across multiple underlying sinks.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink builds a fan-out sink.
func NewMultiSink(sinks ...Sink) *MultiSink {
	filtered := make([]Sink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			filtered = append(filtered, s)
		}
	}
	return &MultiSink{sinks: filtered}
}

// Emit sends alert to all registered sinks, returning the first encountered error.
func (m *MultiSink) Emit(alert Alert) error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Emit(alert); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close closes all registered sinks.
func (m *MultiSink) Close() error {
	var firstErr error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
