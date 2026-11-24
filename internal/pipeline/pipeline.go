package pipeline

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/ingest"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/template"
)

// Stats exposes live Sentinel Tier 0 pipeline telemetry over HTTP /stats and CLI output.
type Stats struct {
	LinesRead        uint64  `json:"lines_read"`
	LinesIgnoredSelf uint64  `json:"lines_ignored_self"`
	TemplatesEmitted uint64  `json:"templates_emitted"`
	CollapseRatio    float64 `json:"collapse_ratio"`
	ClustersActive   int     `json:"clusters_active"`
	RuleHitsTotal    uint64  `json:"rule_hits_total"`
	AlertsEmitted    uint64  `json:"alerts_emitted"`
	InjectionSignals uint64  `json:"injection_signals"`
	SinkErrors       uint64  `json:"sink_errors"`
	CorruptedFrames  uint64  `json:"corrupted_frames"`
	BurnResets       uint64  `json:"burn_resets"`
	EvictionGaps     uint64  `json:"eviction_gaps"`
	EstimatedLost    uint64  `json:"estimated_lost"`
	ActiveSource     string  `json:"active_source"`
	DataDir          string  `json:"data_dir"`
	GenesisDataDir   string  `json:"genesis_data_dir,omitempty"`
	HeapBytes        uint64  `json:"heap_bytes"`
	UptimeSeconds    int64   `json:"uptime_seconds"`
}

// BurnReport summarizes what `sentinel burn` removed locally.
type BurnReport struct {
	Status       string    `json:"status"`
	DataDir      string    `json:"data_dir"`
	FilesRemoved int       `json:"files_removed"`
	BytesRemoved int64     `json:"bytes_removed"`
	Timestamp    time.Time `json:"timestamp"`
	Note         string    `json:"note"`
}

// Pipeline coordinates Tier 0 ingestion, loop prevention, template collapsing,
// deterministic rule evaluation, and Genesis alert emission.
type Pipeline struct {
	cfg          *config.Config
	agg          *template.Aggregator
	ruleEng      *rules.Engine
	sink         emit.Sink
	activeSource string
	startTime    time.Time

	segReader   *ingest.SegReader
	queryPoller *ingest.QueryPoller

	linesRead        atomic.Uint64
	linesIgnoredSelf atomic.Uint64
	templatesEmitted atomic.Uint64
	ruleHitsTotal    atomic.Uint64
	alertsEmitted    atomic.Uint64
	injectionSignals atomic.Uint64
	sinkErrors       atomic.Uint64
	alertSeq         atomic.Uint64
}

// New builds a Pipeline wired with Tier 0 template collapsing and deterministic rules.
func New(cfg *config.Config, ruleEng *rules.Engine, sink emit.Sink, activeSource string) *Pipeline {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	if sink == nil {
		sink = emit.NopSink{}
	}
	return &Pipeline{
		cfg:          cfg,
		agg:          template.NewAggregator(template.DefaultMaxClusters),
		ruleEng:      ruleEng,
		sink:         sink,
		activeSource: activeSource,
		startTime:    time.Now(),
	}
}

// AttachSegReader links a SegReader so Stats() reports segment cursor & corruption telemetry.
func (p *Pipeline) AttachSegReader(r *ingest.SegReader) {
	p.segReader = r
}

// AttachQueryPoller links a QueryPoller so Stats() reports eviction-gap telemetry.
func (p *Pipeline) AttachQueryPoller(q *ingest.QueryPoller) {
	p.queryPoller = q
}

// IngestEvent folds a single incoming LogEvent into Tier 0 while enforcing strict loop prevention.
func (p *Pipeline) IngestEvent(ev model.LogEvent) {
	if emit.ShouldIgnoreEvent(ev, p.cfg.AlertServiceName) {
		p.linesIgnoredSelf.Add(1)
		return
	}
	p.linesRead.Add(1)
	p.agg.Add(ev)
}

// FlushWindow drains collapsed TemplateWindows, runs Tier 0 deterministic rules & prompt-injection
// checks, emits structured alerts to the configured sink, and returns all alerts emitted.
func (p *Pipeline) FlushWindow() []emit.Alert {
	windows := p.agg.Flush()
	if len(windows) == 0 {
		return nil
	}
	p.templatesEmitted.Add(uint64(len(windows)))

	var alerts []emit.Alert
	nowUnix := time.Now().Unix()

	for _, w := range windows {
		eval := p.ruleEng.Evaluate(w, p.cfg.MaxPromptByte)
		if eval.InjectionSuspected {
			p.injectionSignals.Add(1)
		}
		if eval.Suppressed || len(eval.RuleHits) == 0 {
			continue
		}

		p.ruleHitsTotal.Add(uint64(len(eval.RuleHits)))
		seq := p.alertSeq.Add(1)
		alertID := fmt.Sprintf("sentinel-%d-%d", nowUnix, seq)
		severity := emit.HighestSeverity(eval.RuleHits)

		ruleIDs := make([]string, 0, len(eval.RuleHits))
		categories := make([]string, 0, len(eval.RuleHits))
		for _, h := range eval.RuleHits {
			ruleIDs = append(ruleIDs, h.RuleID)
			categories = append(categories, h.Category)
		}

		ts := w.LastSeenUnix
		if ts <= 0 {
			ts = nowUnix
		}

		msg := fmt.Sprintf("[%s] %s on service=%s count=%d entropy=%.2f sample=%q",
			strings.Join(ruleIDs, ","),
			strings.Join(categories, ","),
			w.Service,
			w.Count,
			w.SampleEntropy,
			truncateSummary(eval.SanitizedSample, 240),
		)

		sanitizedTemplate, _ := security.SanitizeUntrustedLogText(w.Template, p.cfg.MaxPromptByte)
		// Round entropy to 4 decimal places so float64 serialization never emits a 16-digit
		// mantissa that triggers Genesis --redact's 16-digit card regex mid-JSON number.
		roundedEntropy := math.Round(w.SampleEntropy*10000) / 10000

		alert := emit.Alert{
			Timestamp:          ts,
			Service:            p.cfg.AlertServiceName,
			Level:              emit.MapSeverityToGenesisLevel(severity),
			TraceID:            alertID,
			Message:            msg,
			AlertID:            alertID,
			Tier:               "tier0",
			SourceService:      w.Service,
			SourceLevel:        w.Level,
			TemplateID:         w.TemplateID,
			Template:           sanitizedTemplate,
			Count:              w.Count,
			SampleEntropy:      roundedEntropy,
			RuleIDs:            ruleIDs,
			Categories:         categories,
			Severity:           severity,
			InjectionSuspected: eval.InjectionSuspected,
			InjectionSignals:   eval.InjectionSignals,
			SanitizedSample:    eval.SanitizedSample,
		}

		if err := p.sink.Emit(alert); err != nil {
			p.sinkErrors.Add(1)
		}
		p.alertsEmitted.Add(1)
		alerts = append(alerts, alert)
	}

	return alerts
}

// Stats returns a thread-safe snapshot of pipeline metrics.
func (p *Pipeline) Stats() Stats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	lines := p.linesRead.Load()
	tmpls := p.templatesEmitted.Load()
	var ratio float64
	if tmpls > 0 {
		ratio = float64(lines) / float64(tmpls)
	}

	st := Stats{
		LinesRead:        lines,
		LinesIgnoredSelf: p.linesIgnoredSelf.Load(),
		TemplatesEmitted: tmpls,
		CollapseRatio:    ratio,
		ClustersActive:   p.agg.ClusterCount(),
		RuleHitsTotal:    p.ruleHitsTotal.Load(),
		AlertsEmitted:    p.alertsEmitted.Load(),
		InjectionSignals: p.injectionSignals.Load(),
		SinkErrors:       p.sinkErrors.Load(),
		ActiveSource:     p.activeSource,
		DataDir:          p.cfg.DataDir,
		GenesisDataDir:   p.cfg.GenesisDataDir,
		HeapBytes:        m.HeapAlloc,
		UptimeSeconds:    int64(time.Since(p.startTime).Seconds()),
	}

	if p.segReader != nil {
		rs := p.segReader.Stats()
		st.CorruptedFrames = rs.CorruptedFrames
		st.BurnResets = rs.BurnResets
	}
	if p.queryPoller != nil {
		qs := p.queryPoller.Stats()
		st.EvictionGaps = qs.EvictionGaps
		st.EstimatedLost = qs.EstimatedLost
	}

	return st
}

// Burn wipes Sentinel's in-memory templates/cursors and deletes local disk state in cfg.DataDir.
func (p *Pipeline) Burn() (BurnReport, error) {
	p.agg.Reset()
	if p.segReader != nil {
		p.segReader.ResetCursor()
	}
	return BurnLocalState(p.cfg.DataDir)
}

// HandleHealthz serves GET /healthz for loopback liveness checks.
func (p *Pipeline) HandleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":        "healthy",
		"active_source": p.activeSource,
		"data_dir":      p.cfg.DataDir,
	})
}

// HandleStats serves GET /stats returning JSON pipeline metrics.
func (p *Pipeline) HandleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(p.Stats())
}

// HandleBurn serves DELETE /burn matching Genesis's CSRF-safe DELETE requirement.
func (p *Pipeline) HandleBurn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"method not allowed; use DELETE"}`, http.StatusMethodNotAllowed)
		return
	}
	rep, err := p.Burn()
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rep)
}

// BurnLocalState removes Sentinel's persisted local state files inside dataDir
// (cursors, baseline snapshots, and unexported feedback queues) while leaving
// external FTaaS model artifacts clearly disclosed to the operator.
func BurnLocalState(dataDir string) (BurnReport, error) {
	rep := BurnReport{
		Status:    "burned",
		DataDir:   dataDir,
		Timestamp: time.Now().UTC(),
		Note:      "Sentinel local state purged. Already-trained FTaaS LoRA weights remain in ml/data/artifacts/ and must be removed separately if desired.",
	}
	if strings.TrimSpace(dataDir) == "" {
		return rep, nil
	}

	info, err := os.Stat(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil
		}
		return rep, fmt.Errorf("stat data dir %q: %w", dataDir, err)
	}
	if !info.IsDir() {
		return rep, fmt.Errorf("data dir %q is not a directory", dataDir)
	}

	var filesRemoved int
	var bytesRemoved int64
	_ = filepath.WalkDir(dataDir, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil || path == dataDir || d.IsDir() {
			return nil
		}
		if fi, statErr := d.Info(); statErr == nil {
			bytesRemoved += fi.Size()
		}
		if remErr := os.Remove(path); remErr == nil {
			filesRemoved++
		}
		return nil
	})

	// Clean any empty subdirectories (e.g., feedback/)
	entries, err := os.ReadDir(dataDir)
	if err == nil {
		for _, e := range entries {
			if e.IsDir() {
				_ = os.RemoveAll(filepath.Join(dataDir, e.Name()))
			}
		}
	}

	rep.FilesRemoved = filesRemoved
	rep.BytesRemoved = bytesRemoved
	return rep, nil
}

func truncateSummary(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	return s[:maxChars] + "..."
}
