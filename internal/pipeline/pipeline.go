package pipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
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
	SaturatedPages   uint64  `json:"saturated_pages"`
	ActiveSource     string  `json:"active_source"`
	DataDir          string  `json:"data_dir"`
	GenesisDataDir   string  `json:"genesis_data_dir,omitempty"`
	HeapBytes        uint64  `json:"heap_bytes"`
	UptimeSeconds    int64   `json:"uptime_seconds"`
}

// FailedAlert pairs an alert with the sink delivery error that prevented emission.
type FailedAlert struct {
	Alert emit.Alert
	Err   error
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

	// burnMu coordinates Burn() with FlushWindow() (RLock during flush, Lock during Burn)
	// so no pre-burn alert can be delivered after Burn acknowledges completion.
	burnMu      sync.RWMutex
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
	p.burnMu.Lock()
	p.segReader = r
	p.burnMu.Unlock()
}

// AttachQueryPoller links a QueryPoller so Stats() reports eviction-gap telemetry.
func (p *Pipeline) AttachQueryPoller(q *ingest.QueryPoller) {
	p.burnMu.Lock()
	p.queryPoller = q
	p.burnMu.Unlock()
}

// IngestEvent folds a single incoming LogEvent into Tier 0 while enforcing strict loop prevention.
func (p *Pipeline) IngestEvent(ev model.LogEvent) {
	if emit.ShouldIgnoreEvent(ev, p.cfg.AlertServiceName) {
		p.linesIgnoredSelf.Add(1)
		return
	}
	p.burnMu.RLock()
	p.linesRead.Add(1)
	p.agg.Add(ev)
	p.burnMu.RUnlock()
}

// FlushWindow drains collapsed TemplateWindows, runs Tier 0 deterministic rules & prompt-injection
// checks, emits structured alerts to the configured sink, and returns successfully emitted alerts
// separately from any failed sink deliveries.
func (p *Pipeline) FlushWindow() ([]emit.Alert, []FailedAlert) {
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()

	windows := p.agg.Flush()
	if len(windows) == 0 {
		return nil, nil
	}
	p.templatesEmitted.Add(uint64(len(windows)))

	var (
		emitted []emit.Alert
		failed  []FailedAlert
	)
	nowUnix := time.Now().Unix()

	for _, w := range windows {
		eval := p.ruleEng.Evaluate(w, p.cfg.MaxPromptByte)

		// Sanitize untrusted log-derived metadata fields (Service, Level, Template)
		// before building alert strings/fields while keeping raw values for rule evaluation.
		cleanService, svcSigs := security.SanitizeUntrustedLogText(w.Service, 128)
		cleanLevel, lvlSigs := security.SanitizeUntrustedLogText(w.Level, 64)
		cleanTemplate, tmplSigs := security.SanitizeUntrustedLogText(w.Template, p.cfg.MaxPromptByte)

		injSignals := mergeSignals(eval.InjectionSignals, svcSigs, lvlSigs, tmplSigs)
		injSuspected := eval.InjectionSuspected || len(injSignals) > 0
		if injSuspected {
			p.injectionSignals.Add(1)
		}

		ruleHits := eval.RuleHits
		if !eval.Suppressed && injSuspected && !hasRuleID(ruleHits, "SENT-006") {
			ruleHits = append(ruleHits, model.RuleHit{
				RuleID:      "SENT-006",
				Category:    "prompt_injection_probe",
				Severity:    "HIGH",
				Description: "Adversarial LLM control delimiter or prompt-injection phrase detected in untrusted log",
			})
		}

		if eval.Suppressed || len(ruleHits) == 0 {
			continue
		}

		p.ruleHitsTotal.Add(uint64(len(ruleHits)))
		seq := p.alertSeq.Add(1)
		alertID := fmt.Sprintf("sentinel-%d-%d", nowUnix, seq)
		severity := emit.HighestSeverity(ruleHits)

		ruleIDs := make([]string, 0, len(ruleHits))
		categories := make([]string, 0, len(ruleHits))
		for _, h := range ruleHits {
			ruleIDs = append(ruleIDs, h.RuleID)
			categories = append(categories, h.Category)
		}

		ts := w.LastSeenUnix
		if ts <= 0 {
			ts = nowUnix
		}

		// Round entropy to 4 decimal places so float64 serialization never emits a 16-digit
		// mantissa that triggers Genesis --redact's 16-digit card regex mid-JSON number.
		roundedEntropy := math.Round(w.SampleEntropy*10000) / 10000

		msg := fmt.Sprintf("[%s] %s on service=%s count=%d entropy=%.2f sample=%q",
			strings.Join(ruleIDs, ","),
			strings.Join(categories, ","),
			cleanService,
			w.Count,
			roundedEntropy,
			truncateSummary(eval.SanitizedSample, 240),
		)

		alert := emit.Alert{
			Timestamp:          ts,
			Service:            p.cfg.AlertServiceName,
			Level:              emit.MapSeverityToGenesisLevel(severity),
			TraceID:            alertID,
			Message:            msg,
			AlertID:            alertID,
			Tier:               "tier0",
			SourceService:      cleanService,
			SourceLevel:        cleanLevel,
			TemplateID:         w.TemplateID,
			Template:           cleanTemplate,
			Count:              w.Count,
			SampleEntropy:      roundedEntropy,
			RuleIDs:            ruleIDs,
			Categories:         categories,
			Severity:           severity,
			InjectionSuspected: injSuspected,
			InjectionSignals:   injSignals,
			SanitizedSample:    eval.SanitizedSample,
		}

		if err := p.sink.Emit(alert); err != nil {
			p.sinkErrors.Add(1)
			failed = append(failed, FailedAlert{Alert: alert, Err: err})
			continue
		}
		p.alertsEmitted.Add(1)
		emitted = append(emitted, alert)
	}

	return emitted, failed
}

func mergeSignals(groups ...[]string) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, g := range groups {
		for _, s := range g {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func hasRuleID(hits []model.RuleHit, id string) bool {
	for _, h := range hits {
		if h.RuleID == id {
			return true
		}
	}
	return false
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

	p.burnMu.RLock()
	segReader := p.segReader
	queryPoller := p.queryPoller
	p.burnMu.RUnlock()

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

	if segReader != nil {
		rs := segReader.Stats()
		st.CorruptedFrames = rs.CorruptedFrames
		st.BurnResets = rs.BurnResets
	}
	if queryPoller != nil {
		qs := queryPoller.Stats()
		st.EvictionGaps = qs.EvictionGaps
		st.EstimatedLost = qs.EstimatedLost
		st.SaturatedPages = qs.SaturatedPages
	}

	return st
}

// Burn waits for any in-flight FlushWindow to finish, resets in-memory templates and
// active ingest cursors (.seg and /query), and deletes Sentinel-owned disk state.
func (p *Pipeline) Burn() (BurnReport, error) {
	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	p.agg.Reset()
	if p.segReader != nil {
		p.segReader.ResetCursor()
	}
	if p.queryPoller != nil {
		p.queryPoller.Reset()
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

// BurnLocalState deletes ONLY known Sentinel-owned regular files inside dataDir
// (cursor files, baseline snapshots, and feedback/*.jsonl), confined via Go 1.24's
// os.Root so symlinks cannot redirect deletion outside dataDir. Unrelated user
// files are preserved, bytes are counted strictly after successful deletion, and
// any errors are returned alongside accurate partial counts.
func BurnLocalState(dataDir string) (BurnReport, error) {
	rep := BurnReport{
		Status:    "burned",
		DataDir:   dataDir,
		Timestamp: time.Now().UTC(),
		Note:      "Sentinel-owned local state purged. Already-trained FTaaS LoRA weights remain in ml/data/artifacts/ and must be removed separately if desired.",
	}
	if strings.TrimSpace(dataDir) == "" {
		return rep, nil
	}

	info, err := os.Stat(dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return rep, nil
		}
		rep.Status = "failed"
		return rep, fmt.Errorf("stat data dir %q: %w", dataDir, err)
	}
	if !info.IsDir() {
		rep.Status = "failed"
		return rep, fmt.Errorf("data dir %q is not a directory", dataDir)
	}

	root, err := os.OpenRoot(dataDir)
	if err != nil {
		rep.Status = "failed"
		return rep, fmt.Errorf("open root %q: %w", dataDir, err)
	}
	defer func() { _ = root.Close() }()

	var errs []error
	removeOwnedRel := func(rel string) {
		fi, statErr := root.Lstat(rel)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				errs = append(errs, fmt.Errorf("lstat %q: %w", rel, statErr))
			}
			return
		}
		if !fi.Mode().IsRegular() {
			// Refuse to follow or unlink symlinks/directories in place of regular Sentinel files.
			if fi.Mode()&os.ModeSymlink != 0 {
				errs = append(errs, fmt.Errorf("refusing to remove symlink at Sentinel state path %q", rel))
			}
			return
		}
		sz := fi.Size()
		if remErr := root.Remove(rel); remErr != nil {
			if !os.IsNotExist(remErr) {
				errs = append(errs, fmt.Errorf("remove %q: %w", rel, remErr))
			}
			return
		}
		rep.FilesRemoved++
		rep.BytesRemoved += sz
	}

	// 1. Known top-level Sentinel state files and atomic cursor temp files.
	topDir, err := root.Open(".")
	if err != nil {
		rep.Status = "failed"
		return rep, fmt.Errorf("open root dir %q: %w", dataDir, err)
	}
	entries, err := topDir.ReadDir(-1)
	_ = topDir.Close()
	if err != nil {
		rep.Status = "failed"
		return rep, fmt.Errorf("read data dir %q: %w", dataDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if isOwnedTopLevelFile(name) {
			removeOwnedRel(name)
		}
	}

	// 2. Known Sentinel feedback JSONL files inside root-confined "feedback/" (reject symlinks!).
	fbInfo, statErr := root.Lstat("feedback")
	if statErr == nil {
		if fbInfo.Mode()&os.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("refusing to follow symlink at %q", filepath.Join(dataDir, "feedback")))
		} else if fbInfo.IsDir() {
			fbDir, openErr := root.Open("feedback")
			if openErr != nil {
				errs = append(errs, fmt.Errorf("open feedback dir: %w", openErr))
			} else {
				fbEntries, readErr := fbDir.ReadDir(-1)
				_ = fbDir.Close()
				if readErr != nil {
					errs = append(errs, fmt.Errorf("read feedback dir: %w", readErr))
				} else {
					for _, e := range fbEntries {
						if e.IsDir() {
							continue
						}
						name := e.Name()
						if strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.tmp") {
							removeOwnedRel(filepath.Join("feedback", name))
						}
					}
					// Remove feedback/ only if now empty.
					if remErr := root.Remove("feedback"); remErr != nil && !os.IsNotExist(remErr) {
						if checkDir, openCheckErr := root.Open("feedback"); openCheckErr == nil {
							remaining, _ := checkDir.ReadDir(1)
							_ = checkDir.Close()
							if len(remaining) == 0 {
								errs = append(errs, fmt.Errorf("remove empty feedback dir: %w", remErr))
							}
						}
					}
				}
			}
		}
	} else if !os.IsNotExist(statErr) {
		errs = append(errs, fmt.Errorf("lstat feedback dir: %w", statErr))
	}

	if len(errs) > 0 {
		rep.Status = "partial"
		return rep, errors.Join(errs...)
	}
	return rep, nil
}

func isOwnedTopLevelFile(name string) bool {
	switch name {
	case "cursor.json", "cursor.json.tmp", "baseline.json", "baseline.json.tmp":
		return true
	}
	return (strings.HasPrefix(name, ".cursor-") && strings.HasSuffix(name, ".tmp")) ||
		(strings.HasPrefix(name, ".baseline-") && strings.HasSuffix(name, ".tmp"))
}

func truncateSummary(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	return s[:maxChars] + "..."
}
