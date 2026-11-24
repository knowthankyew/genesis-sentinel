package pipeline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"sort"
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
	"github.com/knowthankyew/genesis-sentinel/internal/surprisal"
	"github.com/knowthankyew/genesis-sentinel/internal/template"
)

const (
	// defaultMaxPendingRuleBuckets bounds exact per-(window, service, level) rule accumulators between flushes.
	defaultMaxPendingRuleBuckets = 4096
)

// Stats exposes live Sentinel Tier 0 + Tier 1 pipeline telemetry over HTTP /stats and CLI output.
type Stats struct {
	LinesRead                  uint64  `json:"lines_read"`
	LinesIgnoredSelf           uint64  `json:"lines_ignored_self"`
	TemplatesEmitted           uint64  `json:"templates_emitted"`
	CollapseRatio              float64 `json:"collapse_ratio"`
	ClustersActive             int     `json:"clusters_active"`
	RuleHitsTotal              uint64  `json:"rule_hits_total"`
	AlertsEmitted              uint64  `json:"alerts_emitted"`
	InjectionSignals           uint64  `json:"injection_signals"`
	RuleBucketsDropped         uint64  `json:"rule_buckets_dropped"`
	OverflowThresholdSkipped   uint64  `json:"overflow_threshold_skipped"`
	SinkErrors                 uint64  `json:"sink_errors"`
	SurprisalMode              string  `json:"surprisal_mode"`
	SurprisalThresholdNats     float64 `json:"surprisal_threshold_nats"`
	SurprisalScored            uint64  `json:"surprisal_scored"`
	SurprisalAnomalies         uint64  `json:"surprisal_anomalies"`
	SurprisalBaselineCases     int     `json:"surprisal_baseline_cases"`
	SurprisalBaselineCap       int     `json:"surprisal_baseline_capacity"`
	SurprisalWarmupComplete    bool    `json:"surprisal_warmup_complete"`
	SurprisalMaxNats           float64 `json:"surprisal_max_nats"`
	SurprisalHTTPChecks        uint64  `json:"surprisal_http_checks"`
	SurprisalHTTPFallbacks     uint64  `json:"surprisal_http_fallbacks"`
	SurprisalHTTPDisagreements uint64  `json:"surprisal_http_disagreements"`
	CorruptedFrames            uint64  `json:"corrupted_frames"`
	RecoveryStalls             uint64  `json:"recovery_stalls"`
	BurnResets                 uint64  `json:"burn_resets"`
	EvictionGaps               uint64  `json:"eviction_gaps"`
	EstimatedLost              uint64  `json:"estimated_lost"`
	SaturatedPages             uint64  `json:"saturated_pages"`
	ActiveSource               string  `json:"active_source"`
	DataDir                    string  `json:"data_dir"`
	GenesisDataDir             string  `json:"genesis_data_dir,omitempty"`
	HeapBytes                  uint64  `json:"heap_bytes"`
	UptimeSeconds              int64   `json:"uptime_seconds"`
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

// ruleBucketKey uses fixed-size SHA-256 hashes of service and level alongside templateID
// so arbitrarily long adversarial service/level strings never retain megabytes in pendingHits
// while distinct services with matching display prefixes are never merged.
type ruleBucketKey struct {
	templateID  string
	serviceHash [sha256.Size]byte
	levelHash   [sha256.Size]byte
}

type ruleAccumulator struct {
	hit             model.RuleHit
	minCount        uint64
	matchCount      uint64
	sanitizedSample string
	maxEntropy      float64
}

type bucketAccumulator struct {
	key                 ruleBucketKey
	displayService      string
	displayLevel        string
	suppressedTemplates []string
	lastSeenUnix        int64
	rules               map[string]*ruleAccumulator
	injSuspected        bool
	injSignals          []string
	injSample           string
	injSignalLookup     map[string]struct{}
}

// Pipeline coordinates Tier 0 ingestion, loop prevention, template collapsing,
// per-event deterministic rule accumulation, Tier 1 Laplace-LK surprisal scoring,
// and Genesis alert emission.
type Pipeline struct {
	cfg          *config.Config
	agg          *template.Aggregator
	ruleEng      *rules.Engine
	surprisalEng *surprisal.Engine
	sink         emit.Sink
	activeSource string
	startTime    time.Time

	// burnMu coordinates Burn() with IngestEvent()/FlushWindow() so no pre-burn
	// alert can be delivered after Burn acknowledges completion.
	// windowMu coordinates p.agg and p.pendingHits at the exact same window boundary
	// so FlushWindow drains templates and corresponding rule hits atomically.
	burnMu                sync.RWMutex
	windowMu              sync.Mutex
	maxPendingRuleBuckets int
	pendingHits           map[ruleBucketKey]*bucketAccumulator
	droppedRuleBuckets    bool

	segReader   *ingest.SegReader
	queryPoller *ingest.QueryPoller

	linesRead                atomic.Uint64
	linesIgnoredSelf         atomic.Uint64
	templatesEmitted         atomic.Uint64
	ruleHitsTotal            atomic.Uint64
	alertsEmitted            atomic.Uint64
	injectionSignals         atomic.Uint64
	ruleBucketsDropped       atomic.Uint64
	overflowThresholdSkipped atomic.Uint64
	sinkErrors               atomic.Uint64
	alertSeq                 atomic.Uint64
}

// New builds a Pipeline wired with Tier 0 template collapsing, deterministic rules,
// and the Tier 1 Laplace-LK log surprisal engine.
func New(cfg *config.Config, ruleEng *rules.Engine, sink emit.Sink, activeSource string) *Pipeline {
	if cfg == nil {
		cfg = config.DefaultConfig()
	}
	if sink == nil {
		sink = emit.NopSink{}
	}

	var httpClient *surprisal.HTTPClient
	if (cfg.SurprisalMode == "http" || cfg.SurprisalMode == "hybrid") && cfg.SurprisalHTTPAddr != "" {
		if c, err := surprisal.NewHTTPClient(cfg.SurprisalHTTPAddr, 2*time.Second, cfg.AllowRemoteEndpoints); err == nil {
			httpClient = c
		}
	}

	surpEng := surprisal.NewEngine(surprisal.Options{
		Mode:               cfg.SurprisalMode,
		ThresholdNats:      cfg.SurprisalThreshold,
		BaselineWindowSize: cfg.BaselineWindowSize,
		HTTPClient:         httpClient,
	})

	return &Pipeline{
		cfg:                   cfg,
		agg:                   template.NewAggregator(template.DefaultMaxClusters),
		ruleEng:               ruleEng,
		surprisalEng:          surpEng,
		sink:                  sink,
		activeSource:          activeSource,
		startTime:             time.Now(),
		maxPendingRuleBuckets: defaultMaxPendingRuleBuckets,
		pendingHits:           make(map[ruleBucketKey]*bucketAccumulator, 64),
	}
}

// SurprisalEngine returns the active Tier 1 Laplace-LK surprisal engine.
func (p *Pipeline) SurprisalEngine() *surprisal.Engine {
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()
	return p.surprisalEng
}

// AttachSurprisalEngine replaces the Tier 1 surprisal engine (useful for custom
// warmup tuning, preloaded baselines, or HTTP parity test doubles).
func (p *Pipeline) AttachSurprisalEngine(eng *surprisal.Engine) {
	if eng == nil {
		return
	}
	p.burnMu.Lock()
	p.surprisalEng = eng
	p.burnMu.Unlock()
}

// SaveBaseline persists the Tier 1 rolling baseline snapshot while holding burnMu.RLock
// so Burn() strictly waits for any in-flight baseline write before removing baseline.json,
// preventing a pre-burn snapshot from reappearing on disk after Burn completes.
func (p *Pipeline) SaveBaseline(path string, force bool) error {
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()
	if p.surprisalEng == nil {
		return nil
	}
	return p.surprisalEng.SaveToFile(path, force)
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

// IngestEvent folds a single incoming LogEvent into Tier 0 while enforcing strict
// loop prevention and evaluating per-event deterministic signatures & suppressions
// before template collapsing. Template insertion and rule-hit recording execute under
// the same windowMu lock so FlushWindow always drains both at one consistent boundary.
func (p *Pipeline) IngestEvent(ev model.LogEvent) {
	if emit.ShouldIgnoreEvent(ev, p.cfg.AlertServiceName) {
		p.linesIgnoredSelf.Add(1)
		return
	}
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()

	ent := template.PeakShannonEntropy(ev.Message)
	evEval := p.ruleEng.MatchEvent(ev, ent, p.cfg.MaxPromptByte)

	p.windowMu.Lock()
	defer p.windowMu.Unlock()

	p.linesRead.Add(1)
	if evEval.Suppressed {
		// Pattern- or service-suppressed events must neither trigger Tier 0/Tier 1 alerts
		// nor enter the Tier 1 rolling baseline.
		return
	}
	tmplID, isOverflow, _ := p.agg.AddWithEntropy(ev, ent)

	if len(evEval.Matches) == 0 && !evEval.InjectionSuspected {
		return
	}

	// Never combine multi-event burst thresholds (MinCount > 1) across unrelated templates
	// that fell into a shared overflow bucket. Single-event signatures (MinCount <= 1) and
	// prompt-injection detections remain eligible on their own merits.
	matches := evEval.Matches
	if isOverflow && len(matches) > 0 {
		filtered := matches[:0]
		for _, m := range matches {
			if m.MinCount > 1 {
				p.overflowThresholdSkipped.Add(1)
				continue
			}
			filtered = append(filtered, m)
		}
		matches = filtered
		if len(matches) == 0 && !evEval.InjectionSuspected {
			return
		}
	}

	key := ruleBucketKey{
		templateID:  tmplID,
		serviceHash: sha256.Sum256([]byte(ev.Service)),
		levelHash:   sha256.Sum256([]byte(ev.Level)),
	}

	bucket, exists := p.pendingHits[key]
	if !exists {
		if len(p.pendingHits) >= p.maxPendingRuleBuckets {
			p.droppedRuleBuckets = true
			p.ruleBucketsDropped.Add(1)
			return
		}
		cleanSvc, _ := security.SanitizeUntrustedLogText(ev.Service, 128)
		cleanLvl, _ := security.SanitizeUntrustedLogText(ev.Level, 64)
		bucket = &bucketAccumulator{
			key:                 key,
			displayService:      cleanSvc,
			displayLevel:        cleanLvl,
			suppressedTemplates: p.ruleEng.SuppressedTemplatesForService(ev.Service),
			rules:               make(map[string]*ruleAccumulator, 4),
		}
		p.pendingHits[key] = bucket
	}

	if evTS := normalizeAlertTimestamp(ev.Timestamp, 0); evTS > bucket.lastSeenUnix {
		bucket.lastSeenUnix = evTS
	}
	if evEval.InjectionSuspected {
		bucket.injSuspected = true
		if bucket.injSample == "" && evEval.InjectionSample != "" {
			bucket.injSample = evEval.InjectionSample
		}
		if bucket.injSignalLookup == nil {
			bucket.injSignalLookup = make(map[string]struct{}, len(evEval.InjectionSignals))
		}
		for _, s := range evEval.InjectionSignals {
			if _, seen := bucket.injSignalLookup[s]; !seen {
				bucket.injSignalLookup[s] = struct{}{}
				bucket.injSignals = append(bucket.injSignals, s)
			}
		}
	}
	for _, m := range matches {
		acc, ok := bucket.rules[m.RuleHit.RuleID]
		if !ok {
			acc = &ruleAccumulator{
				hit:             m.RuleHit,
				minCount:        m.MinCount,
				sanitizedSample: m.SanitizedSample,
				maxEntropy:      m.Entropy,
			}
			bucket.rules[m.RuleHit.RuleID] = acc
		}
		acc.matchCount++
		if m.Entropy > acc.maxEntropy {
			acc.maxEntropy = m.Entropy
			if m.SanitizedSample != "" {
				acc.sanitizedSample = m.SanitizedSample
			}
		}
	}
}

func bucketKeyForWindow(w model.TemplateWindow) (ruleBucketKey, bool) {
	if w.HasIdentityHash {
		return ruleBucketKey{
			templateID:  w.TemplateID,
			serviceHash: w.ServiceHash,
			levelHash:   w.LevelHash,
		}, true
	}
	// Global mixed overflow buckets have no single source service/level identity.
	if w.TemplateID == "overflow:global" {
		return ruleBucketKey{}, false
	}
	return ruleBucketKey{
		templateID:  w.TemplateID,
		serviceHash: sha256.Sum256([]byte(w.Service)),
		levelHash:   sha256.Sum256([]byte(w.Level)),
	}, true
}

// FlushWindow atomically drains collapsed TemplateWindows and exact per-event rule
// accumulators under windowMu, evaluates Tier 1 Laplace-LK surprisal on every
// unsuppressed window, enriches Tier 0 alerts with surprisal context, emits Tier 1
// alerts for unseen statistical anomalies, and returns emitted alerts separately
// from sink failures.
func (p *Pipeline) FlushWindow() ([]emit.Alert, []FailedAlert) {
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()

	p.windowMu.Lock()
	windows := p.agg.Flush()
	drainedHits := p.pendingHits
	p.pendingHits = make(map[ruleBucketKey]*bucketAccumulator, 64)
	droppedRuleBuckets := p.droppedRuleBuckets
	p.droppedRuleBuckets = false
	p.windowMu.Unlock()

	if len(windows) == 0 && len(drainedHits) == 0 {
		return nil, nil
	}
	p.templatesEmitted.Add(uint64(len(windows)))

	// Sort windows deterministically by (TemplateID, Service, Level, identity hashes)
	// so baseline learning and alert order are reproducible even when long service names share prefixes.
	sort.Slice(windows, func(i, j int) bool {
		if windows[i].TemplateID != windows[j].TemplateID {
			return windows[i].TemplateID < windows[j].TemplateID
		}
		if windows[i].Service != windows[j].Service {
			return windows[i].Service < windows[j].Service
		}
		if windows[i].Level != windows[j].Level {
			return windows[i].Level < windows[j].Level
		}
		if c := bytes.Compare(windows[i].ServiceHash[:], windows[j].ServiceHash[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(windows[i].LevelHash[:], windows[j].LevelHash[:]) < 0
	})

	winByID := make(map[string]model.TemplateWindow, len(windows))
	for _, w := range windows {
		winByID[w.TemplateID] = w
	}

	// Track exact Tier 0 signal keys (using full SHA-256 service/level hashes) so distinct
	// long service names (>128 bytes) never share Tier 1 score enrichment or deduplication.
	tier0SignalKeys := make(map[ruleBucketKey]bool, len(drainedHits))
	for k := range drainedHits {
		tier0SignalKeys[k] = true
	}

	// Evaluate Tier 1 Laplace-LK surprisal on every non-suppressed window with a bounded
	// flush-wide HTTP context so an unreachable/slow sidecar can never stall Tier 0 alerts.
	surpEng := p.surprisalEng
	type scoredWindow struct {
		win        model.TemplateWindow
		bucketKey  ruleBucketKey
		hasKey     bool
		score      model.SurprisalScore
		suppressed bool
	}
	scoredWindows := make([]scoredWindow, 0, len(windows))
	scoresByKey := make(map[ruleBucketKey]model.SurprisalScore, len(windows))
	if surpEng != nil {
		evalCtx, cancelEval := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelEval()
		for _, w := range windows {
			bk, hasKey := bucketKeyForWindow(w)
			if p.ruleEng != nil && p.ruleEng.IsWindowSuppressed(w) {
				scoredWindows = append(scoredWindows, scoredWindow{win: w, bucketKey: bk, hasKey: hasKey, suppressed: true})
				continue
			}
			// Never absorb Tier 0 hits, cluster-overflow buckets, or windows from a flush
			// where pendingHits overflowed (which may have dropped a Tier 0 signal) into
			// the rolling benign baseline.
			blockLearn := droppedRuleBuckets || (hasKey && tier0SignalKeys[bk]) || w.Template == "<OVERFLOW>"
			sc := surpEng.Evaluate(evalCtx, w, blockLearn)
			scoredWindows = append(scoredWindows, scoredWindow{win: w, bucketKey: bk, hasKey: hasKey, score: sc})
			if hasKey {
				if prev, exists := scoresByKey[bk]; !exists || sc.TotalNats > prev.TotalNats {
					scoresByKey[bk] = sc
				}
			}
		}
	}

	// Deterministic alert ordering by (templateID, displayService, displayLevel, hashes)
	keys := make([]ruleBucketKey, 0, len(drainedHits))
	for k := range drainedHits {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].templateID != keys[j].templateID {
			return keys[i].templateID < keys[j].templateID
		}
		bi, bj := drainedHits[keys[i]], drainedHits[keys[j]]
		if bi.displayService != bj.displayService {
			return bi.displayService < bj.displayService
		}
		if bi.displayLevel != bj.displayLevel {
			return bi.displayLevel < bj.displayLevel
		}
		if c := bytes.Compare(keys[i].serviceHash[:], keys[j].serviceHash[:]); c != 0 {
			return c < 0
		}
		return bytes.Compare(keys[i].levelHash[:], keys[j].levelHash[:]) < 0
	})

	var (
		emitted        []emit.Alert
		failed         []FailedAlert
		emittedWinKeys = make(map[ruleBucketKey]bool, len(keys))
	)
	nowUnix := time.Now().Unix()

	for _, k := range keys {
		bucket := drainedHits[k]
		w, hasWin := winByID[k.templateID]
		tmplStr := "<OVERFLOW>"
		if hasWin {
			tmplStr = w.Template
		}

		if isTemplateInList(bucket.suppressedTemplates, tmplStr) {
			continue
		}

		// Collect only rules whose exact per-rule matchCount meets MinCount!
		var (
			qualifyingHits []model.RuleHit
			maxMatchCount  uint64
			bestEntropy    float64
			bestSample     string
		)
		ruleKeys := make([]string, 0, len(bucket.rules))
		for rid := range bucket.rules {
			ruleKeys = append(ruleKeys, rid)
		}
		sort.Strings(ruleKeys)

		for _, rid := range ruleKeys {
			acc := bucket.rules[rid]
			if acc.matchCount < acc.minCount {
				continue
			}
			qualifyingHits = append(qualifyingHits, acc.hit)
			if acc.matchCount > maxMatchCount {
				maxMatchCount = acc.matchCount
			}
			if acc.maxEntropy > bestEntropy {
				bestEntropy = acc.maxEntropy
			}
			if bestSample == "" && acc.sanitizedSample != "" {
				bestSample = acc.sanitizedSample
			}
		}

		if bucket.injSuspected {
			p.injectionSignals.Add(1)
			// Preserve prompt-injection evidence when injection fired alongside other rules.
			if bucket.injSample != "" {
				bestSample = bucket.injSample
			}
		}

		if len(qualifyingHits) == 0 {
			continue
		}

		cleanService := bucket.displayService
		cleanLevel := bucket.displayLevel
		cleanTemplate, _ := security.SanitizeUntrustedLogText(tmplStr, p.cfg.MaxPromptByte)

		p.ruleHitsTotal.Add(uint64(len(qualifyingHits)))
		seq := p.alertSeq.Add(1)
		alertID := fmt.Sprintf("sentinel-%d-%d", nowUnix, seq)
		severity := emit.HighestSeverity(qualifyingHits)

		ruleIDs := make([]string, 0, len(qualifyingHits))
		categories := make([]string, 0, len(qualifyingHits))
		for _, h := range qualifyingHits {
			ruleIDs = append(ruleIDs, h.RuleID)
			categories = append(categories, h.Category)
		}

		ts := bucket.lastSeenUnix
		if ts <= 0 && hasWin {
			ts = w.LastSeenUnix
		}
		ts = normalizeAlertTimestamp(ts, nowUnix)

		roundedEntropy := math.Round(bestEntropy*10000) / 10000

		tierLabel := "tier0"
		var (
			surpNats      float64
			surpThreshold float64
			topFeats      map[string]float64
		)
		if sc, ok := scoresByKey[k]; ok && sc.TotalNats > 0 {
			surpNats = sc.TotalNats
			surpThreshold = sc.ThresholdNats
			topFeats = surprisal.TopFeatures(sc.FeatureContribs, 4)
			if sc.Anomalous {
				tierLabel = "tier0+tier1"
				// Preserve the higher severity across both tiers so a LOW Tier 0 rule
				// never downgrades a HIGH Tier 1 anomaly on the same window.
				severity = emit.HigherSeverity(severity, mapSurprisalSeverity(sc.TotalNats, sc.ThresholdNats, cleanLevel))
			}
		}

		msg := fmt.Sprintf("[%s] %s on service=%s count=%d entropy=%.2f sample=%q",
			strings.Join(ruleIDs, ","),
			strings.Join(categories, ","),
			cleanService,
			maxMatchCount,
			roundedEntropy,
			truncateSummary(bestSample, 240),
		)
		if tierLabel == "tier0+tier1" {
			msg = fmt.Sprintf("[%s] %s on service=%s count=%d entropy=%.2f surprisal=%.2fnats sample=%q",
				strings.Join(ruleIDs, ","),
				strings.Join(categories, ","),
				cleanService,
				maxMatchCount,
				roundedEntropy,
				surpNats,
				truncateSummary(bestSample, 240),
			)
		}

		alert := emit.Alert{
			Timestamp:            ts,
			Service:              p.cfg.AlertServiceName,
			Level:                emit.MapSeverityToGenesisLevel(severity),
			TraceID:              alertID,
			Message:              msg,
			AlertID:              alertID,
			Tier:                 tierLabel,
			SourceService:        cleanService,
			SourceLevel:          cleanLevel,
			TemplateID:           k.templateID,
			Template:             cleanTemplate,
			Count:                maxMatchCount,
			SampleEntropy:        roundedEntropy,
			SurprisalNats:        surpNats,
			SurprisalThreshold:   surpThreshold,
			TopSurprisalFeatures: topFeats,
			RuleIDs:              ruleIDs,
			Categories:           categories,
			Severity:             severity,
			InjectionSuspected:   bucket.injSuspected,
			InjectionSignals:     bucket.injSignals,
			SanitizedSample:      bestSample,
		}

		emittedWinKeys[k] = true
		if err := p.sink.Emit(alert); err != nil {
			p.sinkErrors.Add(1)
			failed = append(failed, FailedAlert{Alert: alert, Err: err})
			continue
		}
		p.alertsEmitted.Add(1)
		emitted = append(emitted, alert)
	}

	// Emit Tier 1-only alerts for unseen anomalous windows that did not already emit a Tier 0 alert.
	for _, sw := range scoredWindows {
		if sw.suppressed || !sw.score.Anomalous {
			continue
		}
		if sw.hasKey && emittedWinKeys[sw.bucketKey] {
			continue
		}
		w := sw.win
		cleanService, svcSigs := security.SanitizeUntrustedLogText(w.Service, 128)
		cleanLevel, lvlSigs := security.SanitizeUntrustedLogText(w.Level, 64)
		cleanTemplate, _ := security.SanitizeUntrustedLogText(w.Template, p.cfg.MaxPromptByte)
		cleanSample, msgSigs := security.SanitizeUntrustedLogText(w.SampleLine, p.cfg.MaxPromptByte)

		var injSignals []string
		seenSig := make(map[string]struct{})
		for _, list := range [][]string{msgSigs, svcSigs, lvlSigs} {
			for _, s := range list {
				if _, ok := seenSig[s]; !ok {
					seenSig[s] = struct{}{}
					injSignals = append(injSignals, s)
				}
			}
		}
		injSuspected := len(injSignals) > 0
		if injSuspected {
			p.injectionSignals.Add(1)
		}

		severity := mapSurprisalSeverity(sw.score.TotalNats, sw.score.ThresholdNats, cleanLevel)
		seq := p.alertSeq.Add(1)
		alertID := fmt.Sprintf("sentinel-%d-%d", nowUnix, seq)
		ts := normalizeAlertTimestamp(w.LastSeenUnix, nowUnix)
		roundedEntropy := math.Round(w.SampleEntropy*10000) / 10000
		topFeats := surprisal.TopFeatures(sw.score.FeatureContribs, 4)

		msg := fmt.Sprintf("[SURPRISAL-001] statistical_anomaly on service=%s count=%d surprisal=%.2fnats (threshold=%.2f) entropy=%.2f sample=%q",
			cleanService,
			w.Count,
			sw.score.TotalNats,
			sw.score.ThresholdNats,
			roundedEntropy,
			truncateSummary(cleanSample, 220),
		)

		alert := emit.Alert{
			Timestamp:            ts,
			Service:              p.cfg.AlertServiceName,
			Level:                emit.MapSeverityToGenesisLevel(severity),
			TraceID:              alertID,
			Message:              msg,
			AlertID:              alertID,
			Tier:                 "tier1",
			SourceService:        cleanService,
			SourceLevel:          cleanLevel,
			TemplateID:           w.TemplateID,
			Template:             cleanTemplate,
			Count:                w.Count,
			SampleEntropy:        roundedEntropy,
			SurprisalNats:        sw.score.TotalNats,
			SurprisalThreshold:   sw.score.ThresholdNats,
			TopSurprisalFeatures: topFeats,
			RuleIDs:              []string{"SURPRISAL-001"},
			Categories:           []string{"statistical_anomaly"},
			Severity:             severity,
			InjectionSuspected:   injSuspected,
			InjectionSignals:     injSignals,
			SanitizedSample:      cleanSample,
		}

		if sw.hasKey {
			emittedWinKeys[sw.bucketKey] = true
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

func mapSurprisalSeverity(totalNats, thresholdNats float64, level string) string {
	upperLvl := strings.ToUpper(strings.TrimSpace(level))
	if upperLvl == "FATAL" || upperLvl == "CRITICAL" || (thresholdNats > 0 && totalNats >= thresholdNats*2.5) {
		return "HIGH"
	}
	if upperLvl == "ERROR" || (thresholdNats > 0 && totalNats >= thresholdNats*1.8) {
		return "HIGH"
	}
	return "MEDIUM"
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
	surpEng := p.surprisalEng
	p.burnMu.RUnlock()

	st := Stats{
		LinesRead:                lines,
		LinesIgnoredSelf:         p.linesIgnoredSelf.Load(),
		TemplatesEmitted:         tmpls,
		CollapseRatio:            ratio,
		ClustersActive:           p.agg.ClusterCount(),
		RuleHitsTotal:            p.ruleHitsTotal.Load(),
		AlertsEmitted:            p.alertsEmitted.Load(),
		InjectionSignals:         p.injectionSignals.Load(),
		RuleBucketsDropped:       p.ruleBucketsDropped.Load(),
		OverflowThresholdSkipped: p.overflowThresholdSkipped.Load(),
		SinkErrors:               p.sinkErrors.Load(),
		ActiveSource:             p.activeSource,
		DataDir:                  p.cfg.DataDir,
		GenesisDataDir:           p.cfg.GenesisDataDir,
		HeapBytes:                m.HeapAlloc,
		UptimeSeconds:            int64(time.Since(p.startTime).Seconds()),
	}

	if surpEng != nil {
		ss := surpEng.Stats()
		st.SurprisalMode = ss.Mode
		st.SurprisalThresholdNats = ss.ThresholdNats
		st.SurprisalScored = ss.ScoredTotal
		st.SurprisalAnomalies = ss.AnomaliesTotal
		st.SurprisalBaselineCases = ss.BaselineCases
		st.SurprisalBaselineCap = ss.BaselineCapacity
		st.SurprisalWarmupComplete = ss.WarmupComplete
		st.SurprisalMaxNats = ss.MaxNatsObserved
		st.SurprisalHTTPChecks = ss.HTTPChecks
		st.SurprisalHTTPFallbacks = ss.HTTPFallbacks
		st.SurprisalHTTPDisagreements = ss.HTTPDisagreements
	}
	if segReader != nil {
		rs := segReader.Stats()
		st.CorruptedFrames = rs.CorruptedFrames
		st.RecoveryStalls = rs.RecoveryStalls
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

// Burn waits for any in-flight FlushWindow to finish, resets in-memory templates,
// pending hits, Tier 1 rolling surprisal baselines, and active ingest cursors
// (.seg and /query), and deletes Sentinel-owned disk state.
func (p *Pipeline) Burn() (BurnReport, error) {
	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	p.windowMu.Lock()
	p.agg.Reset()
	p.pendingHits = make(map[ruleBucketKey]*bucketAccumulator, 64)
	p.droppedRuleBuckets = false
	p.windowMu.Unlock()

	if p.surprisalEng != nil {
		p.surprisalEng.Reset()
	}
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
// On partial failure, returns HTTP 500 with both the error diagnostic and the partial BurnReport.
func (p *Pipeline) HandleBurn(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, `{"error":"method not allowed; use DELETE"}`, http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	rep, err := p.Burn()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":  err.Error(),
			"report": rep,
		})
		return
	}
	_ = json.NewEncoder(w).Encode(rep)
}

// BurnLocalState deletes ONLY known Sentinel-owned regular files inside dataDir
// (cursor files, baseline snapshots, and Sentinel-named feedback/*.jsonl files),
// strictly confined via Go 1.24's os.Root (and nested root.OpenRoot("feedback")
// so enumeration and deletion stay bound to the validated directory handle).
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
	removeOwnedInRoot := func(r *os.Root, rel string) {
		fi, statErr := r.Lstat(rel)
		if statErr != nil {
			if !os.IsNotExist(statErr) {
				errs = append(errs, fmt.Errorf("lstat %q: %w", rel, statErr))
			}
			return
		}
		if !fi.Mode().IsRegular() {
			if fi.Mode()&os.ModeSymlink != 0 {
				errs = append(errs, fmt.Errorf("refusing to remove symlink at Sentinel state path %q", rel))
			}
			return
		}
		sz := fi.Size()
		if remErr := unlinkFileInRoot(r, rel); remErr != nil {
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
		if isOwnedTopLevelFile(entry.Name()) {
			removeOwnedInRoot(root, entry.Name())
		}
	}

	// 2. Known Sentinel-named feedback files inside a nested os.Root handle bound to "feedback".
	fbInfo, statErr := root.Lstat("feedback")
	if statErr == nil {
		if fbInfo.Mode()&os.ModeSymlink != 0 {
			errs = append(errs, fmt.Errorf("refusing to follow symlink at feedback directory"))
		} else if fbInfo.IsDir() {
			fbRoot, openRootErr := root.OpenRoot("feedback")
			if openRootErr != nil {
				errs = append(errs, fmt.Errorf("open feedback root: %w", openRootErr))
			} else {
				fbStat, fbStatErr := fbRoot.Stat(".")
				if fbStatErr != nil {
					errs = append(errs, fmt.Errorf("stat opened feedback dir: %w", fbStatErr))
					_ = fbRoot.Close()
				} else if !fbStat.IsDir() || !os.SameFile(fbInfo, fbStat) {
					errs = append(errs, fmt.Errorf("refusing feedback cleanup: feedback directory identity changed between Lstat and OpenRoot"))
					_ = fbRoot.Close()
				} else {
					fbDir, openErr := fbRoot.Open(".")
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
								if isOwnedFeedbackFile(e.Name()) {
									removeOwnedInRoot(fbRoot, e.Name())
								}
							}
						}
					}
					_ = fbRoot.Close()
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

// isOwnedFeedbackFile enforces an explicit Sentinel filename contract inside dataDir/feedback/
// so unrelated user files (e.g. feedback/import.jsonl) are never deleted by `sentinel burn`.
func isOwnedFeedbackFile(name string) bool {
	if name == "sentinel-feedback.jsonl" || name == "sentinel-feedback.jsonl.tmp" {
		return true
	}
	if strings.HasPrefix(name, "sentinel-feedback-") &&
		(strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".jsonl.tmp")) {
		return true
	}
	return strings.HasPrefix(name, ".sentinel-feedback-") && strings.HasSuffix(name, ".tmp")
}

// normalizeAlertTimestamp enforces the Unix-seconds alert timestamp contract expected by
// Genesis (`parser.LogEntry.Timestamp`). Supported input ranges without explicit unit metadata:
//   - Unix seconds:       1 .. 99_999_999_999 (through year 5138; <= 11 digits)
//   - Contemporary ms:    1_000_000_000_000 .. 999_999_999_999_999 (2001-09-09+) -> / 1e3
//   - Contemporary us:    1_000_000_000_000_000 .. 999_999_999_999_999_999 (16-18 digits) -> / 1e6
//   - Contemporary ns:    >= 1_000_000_000_000_000_000 -> / 1e9
//
// Values outside the supported Unix-second range after normalization (e.g. ambiguous 12-digit
// pre-2001 milliseconds such as 999_999_999_999) fall back to fallbackUnix so Sentinel never
// emits a mis-scaled year or a bare 16-digit integer that breaks Genesis --redact JSON parsing.
func normalizeAlertTimestamp(ts, fallbackUnix int64) int64 {
	const maxSupportedUnixSec = 99_999_999_999 // 11 digits (year 5138)
	if ts <= 0 {
		return fallbackUnix
	}
	if ts >= 1_000_000_000_000_000_000 { // contemporary nanoseconds (>= 1e18)
		ts /= 1_000_000_000
	} else if ts >= 1_000_000_000_000_000 { // contemporary microseconds (>= 1e15)
		ts /= 1_000_000
	} else if ts >= 1_000_000_000_000 { // contemporary milliseconds (>= 1e12)
		ts /= 1_000
	}
	if ts <= 0 || ts > maxSupportedUnixSec {
		return fallbackUnix
	}
	return ts
}

func isTemplateInList(list []string, tmpl string) bool {
	for _, t := range list {
		if t == tmpl {
			return true
		}
	}
	return false
}

func truncateSummary(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	return s[:maxChars] + "..."
}
