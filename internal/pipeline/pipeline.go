package pipeline

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/config"
	"github.com/knowthankyew/genesis-sentinel/internal/emit"
	"github.com/knowthankyew/genesis-sentinel/internal/feedback"
	"github.com/knowthankyew/genesis-sentinel/internal/ingest"
	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/rules"
	"github.com/knowthankyew/genesis-sentinel/internal/security"
	"github.com/knowthankyew/genesis-sentinel/internal/surprisal"
	"github.com/knowthankyew/genesis-sentinel/internal/template"
	"github.com/knowthankyew/genesis-sentinel/internal/train"
	"github.com/knowthankyew/genesis-sentinel/internal/triage"
)

const (
	// defaultMaxPendingRuleBuckets bounds exact per-(window, service, level) rule accumulators between flushes.
	defaultMaxPendingRuleBuckets = 4096
	// defaultAsyncTriageQueueSize bounds pending Tier 2 enrichment jobs in live watch mode
	// so slow or hung inference never stalls deterministic Tier 0/1 alert emission or grows memory unboundedly.
	defaultAsyncTriageQueueSize = 64
)

type asyncTriageTask struct {
	alert     emit.Alert
	burnEpoch uint64
}

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
	JournalErrors              uint64  `json:"journal_errors"`
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
	TriageMode                 string  `json:"triage_mode"`
	TriageAsync                bool    `json:"triage_async,omitempty"`
	TriageModel                string  `json:"triage_model,omitempty"`
	TriageAdapter              string  `json:"triage_adapter,omitempty"`
	TriageEvaluated            uint64  `json:"triage_evaluated"`
	TriageFallbacks            uint64  `json:"triage_fallbacks"`
	TriageInjectionOverrides   uint64  `json:"triage_injection_overrides"`
	TriageUpdatesEmitted       uint64  `json:"triage_updates_emitted,omitempty"`
	TriageQueueDropped         uint64  `json:"triage_queue_dropped,omitempty"`
	EscalationMode             string  `json:"escalation_mode"`
	EscalationPolicy           string  `json:"escalation_policy,omitempty"`
	EscalationModel            string  `json:"escalation_model,omitempty"`
	EscalationAdapter          string  `json:"escalation_adapter,omitempty"`
	EscalationEvaluated        uint64  `json:"escalation_evaluated"`
	EscalationFallbacks        uint64  `json:"escalation_fallbacks"`
	EscalationsTriggered       uint64  `json:"escalations_triggered"`
	AdapterSwapsTotal          uint64  `json:"adapter_swaps_total"`
	LastAdapterSwapUnix        int64   `json:"last_adapter_swap_unix,omitempty"`
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
	cfg                *config.Config
	agg                *template.Aggregator
	ruleEng            *rules.Engine
	surprisalEng       *surprisal.Engine
	triageClient       *triage.Client
	escalationClient   *triage.Client
	alertJournal       *feedback.AlertJournal
	sink               emit.Sink
	activeSource       string
	instanceID         string
	startTime          time.Time
	nowUnixFn          func() int64
	triageReqTimeout   time.Duration
	escalationTimeout  time.Duration
	triageCancelMu     sync.Mutex
	burnPending        int
	nextFlushCancelID  uint64
	activeTriageCancel map[uint64]context.CancelFunc

	// Async Tier 2 enrichment state (enabled by sentinel watch; disabled by default so
	// offline sentinel scan returns enriched alerts synchronously in one pass).
	// Lock hierarchy: burnMu -> asyncMu / adapterMu / corrMu / windowMu (never reverse).
	burnEpoch            atomic.Uint64
	adapterEpoch         atomic.Uint64
	escalationEpoch      atomic.Uint64
	escalationsTriggered atomic.Uint64
	adapterSwapsTotal    atomic.Uint64
	lastAdapterSwapUnix  atomic.Int64
	triageUpdatesEmitted atomic.Uint64
	triageQueueDropped   atomic.Uint64
	asyncMu              sync.Mutex
	asyncEnabled         bool
	asyncClosed          bool
	asyncQueueCap        int
	asyncQueue           []asyncTriageTask
	asyncNotifyCh        chan struct{}
	asyncDoneCh          chan struct{}
	activeAsyncCancel    context.CancelFunc
	beforeAsyncPublishFn func() // optional test hook invoked right before publish check
	afterAsyncTaskFn     func() // optional test hook invoked right after task completes

	adapterMu          sync.Mutex
	adapterHistory     []train.AdapterSwapRecord
	primaryMeta        slotRuntimeMeta
	escalationMeta     slotRuntimeMeta
	lastSyncedManifest [sha256.Size]byte
	hasSyncedManifest  bool

	corrMu            sync.Mutex
	serviceCorrelator map[string][]correlationEntry

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
	journalErrors            atomic.Uint64
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

	var (
		triageClient      *triage.Client
		reqTimeout        time.Duration
		escalationClient  *triage.Client
		escalationTimeout time.Duration
	)
	if strings.EqualFold(cfg.TriageMode, "http") && cfg.InferenceAddr != "" {
		if tc, rt, err := buildSlotClient(
			cfg.InferenceAddr, cfg.BaseModel, cfg.AdapterPath, cfg.FTaaSAPIKey,
			cfg.TriageTimeoutSec, cfg.TriageMaxTokens, cfg.TriageTemperature,
			cfg.MaxPromptByte, cfg.AllowRemoteEndpoints,
		); err == nil {
			triageClient = tc
			reqTimeout = rt
		}
	}
	if strings.EqualFold(cfg.EscalationMode, "http") && cfg.EscalationInferenceAddr != "" {
		if ec, et, err := buildSlotClient(
			cfg.EscalationInferenceAddr, cfg.EscalationBaseModel, cfg.EscalationAdapterPath, cfg.FTaaSAPIKey,
			cfg.EscalationTimeoutSec, cfg.EscalationMaxTokens, cfg.TriageTemperature,
			cfg.MaxPromptByte, cfg.AllowRemoteEndpoints,
		); err == nil {
			escalationClient = ec
			escalationTimeout = et
		}
	}

	var idBytes [4]byte
	_, _ = rand.Read(idBytes[:])
	instanceID := hex.EncodeToString(idBytes[:])

	p := &Pipeline{
		cfg:                   cfg,
		agg:                   template.NewAggregator(template.DefaultMaxClusters),
		ruleEng:               ruleEng,
		surprisalEng:          surpEng,
		triageClient:          triageClient,
		escalationClient:      escalationClient,
		sink:                  sink,
		activeSource:          activeSource,
		instanceID:            instanceID,
		startTime:             time.Now(),
		triageReqTimeout:      reqTimeout,
		escalationTimeout:     escalationTimeout,
		activeTriageCancel:    make(map[uint64]context.CancelFunc),
		maxPendingRuleBuckets: defaultMaxPendingRuleBuckets,
		pendingHits:           make(map[ruleBucketKey]*bucketAccumulator, 64),
	}
	p.initAdapterTracking()
	return p
}

// TriageClient returns the active Tier 2 local inference client (nil when triage_mode=off).
func (p *Pipeline) TriageClient() *triage.Client {
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()
	return p.triageClient
}

// EscalationClient returns the active Phase 5 escalation inference client (nil when escalation_mode=off).
func (p *Pipeline) EscalationClient() *triage.Client {
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()
	return p.escalationClient
}

// AttachTriageClient sets or replaces the Tier 2 local inference client cleanly.
func (p *Pipeline) AttachTriageClient(c *triage.Client) {
	p.burnMu.Lock()
	p.triageClient = c
	p.adapterEpoch.Add(1)
	p.asyncMu.Lock()
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()
	p.burnMu.Unlock()
}

// AttachEscalationClient sets or replaces the Phase 5 escalation inference client cleanly.
func (p *Pipeline) AttachEscalationClient(c *triage.Client) {
	p.burnMu.Lock()
	p.escalationClient = c
	p.escalationEpoch.Add(1)
	p.asyncMu.Lock()
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()
	p.burnMu.Unlock()
}

// EnableAsyncTriage switches Tier 2 inference to non-blocking background enrichment so
// deterministic Tier 0/1 alerts emit and journal immediately in live watch mode even if
// the local inference service is slow or unreachable. Follow-up Tier 2 enrichment updates
// are emitted with the same AlertID/TraceID and upserted in alerts.jsonl. Call Close()
// during shutdown before closing the underlying alert sink.
func (p *Pipeline) EnableAsyncTriage(queueSize int) {
	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	p.asyncMu.Lock()
	defer p.asyncMu.Unlock()
	if p.asyncEnabled || p.asyncClosed {
		return
	}
	if queueSize <= 0 {
		queueSize = defaultAsyncTriageQueueSize
	}
	p.asyncEnabled = true
	p.asyncQueueCap = queueSize
	p.asyncNotifyCh = make(chan struct{}, 1)
	p.asyncDoneCh = make(chan struct{})
	go p.runAsyncTriageWorker()
}

// Close stops the background async Tier 2 enrichment worker (if enabled), cancels any
// in-flight async inference request, and waits for the worker goroutine to exit cleanly.
// Safe to call multiple times or when async triage was never enabled.
func (p *Pipeline) Close() {
	p.asyncMu.Lock()
	doneCh := p.asyncDoneCh
	p.asyncClosed = true
	p.asyncQueue = nil
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	if p.asyncNotifyCh != nil {
		select {
		case p.asyncNotifyCh <- struct{}{}:
		default:
		}
	}
	p.asyncMu.Unlock()

	if doneCh != nil {
		<-doneCh
	}
}

func (p *Pipeline) isAsyncTriageEnabled() bool {
	p.asyncMu.Lock()
	defer p.asyncMu.Unlock()
	return p.asyncEnabled && !p.asyncClosed
}

func (p *Pipeline) enqueueAsyncTriage(alert emit.Alert, burnEpoch uint64) {
	p.asyncMu.Lock()
	defer p.asyncMu.Unlock()
	if !p.asyncEnabled || p.asyncClosed {
		return
	}
	if len(p.asyncQueue) >= p.asyncQueueCap {
		p.triageQueueDropped.Add(1)
		return
	}
	p.asyncQueue = append(p.asyncQueue, asyncTriageTask{
		alert:     cloneAlertForAsync(alert),
		burnEpoch: burnEpoch,
	})
	select {
	case p.asyncNotifyCh <- struct{}{}:
	default:
	}
}

func cloneAlertForAsync(a emit.Alert) emit.Alert {
	if len(a.RuleIDs) > 0 {
		cp := make([]string, len(a.RuleIDs))
		copy(cp, a.RuleIDs)
		a.RuleIDs = cp
	}
	if len(a.Categories) > 0 {
		cp := make([]string, len(a.Categories))
		copy(cp, a.Categories)
		a.Categories = cp
	}
	if len(a.InjectionSignals) > 0 {
		cp := make([]string, len(a.InjectionSignals))
		copy(cp, a.InjectionSignals)
		a.InjectionSignals = cp
	}
	if len(a.CorrelatedWindows) > 0 {
		cp := make([]string, len(a.CorrelatedWindows))
		copy(cp, a.CorrelatedWindows)
		a.CorrelatedWindows = cp
	}
	if len(a.TopSurprisalFeatures) > 0 {
		cp := make(map[string]float64, len(a.TopSurprisalFeatures))
		for k, v := range a.TopSurprisalFeatures {
			cp[k] = v
		}
		a.TopSurprisalFeatures = cp
	}
	return a
}

func (p *Pipeline) runAsyncTriageWorker() {
	defer close(p.asyncDoneCh)
	for {
		p.asyncMu.Lock()
		for len(p.asyncQueue) == 0 && !p.asyncClosed {
			ch := p.asyncNotifyCh
			p.asyncMu.Unlock()
			<-ch
			p.asyncMu.Lock()
		}
		if p.asyncClosed {
			p.asyncQueue = nil
			p.asyncMu.Unlock()
			return
		}
		task := p.asyncQueue[0]
		p.asyncQueue[0] = asyncTriageTask{}
		p.asyncQueue = p.asyncQueue[1:]
		if len(p.asyncQueue) == 0 {
			p.asyncQueue = nil
		}
		p.asyncMu.Unlock()

		p.processAsyncTriageTask(task)
	}
}

func (p *Pipeline) processAsyncTriageTask(task asyncTriageTask) {
	// Select clients/epochs AND register activeAsyncCancel atomically under the standard
	// burnMu.RLock -> asyncMu.Lock order so an adapter hot-swap occurring before this point
	// never cancels a freshly dequeued task that is about to use the new adapter.
	p.burnMu.RLock()
	client := p.triageClient
	escClient := p.escalationClient
	curBurnEpoch := p.burnEpoch.Load()
	startAdapterEpoch := p.adapterEpoch.Load()
	startEscEpoch := p.escalationEpoch.Load()
	if (client == nil && escClient == nil) || curBurnEpoch != task.burnEpoch {
		p.burnMu.RUnlock()
		return
	}
	p.asyncMu.Lock()
	if p.asyncClosed {
		p.asyncMu.Unlock()
		p.burnMu.RUnlock()
		return
	}
	reqCtx, cancelReq := context.WithCancel(context.Background())
	p.activeAsyncCancel = cancelReq
	p.asyncMu.Unlock()
	p.burnMu.RUnlock()

	defer func() {
		p.asyncMu.Lock()
		p.activeAsyncCancel = nil
		p.asyncMu.Unlock()
		cancelReq()
		if p.afterAsyncTaskFn != nil {
			p.afterAsyncTaskFn()
		}
	}()

	enriched := task.alert
	if !p.enrichWithTier2Dual(reqCtx, client, escClient, &enriched) {
		return
	}
	if p.beforeAsyncPublishFn != nil {
		p.beforeAsyncPublishFn()
	}

	// Re-verify under burnMu.RLock that neither Burn(), Close(), nor a primary/escalation
	// adapter hot-swap retired this task while Tier 2 inference was in flight.
	p.burnMu.RLock()
	defer p.burnMu.RUnlock()

	if p.burnEpoch.Load() != task.burnEpoch ||
		p.adapterEpoch.Load() != startAdapterEpoch ||
		p.escalationEpoch.Load() != startEscEpoch ||
		p.triageClient != client ||
		p.escalationClient != escClient {
		return
	}
	p.asyncMu.Lock()
	closed := p.asyncClosed
	p.asyncMu.Unlock()
	if closed {
		return
	}

	if err := p.sink.Emit(enriched); err != nil {
		p.sinkErrors.Add(1)
		return
	}
	p.triageUpdatesEmitted.Add(1)
	p.recordCorrelationWindow(enriched)
	if p.alertJournal != nil {
		// Use UpdateIfPresent so a delayed async Tier 2 result updates its existing alert
		// in-place and never evicts newer alerts if the original record aged out or was burned.
		if err := p.alertJournal.UpdateIfPresent(enriched); err != nil {
			p.journalErrors.Add(1)
		}
	}
}

// AttachAlertJournal attaches a bounded local alerts.jsonl journal so operators can
// curate feedback by alert ID (`sentinel feedback --alert-id <ID>`).
func (p *Pipeline) AttachAlertJournal(j *feedback.AlertJournal) {
	p.burnMu.Lock()
	p.alertJournal = j
	p.burnMu.Unlock()
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
	// When redaction is enabled, compute a pre-truncation redacted sample once per matching
	// event so a credential spanning MaxPromptByte (e.g. long URL userinfo) cannot leak a prefix.
	var redactedEventSample string
	redactedSampleReady := false
	getSafeSample := func(fallback string) string {
		if !p.cfg.RequireRedaction {
			return fallback
		}
		if !redactedSampleReady {
			redactedEventSample = sanitizeAndRedactField(ev.Message, p.cfg.MaxPromptByte, true)
			redactedSampleReady = true
		}
		return redactedEventSample
	}
	if evEval.InjectionSuspected {
		bucket.injSuspected = true
		if bucket.injSample == "" && evEval.InjectionSample != "" {
			bucket.injSample = getSafeSample(evEval.InjectionSample)
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
				sanitizedSample: getSafeSample(m.SanitizedSample),
				maxEntropy:      m.Entropy,
			}
			bucket.rules[m.RuleHit.RuleID] = acc
		}
		acc.matchCount++
		if m.Entropy > acc.maxEntropy {
			acc.maxEntropy = m.Entropy
			if m.SanitizedSample != "" {
				acc.sanitizedSample = getSafeSample(m.SanitizedSample)
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
	if p.nowUnixFn != nil {
		nowUnix = p.nowUnixFn()
	}

	triageClient := p.triageClient
	escClient := p.escalationClient
	hasTier2 := triageClient != nil || escClient != nil
	asyncTriage := p.isAsyncTriageEnabled()
	curBurnEpoch := p.burnEpoch.Load()
	var (
		triageCtx    context.Context
		cancelTriage context.CancelFunc
	)
	if hasTier2 && !asyncTriage {
		flushBudget := 0 * time.Second
		if triageClient != nil {
			t := time.Duration(p.cfg.TriageTimeoutSec) * time.Second
			if t <= 0 {
				t = config.DefaultTriageTimeoutSec * time.Second
			}
			flushBudget += t
		}
		if escClient != nil {
			et := time.Duration(p.cfg.EscalationTimeoutSec) * time.Second
			if et <= 0 {
				et = config.DefaultEscalationTimeoutSec * time.Second
			}
			flushBudget += et
		}
		if flushBudget <= 0 {
			flushBudget = config.DefaultTriageTimeoutSec * time.Second
		}
		triageCtx, cancelTriage = context.WithTimeout(context.Background(), flushBudget)
		p.triageCancelMu.Lock()
		var flushCancelID uint64
		if p.burnPending > 0 {
			// A Burn() is already pending: cancel immediately so no new inference starts behind Burn.
			cancelTriage()
		} else {
			p.nextFlushCancelID++
			flushCancelID = p.nextFlushCancelID
			if p.activeTriageCancel == nil {
				p.activeTriageCancel = make(map[uint64]context.CancelFunc)
			}
			p.activeTriageCancel[flushCancelID] = cancelTriage
		}
		p.triageCancelMu.Unlock()
		defer func() {
			if flushCancelID != 0 {
				p.triageCancelMu.Lock()
				delete(p.activeTriageCancel, flushCancelID)
				p.triageCancelMu.Unlock()
			}
			cancelTriage()
		}()
	}

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
		cleanTemplate, tmplSigs := sanitizeAndRedactWithSignals(tmplStr, p.cfg.MaxPromptByte, p.cfg.RequireRedaction)
		if p.cfg.RequireRedaction {
			cleanService, _ = feedback.RedactText(cleanService)
			cleanLevel, _ = feedback.RedactText(cleanLevel)
			bestSample, _ = feedback.RedactText(bestSample)
		}
		alertInjSuspected := bucket.injSuspected
		alertInjSignals := append([]string(nil), bucket.injSignals...)
		if len(tmplSigs) > 0 {
			seenSig := make(map[string]struct{}, len(alertInjSignals)+len(tmplSigs))
			for _, s := range alertInjSignals {
				seenSig[s] = struct{}{}
			}
			for _, s := range tmplSigs {
				if _, ok := seenSig[s]; !ok {
					seenSig[s] = struct{}{}
					alertInjSignals = append(alertInjSignals, s)
				}
			}
			if !alertInjSuspected {
				alertInjSuspected = true
				p.injectionSignals.Add(1)
			}
		}

		p.ruleHitsTotal.Add(uint64(len(qualifyingHits)))
		seq := p.alertSeq.Add(1)
		alertID := fmt.Sprintf("sentinel-%d-%s-%d", nowUnix, p.instanceID, seq)
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
			surpNats = round4(sc.TotalNats)
			surpThreshold = round4(sc.ThresholdNats)
			topFeats = roundFeatureMap4(surprisal.TopFeatures(sc.FeatureContribs, 4))
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
			InjectionSuspected:   alertInjSuspected,
			InjectionSignals:     alertInjSignals,
			SanitizedSample:      bestSample,
		}

		alert.CorrelatedWindows = p.collectCorrelatedContext(alert.SourceService, alert.TemplateID, alert.Timestamp)
		if hasTier2 && !asyncTriage {
			p.enrichWithTier2Dual(triageCtx, triageClient, escClient, &alert)
		}

		emittedWinKeys[k] = true
		if err := p.sink.Emit(alert); err != nil {
			p.sinkErrors.Add(1)
			failed = append(failed, FailedAlert{Alert: alert, Err: err})
			continue
		}
		p.alertsEmitted.Add(1)
		p.recordCorrelationWindow(alert)
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
		cleanService, svcSigs := sanitizeAndRedactWithSignals(w.Service, 128, p.cfg.RequireRedaction)
		cleanLevel, lvlSigs := sanitizeAndRedactWithSignals(w.Level, 64, p.cfg.RequireRedaction)
		cleanTemplate, tmplSigs := sanitizeAndRedactWithSignals(w.Template, p.cfg.MaxPromptByte, p.cfg.RequireRedaction)
		cleanSample, msgSigs := sanitizeAndRedactWithSignals(w.SampleLine, p.cfg.MaxPromptByte, p.cfg.RequireRedaction)

		var injSignals []string
		seenSig := make(map[string]struct{})
		for _, list := range [][]string{msgSigs, tmplSigs, svcSigs, lvlSigs} {
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
		alertID := fmt.Sprintf("sentinel-%d-%s-%d", nowUnix, p.instanceID, seq)
		ts := normalizeAlertTimestamp(w.LastSeenUnix, nowUnix)
		roundedEntropy := round4(w.SampleEntropy)
		roundedSurp := round4(sw.score.TotalNats)
		roundedThresh := round4(sw.score.ThresholdNats)
		topFeats := roundFeatureMap4(surprisal.TopFeatures(sw.score.FeatureContribs, 4))

		msg := fmt.Sprintf("[SURPRISAL-001] statistical_anomaly on service=%s count=%d surprisal=%.2fnats (threshold=%.2f) entropy=%.2f sample=%q",
			cleanService,
			w.Count,
			roundedSurp,
			roundedThresh,
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
			SurprisalNats:        roundedSurp,
			SurprisalThreshold:   roundedThresh,
			TopSurprisalFeatures: topFeats,
			RuleIDs:              []string{"SURPRISAL-001"},
			Categories:           []string{"statistical_anomaly"},
			Severity:             severity,
			InjectionSuspected:   injSuspected,
			InjectionSignals:     injSignals,
			SanitizedSample:      cleanSample,
		}

		alert.CorrelatedWindows = p.collectCorrelatedContext(alert.SourceService, alert.TemplateID, alert.Timestamp)
		if hasTier2 && !asyncTriage {
			p.enrichWithTier2Dual(triageCtx, triageClient, escClient, &alert)
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
		p.recordCorrelationWindow(alert)
		emitted = append(emitted, alert)
	}

	if p.alertJournal != nil && len(emitted) > 0 {
		if err := p.alertJournal.Record(emitted...); err != nil {
			p.journalErrors.Add(1)
		}
	}

	// Enqueue async Tier 2 enrichment AFTER emitting and journaling the deterministic alerts
	// so every async update strictly follows and upserts on top of its deterministic base alert.
	if hasTier2 && asyncTriage && len(emitted) > 0 {
		for _, a := range emitted {
			p.enqueueAsyncTriage(a, curBurnEpoch)
		}
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
	triageClient := p.triageClient
	escClient := p.escalationClient
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
		JournalErrors:            p.journalErrors.Load(),
		TriageMode:               "off",
		EscalationMode:           "off",
		EscalationPolicy:         p.cfg.EscalationPolicy,
		EscalationsTriggered:     p.escalationsTriggered.Load(),
		AdapterSwapsTotal:        p.adapterSwapsTotal.Load(),
		LastAdapterSwapUnix:      p.lastAdapterSwapUnix.Load(),
		ActiveSource:             p.activeSource,
		DataDir:                  p.cfg.DataDir,
		GenesisDataDir:           p.cfg.GenesisDataDir,
		HeapBytes:                m.HeapAlloc,
		UptimeSeconds:            int64(time.Since(p.startTime).Seconds()),
	}

	if triageClient != nil {
		ts := triageClient.Stats()
		st.TriageMode = "http"
		st.TriageAsync = p.isAsyncTriageEnabled()
		st.TriageModel = ts.BaseModel
		st.TriageAdapter = ts.AdapterPath
		st.TriageEvaluated = ts.EvaluatedTotal
		st.TriageFallbacks = ts.FallbacksTotal
		st.TriageInjectionOverrides = ts.InjectionOverrides
		st.TriageUpdatesEmitted = p.triageUpdatesEmitted.Load()
		st.TriageQueueDropped = p.triageQueueDropped.Load()
	}
	if escClient != nil {
		es := escClient.Stats()
		st.EscalationMode = "http"
		st.EscalationModel = es.BaseModel
		st.EscalationAdapter = es.AdapterPath
		st.EscalationEvaluated = es.EvaluatedTotal
		st.EscalationFallbacks = es.FallbacksTotal
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
	// Mark Burn as pending and cancel ALL active in-flight Tier 2 HTTP calls immediately
	// (both sync flush contexts and async background worker requests) so Burn never stalls.
	p.triageCancelMu.Lock()
	p.burnPending++
	for _, cancelFn := range p.activeTriageCancel {
		cancelFn()
	}
	p.triageCancelMu.Unlock()
	defer func() {
		p.triageCancelMu.Lock()
		p.burnPending--
		p.triageCancelMu.Unlock()
	}()

	p.asyncMu.Lock()
	p.asyncQueue = nil
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()

	p.burnMu.Lock()
	defer p.burnMu.Unlock()

	// Bump burnEpoch and clear/cancel async triage again under burnMu.Lock so any task
	// queued by a FlushWindow that exited just before Burn acquired burnMu.Lock is purged
	// and any racing in-flight worker sees the updated burnEpoch and drops its pre-burn verdict.
	p.burnEpoch.Add(1)
	p.asyncMu.Lock()
	p.asyncQueue = nil
	if p.activeAsyncCancel != nil {
		p.activeAsyncCancel()
	}
	p.asyncMu.Unlock()

	p.windowMu.Lock()
	p.agg.Reset()
	p.pendingHits = make(map[ruleBucketKey]*bucketAccumulator, 64)
	p.droppedRuleBuckets = false
	p.windowMu.Unlock()

	if p.surprisalEng != nil {
		p.surprisalEng.Reset()
	}
	if p.triageClient != nil {
		p.triageClient.ResetAdapter()
	}
	if p.escalationClient != nil {
		p.escalationClient.ResetAdapter()
	}
	p.escalationEpoch.Add(1)
	p.corrMu.Lock()
	p.serviceCorrelator = nil
	p.corrMu.Unlock()
	p.adapterMu.Lock()
	p.primaryMeta = slotRuntimeMeta{}
	p.escalationMeta = slotRuntimeMeta{}
	p.adapterHistory = nil
	p.hasSyncedManifest = false
	p.lastSyncedManifest = [sha256.Size]byte{}
	p.adapterMu.Unlock()
	if p.segReader != nil {
		p.segReader.ResetCursor()
	}
	if p.queryPoller != nil {
		p.queryPoller.Reset()
	}
	return BurnLocalStateWithFeedbackDir(p.cfg.DataDir, p.cfg.FeedbackDir)
}

// HandleAdapter serves GET, POST, and DELETE /adapter to inspect, hot-swap, roll back,
// verify, or deactivate active Tier 2 / escalation LoRA adapters cleanly under burnMu.
func (p *Pipeline) HandleAdapter(w http.ResponseWriter, r *http.Request) {
	p.handleAdapterRequest(w, r)
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
// (cursor files, baseline snapshots, alerts.jsonl, active-adapter.json, and Sentinel-named
// feedback/*.jsonl files), strictly confined via Go 1.24's os.Root.
func BurnLocalState(dataDir string) (BurnReport, error) {
	return BurnLocalStateWithFeedbackDir(dataDir, "")
}

// BurnLocalStateWithFeedbackDir purges Sentinel-owned files in dataDir and, when a separate
// custom feedbackDir is configured outside dataDir/feedback, also purges Sentinel-named
// feedback files inside feedbackDir using an os.Root-confined directory handle.
func BurnLocalStateWithFeedbackDir(dataDir, feedbackDir string) (BurnReport, error) {
	rep := BurnReport{
		Status:    "burned",
		DataDir:   dataDir,
		Timestamp: time.Now().UTC(),
		Note:      "Sentinel-owned local state purged. Already-trained FTaaS LoRA weights remain in ml/data/artifacts/ and must be removed separately if desired.",
	}
	if strings.TrimSpace(dataDir) == "" && strings.TrimSpace(feedbackDir) == "" {
		return rep, nil
	}

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

	var defaultFeedbackStat os.FileInfo
	if strings.TrimSpace(dataDir) != "" {
		info, err := os.Stat(dataDir)
		if err != nil {
			if !os.IsNotExist(err) {
				errs = append(errs, fmt.Errorf("stat data dir %q: %w", dataDir, err))
			}
		} else if !info.IsDir() {
			errs = append(errs, fmt.Errorf("data dir %q is not a directory", dataDir))
		} else {
			root, openRootErr := os.OpenRoot(dataDir)
			if openRootErr != nil {
				errs = append(errs, fmt.Errorf("open root %q: %w", dataDir, openRootErr))
			} else {
				// 1. Known top-level Sentinel state files and atomic temp files, serialized with
				// AlertJournal writers via the shared cross-process directory lock.
				unlockData, lockErr := feedback.AcquireDirLock(dataDir)
				if lockErr != nil {
					errs = append(errs, fmt.Errorf("lock data dir %q: %w", dataDir, lockErr))
				} else {
					topDir, topOpenErr := root.Open(".")
					if topOpenErr != nil {
						errs = append(errs, fmt.Errorf("open root dir %q: %w", dataDir, topOpenErr))
					} else {
						entries, readErr := topDir.ReadDir(-1)
						_ = topDir.Close()
						if readErr != nil {
							errs = append(errs, fmt.Errorf("read data dir %q: %w", dataDir, readErr))
						} else {
							for _, entry := range entries {
								if entry.IsDir() {
									continue
								}
								if isOwnedTopLevelFile(entry.Name()) {
									removeOwnedInRoot(root, entry.Name())
								}
							}
						}
					}
					unlockData()
				}

				// 2. Known Sentinel-named feedback files inside a nested os.Root handle bound to "feedback",
				// serialized with Store.Append/ExportFTaaS writers via the shared directory lock.
				fbInfo, statErr := root.Lstat("feedback")
				if statErr == nil {
					if fbInfo.Mode()&os.ModeSymlink != 0 {
						errs = append(errs, fmt.Errorf("refusing to follow symlink at feedback directory"))
					} else if fbInfo.IsDir() {
						defaultFeedbackStat = fbInfo
						unlockFB, fbLockErr := feedback.AcquireDirLock(filepath.Join(dataDir, "feedback"))
						if fbLockErr != nil {
							errs = append(errs, fmt.Errorf("lock feedback dir: %w", fbLockErr))
						} else {
							fbRoot, fbOpenRootErr := root.OpenRoot("feedback")
							if fbOpenRootErr != nil {
								errs = append(errs, fmt.Errorf("open feedback root: %w", fbOpenRootErr))
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
												if feedback.IsOwnedFeedbackFilename(e.Name()) {
													removeOwnedInRoot(fbRoot, e.Name())
												}
											}
										}
									}
									_ = fbRoot.Close()
								}
							}
							unlockFB()
						}
					}
				} else if !os.IsNotExist(statErr) {
					errs = append(errs, fmt.Errorf("lstat feedback dir: %w", statErr))
				}
				_ = root.Close()
			}
		}
	}

	// 3. If a separate custom feedbackDir was configured outside dataDir/feedback, purge ONLY
	// Sentinel-named feedback files there via an os.Root handle and shared directory lock.
	// Normalize with filepath.Clean (matching Store.PathFor) and strip redundant trailing
	// OS path separators (so Linux Lstat never follows a symlink ending in '/') while
	// preserving exact directory names (including trailing spaces and Unix backslashes).
	if strings.TrimSpace(feedbackDir) != "" {
		checkedFeedbackDir := filepath.Clean(stripTrailingPathSeparators(feedbackDir))
		cleanDefault := ""
		if strings.TrimSpace(dataDir) != "" {
			cleanDefault = filepath.Clean(filepath.Join(dataDir, "feedback"))
		}
		if checkedFeedbackDir != cleanDefault {
			customInfo, lstatErr := os.Lstat(checkedFeedbackDir)
			if lstatErr == nil {
				if customInfo.Mode()&os.ModeSymlink != 0 {
					errs = append(errs, fmt.Errorf("refusing to follow symlink at custom feedback directory %q", checkedFeedbackDir))
				} else if !customInfo.IsDir() {
					errs = append(errs, fmt.Errorf("custom feedback dir %q is not a directory", checkedFeedbackDir))
				} else if defaultFeedbackStat == nil || !os.SameFile(defaultFeedbackStat, customInfo) {
					unlockCustom, cLockErr := feedback.AcquireDirLock(checkedFeedbackDir)
					if cLockErr != nil {
						errs = append(errs, fmt.Errorf("lock custom feedback dir %q: %w", checkedFeedbackDir, cLockErr))
					} else {
						customRoot, openErr := os.OpenRoot(checkedFeedbackDir)
						if openErr != nil {
							errs = append(errs, fmt.Errorf("open custom feedback root %q: %w", checkedFeedbackDir, openErr))
						} else {
							cStat, cStatErr := customRoot.Stat(".")
							if cStatErr != nil {
								errs = append(errs, fmt.Errorf("stat opened custom feedback dir %q: %w", checkedFeedbackDir, cStatErr))
							} else if !cStat.IsDir() || !os.SameFile(customInfo, cStat) {
								errs = append(errs, fmt.Errorf("refusing custom feedback cleanup: directory identity changed between Lstat and OpenRoot"))
							} else {
								cDir, dOpenErr := customRoot.Open(".")
								if dOpenErr != nil {
									errs = append(errs, fmt.Errorf("open custom feedback dir %q: %w", checkedFeedbackDir, dOpenErr))
								} else {
									cEntries, readErr := cDir.ReadDir(-1)
									_ = cDir.Close()
									if readErr != nil {
										errs = append(errs, fmt.Errorf("read custom feedback dir %q: %w", checkedFeedbackDir, readErr))
									} else {
										for _, e := range cEntries {
											if e.IsDir() {
												continue
											}
											if feedback.IsOwnedFeedbackFilename(e.Name()) {
												removeOwnedInRoot(customRoot, e.Name())
											}
										}
									}
								}
							}
							_ = customRoot.Close()
						}
						unlockCustom()
					}
				}
			} else if !os.IsNotExist(lstatErr) {
				errs = append(errs, fmt.Errorf("lstat custom feedback dir %q: %w", checkedFeedbackDir, lstatErr))
			}
		}
	}

	if len(errs) > 0 {
		if rep.FilesRemoved > 0 {
			rep.Status = "partial"
		} else {
			rep.Status = "failed"
		}
		return rep, errors.Join(errs...)
	}
	return rep, nil
}

var ownedTopLevelTempRe = regexp.MustCompile(`^\.(?:cursor|baseline|alerts|active-adapter)-[0-9]+\.tmp$`)

func isOwnedTopLevelFile(name string) bool {
	switch name {
	case "cursor.json", "cursor.json.tmp",
		"baseline.json", "baseline.json.tmp",
		"alerts.jsonl", "alerts.jsonl.tmp",
		"active-adapter.json", "active-adapter.json.tmp":
		return true
	}
	return ownedTopLevelTempRe.MatchString(name)
}

func stripTrailingPathSeparators(p string) string {
	volLen := len(filepath.VolumeName(p))
	trimmed := p
	for len(trimmed) > volLen+1 && os.IsPathSeparator(trimmed[len(trimmed)-1]) {
		trimmed = trimmed[:len(trimmed)-1]
	}
	return trimmed
}

func sanitizeAndRedactField(raw string, maxBytes int, requireRedaction bool) string {
	s, _ := sanitizeAndRedactWithSignals(raw, maxBytes, requireRedaction)
	return s
}

// round4 normalizes alert float fields to <= 4 decimal places so JSON encoding never emits
// 16-digit float mantissas that could interact with Genesis --redact numeric patterns.
func round4(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*10000) / 10000
}

func roundFeatureMap4(m map[string]float64) map[string]float64 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = round4(v)
	}
	return out
}

// sanitizeAndRedactWithSignals neutralizes chat delimiters and scrubs credentials/URL userinfo
// BEFORE enforcing maxBytes truncation so a secret spanning the truncation boundary (such as a
// long URL userinfo whose '@' sits past maxBytes) cannot leave an unmasked prefix behind.
func sanitizeAndRedactWithSignals(raw string, maxBytes int, requireRedaction bool) (string, []string) {
	if requireRedaction {
		fullCap := len(raw)*3 + 64
		if maxBytes > fullCap {
			fullCap = maxBytes
		}
		sanitized, sigs := security.SanitizeUntrustedLogText(raw, fullCap)
		redacted, _ := feedback.RedactText(sanitized)
		if maxBytes > 0 && len(redacted) > maxBytes {
			redacted, _ = security.SanitizeUntrustedLogText(redacted, maxBytes)
		}
		return redacted, sigs
	}
	return security.SanitizeUntrustedLogText(raw, maxBytes)
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
