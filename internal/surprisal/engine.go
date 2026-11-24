package surprisal

import (
	"context"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

const defaultHTTPCircuitCooldown = 30 * time.Second

// Options configures the Tier 1 Laplace-LK Log Surprisal Engine.
type Options struct {
	Mode               string // "inprocess" (default) | "http" | "hybrid"
	ThresholdNats      float64
	BaselineWindowSize int
	WarmupMinCases     int
	KNeighbors         int
	MaxCandidateCases  int
	HTTPCooldown       time.Duration // circuit-breaker cooldown after HTTP parity failure (default 30s)
	HTTPClient         *HTTPClient
}

// Stats reports diagnostic counters for Tier 1 surprisal scoring.
type Stats struct {
	Mode             string  `json:"mode"`
	ThresholdNats    float64 `json:"threshold_nats"`
	ScoredTotal      uint64  `json:"scored_total"`
	AnomaliesTotal   uint64  `json:"anomalies_total"`
	BaselineCases    int     `json:"baseline_cases"`
	BaselineCapacity int     `json:"baseline_capacity"`
	WarmupMinCases   int     `json:"warmup_min_cases"`
	WarmupComplete   bool    `json:"warmup_complete"`
	MaxNatsObserved  float64 `json:"max_nats_observed"`
	HTTPChecks       uint64  `json:"http_checks"`
	HTTPFallbacks    uint64  `json:"http_fallbacks"`
}

// Engine scores collapsed Tier 0 TemplateWindows using a bounded rolling Laplace-LK
// baseline in pure Go stdlib, with optional loopback parity calls to surprisal-service.
type Engine struct {
	mu             sync.Mutex
	saveMu         sync.Mutex // serializes SaveToFile from snapshot capture through publication
	mode           string
	thresholdNats  float64
	maxSize        int
	warmupMinCases int
	kNeighbors     int
	maxCandidates  int
	httpCooldown   time.Duration
	httpOpenUntil  time.Time
	httpClient     *HTTPClient

	// Fixed-capacity circular buffer of benign baseline LogFeatures.
	ring      []LogFeatures
	head      int // next write position
	count     int // number of populated entries (<= maxSize)
	revision  uint64
	resetGen  uint64 // incremented ONLY by Reset() to discard pre-reset in-flight HTTP updates
	devs      [ContinuousFeatureCount]float64
	devsDirty bool
	dirtyDisk bool

	scoredTotal     uint64
	anomaliesTotal  uint64
	maxNatsObserved float64
	httpChecks      uint64
	httpFallbacks   uint64
}

// NewEngine builds a Tier 1 Laplace-LK Surprisal Engine with safe operational defaults.
func NewEngine(opts Options) *Engine {
	mode := strings.ToLower(strings.TrimSpace(opts.Mode))
	switch mode {
	case "inprocess", "http", "hybrid":
	default:
		mode = "inprocess"
	}

	threshold := opts.ThresholdNats
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold <= 0 {
		threshold = DefaultThresholdNats
	}
	maxSize := opts.BaselineWindowSize
	if maxSize <= 0 {
		maxSize = DefaultBaselineWindowSize
	}
	warmup := opts.WarmupMinCases
	if warmup <= 0 {
		warmup = DefaultWarmupMinCases
	}
	if warmup > maxSize {
		warmup = maxSize
	}
	k := opts.KNeighbors
	if k <= 0 {
		k = DefaultKNeighbors
	}
	maxCand := opts.MaxCandidateCases
	if maxCand <= 0 {
		maxCand = DefaultMaxCandidateCases
	}
	cooldown := opts.HTTPCooldown
	if cooldown <= 0 {
		cooldown = defaultHTTPCircuitCooldown
	}

	e := &Engine{
		mode:           mode,
		thresholdNats:  threshold,
		maxSize:        maxSize,
		warmupMinCases: warmup,
		kNeighbors:     k,
		maxCandidates:  maxCand,
		httpCooldown:   cooldown,
		httpClient:     opts.HTTPClient,
		ring:           make([]LogFeatures, maxSize),
		devsDirty:      true,
	}
	for i := range e.devs {
		e.devs[i] = MinDeviationFloor
	}
	return e
}

// LoadFromFile hydrates the rolling baseline from path if present.
// Does not mark dirtyDisk since state was just read from disk.
func (e *Engine) LoadFromFile(path string) (int, error) {
	snap, err := LoadBaselineSnapshot(path, e.maxSize)
	if err != nil {
		return 0, err
	}
	if len(snap.Cases) == 0 {
		return 0, nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.head = 0
	e.count = 0
	for _, c := range snap.Cases {
		e.appendLocked(c)
	}
	e.devsDirty = true
	e.dirtyDisk = false
	return e.count, nil
}

// SaveToFile serializes persistence across callers (via saveMu) and atomically writes
// the current rolling baseline to path if new cases have been learned since the last
// save (or if force is true). Callers that coordinate with Burn() should hold the
// pipeline burn lock across SaveToFile so Burn waits for any in-flight write.
func (e *Engine) SaveToFile(path string, force bool) error {
	if path == "" {
		return nil
	}
	e.saveMu.Lock()
	defer e.saveMu.Unlock()

	e.mu.Lock()
	if !force && !e.dirtyDisk {
		e.mu.Unlock()
		return nil
	}
	snap := BaselineSnapshot{
		Version: baselineSnapshotVersion,
		MaxSize: e.maxSize,
		Cases:   e.orderedCasesLocked(),
	}
	rev := e.revision
	e.mu.Unlock()

	if err := SaveBaselineSnapshot(path, snap); err != nil {
		return err
	}

	e.mu.Lock()
	// Clear dirtyDisk only if no mutations (learn or reset) occurred while writing.
	if e.revision == rev {
		e.dirtyDisk = false
	}
	e.mu.Unlock()
	return nil
}

// Dirty reports whether the rolling baseline has unsaved changes since the last SaveToFile or Reset.
func (e *Engine) Dirty() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dirtyDisk
}

// Reset clears the in-memory rolling baseline, circuit-breaker state, and cached
// deviations cleanly (used by Burn), bumping resetGen so any in-flight HTTP evaluation
// discards pre-reset metric or baseline updates.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()

	clear(e.ring)
	e.head = 0
	e.count = 0
	e.revision++
	e.resetGen++
	e.httpOpenUntil = time.Time{}
	for i := range e.devs {
		e.devs[i] = MinDeviationFloor
	}
	e.devsDirty = true
	e.dirtyDisk = false
	e.scoredTotal = 0
	e.anomaliesTotal = 0
	e.maxNatsObserved = 0
	e.httpChecks = 0
	e.httpFallbacks = 0
}

// LearnBaseline inserts a known-benign window directly into the rolling baseline
// without emitting an anomaly score (useful for baseline seeding and tests).
func (e *Engine) LearnBaseline(w model.TemplateWindow) {
	feat := ExtractFeatures(w)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.appendLocked(feat)
	e.devsDirty = true
	e.dirtyDisk = true
}

// Evaluate scores a collapsed Tier 0 TemplateWindow against the rolling Laplace-LK
// baseline and selectively updates the baseline with non-anomalous benign windows.
//
// Poisoning protection: windows that already matched a Tier 0 deterministic rule or
// prompt-injection heuristic (`hasTier0Signal == true`), or windows flagged anomalous
// after warmup, are NOT learned into the benign baseline so attackers cannot shift
// the baseline by flooding malicious payloads.
func (e *Engine) Evaluate(ctx context.Context, w model.TemplateWindow, hasTier0Signal bool) model.SurprisalScore {
	feat := ExtractFeatures(w)

	e.mu.Lock()
	e.scoredTotal++
	baseCount := e.count
	warmupDone := baseCount >= e.warmupMinCases
	gen := e.resetGen

	var (
		totalNats float64
		contribs  map[string]float64
		refsCopy  []LogFeatures
		mode      = e.mode
		threshold = e.thresholdNats
		client    = e.httpClient
	)

	if baseCount > 0 {
		if e.devsDirty {
			e.devs = ComputeLogDeviations(e.activeSliceLocked())
			e.devsDirty = false
		}
		totalNats, contribs = e.scoreAgainstBaselineLocked(feat)
	}

	localAnomalous := warmupDone && totalNats >= threshold
	anomalous := localAnomalous
	now := time.Now()
	circuitOpen := !e.httpOpenUntil.IsZero() && now.Before(e.httpOpenUntil)
	needHTTP := client != nil && warmupDone && !circuitOpen && (mode == "http" || (mode == "hybrid" && localAnomalous))

	if mode == "inprocess" || !needHTTP {
		if (mode == "http" || mode == "hybrid") && client != nil && warmupDone && circuitOpen && (mode == "http" || localAnomalous) {
			e.httpFallbacks++
		}
		if anomalous {
			e.anomaliesTotal++
		}
		if totalNats > e.maxNatsObserved {
			e.maxNatsObserved = totalNats
		}
		// Only absorb benign, non-anomalous, non-rule-flagged windows into the rolling baseline.
		if !hasTier0Signal && !anomalous {
			e.appendLocked(feat)
			e.devsDirty = true
			e.dirtyDisk = true
		}
		e.mu.Unlock()

		return model.SurprisalScore{
			TemplateID:        w.TemplateID,
			TotalNats:         round4(totalNats),
			ThresholdNats:     threshold,
			Anomalous:         anomalous,
			FeatureContribs:   contribs,
			BaselineCaseCount: baseCount,
		}
	}

	// Copy chronological baseline references ONLY when an HTTP parity call will execute.
	refsCopy = e.orderedCasesLocked()
	// Release lock before loopback HTTP parity request (never hold mutex across I/O).
	e.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	vResp, err := client.VerifyWindow(ctx, w, refsCopy, threshold)

	e.mu.Lock()
	if e.resetGen != gen {
		// Burn/Reset occurred mid-request: discard all pre-reset counters and baseline updates.
		e.mu.Unlock()
		return model.SurprisalScore{
			TemplateID:        w.TemplateID,
			TotalNats:         round4(totalNats),
			ThresholdNats:     threshold,
			Anomalous:         anomalous,
			FeatureContribs:   contribs,
			BaselineCaseCount: baseCount,
		}
	}

	e.httpChecks++
	if err != nil {
		e.httpFallbacks++
		e.httpOpenUntil = time.Now().Add(e.httpCooldown)
	} else if mode == "http" {
		sidecarAnomalous := !vResp.IsConforming || vResp.MeasuredSurprisalNats >= threshold
		if sidecarAnomalous || !localAnomalous {
			// Adopt sidecar measurement and clear local contributions so attributions never
			// describe a different calculation than the score that produced the verdict.
			totalNats = vResp.MeasuredSurprisalNats
			anomalous = sidecarAnomalous
			contribs = nil
		} else {
			// Defense-in-depth: if local pure-Go Laplace-LK detected a log-domain burst/anomaly
			// that a general-purpose sidecar missed, fail closed on local detection and keep
			// local attributions so anomalies never poison the rolling baseline.
			anomalous = true
		}
	}

	if anomalous {
		e.anomaliesTotal++
	}
	if totalNats > e.maxNatsObserved {
		e.maxNatsObserved = totalNats
	}
	if !hasTier0Signal && !anomalous && !localAnomalous {
		e.appendLocked(feat)
		e.devsDirty = true
		e.dirtyDisk = true
	}
	e.mu.Unlock()

	return model.SurprisalScore{
		TemplateID:        w.TemplateID,
		TotalNats:         round4(totalNats),
		ThresholdNats:     threshold,
		Anomalous:         anomalous,
		FeatureContribs:   contribs,
		BaselineCaseCount: baseCount,
	}
}

// Stats returns a thread-safe snapshot of Tier 1 engine diagnostics.
func (e *Engine) Stats() Stats {
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{
		Mode:             e.mode,
		ThresholdNats:    e.thresholdNats,
		ScoredTotal:      e.scoredTotal,
		AnomaliesTotal:   e.anomaliesTotal,
		BaselineCases:    e.count,
		BaselineCapacity: e.maxSize,
		WarmupMinCases:   e.warmupMinCases,
		WarmupComplete:   e.count >= e.warmupMinCases,
		MaxNatsObserved:  round4(e.maxNatsObserved),
		HTTPChecks:       e.httpChecks,
		HTTPFallbacks:    e.httpFallbacks,
	}
}

// TopFeatures returns at most limit highest-contributing non-zero features from contribs.
func TopFeatures(contribs map[string]float64, limit int) map[string]float64 {
	if len(contribs) == 0 || limit <= 0 {
		return nil
	}
	type kv struct {
		k string
		v float64
	}
	items := make([]kv, 0, len(contribs))
	for k, v := range contribs {
		if v > 0 && !math.IsNaN(v) && !math.IsInf(v, 0) {
			items = append(items, kv{k: k, v: v})
		}
	}
	if len(items) == 0 {
		return nil
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].v != items[j].v {
			return items[i].v > items[j].v
		}
		return items[i].k < items[j].k
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make(map[string]float64, len(items))
	for _, it := range items {
		out[it.k] = round4(it.v)
	}
	return out
}

func (e *Engine) appendLocked(f LogFeatures) {
	e.ring[e.head] = f
	e.head = (e.head + 1) % e.maxSize
	if e.count < e.maxSize {
		e.count++
	}
	e.revision++
}

func (e *Engine) activeSliceLocked() []LogFeatures {
	if e.count < e.maxSize {
		return e.ring[:e.count]
	}
	return e.ring
}

func (e *Engine) orderedCasesLocked() []LogFeatures {
	out := make([]LogFeatures, 0, e.count)
	if e.count == 0 {
		return out
	}
	if e.count < e.maxSize {
		out = append(out, e.ring[:e.count]...)
		return out
	}
	// Ring is full: oldest entry sits at e.head.
	out = append(out, e.ring[e.head:]...)
	out = append(out, e.ring[:e.head]...)
	return out
}

type neighborResult struct {
	score    float64
	contribs [ContinuousFeatureCount + NominalFeatureCount]float64
}

func (e *Engine) chronologicalAtLocked(pos int) LogFeatures {
	if e.count < e.maxSize {
		return e.ring[pos]
	}
	return e.ring[(e.head+pos)%e.maxSize]
}

// scoreAgainstBaselineLocked computes the k-NN mean Laplace-LK surprisal (and
// averaged per-feature marginal breakdown) across up to maxCandidates evenly-strided
// baseline records traversed in chronological oldest-first order so wrapped rings
// produce identical results before and after SaveToFile/LoadFromFile round-trips.
func (e *Engine) scoreAgainstBaselineLocked(cand LogFeatures) (float64, map[string]float64) {
	n := e.count
	if n == 0 {
		return 0, nil
	}

	k := e.kNeighbors
	if k > n {
		k = n
	}

	// Collect chronological positions of same-service peers so rare benign services
	// are never lost behind high-volume services and wraparound order stays deterministic.
	var peerPos []int
	for pos := 0; pos < n; pos++ {
		if e.chronologicalAtLocked(pos).Nominal[0] == cand.Nominal[0] {
			peerPos = append(peerPos, pos)
		}
	}

	usePeers := len(peerPos) >= k
	poolLen := n
	if usePeers {
		poolLen = len(peerPos)
	}

	numCand := poolLen
	stride := 1.0
	if poolLen > e.maxCandidates {
		numCand = e.maxCandidates
		stride = float64(poolLen) / float64(e.maxCandidates)
	}
	if k > numCand {
		k = numCand
	}

	// Keep the k smallest neighbor scores in a tiny sorted slice (typically k <= 3).
	best := make([]neighborResult, 0, k+1)

	for i := 0; i < numCand; i++ {
		posInPool := i
		if stride > 1.0 {
			posInPool = int(float64(i) * stride)
			if posInPool >= poolLen {
				posInPool = poolLen - 1
			}
		}
		chronPos := posInPool
		if usePeers {
			chronPos = peerPos[posInPool]
		}
		s, c := pairSurprisal(cand, e.chronologicalAtLocked(chronPos), e.devs)

		if len(best) < k || s < best[len(best)-1].score {
			pos := len(best)
			for pos > 0 && s < best[pos-1].score {
				pos--
			}
			if len(best) < k {
				best = append(best, neighborResult{})
			}
			copy(best[pos+1:], best[pos:])
			best[pos] = neighborResult{score: s, contribs: c}
		}
	}

	if len(best) == 0 {
		return 0, nil
	}

	invK := 1.0 / float64(len(best))
	var meanScore float64
	var meanContribs [ContinuousFeatureCount + NominalFeatureCount]float64
	for _, b := range best {
		meanScore += b.score
		for j := range meanContribs {
			meanContribs[j] += b.contribs[j]
		}
	}
	meanScore *= invK

	contribMap := make(map[string]float64, ContinuousFeatureCount+NominalFeatureCount)
	for j := 0; j < ContinuousFeatureCount; j++ {
		contribMap[ContinuousFeatureNames[j]] = round4(meanContribs[j] * invK)
	}
	for j := 0; j < NominalFeatureCount; j++ {
		contribMap[NominalFeatureNames[j]] = round4(meanContribs[ContinuousFeatureCount+j] * invK)
	}

	return meanScore, contribMap
}

func selectStrided(cases []LogFeatures, maxN int) []LogFeatures {
	if len(cases) <= maxN || maxN <= 0 {
		return cases
	}
	out := make([]LogFeatures, 0, maxN)
	step := float64(len(cases)) / float64(maxN)
	for i := 0; i < maxN; i++ {
		idx := int(float64(i) * step)
		if idx >= len(cases) {
			idx = len(cases) - 1
		}
		out = append(out, cases[idx])
	}
	return out
}

func round4(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	if math.Abs(v) >= math.MaxFloat64/10000 {
		return v
	}
	return math.Round(v*10000) / 10000
}
