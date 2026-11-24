package template

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"math"
	"slices"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

const (
	// DefaultMaxClusters bounds unique template clusters in RAM under adversarial token floods.
	DefaultMaxClusters = 4096
	// DefaultMaxClusterBytes bounds total string bytes retained inside learned Drain clusters and tree keys.
	DefaultMaxClusterBytes = 8 * 1024 * 1024 // 8 MiB
	// DefaultMaxWindows bounds distinct dedicated TemplateWindow entries retained between Flush calls.
	DefaultMaxWindows = 4096
	// DefaultMaxRetainedSampleBytes bounds total preview sample bytes retained across all windows between Flush calls.
	DefaultMaxRetainedSampleBytes = 16 * 1024 * 1024 // 16 MiB
	// DefaultMaxWindowSampleBytes bounds preview sample bytes retained by a single TemplateWindow.
	DefaultMaxWindowSampleBytes = 16 * 1024 // 16 KiB
	// DefaultMaxSingleSampleBytes bounds any single retained preview sample string.
	DefaultMaxSingleSampleBytes = 4096 // 4 KiB
	// DefaultSimilarityThreshold is the Drain token match ratio required to merge into an existing cluster.
	DefaultSimilarityThreshold = 0.50
	// DefaultMaxDepth is the fixed prefix-tree token depth before cluster leaf lookup.
	DefaultMaxDepth = 2
	// minEntropyTokenLen is the minimum token length checked for whitespace/dot-delimited entropy peaks.
	minEntropyTokenLen = 24
	// maxAdditionalSamples bounds extra preview samples retained per TemplateWindow.
	maxAdditionalSamples = 16
	// maxOverflowBuckets bounds distinct (service, level) overflow windows when at capacity.
	maxOverflowBuckets = 256
	// maxClusterTokenBytes masks overly long individual tokens in templates so random blobs do not bloat clusters.
	maxClusterTokenBytes = 256
	// maxClusterTokens caps normalized tokens retained per cluster template.
	maxClusterTokens = 128
	// maxWindowServiceBytes and maxWindowLevelBytes cap display identity bytes retained per active TemplateWindow.
	maxWindowServiceBytes = 128
	maxWindowLevelBytes   = 64
)

type drainRootKey struct {
	service    string
	level      string
	tokenCount int
}

type drainCluster struct {
	id     string // stable aggregation ID preserved across token generalizations
	tokens []string
}

type drainNode struct {
	children map[string]*drainNode
	clusters []*drainCluster
}

// DrainMiner implements a fast, bounded, pure-Go Drain-style log template miner.
// Dynamic parameters (IPs, UUIDs, timestamps, hex values, numbers) are pre-masked
// before fixed-depth prefix lookup so repetitive log lines collapse into stable
// structural templates with bounded cluster count and retained string bytes.
type DrainMiner struct {
	mu                  sync.Mutex
	roots               map[drainRootKey]*drainNode
	maxClusters         int
	maxClusterBytes     int
	clusterCount        int
	clusterBytes        int
	similarityThreshold float64
}

// NewDrainMiner creates a Drain-style template miner with safe cluster-count and byte bounds.
func NewDrainMiner(maxClusters int, similarityThreshold float64) *DrainMiner {
	if maxClusters <= 0 {
		maxClusters = DefaultMaxClusters
	}
	if math.IsNaN(similarityThreshold) || similarityThreshold <= 0 || similarityThreshold > 1 {
		similarityThreshold = DefaultSimilarityThreshold
	}
	return &DrainMiner{
		roots:               make(map[drainRootKey]*drainNode, 64),
		maxClusters:         maxClusters,
		maxClusterBytes:     DefaultMaxClusterBytes,
		similarityThreshold: similarityThreshold,
	}
}

// SetMaxClusterBytes overrides the cluster string-byte cap. Returns an error if n <= 0
// or n is below the currently retained ClusterBytes() so the active tree never violates
// its configured cap (call Reset() first to shrink below current usage).
func (m *DrainMiner) SetMaxClusterBytes(n int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if n <= 0 {
		return fmt.Errorf("max cluster bytes must be positive, got %d", n)
	}
	if n < m.clusterBytes {
		return fmt.Errorf("cannot set max cluster bytes to %d below current usage %d (reset miner first)", n, m.clusterBytes)
	}
	m.maxClusterBytes = n
	return nil
}

// ClusterBytes reports total retained string bytes inside learned Drain clusters and tree keys.
func (m *DrainMiner) ClusterBytes() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clusterBytes
}

// extractBoundedTokens iterates msg lazily via Go 1.24 strings.FieldsSeq, masking only
// up to maxTokens fields and skipping normalization work on raw tokens exceeding
// maxTokenBytes*2 so giant slash-heavy payloads cannot trigger large temporary allocations.
func extractBoundedTokens(msg string, maxTokens, maxTokenBytes int) []string {
	maxRawNormBytes := maxTokenBytes * 2
	var tokens []string
	for rawTok := range strings.FieldsSeq(msg) {
		if len(tokens) >= maxTokens {
			tokens = append(tokens, "<*>")
			break
		}
		if tokens == nil {
			tokens = make([]string, 0, 16)
		}
		if len(rawTok) > maxRawNormBytes {
			tokens = append(tokens, "<*>")
			continue
		}
		tok := maskToken(rawTok)
		if len(tok) > maxTokenBytes {
			tok = "<*>"
		}
		tokens = append(tokens, tok)
	}
	return tokens
}

// ExtractTemplate normalizes msg into bounded masked tokens, merges it into the Drain prefix
// tree for (service, level), and returns (stableTemplateID, templateString, overflowed).
// Retained cluster tokens and tree keys are detached via strings.Clone and capped by
// maxClusters and maxClusterBytes so giant log lines cannot pin backing arrays after Flush.
func (m *DrainMiner) ExtractTemplate(service, level, msg string) (string, string, bool) {
	tokens := extractBoundedTokens(msg, maxClusterTokens, maxClusterTokenBytes)
	if len(tokens) == 0 {
		tmpl := "<EMPTY>"
		return TemplateHash(service, level, tmpl), tmpl, false
	}

	rootKey := drainRootKey{
		service:    service,
		level:      level,
		tokenCount: len(tokens),
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	atCap := m.clusterCount >= m.maxClusters || m.clusterBytes >= m.maxClusterBytes

	// Track newly created prefix-tree entries so a rejected cluster insertion rolls back
	// cleanly without stranding tree keys or consuming clusterBytes budget.
	var (
		addedRoot    bool
		addedRootKey drainRootKey
		addedNodes   [DefaultMaxDepth]struct {
			parent *drainNode
			key    string
		}
		addedNodeCount int
		addedBytes     int
	)
	rollback := func() {
		for j := addedNodeCount - 1; j >= 0; j-- {
			delete(addedNodes[j].parent.children, addedNodes[j].key)
			if len(addedNodes[j].parent.children) == 0 {
				addedNodes[j].parent.children = nil
			}
		}
		if addedRoot {
			delete(m.roots, addedRootKey)
		}
		m.clusterBytes -= addedBytes
		if m.clusterBytes < 0 {
			m.clusterBytes = 0
		}
	}

	root, ok := m.roots[rootKey]
	if !ok {
		rootCost := len(service) + len(level)
		if atCap || m.clusterBytes+rootCost > m.maxClusterBytes {
			return OverflowTemplateID(service, level), "<OVERFLOW>", true
		}
		clonedKey := drainRootKey{
			service:    strings.Clone(service),
			level:      strings.Clone(level),
			tokenCount: len(tokens),
		}
		root = &drainNode{}
		m.roots[clonedKey] = root
		m.clusterBytes += rootCost
		addedRoot = true
		addedRootKey = clonedKey
		addedBytes += rootCost
	}

	node := root
	depth := min(DefaultMaxDepth, len(tokens))
	for i := 0; i < depth; i++ {
		tok := tokens[i]
		if isWildcardToken(tok) {
			tok = "<*>"
		}
		if node.children == nil {
			if atCap || m.clusterBytes+len(tok) > m.maxClusterBytes {
				rollback()
				return OverflowTemplateID(service, level), "<OVERFLOW>", true
			}
			node.children = make(map[string]*drainNode, 8)
		}
		child, exists := node.children[tok]
		if !exists {
			if atCap {
				// Fallback read-only check into wildcard branch if one already exists.
				wild, hasWild := node.children["<*>"]
				if !hasWild {
					rollback()
					return OverflowTemplateID(service, level), "<OVERFLOW>", true
				}
				child = wild
			} else if len(node.children) >= 64 {
				child, exists = node.children["<*>"]
				if !exists {
					if m.clusterBytes+len("<*>") > m.maxClusterBytes {
						rollback()
						return OverflowTemplateID(service, level), "<OVERFLOW>", true
					}
					child = &drainNode{}
					node.children["<*>"] = child
					m.clusterBytes += len("<*>")
					addedNodes[addedNodeCount] = struct {
						parent *drainNode
						key    string
					}{parent: node, key: "<*>"}
					addedNodeCount++
					addedBytes += len("<*>")
				}
			} else {
				if m.clusterBytes+len(tok) > m.maxClusterBytes {
					wild, hasWild := node.children["<*>"]
					if !hasWild {
						rollback()
						return OverflowTemplateID(service, level), "<OVERFLOW>", true
					}
					child = wild
				} else {
					clonedTok := strings.Clone(tok)
					child = &drainNode{}
					node.children[clonedTok] = child
					m.clusterBytes += len(clonedTok)
					addedNodes[addedNodeCount] = struct {
						parent *drainNode
						key    string
					}{parent: node, key: clonedTok}
					addedNodeCount++
					addedBytes += len(clonedTok)
				}
			}
		}
		node = child
	}

	// Find best matching cluster in leaf
	var best *drainCluster
	bestSim := -1.0
	for _, c := range node.clusters {
		sim := tokenSimilarity(c.tokens, tokens)
		if sim >= m.similarityThreshold && sim > bestSim {
			bestSim = sim
			best = c
		}
	}

	if best != nil {
		// Verify clusterBytes cap BEFORE generalizing tokens (e.g. 1-byte token -> 3-byte "<*>").
		delta := 0
		for i := range best.tokens {
			if best.tokens[i] != tokens[i] {
				delta += len("<*>") - len(best.tokens[i])
			}
		}
		if m.clusterBytes+delta > m.maxClusterBytes {
			rollback()
			return OverflowTemplateID(service, level), "<OVERFLOW>", true
		}
		for i := range best.tokens {
			if best.tokens[i] != tokens[i] {
				best.tokens[i] = "<*>"
			}
		}
		m.clusterBytes += delta
		if m.clusterBytes < 0 {
			m.clusterBytes = 0
		}
		// Keep stable best.id even after token generalization so counts stay aggregated in one window.
		return best.id, strings.Join(best.tokens, " "), false
	}

	// Charge both the retained 16-byte cluster ID and all retained token bytes against maxClusterBytes.
	const clusterIDBytes = 16
	clusterCost := clusterIDBytes
	for _, tok := range tokens {
		clusterCost += len(tok)
	}
	if atCap || m.clusterBytes+clusterCost > m.maxClusterBytes {
		rollback()
		return OverflowTemplateID(service, level), "<OVERFLOW>", true
	}

	copied := make([]string, len(tokens))
	for i, tok := range tokens {
		copied[i] = strings.Clone(tok)
	}
	tmpl := strings.Join(copied, " ")
	m.clusterCount++
	c := &drainCluster{
		id:     TemplateHash(service, level, fmt.Sprintf("cluster:%d:%s", m.clusterCount, tmpl)),
		tokens: copied,
	}
	m.clusterBytes += len(c.id) + (clusterCost - clusterIDBytes)
	node.clusters = append(node.clusters, c)

	return c.id, tmpl, false
}

// Reset clears all learned prefix-tree clusters (used by `sentinel burn`).
func (m *DrainMiner) Reset() {
	m.mu.Lock()
	m.roots = make(map[drainRootKey]*drainNode, 64)
	m.clusterCount = 0
	m.clusterBytes = 0
	m.mu.Unlock()
}

// ClusterCount returns the active number of learned template clusters.
func (m *DrainMiner) ClusterCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clusterCount
}

// Aggregator collects incoming model.LogEvents over a window and collapses identical
// templates into bounded model.TemplateWindow records for Tier 0/1/2 evaluation.
// Dedicated window slots are tracked separately from overflow buckets, and retained
// preview sample bytes are bounded per sample, per window, and globally across windows.
type Aggregator struct {
	mu                  sync.Mutex
	miner               *DrainMiner
	windows             map[string]*model.TemplateWindow
	windowBytes         map[string]int
	maxWindows          int
	dedicatedWindows    int
	overflowBuckets     int
	totalSampleBytes    int
	maxTotalSampleBytes int
	maxWindowBytes      int
	maxSingleSample     int
}

// NewAggregator creates a window aggregator backed by a bounded DrainMiner.
func NewAggregator(maxClusters int) *Aggregator {
	maxWin := maxClusters
	if maxWin <= 0 {
		maxWin = DefaultMaxWindows
	}
	return &Aggregator{
		miner:               NewDrainMiner(maxClusters, DefaultSimilarityThreshold),
		windows:             make(map[string]*model.TemplateWindow, 128),
		windowBytes:         make(map[string]int, 128),
		maxWindows:          maxWin,
		maxTotalSampleBytes: DefaultMaxRetainedSampleBytes,
		maxWindowBytes:      DefaultMaxWindowSampleBytes,
		maxSingleSample:     DefaultMaxSingleSampleBytes,
	}
}

// SetSampleByteLimits overrides retained preview sample byte budgets (primarily for testing).
// Rejects non-positive limits or limits below currently retained active-window preview bytes
// without mutating any limit so active windows never exceed configured bounds.
func (a *Aggregator) SetSampleByteLimits(maxTotal, maxPerWindow, maxSingle int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if maxTotal <= 0 || maxPerWindow <= 0 || maxSingle <= 0 {
		return fmt.Errorf("sample byte limits must be positive (got total=%d window=%d single=%d)", maxTotal, maxPerWindow, maxSingle)
	}
	if a.totalSampleBytes > maxTotal {
		return fmt.Errorf("cannot set maxTotalSampleBytes=%d below currently retained %d bytes", maxTotal, a.totalSampleBytes)
	}
	for id, wb := range a.windowBytes {
		if wb > maxPerWindow {
			return fmt.Errorf("cannot set maxWindowBytes=%d below window %q retained %d bytes", maxPerWindow, id, wb)
		}
	}
	for id, w := range a.windows {
		if len(w.SampleLine) > maxSingle {
			return fmt.Errorf("cannot set maxSingleSample=%d below window %q SampleLine length %d", maxSingle, id, len(w.SampleLine))
		}
		for _, extra := range w.AdditionalSamples {
			if len(extra) > maxSingle {
				return fmt.Errorf("cannot set maxSingleSample=%d below window %q AdditionalSample length %d", maxSingle, id, len(extra))
			}
		}
	}
	a.maxTotalSampleBytes = maxTotal
	a.maxWindowBytes = maxPerWindow
	a.maxSingleSample = maxSingle
	return nil
}

// SetMaxClusterBytes overrides the underlying DrainMiner's cluster string-byte cap.
func (a *Aggregator) SetMaxClusterBytes(n int) error {
	return a.miner.SetMaxClusterBytes(n)
}

// RetainedSampleBytes returns the total preview sample bytes currently retained in active windows.
func (a *Aggregator) RetainedSampleBytes() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.totalSampleBytes
}

// ClusterBytes returns the total string bytes retained inside the underlying DrainMiner.
func (a *Aggregator) ClusterBytes() int {
	return a.miner.ClusterBytes()
}

// Add folds a single LogEvent into the current window's collapsed templates and
// returns (windowID, isOverflow, peakEntropy).
func (a *Aggregator) Add(ev model.LogEvent) (string, bool, float64) {
	return a.AddWithEntropy(ev, PeakShannonEntropy(ev.Message))
}

// AddWithEntropy folds a single LogEvent using a precomputed peak entropy value so
// callers coordinating event-level rule evaluation avoid redundant entropy scans.
// Returns (windowID, isOverflow, peakEntropy).
func (a *Aggregator) AddWithEntropy(ev model.LogEvent, ent float64) (string, bool, float64) {
	a.mu.Lock()
	defer a.mu.Unlock()

	tmplID, tmpl, overflowed := a.miner.ExtractTemplate(ev.Service, ev.Level, ev.Message)
	isGlobalOverflow := false

	var (
		w      *model.TemplateWindow
		exists bool
	)
	if !overflowed {
		w, exists = a.windows[tmplID]
		if !exists && a.dedicatedWindows >= a.maxWindows {
			overflowed = true
		}
	}

	if overflowed {
		tmpl = "<OVERFLOW>"
		ovID := OverflowTemplateID(ev.Service, ev.Level)
		if existingOv, ok := a.windows[ovID]; ok {
			w = existingOv
			tmplID = ovID
			exists = true
		} else if a.overflowBuckets < maxOverflowBuckets {
			a.overflowBuckets++
			tmplID = ovID
			exists = false
		} else {
			const globalOvID = "overflow:global"
			isGlobalOverflow = true
			tmplID = globalOvID
			if globalOv, ok := a.windows[globalOvID]; ok {
				w = globalOv
				exists = true
			} else {
				exists = false
			}
		}
	}

	sample := truncateUTF8Clone(ev.Message, a.maxSingleSample)

	if !exists {
		// Bound retained window display identity strings so huge adversarial service/level
		// values cannot accumulate megabytes across active/overflow windows. Rule matching
		// still evaluates on the original untruncated LogEvent identity.
		svc := truncateUTF8Clone(ev.Service, maxWindowServiceBytes)
		lvl := truncateUTF8Clone(ev.Level, maxWindowLevelBytes)
		if isGlobalOverflow {
			// Keep global overflow bucket strictly unattributed so service/level rules
			// evaluate each event with its real identity rather than the first overflow event's.
			svc = "<MIXED>"
			lvl = "<MIXED>"
		}
		allowed := min(a.maxWindowBytes, a.maxTotalSampleBytes-a.totalSampleBytes)
		retainedSample := ""
		if allowed > 0 && sample != "" {
			if len(sample) > allowed {
				retainedSample = truncateUTF8Clone(sample, allowed)
			} else {
				retainedSample = sample
			}
		}
		win := &model.TemplateWindow{
			TemplateID:       tmplID,
			Template:         tmpl,
			Service:          svc,
			ServiceTruncated: !isGlobalOverflow && len(svc) < len(ev.Service),
			Level:            lvl,
			Count:            1,
			FirstSeenUnix:    ev.Timestamp,
			LastSeenUnix:     ev.Timestamp,
			SampleLine:       retainedSample,
			SampleTruncated:  len(retainedSample) < len(ev.Message),
			SampleEntropy:    ent,
		}
		if !isGlobalOverflow {
			win.HasIdentityHash = true
			win.ServiceHash = sha256.Sum256([]byte(ev.Service))
			win.LevelHash = sha256.Sum256([]byte(ev.Level))
		}
		a.windows[tmplID] = win
		a.windowBytes[tmplID] = len(retainedSample)
		a.totalSampleBytes += len(retainedSample)
		if !overflowed {
			a.dedicatedWindows++
		}
		return tmplID, overflowed, ent
	}

	w.Count++
	if !overflowed && tmpl != "<OVERFLOW>" {
		w.Template = tmpl
	}
	if ev.Timestamp > 0 && (w.FirstSeenUnix == 0 || ev.Timestamp < w.FirstSeenUnix) {
		w.FirstSeenUnix = ev.Timestamp
	}
	if ev.Timestamp > w.LastSeenUnix {
		w.LastSeenUnix = ev.Timestamp
	}

	// Retain the highest-entropy sample in SampleLine and keep a byte-bounded best-effort
	// preview cache (up to maxAdditionalSamples) in AdditionalSamples. Deterministic
	// Tier 0 rule coverage evaluates each full event at ingest time rather than relying on this cache.
	prevSample := w.SampleLine
	prevTruncated := w.SampleTruncated
	sampleTruncated := len(sample) < len(ev.Message)
	if ent > w.SampleEntropy {
		// If the incoming preview already exists in AdditionalSamples, remove it first so
		// promotion never duplicates the sample or double-charges the preview byte budget.
		// Track whether the removed equal preview was complete (untruncated) so an equal
		// clipped preview never overwrites complete evidence for anchored rules.
		hadCompleteEqual := a.removeEvidenceSampleLocked(tmplID, w, sample)
		winAvail := a.maxWindowBytes - (a.windowBytes[tmplID] - len(prevSample))
		totAvail := a.maxTotalSampleBytes - (a.totalSampleBytes - len(prevSample))
		allowed := min(winAvail, totAvail)
		newPrimary := ""
		if allowed > 0 && sample != "" {
			if len(sample) > allowed {
				newPrimary = truncateUTF8Clone(sample, allowed)
			} else {
				newPrimary = sample
			}
		}
		if newPrimary != "" && newPrimary != sample {
			hadCompleteEqual = a.removeEvidenceSampleLocked(tmplID, w, newPrimary)
		}
		delta := len(newPrimary) - len(prevSample)
		a.windowBytes[tmplID] += delta
		a.totalSampleBytes += delta
		w.SampleLine = newPrimary
		if newPrimary != "" && hadCompleteEqual && len(newPrimary) < len(ev.Message) {
			// Preserve the previously retained complete record's metadata (untruncated + its exact entropy)
			// when a longer clipped message collapses onto the exact same preview bytes.
			w.SampleTruncated = false
			w.SampleEntropy = PeakShannonEntropy(newPrimary)
		} else {
			w.SampleTruncated = len(newPrimary) < len(ev.Message)
			w.SampleEntropy = ent
		}
		if prevSample != "" && prevSample != newPrimary {
			a.addEvidenceSampleLocked(tmplID, w, prevSample, prevTruncated)
		}
	} else if sample != "" && sample == w.SampleLine {
		if w.SampleTruncated && !sampleTruncated {
			// A complete message replaced a clipped preview of identical bytes: update
			// SampleEntropy to the complete event's true score before clearing SampleTruncated.
			w.SampleEntropy = ent
			w.SampleTruncated = false
		}
	} else if sample != "" && sample != w.SampleLine {
		a.addEvidenceSampleLocked(tmplID, w, sample, sampleTruncated)
	}
	return tmplID, overflowed, ent
}

// removeEvidenceSampleLocked removes target from w.AdditionalSamples using slices.Delete
// (clearing vacated backing slots for GC) and reports whether the removed entry was complete.
func (a *Aggregator) removeEvidenceSampleLocked(tmplID string, w *model.TemplateWindow, target string) bool {
	if target == "" || len(w.AdditionalSamples) == 0 {
		return false
	}
	for i, existing := range w.AdditionalSamples {
		if existing == target {
			wasComplete := true
			if i < len(w.AdditionalSamplesTruncated) {
				wasComplete = !w.AdditionalSamplesTruncated[i]
				w.AdditionalSamplesTruncated = slices.Delete(w.AdditionalSamplesTruncated, i, i+1)
			}
			w.AdditionalSamples = slices.Delete(w.AdditionalSamples, i, i+1)
			a.windowBytes[tmplID] -= len(existing)
			a.totalSampleBytes -= len(existing)
			return wasComplete
		}
	}
	return false
}

func (a *Aggregator) addEvidenceSampleLocked(tmplID string, w *model.TemplateWindow, sample string, truncated bool) {
	if sample == "" || sample == w.SampleLine {
		return
	}
	for i, existing := range w.AdditionalSamples {
		if existing == sample {
			// If an earlier clipped preview matches a complete message, upgrade it to complete.
			if i < len(w.AdditionalSamplesTruncated) && w.AdditionalSamplesTruncated[i] && !truncated {
				w.AdditionalSamplesTruncated[i] = false
			}
			return
		}
	}
	winRoom := a.maxWindowBytes - a.windowBytes[tmplID]
	totRoom := a.maxTotalSampleBytes - a.totalSampleBytes
	if len(w.AdditionalSamples) < maxAdditionalSamples && len(sample) <= winRoom && len(sample) <= totRoom {
		w.AdditionalSamples = append(w.AdditionalSamples, sample)
		w.AdditionalSamplesTruncated = append(w.AdditionalSamplesTruncated, truncated)
		a.windowBytes[tmplID] += len(sample)
		a.totalSampleBytes += len(sample)
		return
	}
	// When full on count or byte budget, prioritize retaining samples carrying security-relevant cues.
	if hasSecurityCue(sample) {
		for i, existing := range w.AdditionalSamples {
			if !hasSecurityCue(existing) {
				delta := len(sample) - len(existing)
				if delta <= winRoom && delta <= totRoom {
					w.AdditionalSamples[i] = sample
					if i < len(w.AdditionalSamplesTruncated) {
						w.AdditionalSamplesTruncated[i] = truncated
					}
					a.windowBytes[tmplID] += delta
					a.totalSampleBytes += delta
					return
				}
			}
		}
	}
}

func truncateUTF8Clone(s string, maxBytes int) string {
	if maxBytes <= 0 || s == "" {
		return ""
	}
	if len(s) <= maxBytes {
		return strings.Clone(s)
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(s[end]) {
		end--
	}
	if end == 0 {
		return ""
	}
	return strings.Clone(s[:end])
}

func hasSecurityCue(s string) bool {
	lower := strings.ToLower(s)
	for _, cue := range []string{
		"../", "%2e%2e", "/etc/passwd", "/etc/shadow",
		"union ", "select ", "information_schema", "xp_cmdshell",
		"<|", "<start_of_turn>", "ignore previous", "disregard",
		"curl ", "wget ", "/dev/tcp/", "bash -i", "command not allowed",
		"failed password", "invalid user", "authentication failure",
	} {
		if strings.Contains(lower, cue) {
			return true
		}
	}
	return false
}

// Flush drains and returns all collapsed TemplateWindows accumulated since the last Flush,
// sorted deterministically by (FirstSeenUnix, TemplateID).
func (a *Aggregator) Flush() []model.TemplateWindow {
	a.mu.Lock()
	if len(a.windows) == 0 {
		a.mu.Unlock()
		return nil
	}
	drained := a.windows
	a.windows = make(map[string]*model.TemplateWindow, 128)
	a.windowBytes = make(map[string]int, 128)
	a.dedicatedWindows = 0
	a.overflowBuckets = 0
	a.totalSampleBytes = 0
	a.mu.Unlock()

	out := make([]model.TemplateWindow, 0, len(drained))
	for _, w := range drained {
		copied := *w
		if len(w.AdditionalSamples) > 0 {
			copied.AdditionalSamples = append([]string(nil), w.AdditionalSamples...)
		}
		if len(w.AdditionalSamplesTruncated) > 0 {
			copied.AdditionalSamplesTruncated = append([]bool(nil), w.AdditionalSamplesTruncated...)
		}
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FirstSeenUnix != out[j].FirstSeenUnix {
			return out[i].FirstSeenUnix < out[j].FirstSeenUnix
		}
		return out[i].TemplateID < out[j].TemplateID
	})
	return out
}

// Reset atomically wipes both buffered windows and learned Drain clusters under a.mu.
func (a *Aggregator) Reset() {
	a.mu.Lock()
	a.windows = make(map[string]*model.TemplateWindow, 128)
	a.windowBytes = make(map[string]int, 128)
	a.dedicatedWindows = 0
	a.overflowBuckets = 0
	a.totalSampleBytes = 0
	a.miner.Reset()
	a.mu.Unlock()
}

// ClusterCount reports total learned template clusters in the underlying DrainMiner.
func (a *Aggregator) ClusterCount() int {
	return a.miner.ClusterCount()
}

// NormalizeTokens tokenizes msg on whitespace and masks dynamic parameter classes
// (IPv4, UUID, RFC3339 timestamp, hex blobs, numeric IDs, key=value numerics, path IDs)
// using fast linear ASCII scans (no backtracking regexes).
func NormalizeTokens(msg string) []string {
	raw := strings.Fields(msg)
	if len(raw) == 0 {
		return nil
	}
	out := make([]string, len(raw))
	for i, tok := range raw {
		out[i] = maskToken(tok)
	}
	return out
}

func maskToken(tok string) string {
	if tok == "" {
		return tok
	}

	if eqIdx := strings.IndexByte(tok, '='); eqIdx > 0 && eqIdx < len(tok)-1 {
		key := tok[:eqIdx]
		val := tok[eqIdx+1:]
		if isSimpleKey(key) {
			return key + "=" + maskScalar(val)
		}
	}

	return maskScalar(tok)
}

func maskScalar(tok string) string {
	if strings.HasPrefix(tok, "/") && !strings.Contains(tok, "..") && !strings.Contains(tok, "?") {
		return maskPathSegments(tok)
	}
	if isIPv4(tok) {
		return "<IP>"
	}
	if isUUID(tok) {
		return "<UUID>"
	}
	if isRFC3339Like(tok) {
		return "<TS>"
	}
	if isHexBlob(tok) {
		return "<HEX>"
	}
	if isNumericOrDuration(tok) {
		return "<NUM>"
	}
	return tok
}

func maskPathSegments(p string) string {
	needsMask := false
	for seg := range strings.SplitSeq(p, "/") {
		if seg != "" && (isUUID(seg) || isHexBlob(seg) || isAllDigitsStr(seg)) {
			needsMask = true
			break
		}
	}
	if !needsMask {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	first := true
	for seg := range strings.SplitSeq(p, "/") {
		if !first {
			b.WriteByte('/')
		}
		first = false
		if seg != "" {
			if isUUID(seg) {
				b.WriteString("<UUID>")
				continue
			}
			if isHexBlob(seg) {
				b.WriteString("<HEX>")
				continue
			}
			if isAllDigitsStr(seg) {
				b.WriteString("<NUM>")
				continue
			}
		}
		b.WriteString(seg)
	}
	return b.String()
}

func isSimpleKey(s string) bool {
	if len(s) == 0 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func isIPv4(s string) bool {
	if colon := strings.LastIndexByte(s, ':'); colon > 0 && isAllDigitsStr(s[colon+1:]) {
		s = s[:colon]
	}
	dots := 0
	partVal := 0
	partDigits := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if partDigits == 0 || partVal > 255 {
				return false
			}
			dots++
			partVal = 0
			partDigits = 0
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		partVal = partVal*10 + int(c-'0')
		partDigits++
		if partDigits > 3 {
			return false
		}
	}
	return dots == 3 && partDigits > 0 && partVal <= 255
}

func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !isHexChar(c) {
			return false
		}
	}
	return true
}

func isRFC3339Like(s string) bool {
	if len(s) < 19 {
		return false
	}
	return s[4] == '-' && s[7] == '-' && (s[10] == 'T' || s[10] == 't') && s[13] == ':' && s[16] == ':' && isAllDigitsStr(s[0:4])
}

func isHexBlob(s string) bool {
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		rest := s[2:]
		if len(rest) < 2 {
			return false
		}
		for i := 0; i < len(rest); i++ {
			if !isHexChar(rest[i]) {
				return false
			}
		}
		return true
	}
	if len(s) < 12 {
		return false
	}
	hasDigit := false
	hasHexAlpha := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			hasDigit = true
		} else if (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			hasHexAlpha = true
		} else {
			return false
		}
	}
	return hasDigit && hasHexAlpha
}

func isNumericOrDuration(s string) bool {
	if s == "" {
		return false
	}
	trimmed := s
	for _, suffix := range []string{"ms", "us", "ns", "kb", "mb", "gb", "s", "%"} {
		if len(trimmed) > len(suffix) && strings.HasSuffix(strings.ToLower(trimmed), suffix) {
			trimmed = trimmed[:len(trimmed)-len(suffix)]
			break
		}
	}
	if trimmed == "" {
		return false
	}
	start := 0
	if trimmed[0] == '-' || trimmed[0] == '+' {
		if len(trimmed) == 1 {
			return false
		}
		start = 1
	}
	dots := 0
	digits := 0
	for i := start; i < len(trimmed); i++ {
		c := trimmed[i]
		if c == '.' {
			dots++
			if dots > 1 {
				return false
			}
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		digits++
	}
	return digits > 0
}

func isAllDigitsStr(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHexChar(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isWildcardToken(tok string) bool {
	return tok == "<*>" || tok == "<IP>" || tok == "<NUM>" || tok == "<UUID>" || tok == "<HEX>" || tok == "<TS>"
}

func tokenSimilarity(a, b []string) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	matches := 0
	for i := range a {
		if a[i] == "<*>" || a[i] == b[i] {
			matches++
		}
	}
	return float64(matches) / float64(len(a))
}

// TemplateHash computes a deterministic 64-bit FNV-1a hex identifier using
// unambiguous length-prefixed framing so delimiter characters inside service
// or level values cannot collide.
func TemplateHash(service, level, tmpl string) string {
	h := fnv.New64a()
	writeFramed(h, service)
	writeFramed(h, level)
	writeFramed(h, tmpl)
	return fmt.Sprintf("%016x", h.Sum64())
}

// OverflowTemplateID returns a deterministic overflow bucket ID for (service, level).
func OverflowTemplateID(service, level string) string {
	return "overflow:" + TemplateHash(service, level, "<OVERFLOW>")
}

func writeFramed(h interface{ Write([]byte) (int, error) }, s string) {
	_, _ = fmt.Fprintf(h, "%d:", len(s))
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

// ShannonEntropy computes byte-level Shannon entropy in bits/byte (0.0 to 8.0).
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var ent float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

// PeakShannonEntropy computes the maximum byte-level Shannon entropy across:
// (1) the entire message, (2) any whitespace-delimited field of length >= 24 bytes,
// and (3) any dot-delimited label of length >= 24 bytes inside a long field.
// High-entropy spans delimited only by other punctuation (e.g. '=' or '/') remain
// scored at their enclosing field boundary.
func PeakShannonEntropy(msg string) float64 {
	peak := ShannonEntropy(msg)
	for field := range strings.FieldsSeq(msg) {
		if len(field) >= minEntropyTokenLen {
			if e := ShannonEntropy(field); e > peak {
				peak = e
			}
			if strings.ContainsRune(field, '.') {
				for label := range strings.SplitSeq(field, ".") {
					if len(label) >= minEntropyTokenLen {
						if e := ShannonEntropy(label); e > peak {
							peak = e
						}
					}
				}
			}
		}
	}
	return peak
}
