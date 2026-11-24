package template

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
)

const (
	// DefaultMaxClusters bounds unique template clusters in RAM to prevent memory exhaustion
	// under adversarial random-token log floods.
	DefaultMaxClusters = 4096
	// DefaultMaxWindows bounds distinct TemplateWindow entries retained between Flush calls.
	DefaultMaxWindows = 4096
	// DefaultSimilarityThreshold is the Drain token match ratio required to merge into an existing cluster.
	DefaultSimilarityThreshold = 0.50
	// DefaultMaxDepth is the fixed prefix-tree token depth before cluster leaf lookup.
	DefaultMaxDepth = 2
	// minEntropyTokenLen is the minimum token length checked for whitespace/dot-delimited entropy peaks.
	minEntropyTokenLen = 24
	// maxAdditionalSamples bounds extra signature-evidence samples retained per TemplateWindow.
	maxAdditionalSamples = 16
	// maxOverflowBuckets bounds distinct (service, level) overflow windows when at maxWindows.
	maxOverflowBuckets = 256
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
// structural templates with bounded RAM even under adversarial token floods.
type DrainMiner struct {
	mu                  sync.Mutex
	roots               map[drainRootKey]*drainNode
	maxClusters         int
	clusterCount        int
	similarityThreshold float64
}

// NewDrainMiner creates a Drain-style template miner with safe memory bounds.
func NewDrainMiner(maxClusters int, similarityThreshold float64) *DrainMiner {
	if maxClusters <= 0 {
		maxClusters = DefaultMaxClusters
	}
	if similarityThreshold <= 0 || similarityThreshold > 1 {
		similarityThreshold = DefaultSimilarityThreshold
	}
	return &DrainMiner{
		roots:               make(map[drainRootKey]*drainNode, 64),
		maxClusters:         maxClusters,
		similarityThreshold: similarityThreshold,
	}
}

// ExtractTemplate normalizes msg into masked tokens, merges it into the Drain prefix
// tree for (service, level), and returns (stableTemplateID, templateString, overflowed).
// Once maxClusters is reached, lookup continues across existing clusters without allocating
// any new tree nodes; unmatched events return a bounded overflow ID.
func (m *DrainMiner) ExtractTemplate(service, level, msg string) (string, string, bool) {
	tokens := NormalizeTokens(msg)
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

	atCap := m.clusterCount >= m.maxClusters

	root, ok := m.roots[rootKey]
	if !ok {
		if atCap {
			tmpl := strings.Join(tokens, " ")
			return OverflowTemplateID(service, level), tmpl, true
		}
		root = &drainNode{}
		m.roots[rootKey] = root
	}

	node := root
	depth := min(DefaultMaxDepth, len(tokens))
	for i := 0; i < depth; i++ {
		tok := tokens[i]
		if isWildcardToken(tok) {
			tok = "<*>"
		}
		if node.children == nil {
			if atCap {
				tmpl := strings.Join(tokens, " ")
				return OverflowTemplateID(service, level), tmpl, true
			}
			node.children = make(map[string]*drainNode, 8)
		}
		child, exists := node.children[tok]
		if !exists {
			if atCap {
				// Fallback read-only check into wildcard branch if one already exists.
				wild, hasWild := node.children["<*>"]
				if !hasWild {
					tmpl := strings.Join(tokens, " ")
					return OverflowTemplateID(service, level), tmpl, true
				}
				child = wild
			} else if len(node.children) >= 64 {
				child, exists = node.children["<*>"]
				if !exists {
					child = &drainNode{}
					node.children["<*>"] = child
				}
			} else {
				child = &drainNode{}
				node.children[tok] = child
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
		for i := range best.tokens {
			if best.tokens[i] != tokens[i] {
				best.tokens[i] = "<*>"
			}
		}
		// Keep stable best.id even after token generalization so counts stay aggregated in one window.
		return best.id, strings.Join(best.tokens, " "), false
	}

	if atCap {
		tmpl := strings.Join(tokens, " ")
		return OverflowTemplateID(service, level), tmpl, true
	}

	copied := make([]string, len(tokens))
	copy(copied, tokens)
	tmpl := strings.Join(copied, " ")
	m.clusterCount++
	c := &drainCluster{
		id:     TemplateHash(service, level, fmt.Sprintf("cluster:%d:%s", m.clusterCount, tmpl)),
		tokens: copied,
	}
	node.clusters = append(node.clusters, c)

	return c.id, tmpl, false
}

// Reset clears all learned prefix-tree clusters (used by `sentinel burn`).
func (m *DrainMiner) Reset() {
	m.mu.Lock()
	m.roots = make(map[drainRootKey]*drainNode, 64)
	m.clusterCount = 0
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
// A single mutex coordinates Add, Flush, and Reset across both miner and window map.
type Aggregator struct {
	mu              sync.Mutex
	miner           *DrainMiner
	windows         map[string]*model.TemplateWindow
	maxWindows      int
	overflowBuckets int
}

// NewAggregator creates a window aggregator backed by a bounded DrainMiner.
func NewAggregator(maxClusters int) *Aggregator {
	maxWin := maxClusters
	if maxWin <= 0 {
		maxWin = DefaultMaxWindows
	}
	return &Aggregator{
		miner:      NewDrainMiner(maxClusters, DefaultSimilarityThreshold),
		windows:    make(map[string]*model.TemplateWindow, 128),
		maxWindows: maxWin,
	}
}

// Add folds a single LogEvent into the current window's collapsed templates and
// returns (windowID, isGlobalOverflow, peakEntropy). Both miner extraction and
// window insertion run under a.mu so Reset is atomic.
func (a *Aggregator) Add(ev model.LogEvent) (string, bool, float64) {
	ent := PeakShannonEntropy(ev.Message)

	a.mu.Lock()
	defer a.mu.Unlock()

	tmplID, tmpl, overflowed := a.miner.ExtractTemplate(ev.Service, ev.Level, ev.Message)
	isGlobalOverflow := false
	if overflowed {
		tmpl = "<OVERFLOW>"
	}

	w, exists := a.windows[tmplID]
	if !exists {
		// Enforce window count cap between flushes under adversarial random floods.
		if len(a.windows) >= a.maxWindows {
			overflowed = true
			ovID := OverflowTemplateID(ev.Service, ev.Level)
			if existingOv, ok := a.windows[ovID]; ok {
				w = existingOv
				tmplID = ovID
				exists = true
			} else if a.overflowBuckets < maxOverflowBuckets {
				a.overflowBuckets++
				tmplID = ovID
				tmpl = "<OVERFLOW>"
			} else {
				const globalOvID = "overflow:global"
				isGlobalOverflow = true
				tmplID = globalOvID
				if globalOv, ok := a.windows[globalOvID]; ok {
					w = globalOv
					exists = true
				} else {
					tmpl = "<OVERFLOW>"
				}
			}
		}
	}

	if !exists {
		svc := ev.Service
		lvl := ev.Level
		if isGlobalOverflow {
			// Keep global overflow bucket strictly unattributed so service/level rules
			// evaluate each event with its real identity rather than the first overflow event's.
			svc = "<MIXED>"
			lvl = "<MIXED>"
		}
		a.windows[tmplID] = &model.TemplateWindow{
			TemplateID:    tmplID,
			Template:      tmpl,
			Service:       svc,
			Level:         lvl,
			Count:         1,
			FirstSeenUnix: ev.Timestamp,
			LastSeenUnix:  ev.Timestamp,
			SampleLine:    ev.Message,
			SampleEntropy: ent,
		}
		return tmplID, isGlobalOverflow, ent
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

	// Retain the highest-entropy sample in SampleLine and keep a bounded best-effort
	// preview cache (up to maxAdditionalSamples) in AdditionalSamples. Deterministic
	// Tier 0 rule coverage evaluates each event at ingest time rather than relying on this cache.
	prevSample := w.SampleLine
	if ent > w.SampleEntropy {
		w.SampleEntropy = ent
		w.SampleLine = ev.Message
		if prevSample != "" && prevSample != ev.Message {
			addEvidenceSample(w, prevSample)
		}
	} else if ev.Message != w.SampleLine {
		addEvidenceSample(w, ev.Message)
	}
	return tmplID, isGlobalOverflow, ent
}

func addEvidenceSample(w *model.TemplateWindow, sample string) {
	if sample == "" || sample == w.SampleLine {
		return
	}
	for _, existing := range w.AdditionalSamples {
		if existing == sample {
			return
		}
	}
	if len(w.AdditionalSamples) < maxAdditionalSamples {
		w.AdditionalSamples = append(w.AdditionalSamples, sample)
		return
	}
	// When full, prioritize retaining samples carrying security-relevant cues over plain lines.
	if hasSecurityCue(sample) {
		for i, existing := range w.AdditionalSamples {
			if !hasSecurityCue(existing) {
				w.AdditionalSamples[i] = sample
				return
			}
		}
	}
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
	a.overflowBuckets = 0
	a.mu.Unlock()

	out := make([]model.TemplateWindow, 0, len(drained))
	for _, w := range drained {
		copied := *w
		if len(w.AdditionalSamples) > 0 {
			copied.AdditionalSamples = append([]string(nil), w.AdditionalSamples...)
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
	a.overflowBuckets = 0
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
	parts := strings.Split(p, "/")
	changed := false
	for i, seg := range parts {
		if seg == "" {
			continue
		}
		if isUUID(seg) {
			parts[i] = "<UUID>"
			changed = true
		} else if isHexBlob(seg) {
			parts[i] = "<HEX>"
			changed = true
		} else if isAllDigitsStr(seg) {
			parts[i] = "<NUM>"
			changed = true
		}
	}
	if !changed {
		return p
	}
	return strings.Join(parts, "/")
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
	for _, field := range strings.Fields(msg) {
		if len(field) >= minEntropyTokenLen {
			if e := ShannonEntropy(field); e > peak {
				peak = e
			}
			if strings.ContainsRune(field, '.') {
				for _, label := range strings.Split(field, ".") {
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
