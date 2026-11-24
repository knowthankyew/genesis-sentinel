package surprisal

import (
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/knowthankyew/genesis-sentinel/internal/model"
	"github.com/knowthankyew/genesis-sentinel/internal/template"
)

// Fixed feature array sizes keep hot-path Tier 1 feature extraction and scoring
// allocation-free while maintaining clear named attributions.
const (
	ContinuousFeatureCount = 8
	NominalFeatureCount    = 4

	maxServiceFeatureBytes  = 128
	maxLevelFeatureBytes    = 32
	maxTemplateFeatureBytes = 64
	maxProtoFeatureBytes    = 32
)

// ContinuousFeatureNames maps fixed continuous array indices to stable telemetry keys.
var ContinuousFeatureNames = [ContinuousFeatureCount]string{
	"log_token_count",
	"log_byte_len",
	"shannon_entropy",
	"symbol_ratio_x10",
	"log_burst_count",
	"log_interarrival_ms",
	"digit_ratio_x10",
	"upper_ratio_x10",
}

// NominalFeatureNames maps fixed nominal array indices to stable telemetry keys.
var NominalFeatureNames = [NominalFeatureCount]string{
	"service",
	"level",
	"template_class",
	"proto_class",
}

// LogFeatures holds the fixed-size continuous and nominal feature representation
// of a single collapsed Tier 0 TemplateWindow.
//
// Continuous features are scaled to a well-conditioned ~[0, 12] range so that
// MinDeviationFloor (0.25) avoids false positives on tiny benign fluctuations
// while preserving crisp separation on real length, entropy, symbol, or burst spikes.
type LogFeatures struct {
	Continuous [ContinuousFeatureCount]float64 `json:"continuous"`
	Nominal    [NominalFeatureCount]string     `json:"nominal"`
}

// ExtractFeatures derives deterministic, linear-time log-domain continuous and
// nominal features from a collapsed Tier 0 TemplateWindow.
func ExtractFeatures(w model.TemplateWindow) LogFeatures {
	var f LogFeatures

	// 1. Structural token count of template (log1p scale)
	tokCount := countWhitespaceTokens(w.Template)
	if tokCount == 0 && w.SampleLine != "" {
		tokCount = countWhitespaceTokens(w.SampleLine)
	}
	f.Continuous[0] = math.Log1p(float64(tokCount))

	// 2. Sample payload byte length (log1p scale)
	sample := w.SampleLine
	f.Continuous[1] = math.Log1p(float64(len(sample)))

	// 3. Peak Shannon entropy (0..8 bits/byte)
	ent := sanitizeFinite(w.SampleEntropy)
	if ent <= 0 && sample != "" {
		ent = sanitizeFinite(template.PeakShannonEntropy(sample))
	}
	if ent < 0 {
		ent = 0
	} else if ent > 8 {
		ent = 8
	}
	f.Continuous[2] = ent

	// 4, 7, 8. Character class ratios scaled x10 (0..10) in a single O(L) byte pass
	symRatio, digRatio, upRatio := computeCharClassRatios(sample)
	f.Continuous[3] = symRatio * 10.0
	f.Continuous[6] = digRatio * 10.0
	f.Continuous[7] = upRatio * 10.0

	// 5. Burst count per window (log1p scale)
	cnt := w.Count
	if cnt == 0 {
		cnt = 1
	}
	f.Continuous[4] = math.Log1p(float64(cnt))

	// 6. Average inter-arrival delta in milliseconds (log1p scale).
	// Normalize each endpoint timestamp individually into milliseconds while preserving
	// subsecond precision for ms/us/ns epochs so identical 100ms bursts produce the same
	// span regardless of whether they straddle a whole-second boundary.
	var interArrivalMs float64
	if cnt <= 1 {
		interArrivalMs = 1000.0
	} else {
		firstMs := normalizeFeatureTimestampMs(w.FirstSeenUnix)
		lastMs := normalizeFeatureTimestampMs(w.LastSeenUnix)
		spanMs := lastMs - firstMs
		if spanMs < 0 {
			spanMs = 0
		}
		interArrivalMs = spanMs / float64(cnt-1)
	}
	f.Continuous[5] = math.Log1p(interArrivalMs)

	// Nominal features (bounded & normalized)
	f.Nominal[0] = clampStr(strings.ToLower(strings.TrimSpace(w.Service)), maxServiceFeatureBytes)
	if f.Nominal[0] == "" {
		f.Nominal[0] = "unknown"
	}
	f.Nominal[1] = clampStr(strings.ToUpper(strings.TrimSpace(w.Level)), maxLevelFeatureBytes)
	if f.Nominal[1] == "" {
		f.Nominal[1] = "INFO"
	}
	tmplID := strings.TrimSpace(w.TemplateID)
	if tmplID == "" {
		tmplID = "<UNKNOWN>"
	}
	f.Nominal[2] = clampStr(tmplID, maxTemplateFeatureBytes)
	f.Nominal[3] = clampStr(extractProtoClass(sample), maxProtoFeatureBytes)

	return f
}

// ComputeLogDeviations computes overflow-safe per-feature MAD substitutability
// deviations across a slice of LogFeatures with zero heap allocations.
func ComputeLogDeviations(cases []LogFeatures) [ContinuousFeatureCount]float64 {
	var devs [ContinuousFeatureCount]float64
	n := len(cases)
	if n == 0 {
		for k := range devs {
			devs[k] = MinDeviationFloor
		}
		return devs
	}

	var scales [ContinuousFeatureCount]float64
	var counts [ContinuousFeatureCount]int
	for i := range cases {
		for k := 0; k < ContinuousFeatureCount; k++ {
			v := cases[i].Continuous[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			if av := math.Abs(v); av > scales[k] {
				scales[k] = av
			}
			counts[k]++
		}
	}

	var meansScaled [ContinuousFeatureCount]float64
	for i := range cases {
		for k := 0; k < ContinuousFeatureCount; k++ {
			if scales[k] == 0 {
				continue
			}
			v := cases[i].Continuous[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			meansScaled[k] += v / scales[k]
		}
	}
	for k := 0; k < ContinuousFeatureCount; k++ {
		if counts[k] > 0 && scales[k] > 0 {
			meansScaled[k] /= float64(counts[k])
		}
	}

	var absSumsScaled [ContinuousFeatureCount]float64
	for i := range cases {
		for k := 0; k < ContinuousFeatureCount; k++ {
			if scales[k] == 0 {
				continue
			}
			v := cases[i].Continuous[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			absSumsScaled[k] += math.Abs((v / scales[k]) - meansScaled[k])
		}
	}
	for k := 0; k < ContinuousFeatureCount; k++ {
		if counts[k] == 0 || scales[k] == 0 {
			devs[k] = MinDeviationFloor
			continue
		}
		mad := (absSumsScaled[k] / float64(counts[k])) * scales[k]
		if mad < MinDeviationFloor || math.IsNaN(mad) || math.IsInf(mad, 0) {
			mad = MinDeviationFloor
		}
		devs[k] = mad
	}
	return devs
}

// pairSurprisal computes joint Laplace-LK surprisal (Eq. 8) between two LogFeatures
// along with per-feature marginal contributions (continuous + nominal) with zero
// heap allocations.
func pairSurprisal(
	a, b LogFeatures,
	devs [ContinuousFeatureCount]float64,
) (float64, [ContinuousFeatureCount + NominalFeatureCount]float64) {
	var contribs [ContinuousFeatureCount + NominalFeatureCount]float64
	var total float64
	for k := 0; k < ContinuousFeatureCount; k++ {
		m := MarginalSurprisalCont(a.Continuous[k], b.Continuous[k], devs[k])
		contribs[k] = m
		total += m
	}
	for k := 0; k < NominalFeatureCount; k++ {
		m := MarginalSurprisalNom(a.Nominal[k], b.Nominal[k])
		contribs[ContinuousFeatureCount+k] = m
		total += m
	}
	return total, contribs
}

func countWhitespaceTokens(s string) int {
	count := 0
	inTok := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			inTok = false
		} else if !inTok {
			inTok = true
			count++
		}
	}
	return count
}

func computeCharClassRatios(s string) (symbolRatio, digitRatio, upperRatio float64) {
	n := len(s)
	if n == 0 {
		return 0, 0, 0
	}
	var sym, dig, up int
	for i := 0; i < n; i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			up++
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
			dig++
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
		default:
			sym++
		}
	}
	inv := 1.0 / float64(n)
	return float64(sym) * inv, float64(dig) * inv, float64(up) * inv
}

// extractProtoClass extracts a strictly structural protocol/status/facility label
// (HTTP status family or RFC syslog <PRI> facility) in linear time without regex.
func extractProtoClass(sample string) string {
	trimmed := strings.TrimSpace(sample)
	if trimmed == "" {
		return "none"
	}

	// 1. Syslog <PRI> prefix (RFC 5424 / RFC 3164): facility = pri >> 3 (0..23)
	if trimmed[0] == '<' {
		if end := strings.IndexByte(trimmed[1:], '>'); end >= 1 && end <= 3 {
			if pri, err := strconv.Atoi(trimmed[1 : 1+end]); err == nil && pri >= 0 && pri <= 191 {
				fac := pri >> 3
				return "syslog_fac_" + strconv.Itoa(fac)
			}
		}
	}

	// 2. HTTP status family when an HTTP method/version or status= token is present.
	if idx := strings.Index(trimmed, "HTTP/"); idx >= 0 {
		rest := trimmed[idx+5:]
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			after := strings.TrimLeft(rest[sp+1:], " ")
			if fam := parseHTTPStatusFamily(after); fam != "" {
				return fam
			}
		}
	}
	lower := strings.ToLower(trimmed)
	for _, key := range []string{"status=", "status:", `"status":`, "code="} {
		searchFrom := 0
		for searchFrom < len(lower) {
			rel := strings.Index(lower[searchFrom:], key)
			if rel < 0 {
				break
			}
			idx := searchFrom + rel
			searchFrom = idx + len(key)
			if key[0] != '"' && !isStatusKeyBoundary(lower, idx) {
				continue
			}
			// Slice from `lower` (same string as `idx`) so Unicode case folding that
			// expands UTF-8 byte lengths (e.g. U+023A Ⱥ) can never exceed slice bounds.
			after := strings.TrimLeft(lower[idx+len(key):], " \"")
			if fam := parseHTTPStatusFamily(after); fam != "" {
				return fam
			}
		}
	}
	if hasHTTPMethodPrefix(trimmed) {
		// Common compact access-log tail: "GET /path 403" or "POST /login 200 12ms"
		for tok := range strings.FieldsSeq(trimmed) {
			if len(tok) == 3 && tok[0] >= '1' && tok[0] <= '5' && isAllDigits(tok) {
				return "http_" + tok[:1] + "xx"
			}
		}
	}

	return "none"
}

func hasHTTPMethodPrefix(s string) bool {
	for _, m := range []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS "} {
		if strings.HasPrefix(s, m) || strings.Contains(s, `"`+m) {
			return true
		}
	}
	return false
}

func parseHTTPStatusFamily(s string) string {
	if len(s) < 3 {
		return ""
	}
	code := s[:3]
	if code[0] < '1' || code[0] > '5' || !isAllDigits(code) {
		return ""
	}
	if len(s) > 3 {
		next := s[3]
		if (next >= '0' && next <= '9') || (next >= 'a' && next <= 'z') || (next >= 'A' && next <= 'Z') {
			return ""
		}
	}
	return "http_" + code[:1] + "xx"
}

func isAllDigits(s string) bool {
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

func normalizeFeatureTimestampMs(ts int64) float64 {
	if ts <= 0 {
		return 0
	}
	if ts >= 1_000_000_000_000_000_000 { // contemporary nanoseconds (>= 1e18)
		return float64(ts) / 1_000_000.0
	}
	if ts >= 1_000_000_000_000_000 { // contemporary microseconds (>= 1e15)
		return float64(ts) / 1_000.0
	}
	if ts >= 1_000_000_000_000 { // contemporary milliseconds (>= 1e12)
		return float64(ts)
	}
	return float64(ts) * 1000.0
}

func isStatusKeyBoundary(s string, idx int) bool {
	if idx <= 0 {
		return true
	}
	prev := s[idx-1]
	return !((prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' || prev == '-')
}

// clampStr truncates s to at most maxBytes at a valid UTF-8 character boundary so
// multi-byte runes are never split into invalid UTF-8 sequences.
func clampStr(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
