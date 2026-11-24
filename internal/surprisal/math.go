package surprisal

import (
	"math"
	"sort"
)

// Clean-room mathematical constants matching ml/src/surprisal-service/service.py
// (adapted from Hazard et al., arXiv:2510.22809, Equations 4, 6, 7, 8).
const (
	// MinDeviationFloor prevents division by zero or unstable divergence when baseline
	// values are nearly identical, matching max(mad, 0.25) in service.py.
	MinDeviationFloor = 0.25
	// NominalMismatchNats is the marginal surprisal penalty (nats) when two nominal
	// feature values differ, matching marginal_surprisal_nom in service.py.
	NominalMismatchNats = 2.5
	// DefaultKNeighbors is the k-NN neighborhood size averaged for anomaly scoring.
	DefaultKNeighbors = 3
	// DefaultWarmupMinCases is the minimum number of baseline windows learned before
	// Tier 1 flags anomalies (prevents cold-start alert storms).
	DefaultWarmupMinCases = 20
	// DefaultMaxCandidateCases bounds pairwise baseline evaluations per window,
	// matching MAX_ANOMALY_CANDIDATES = 120 in service.py.
	DefaultMaxCandidateCases = 120
	// DefaultBaselineWindowSize is the default rolling baseline ring buffer capacity.
	DefaultBaselineWindowSize = 2000
	// MaxBaselineWindowSize caps rolling baseline capacity so valid snapshots fit safely
	// within MaxBaselineSnapshotBytes (16 MiB) on disk.
	MaxBaselineWindowSize = 10000
	// DefaultThresholdNats is the default Tier 1 surprisal threshold in nats.
	DefaultThresholdNats = 5.0
	// MaxBaselineSnapshotBytes bounds disk reads when loading baseline.json.
	MaxBaselineSnapshotBytes = 16 * 1024 * 1024 // 16 MiB
)

// CaseVector is a generic feature container used for cross-repo numerical parity
// verification against ml/src/surprisal-service/service.py.
type CaseVector struct {
	Continuous map[string]float64
	Nominal    map[string]string
}

// ComputeDeviations computes empirical Substitutability Deviations (delta) via Mean
// Absolute Deviation (MAD) around the sample mean for each key in keys, floored at
// MinDeviationFloor (0.25). Uses max-magnitude scaling to prevent float64 overflow on
// extreme finite ranges (e.g. [-1e308, 1e308]) and ignores non-finite values safely.
func ComputeDeviations(cases []map[string]float64, keys []string) map[string]float64 {
	deviations := make(map[string]float64, len(keys))
	if len(cases) == 0 {
		return deviations
	}
	for _, k := range keys {
		var scale float64
		var count int
		for _, c := range cases {
			v := c[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			if av := math.Abs(v); av > scale {
				scale = av
			}
			count++
		}
		if count == 0 || scale == 0 {
			deviations[k] = MinDeviationFloor
			continue
		}
		var sumScaled float64
		for _, c := range cases {
			v := c[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			sumScaled += v / scale
		}
		meanScaled := sumScaled / float64(count)
		var absSumScaled float64
		for _, c := range cases {
			v := c[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			absSumScaled += math.Abs((v / scale) - meanScaled)
		}
		mad := (absSumScaled / float64(count)) * scale
		if mad < MinDeviationFloor || math.IsNaN(mad) || math.IsInf(mad, 0) {
			mad = MinDeviationFloor
		}
		deviations[k] = mad
	}
	return deviations
}

// LukaszykKarmowskiDiff implements Equation 4: Lukaszyk-Karmowski expected distance
// under Laplace uncertainty with substitutability deviation delta:
//
//	E_LK(d, delta) = d + 0.5 * exp(-d / delta) * (3*delta + d)
//
// Evaluated in normalized units u = d / delta so extreme finite inputs
// (e.g. d = delta = 5e307) do not overflow intermediate 3*delta + d sums.
func LukaszykKarmowskiDiff(d, delta float64) float64 {
	if math.IsNaN(d) || math.IsInf(d, 0) {
		d = 0
	}
	if d < 0 {
		d = -d
	}
	if math.IsNaN(delta) || math.IsInf(delta, 0) || delta < MinDeviationFloor {
		delta = MinDeviationFloor
	}
	u := d / delta
	if math.IsInf(u, 0) || math.IsNaN(u) {
		// Limiting correction for d/delta -> +Inf is 0.
		return d
	}
	corr := 0.5 * math.Exp(-u) * (3.0 + u) * delta
	if math.IsNaN(corr) {
		return d
	}
	if math.IsInf(corr, 1) {
		return math.MaxFloat64
	}
	return saturatingAdd(d, corr)
}

// MarginalSurprisalCont implements Equation 6: continuous marginal surprisal in nats
// with the Lukaszyk-Karmowski self-distance (1.5 * delta) subtracted and clamped >= 0.
// Evaluated in dimensionless normalized units u = |x1 - x2| / delta via max-magnitude
// scaling so extreme finite ranges (e.g. x1=1e308, x2=-1e308, delta=1e308) do not overflow:
//
//	S_cont(u) = max(0, u + 0.5 * exp(-u) * (3 + u) - 1.5)
func MarginalSurprisalCont(x1, x2, delta float64) float64 {
	if math.IsNaN(x1) || math.IsInf(x1, 0) || math.IsNaN(x2) || math.IsInf(x2, 0) {
		return 0
	}
	if math.IsNaN(delta) || math.IsInf(delta, 0) || delta < MinDeviationFloor {
		delta = MinDeviationFloor
	}
	if x1 == x2 {
		return 0
	}
	scale := math.Max(math.Abs(x1), math.Abs(x2))
	if delta > scale {
		scale = delta
	}
	if scale == 0 {
		return 0
	}
	scaledDiff := math.Abs((x1 / scale) - (x2 / scale))
	scaledDelta := delta / scale
	if scaledDelta == 0 {
		return math.MaxFloat64
	}
	u := scaledDiff / scaledDelta
	if math.IsNaN(u) || math.IsInf(u, 0) {
		return math.MaxFloat64
	}
	s := u + 0.5*math.Exp(-u)*(3.0+u) - 1.5
	if s < 0 || math.IsNaN(s) {
		return 0
	}
	if math.IsInf(s, 0) {
		return math.MaxFloat64
	}
	return s
}

// MarginalSurprisalNom implements Equation 7: nominal marginal surprisal in nats.
// Returns 0.0 on exact equality and NominalMismatchNats (2.5) on mismatch.
func MarginalSurprisalNom(val1, val2 string) float64 {
	if val1 == val2 {
		return 0
	}
	return NominalMismatchNats
}

// CaseSurprisal implements Equation 8: total joint surprisal (nats) between two
// generic CaseVectors across active continuous and nominal keys, returning both the
// total joint surprisal and per-feature marginal contributions.
func CaseSurprisal(c1, c2 CaseVector, deviations map[string]float64, contKeys, nomKeys []string) (float64, map[string]float64) {
	contribs := make(map[string]float64, len(contKeys)+len(nomKeys))
	var total float64
	for _, k := range contKeys {
		delta, ok := deviations[k]
		if !ok || delta < MinDeviationFloor {
			delta = MinDeviationFloor
		}
		m := MarginalSurprisalCont(c1.Continuous[k], c2.Continuous[k], delta)
		contribs[k] = m
		total = saturatingAdd(total, m)
	}
	for _, k := range nomKeys {
		m := MarginalSurprisalNom(c1.Nominal[k], c2.Nominal[k])
		contribs[k] = m
		total = saturatingAdd(total, m)
	}
	return total, contribs
}

// KNNMean returns the overflow-safe mean of the k smallest finite values in scores
// (matching statistics.mean(sorted(surprisals)[:min(k, len(surprisals))]) in service.py).
// Uses max-magnitude scaling so both same-sign and opposite-sign extreme finite inputs
// (e.g. [1e308, 1e308] and [-1e308, 1e308]) remain exact and finite.
func KNNMean(scores []float64, k int) float64 {
	if len(scores) == 0 || k <= 0 {
		return 0
	}
	cp := make([]float64, 0, len(scores))
	for _, s := range scores {
		if !math.IsNaN(s) && !math.IsInf(s, 0) {
			cp = append(cp, s)
		}
	}
	if len(cp) == 0 {
		return 0
	}
	sort.Float64s(cp)
	if k > len(cp) {
		k = len(cp)
	}
	var scale float64
	for i := 0; i < k; i++ {
		if av := math.Abs(cp[i]); av > scale {
			scale = av
		}
	}
	if scale == 0 {
		return 0
	}
	var sumScaled float64
	for i := 0; i < k; i++ {
		sumScaled += cp[i] / scale
	}
	return (sumScaled / float64(k)) * scale
}

// saturatingAdd adds two nonnegative finite floats, saturating at math.MaxFloat64
// instead of overflowing to +Inf (which would poison downstream averaging with Inf-Inf=NaN).
func saturatingAdd(a, b float64) float64 {
	if math.IsNaN(a) || a < 0 {
		a = 0
	}
	if math.IsNaN(b) || b < 0 {
		b = 0
	}
	if math.IsInf(a, 0) || math.IsInf(b, 0) || b > math.MaxFloat64-a {
		return math.MaxFloat64
	}
	return a + b
}

func sanitizeFinite(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}
