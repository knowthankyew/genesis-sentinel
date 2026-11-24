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
// MinDeviationFloor (0.25). Non-finite values are ignored safely.
func ComputeDeviations(cases []map[string]float64, keys []string) map[string]float64 {
	deviations := make(map[string]float64, len(keys))
	if len(cases) == 0 {
		return deviations
	}
	for _, k := range keys {
		var sum float64
		var count int
		for _, c := range cases {
			v := c[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			sum += v
			count++
		}
		if count == 0 {
			deviations[k] = MinDeviationFloor
			continue
		}
		mean := sum / float64(count)
		var absSum float64
		for _, c := range cases {
			v := c[k]
			if math.IsNaN(v) || math.IsInf(v, 0) {
				continue
			}
			absSum += math.Abs(v - mean)
		}
		mad := absSum / float64(count)
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
	return d + 0.5*math.Exp(-d/delta)*(3.0*delta+d)
}

// MarginalSurprisalCont implements Equation 6: continuous marginal surprisal in nats
// with the Lukaszyk-Karmowski self-distance (1.5 * delta) subtracted and clamped >= 0:
//
//	S_cont(x1, x2, delta) = max(0, E_LK(|x1 - x2|, delta)/delta - 1.5)
func MarginalSurprisalCont(x1, x2, delta float64) float64 {
	if math.IsNaN(x1) || math.IsInf(x1, 0) || math.IsNaN(x2) || math.IsInf(x2, 0) {
		return 0
	}
	if math.IsNaN(delta) || math.IsInf(delta, 0) || delta < MinDeviationFloor {
		delta = MinDeviationFloor
	}
	d := math.Abs(x1 - x2)
	elk := LukaszykKarmowskiDiff(d, delta)
	s := (elk / delta) - 1.5
	if s < 0 || math.IsNaN(s) || math.IsInf(s, 0) {
		return 0
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
		total += m
	}
	for _, k := range nomKeys {
		m := MarginalSurprisalNom(c1.Nominal[k], c2.Nominal[k])
		contribs[k] = m
		total += m
	}
	return total, contribs
}

// KNNMean returns the mean of the k smallest finite values in scores (matching
// statistics.mean(sorted(surprisals)[:min(k, len(surprisals))]) in service.py).
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
	var sum float64
	for i := 0; i < k; i++ {
		sum += cp[i]
	}
	return sum / float64(k)
}

func sanitizeFinite(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return v
}
