package surprisal

import (
	"math"
	"testing"
)

// Reference values generated directly from ml/src/surprisal-service/service.py
// (Hazard et al., arXiv:2510.22809 Equations 4, 6, 7, 8) to verify cross-repo
// numerical parity within 1e-6 nats without requiring Python at test runtime.
const parityTolerance = 1e-6

func assertClose(t *testing.T, label string, got, want float64) {
	t.Helper()
	// Negated <= rejects NaN (whereas math.Abs(NaN) > tol evaluates to false).
	if !(math.Abs(got-want) <= parityTolerance) {
		t.Errorf("%s = %.15f, want %.15f (diff=%g)", label, got, want, math.Abs(got-want))
	}
}

func TestLukaszykKarmowskiParityWithPythonService(t *testing.T) {
	cases := []struct {
		d, delta, want float64
	}{
		{0.0, 0.25, 0.375},
		{0.0, 1.0, 1.5},
		{0.5, 0.25, 0.584584552022883},
		{1.0, 1.0, 1.7357588823428847},
		{2.5, 0.5, 2.5134758939981707},
		{10.0, 2.0, 10.053903575992683},
		{50.0, 0.25, 50.0},
	}

	for _, tc := range cases {
		got := LukaszykKarmowskiDiff(tc.d, tc.delta)
		assertClose(t, "LukaszykKarmowskiDiff", got, tc.want)
	}
}

func TestMarginalSurprisalContParityWithPythonService(t *testing.T) {
	cases := []struct {
		x1, x2, delta, want float64
	}{
		{10.0, 10.0, 1.0, 0.0},
		{10.0, 11.0, 1.0, 0.23575888234288467},
		{10.0, 15.0, 1.0, 3.5269517879963415},
		{0.0, 5.0, 0.25, 18.500000023703265},
		{3.2, 7.8, 0.75, 4.643239975814223},
	}

	for _, tc := range cases {
		got := MarginalSurprisalCont(tc.x1, tc.x2, tc.delta)
		assertClose(t, "MarginalSurprisalCont", got, tc.want)
	}
}

func TestJointCaseSurprisalAndKNNParityWithPythonService(t *testing.T) {
	rawCases := []map[string]float64{
		{"prompt_len": 80.0, "prompt_ent": 3.50, "prompt_sym": 0.10, "completion_cnt": 2.0},
		{"prompt_len": 85.0, "prompt_ent": 3.60, "prompt_sym": 0.11, "completion_cnt": 2.1},
		{"prompt_len": 82.0, "prompt_ent": 3.55, "prompt_sym": 0.10, "completion_cnt": 2.0},
		{"prompt_len": 90.0, "prompt_ent": 3.70, "prompt_sym": 0.12, "completion_cnt": 2.3},
		{"prompt_len": 78.0, "prompt_ent": 3.45, "prompt_sym": 0.09, "completion_cnt": 1.9},
	}
	contKeys := []string{"prompt_len", "prompt_ent", "prompt_sym", "completion_cnt"}
	nomKeys := []string{"tag"}

	devs := ComputeDeviations(rawCases, contKeys)
	wantDevs := map[string]float64{
		"prompt_len":     3.6,
		"prompt_ent":     0.25,
		"prompt_sym":     0.25,
		"completion_cnt": 0.25,
	}
	for k, want := range wantDevs {
		assertClose(t, "deviation["+k+"]", devs[k], want)
	}

	baseline := make([]CaseVector, len(rawCases))
	for i, c := range rawCases {
		baseline[i] = CaseVector{Continuous: c, Nominal: map[string]string{"tag": "INFO"}}
	}

	queryNormal := CaseVector{
		Continuous: map[string]float64{"prompt_len": 83.0, "prompt_ent": 3.58, "prompt_sym": 0.105, "completion_cnt": 2.05},
		Nominal:    map[string]string{"tag": "INFO"},
	}
	queryAnomalous := CaseVector{
		Continuous: map[string]float64{"prompt_len": 320.0, "prompt_ent": 5.85, "prompt_sym": 0.42, "completion_cnt": 7.50},
		Nominal:    map[string]string{"tag": "ERROR"},
	}

	wantNormalPairwise := []float64{
		0.20178983613219859,
		0.08723001191993807,
		0.03284404332509938,
		1.0914787972789797,
		0.5911953039308677,
	}
	wantAnomalousPairwise := []float64{
		96.4421793823298,
		94.2320127837516,
		95.68672727791899,
		91.6224645585288,
		97.61966116788304,
	}

	normalScores := make([]float64, len(baseline))
	anomScores := make([]float64, len(baseline))
	for i, b := range baseline {
		sNorm, _ := CaseSurprisal(queryNormal, b, devs, contKeys, nomKeys)
		normalScores[i] = sNorm
		assertClose(t, "normal pairwise", sNorm, wantNormalPairwise[i])

		sAnom, _ := CaseSurprisal(queryAnomalous, b, devs, contKeys, nomKeys)
		anomScores[i] = sAnom
		assertClose(t, "anomalous pairwise", sAnom, wantAnomalousPairwise[i])
	}

	assertClose(t, "normal kNN-3", KNNMean(normalScores, 3), 0.10728796379241201)
	assertClose(t, "anomalous kNN-3", KNNMean(anomScores, 3), 93.84706820673313)
}

func TestMathSanitizesNonFiniteAndZeroDelta(t *testing.T) {
	if got := LukaszykKarmowskiDiff(math.NaN(), 0); math.IsNaN(got) || math.IsInf(got, 0) || got <= 0 {
		t.Fatalf("unexpected LukaszykKarmowskiDiff(NaN, 0) = %v", got)
	}
	if got := MarginalSurprisalCont(math.Inf(1), 1.0, 0); got != 0 {
		t.Fatalf("expected 0 for Inf input, got %v", got)
	}
	if got := MarginalSurprisalCont(1.0, 1.0, -5.0); got != 0 {
		t.Fatalf("expected 0 for identical inputs with negative delta, got %v", got)
	}
	if got := MarginalSurprisalNom("INFO", "INFO"); got != 0 {
		t.Fatalf("expected 0 for equal nominal values, got %v", got)
	}
	if got := MarginalSurprisalNom("INFO", "ERROR"); got != NominalMismatchNats {
		t.Fatalf("expected %v for mismatched nominal values, got %v", NominalMismatchNats, got)
	}
}
