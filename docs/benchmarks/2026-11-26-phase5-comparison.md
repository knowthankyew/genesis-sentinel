# Phase 5 Empirical Model Comparison: SmolLM2-135M-Instruct vs Gemma 2 2B IT (a676346)

- **Date:** 2026-11-27T01:27:00Z
- **Commit:** `a676346`
- **Platform:** `Darwin x86_64` (`Intel(R) Core(TM) i9-9880H CPU @ 2.30GHz`, `16` logical cores, `torch_threads=8`) | `Python 3.12.1` | `torch 2.2.2` | `peft 0.21.2` | `cpu float32`
- **Dataset:** 40 balanced training windows (8 classes) / 20 unseen holdout windows (5 benign-cohort windows: 1 LOW control + 4 Tier-1 FP traps, 13 attacks incl. 4 correlated chains & 2 injections, 2 ambiguous)
- **Isolation:** `ru_maxrss_peak_subprocess_post_import` across fresh subprocesses per model (`warmup_samples_excluded=1`, binary `go build ./cmd/sentinel @ a676346` sha256=`b33461260e94bd72`)

## Side-by-Side Triage Accuracy, Quality, Footprint & Latency

| Tier / Model | Format Compliance | Class Accuracy | Benign Error (Rate) | Correlated Accuracy | MITRE Accuracy | Explanation Quality | Peak RSS (Delta) | P50 Latency | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `SmolLM2-135M-Instruct` (Base) | 0.0000 | 0.0000 (0/20) | 5 (1.0000) | 0.0000 | 0.0000 | 0.0000 | 991.16 MB (+792.40) | 1037.72 ms | 1027.18 ms |
| `SmolLM2-135M-Instruct` (LoRA) | 1.0000 | 0.3000 (6/20) | 4 (0.8000) | 0.2500 | 0.2308 | 0.6350 | 990.96 MB (+792.41) | 1916.64 ms | 2009.80 ms |
| `google/gemma-2-2b-it` (Base) | 0.6000 | 0.1000 (2/20) | 4 (0.8000) | 0.2500 | 0.0000 | 0.5650 | 10883.33 MB (+10684.66) | 29924.94 ms | 29344.30 ms |
| `google/gemma-2-2b-it` (LoRA) | 1.0000 | 0.6500 (13/20) | 1 (0.2000) | 0.5000 | 0.1538 | 0.8525 | 10956.47 MB (+10758.28) | 22277.26 ms | 21811.33 ms |
| **Hybrid Escalation (`high_critical`, 0.9500 escalated)** | — | **0.6500 (13/20)** | **1 (0.2000)** | **0.5000** | **0.1538** | **0.8450** | Primary 990.96 MB isolated peak RSS (+ Gemma on-demand, not co-measured) | **24160.50 ms** | **22847.65 ms** |

## LoRA Fine-Tuning Provenance

- **SmolLM2-135M-Instruct LoRA:** 10 epochs (50 steps, `r=8`), loss `3.5568` -> `1.3140` in `485.32s` (adapter `1.77 MB`)
- **google/gemma-2-2b-it LoRA:** 2 epochs (16 steps, `r=8`), loss `3.1298` -> `0.9347` in `1709.61s` (adapter `12.21 MB`)

## Live Adapter Hot-Swap Benchmark

| Operation | Backend | Measured Latency |
| :--- | :--- | :---: |
| PyTorch PEFT Additional Adapter Load (`load_adapter`) | `pytorch-peft` | 231.47 ms |
| PyTorch PEFT Resident Adapter Switch (`set_adapter` P50 / Max) | `pytorch-peft` | 5.9823 ms / 6.4394 ms |
| Sentinel Sidecar CLI Swap (`sentinel adapter swap --verify`, P50 / Max) | `mock-inference-healthz` | 36.84 ms / 40.75 ms |
| Sentinel Sidecar CLI Rollback (`sentinel adapter rollback --verify`) | `mock-inference-healthz` | 38.46 ms |

## Conclusion

In offline side-by-side holdout evaluation, Gemma-2B-IT LoRA improved holdout triage accuracy from 0.3000 (SmolLM2-135M-Instruct LoRA) to 0.6500, moved benign-cohort errors from 4 to 1, changed multi-window correlation accuracy from 0.2500 to 0.5000, and moved explanation quality from 0.6350 to 0.8525. At P50 per-incident latency, Gemma-2B-IT took 22277.26 ms vs 1916.64 ms (11.62x slower on CPU), while selective escalation replay routed 95.00% of alerts to Gemma-2B-IT for 0.6500 combined accuracy at 22847.65 ms blended replayed mean latency (4.75% slower replayed mean generation latency than always running Gemma-2B-IT), with resident PEFT hot-swaps completing in 5.9823 ms P50.
