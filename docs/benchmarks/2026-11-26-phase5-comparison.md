# Phase 5 Empirical Model Comparison: SmolLM2-135M-Instruct vs Gemma 2 2B IT (67706a9)

- **Date:** 2026-11-26T19:23:28Z
- **Commit:** `67706a9`
- **Platform:** `Darwin x86_64` | `Python 3.12.1` | `torch 2.2.2` | `peft 0.20.0` | `cpu float32`
- **Dataset:** 40 balanced training windows (8 classes) / 20 unseen holdout windows (5 benign FP traps, 13 attacks incl. 4 correlated chains & 2 injections, 2 ambiguous)
- **Isolation:** `ru_maxrss_peak_subprocess_post_import` across fresh subprocesses per model (`warmup_samples_excluded=1`)

## Side-by-Side Triage Accuracy, Quality, Footprint & Latency

| Tier / Model | Format Compliance | Class Accuracy | Benign FP (Rate) | Correlated Accuracy | MITRE Accuracy | Explanation Quality | Peak RSS (Delta) | P50 Latency | Mean Latency |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `SmolLM2-135M-Instruct` (Base) | 0.0000 | 0.1000 (2/20) | 5 (1.0000) | 0.0000 | 0.0000 | 0.0300 | 1164.72 MB (+790.27) | 1036.79 ms | 1026.01 ms |
| `SmolLM2-135M-Instruct` (LoRA) | 1.0000 | 0.3000 (6/20) | 4 (0.8000) | 0.2500 | 0.2308 | 0.6350 | 1164.71 MB (+790.52) | 1798.12 ms | 1916.48 ms |
| `google/gemma-2-2b-it` (Base) | 0.9500 | 0.4000 (8/20) | 4 (0.8000) | 0.5000 | 0.0000 | 0.6350 | 10301.46 MB (+9927.42) | 29011.90 ms | 28461.54 ms |
| `google/gemma-2-2b-it` (LoRA) | 1.0000 | 0.6500 (13/20) | 1 (0.2000) | 0.5000 | 0.1538 | 0.8525 | 11383.68 MB (+11009.71) | 21045.43 ms | 20816.82 ms |
| **Hybrid Escalation (`high_critical`, 0.9500 escalated)** | — | **0.6500 (13/20)** | **1 (0.2000)** | **0.5000** | **0.1538** | **0.8450** | Primary 1165 MB steady + Gemma on-demand | **22812.70 ms** | **21827.03 ms** |

## LoRA Fine-Tuning Provenance

- **SmolLM2-135M-Instruct LoRA:** 10 epochs (50 steps, `r=8`), loss `3.5568` -> `1.3140` in `454.53s` (adapter `1.77 MB`)
- **google/gemma-2-2b-it LoRA:** 2 epochs (16 steps, `r=8`), loss `3.1298` -> `0.9347` in `1576.32s` (adapter `12.21 MB`)

## Live Adapter Hot-Swap Benchmark

| Operation | Measured Latency |
| :--- | :---: |
| PyTorch PEFT Cold LoRA Mount (`from_pretrained`) | 182.91 ms |
| PyTorch PEFT Warm LRU Adapter Switch (`set_adapter` P50 / Max) | 5.2878 ms / 5.4405 ms |
| Sentinel Sidecar Preflight-Checked Live Swap (`sentinel adapter swap --verify`, P50 / Max) | 46.37 ms / 49.88 ms |
| Sentinel Sidecar Preflight-Checked Rollback (`sentinel adapter rollback --verify`) | 41.59 ms |

## Conclusion

In offline side-by-side holdout evaluation, Gemma-2B-IT LoRA improved holdout triage accuracy from 0.3000 (SmolLM2-135M-Instruct LoRA) to 0.6500, moved benign false positives from 4 to 1, changed multi-window correlation accuracy from 0.2500 to 0.5000, and moved explanation quality from 0.6350 to 0.8525. At P50 per-incident latency, Gemma-2B-IT took 21045.43 ms vs 1798.12 ms (11.70x slower on CPU), while selective escalation routed 95.00% of alerts to Gemma-2B-IT for 0.6500 combined accuracy at 21827.03 ms blended mean latency (0.95x faster mean turnaround than always running Gemma-2B-IT), with cached PEFT hot-swaps completing in 5.2878 ms P50.
