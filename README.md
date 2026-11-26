# Genesis Sentinel: Local-First Tiered Log Triage & Anomaly Sidecar

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/knowthankyew/genesis-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/knowthankyew/genesis-sentinel/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg)](go.mod)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-0%20(Stdlib%20Only)-success.svg)](docs/DECISIONS.md)
[![Stage: Phase 5 Complete](https://img.shields.io/badge/Stage-Phase%205%20Complete-brightgreen.svg)](docs/ROADMAP.md)

**Genesis Sentinel** (<!-- claim:sentinel_version -->`v0.6.0-phase5`<!-- /claim -->) is a standalone, pure-Go standard library sidecar for Project Genesis that scans local logs for malicious activity, anomalous bursts, and operator-defined interesting traffic—combining deterministic rules, information-theoretic Laplace-LK surprisal scoring, and locally trained FTaaS LoRA adapters with on-demand `google/gemma-2-2b-it` reasoning escalation and zero-downtime live adapter hot-swap, loopback-only by default (zero external network egress unless explicitly overridden).

> **Current Status (Phase 5 Complete — Gemma 2 2B IT Escalation & Live Adapter Hot-Swap):** All Phases 0–5 deliverables are implemented and race-tested: the Genesis Bridge (buffered lossless `.seg` CRC32 tailer + `/query` fallback), Tier 0 Drain-style template collapser with single-leaf anti-DoS bounds and RE2 syntax literal prefilters, Tier 1 pure-Go Laplace-LK log surprisal engine, Tier 2 **SmolLM2-Instruct + on-demand `google/gemma-2-2b-it` escalation routing** with bounded multi-window service correlation, **dual-slot zero-downtime live adapter hot-swap/rollback (`sentinel adapter`, `/adapter`, automatic disk reload)**, **adversarial hostile-log test suite**, **pure-Go replay benchmark harness (`cmd/sentinel-bench`)**, **side-by-side SmolLM2 vs Gemma 2 2B IT LoRA evaluation (`scripts/eval_phase5_models.py`)**, and **independent claims math recomputation**. See [docs/ROADMAP.md](docs/ROADMAP.md).

---

## Why a Tiered Funnel?

Project Genesis can ingest over one million lines per second in RAM, while local LLM inference evaluates a few completions per second. Following classic host antivirus and EDR design, Sentinel narrows raw telemetry across three tiers before invoking a language model:

1. **Tier 0 — Deterministic Rules & Template Collapse (Pure Go, Phase 1):** Reads Genesis `--data-dir` CRC32 `.seg` segments losslessly (or `/query` sliding windows), collapses repetitive lines into structural templates (Drain-style), and evaluates fast JSON IOC/regex/rate rules.
2. **Tier 1 — Laplace-LK Log Surprisal (Information-Theoretic Math, Phase 2):** Measures per-feature and joint novelty in nats using clean-room Laplace-LK equations (Hazard et al., `arXiv:2510.22809`) to surface unseen anomalies without requiring prior threat labels, with optional HTTP parity against `ml/src/surprisal-service`.
3. **Tier 2 — FTaaS-Trained LoRA Triage & On-Demand Gemma 2B Escalation (Phases 3–5):** Evaluates rule-flagged or high-surprisal event windows using a locally fine-tuned LoRA adapter on `SmolLM2-Instruct` (`:8000`) for routine triage (~310 MB–1.2 GB depending on precision/backend) and selectively escalates `HIGH`/`CRITICAL`, prompt-injection, `NEEDS-REVIEW`, primary-fallback, or multi-window correlated alerts to <!-- claim:phase5_base_model -->`google/gemma-2-2b-it`<!-- /claim --> (`:8001`), writing structured alerts back into Genesis (`service=sentinel`).
4. **Adaptive Feedback Loop & Zero-Downtime Hot-Swap (Phases 3 & 5):** Operator labels (`true positive` / `false positive`) accumulate into a redacted JSONL dataset and trigger periodic async FTaaS LoRA jobs across **SmolLM2-Instruct** (<!-- claim:default_base_model -->`HuggingFaceTB/SmolLM2-135M-Instruct`<!-- /claim --> default, <!-- claim:stepup_base_model -->`HuggingFaceTB/SmolLM2-360M-Instruct`<!-- /claim --> optional step-up) and <!-- claim:phase5_base_model -->`google/gemma-2-2b-it`<!-- /claim -->, with dual-slot live hot-swapping, `/healthz` preflight verification, rollback, and auto-reload (`sentinel adapter`). Experimental **BitNet b1.58** models remain excluded pending upstream toolchain maturity.

---

## Intentional Variance from Portfolio Pillar 1 (Disk Persistence & Transparency)

> **Transparency Notice:** The `knowthankyew` Portfolio Master Brief defines **Pillar 1 (Volatile Memory-Only Telemetry & Amnesiac State Purge)** for client reality engines, and Project Genesis defaults to volatile RAM. **Genesis Sentinel intentionally varies from the volatile-only default** for a concrete security engineering reason documented in [ADR-4](docs/DECISIONS.md):
>
> * **Why disk access is primary:** Under sudden traffic spikes or an intentional attacker log flood, volatile RAM eviction or Genesis's 512-slot `/tail` SSE drop channel can blind a real-time scanner before logs are analyzed. Tailing Genesis's `--data-dir` CRC32 `.seg` segments losslessly and persisting Sentinel's read cursor, rolling surprisal baselines, and redacted feedback queues in `~/.genesis-sentinel/` (configurable via `SENTINEL_DATA_DIR`) keeps detection reliable across bursts and restarts.
> * **Zero hidden-folder friction:** Operators never have to memorize dotfile paths or toggle hidden folders in Finder. Run `sentinel data path`, `sentinel data status`, or `sentinel data open` (opens the directory directly in Finder / your OS file manager) at any time, and run `sentinel burn` to wipe Sentinel's local state.
> * **Unchanged pillars:** Zero external network egress (loopback-only default), pure-Go zero-dependency core, strict allowlists, alert-only safety boundary, and "claims are measured, not asserted" remain strictly enforced.

---

## Core Invariants

* **Zero External Go Dependencies:** `go.mod` uses only the Go 1.24+ standard library.
* **Localhost-by-Default Zero Egress:** Listen addresses and upstream service URLs (`genesis`, `surprisal-service`, `ftaas`, `inference`) must target loopback (`127.0.0.1` / `localhost` / `::1`) unless explicitly overridden.
* **Alert-Only Safety Boundary:** Sentinel classifies, alerts, and explains. It never executes destructive host actions (firewall blocks, process kills) from model output.
* **Hostile-Log Sanitization:** Untrusted log lines are stripped of chat-template control delimiters (`<|...|>`, `<start_of_turn>`, etc.) and scanned for prompt-injection cues before reaching Tier 2.
* **Claims Are Measured, Not Asserted:** Replay benchmark figures in the table below are generated by `cmd/sentinel-bench` into [docs/benchmarks/empirical_benchmarks.json](docs/benchmarks/empirical_benchmarks.json), offline semantic embedding comparisons come from `scripts/eval_embedding_comparison.py` into [docs/benchmarks/embedding_comparison.json](docs/benchmarks/embedding_comparison.json), and Phase 5 `SmolLM2` vs `Gemma 2 2B IT` + hot-swap benchmarks come from `scripts/eval_phase5_models.py` into [docs/benchmarks/phase5_gemma_comparison.json](docs/benchmarks/phase5_gemma_comparison.json). `scripts/sync_docs.py` and `scripts/audit-claims.py` independently recompute derived ratios, rates, and gate statuses from raw counts/timings while checking recorded hardware and latency measurements for monotonicity and row-level Markdown parity.

---

## Empirical Benchmarks (Phases 4–5)

Measured via `cmd/sentinel-bench` on a 100,000-line Track A CRC32 `.seg` corpus, a full-capacity 2,000-case Laplace-LK rolling baseline, a 200-window labeled synthetic evaluation, and live loopback CPU inference against `HuggingFaceTB/SmolLM2-135M-Instruct` (see full hardware metadata and breakdown in [docs/benchmarks/2026-11-26-4d4f79c.md](docs/benchmarks/2026-11-26-4d4f79c.md)).

<!-- BEGIN_EMPIRICAL -->
| Benchmark Gate | Target | Measured Result | Status |
| :--- | :--- | :--- | :--- |
| **Tier 0+1 `.seg` Replay Throughput** | <!-- claim:bench_tier0_target_lps -->>= 50,000 lines/sec<!-- /claim --> | **<!-- claim:bench_tier0_throughput_lps -->85,346.01 lines/sec<!-- /claim -->** (<!-- claim:bench_tier0_collapse_ratio -->403.23x<!-- /claim --> collapse) | <!-- claim:bench_tier0_throughput_status -->PASSED<!-- /claim --> |
| **Lossless `.seg` Ingestion** | <!-- claim:bench_tier0_dropped_target -->0 dropped<!-- /claim --> | **<!-- claim:bench_tier0_lines_read -->100,000 read<!-- /claim -->** / <!-- claim:bench_tier0_lines_dropped -->0 dropped<!-- /claim --> | <!-- claim:bench_tier0_lossless_status -->PASSED<!-- /claim --> |
| **Tier 1 Laplace-LK Surprisal Latency** | <!-- claim:bench_tier1_p99_target_us -->< 2,000 us<!-- /claim --> | **<!-- claim:bench_tier1_p50_us -->P50 48.827 us<!-- /claim -->** / **<!-- claim:bench_tier1_p99_us -->P99 144.213 us<!-- /claim -->** | <!-- claim:bench_tier1_p99_status -->PASSED<!-- /claim --> |
| **Synthetic Detection Accuracy (Tier 0+1)** | <!-- claim:bench_detection_f1_target -->F1 >= 0.90<!-- /claim --> | **<!-- claim:bench_detection_f1 -->F1 1.0000<!-- /claim -->** (<!-- claim:bench_detection_tp -->TP=100<!-- /claim -->, <!-- claim:bench_detection_fp -->FP=0<!-- /claim -->) | <!-- claim:bench_detection_f1_status -->PASSED<!-- /claim --> |
| **Tier 2 Live SmolLM2-135M-Instruct Triage** | Fail-closed safety | **<!-- claim:bench_tier2_p50_ms -->P50 3,375.24 ms<!-- /claim -->** / **<!-- claim:bench_tier2_p99_ms -->P99 3,573.74 ms<!-- /claim -->** (<!-- claim:bench_tier2_inj_enforced -->3<!-- /claim -->/<!-- claim:bench_tier2_inj_tested -->3<!-- /claim --> safe non-benign) | <!-- claim:bench_tier2_override_status -->PASSED<!-- /claim --> |
| **Memory Footprint (Sampled Heap & RSS)** | Heap <!-- claim:bench_mem_ceiling_mb --><= 256 MB<!-- /claim --> | Sampled heap peak **<!-- claim:bench_mem_heap_peak_mb -->5.54 MB<!-- /claim -->** / RSS peak **<!-- claim:bench_mem_rss_peak_mb -->17.27 MB<!-- /claim -->** | <!-- claim:bench_mem_heap_status -->PASSED<!-- /claim --> |
| **Adversarial Hostile-Log Self-Checks** | All pass | **<!-- claim:bench_adv_passed -->9<!-- /claim -->/<!-- claim:bench_adv_total -->9<!-- /claim -->** passed | <!-- claim:bench_adv_status -->PASSED<!-- /claim --> |
<!-- END_EMPIRICAL -->

**Offline Semantic Embedding Tradeoff (`sentence-transformers/all-MiniLM-L6-v2`):** In our offline Python proxy comparison ([docs/benchmarks/embedding_comparison.json](docs/benchmarks/embedding_comparison.json)) over structural + semantically disguised `200 OK` attack logs, combining `all-MiniLM-L6-v2` with Laplace-LK changed overall F1 from **<!-- claim:embed_pure_lk_f1 -->0.7500<!-- /claim -->** to **<!-- claim:embed_hybrid_minilm_f1 -->1.0000<!-- /claim -->** at a cost of **<!-- claim:embed_slowdown_x -->347.6x<!-- /claim -->** slower median Python proxy latency and **<!-- claim:embed_rss_delta_mb -->+133.08 MB<!-- /claim -->** peak process RSS delta after PyTorch/Transformers imports—supporting our decision to keep pure-Go Laplace-LK on the Tier 1 hot path and reserve neural embeddings for optional sidecar/offline enrichment.

**Phase 5 Side-by-Side Comparison (`SmolLM2-135M-Instruct` vs `google/gemma-2-2b-it`) & Live Hot-Swap:** In isolated offline holdout benchmarks ([docs/benchmarks/2026-11-26-phase5-comparison.md](docs/benchmarks/2026-11-26-phase5-comparison.md), [phase5_gemma_comparison.json](docs/benchmarks/phase5_gemma_comparison.json)) fine-tuning both LoRA models locally on 40 balanced Sentinel telemetry examples, `google/gemma-2-2b-it` LoRA raised holdout 8-class triage accuracy from **<!-- claim:p5_smol_lora_acc -->0.3000<!-- /claim -->** (`SmolLM2-135M-Instruct` LoRA) to **<!-- claim:p5_gemma_lora_acc -->0.6500<!-- /claim -->**, reduced noisy benign false positives from **<!-- claim:p5_smol_lora_fp -->4 FP<!-- /claim -->** to **<!-- claim:p5_gemma_lora_fp -->1 FP<!-- /claim -->**, doubled multi-window correlation accuracy (**<!-- claim:p5_smol_corr_acc -->0.2500<!-- /claim -->** -> **<!-- claim:p5_gemma_corr_acc -->0.5000<!-- /claim -->**), and improved explanation quality (**<!-- claim:p5_smol_qual -->0.6350<!-- /claim -->** -> **<!-- claim:p5_gemma_qual -->0.8525<!-- /claim -->**). On CPU `float32`, Gemma 2 2B IT traded higher resource usage (**<!-- claim:p5_gemma_p50_ms -->21045.43 ms<!-- /claim -->** P50 and **<!-- claim:p5_gemma_rss_mb -->11383.68 MB<!-- /claim -->** peak RSS vs **<!-- claim:p5_smol_p50_ms -->1798.12 ms<!-- /claim -->** P50 and **<!-- claim:p5_smol_rss_mb -->1164.71 MB<!-- /claim -->** RSS for SmolLM2 LoRA), motivating Sentinel's selective escalation router (yielding **<!-- claim:p5_hybrid_acc -->0.6500<!-- /claim -->** combined accuracy). Live adapter hot-swaps measured **<!-- claim:p5_peft_warm_swap_ms -->5.2878 ms<!-- /claim -->** P50 for resident PyTorch PEFT `set_adapter` switching, while end-to-end mock-backed CLI control-plane checks measured **<!-- claim:p5_sidecar_swap_ms -->46.37 ms<!-- /claim -->** P50 for `sentinel adapter swap --verify` and **<!-- claim:p5_sidecar_rollback_ms -->41.59 ms<!-- /claim -->** for live rollback with zero sidecar restarts.

---

## CLI Usage

```text
Genesis Sentinel - Local-First Tiered Log Triage & Anomaly Sidecar

Usage:
  sentinel [command] [flags]

Commands:
  watch     Watch Genesis .seg files (or /query windows) through Tier 0 -> 1 -> 2
  scan      Run an offline scan over Genesis .seg files, raw log files, or synthetic replay
  feedback  Label alerts as true/false positives, seed starter data, and export redacted JSONL
  train     Audit/submit redacted feedback datasets to local FTaaS and activate LoRA adapters
  adapter   Inspect, hot-swap, verify, roll back, or deactivate live Tier 2 LoRA adapters
  stats     Display live pipeline throughput, surprisal, triage, and alert metrics
  burn      Purge Sentinel disk state, baselines, alert journals, and unexported feedback queues
  data      Inspect or open Sentinel's local data directory (path | status | open)
  config    Validate and print the resolved Sentinel configuration
  version   Print the Genesis Sentinel version
  help      Show help for Genesis Sentinel
```

### Quickstart

```bash
# Build the pure-Go binary
make build

# Run an offline 100,000-line Track A synthetic .seg replay scan
./bin/sentinel scan --synthetic 100000

# Watch a live Genesis instance in lossless .seg mode and emit alerts back to Genesis
./bin/sentinel watch --genesis-data-dir /path/to/genesis-segs --genesis-tcp 127.0.0.1:9000

# Generate a balanced, PII-free starter triage dataset (+ holdout validation split)
./bin/sentinel feedback seed --per-class 10 --val-per-class 2

# Label a captured alert as false positive or true positive (PII/secrets scrubbed automatically)
./bin/sentinel feedback alerts --limit 10
./bin/sentinel feedback add --alert-id sentinel-1763997000-1 --label fp

# Dry-run FTaaS surprisal preflight audit, then train & activate a SmolLM2-135M-Instruct LoRA adapter
./bin/sentinel train submit --seed-per-class 10 --audit-only
./bin/sentinel train submit --seed-per-class 10 --wait --activate --sentinel-http http://127.0.0.1:8090

# Run Tier 2 local LoRA triage with on-demand Gemma 2 2B IT escalation during watch
./bin/sentinel watch --genesis-data-dir /path/to/genesis-segs --triage-mode http \
  --escalation-mode http --escalation-inference-http http://127.0.0.1:8001 --escalation-policy high_critical

# Live dual-slot adapter hot-swap, /healthz check, rollback, and inspection (zero restart)
./bin/sentinel adapter swap --slot escalation --adapter-path artifacts/gemma-v2/model_adapters --verify --enable --sentinel-http http://127.0.0.1:8090
./bin/sentinel adapter rollback --slot escalation --verify --sentinel-http http://127.0.0.1:8090
./bin/sentinel adapter status --sentinel-http http://127.0.0.1:8090
./bin/sentinel adapter history --sentinel-http http://127.0.0.1:8090

# Inspect live Sentinel stats or open Sentinel's local data directory
./bin/sentinel stats
./bin/sentinel data status
./bin/sentinel data open

# Purge Sentinel local state (cursors, baselines, alert journals, unexported feedback queues)
./bin/sentinel burn -y
```

---

## Documentation Index

* [Execution Roadmap & Model Inventory](docs/ROADMAP.md)
* [Architecture Specification & Invariants](docs/ARCHITECTURE.md)
* [Architecture Decision Records (ADRs)](docs/DECISIONS.md)
* [When to Use Genesis Sentinel (Alternatives)](docs/ALTERNATIVES.md)
* [Security Policy & Hostile-Log Threat Model](SECURITY.md)
* [Governance & Third-Party Attribution Notice](NOTICE.md)
* [Contributing Guidelines](CONTRIBUTING.md)
* [Empirical Benchmark Report (Phases 4–5)](docs/benchmarks/2026-11-26-4d4f79c.md) & [JSON Artifact](docs/benchmarks/empirical_benchmarks.json)
* [Phase 5 Model Comparison (`SmolLM2` vs `Gemma 2 2B IT`) & Hot-Swap Report](docs/benchmarks/2026-11-26-phase5-comparison.md) & [JSON Artifact](docs/benchmarks/phase5_gemma_comparison.json)
* [Semantic Embedding Tradeoff Experiment](docs/benchmarks/embedding_comparison.json)
* **Operational Service Units:** [macOS `launchd` plist](deploy/launchd/com.knowthankyew.genesis-sentinel.plist) &bull; [Linux `systemd` unit](deploy/systemd/genesis-sentinel.service) &bull; [Docker Compose example](deploy/docker-compose.example.yml) &bull; [Dockerfile](Dockerfile)
* [Changelog](CHANGELOG.md)

---

## Verification & Testing

```bash
# Build sentinel and sentinel-bench pure-Go binaries
make build

# Run offline Tier 0+1 benchmark verification (writes to untracked bin/bench-local/; skips Tier 2)
make bench

# Regenerate governed docs/benchmarks/ artifacts against a running loopback Tier 2 inference server
# (overwrites docs/benchmarks/empirical_benchmarks.json and dated Markdown report)
make bench-publish INFERENCE_HTTP=http://127.0.0.1:8000

# Run unit tests
make test

# Run race detector tests
make race

# Run Go vet / static checks
make lint

# Run claims, benchmark math recomputation, zero-dependency, diagram freshness & SBOM audit
make audit

# Regenerate deterministic CycloneDX 1.5 SBOM (bom.json)
make sbom
```

---

## License

[MIT](LICENSE)
