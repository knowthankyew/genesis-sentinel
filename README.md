# Genesis Sentinel: Local-First Tiered Log Triage & Anomaly Sidecar

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8.svg)](go.mod)
[![Zero External Dependencies](https://img.shields.io/badge/Dependencies-0%20(Stdlib%20Only)-success.svg)](docs/DECISIONS.md)
[![Stage: Phase 0 Scaffold](https://img.shields.io/badge/Stage-Phase%200%20Scaffold-yellow.svg)](docs/ROADMAP.md)

**Genesis Sentinel** is a standalone, pure-Go standard library sidecar for Project Genesis that scans local logs for malicious activity, anomalous bursts, and operator-defined interesting traffic—combining deterministic rules, information-theoretic Laplace-LK surprisal scoring, and locally trained FTaaS LoRA adapters with zero external network egress.

> **Current Status (Phase 0 Scaffold):** The core CLI, configuration loader, domain contracts, fail-closed model allowlist, loopback/auth guards, untrusted-log sanitizer, architecture specification, ADRs, and execution roadmap are implemented and unit-tested. Live ingestion, surprisal scoring, and SmolLM2 triage pipelines begin in Phases 1–3; see [docs/ROADMAP.md](docs/ROADMAP.md).

---

## Why a Tiered Funnel?

Project Genesis can ingest over one million lines per second in RAM, while local LLM inference evaluates a few completions per second. Following classic host antivirus and EDR design, Sentinel narrows raw telemetry across three tiers before invoking a language model:

1. **Tier 0 — Deterministic Rules & Template Collapse (Pure Go, Phase 1):** Reads Genesis `--data-dir` CRC32 `.seg` segments losslessly (or `/query` sliding windows), collapses repetitive lines into structural templates (Drain-style), and evaluates fast JSON IOC/regex/rate rules.
2. **Tier 1 — Laplace-LK Log Surprisal (Information-Theoretic Math, Phase 2):** Measures per-feature and joint novelty in nats using clean-room Laplace-LK equations (Hazard et al., `arXiv:2510.22809`) to surface unseen anomalies without requiring prior threat labels, with optional HTTP parity against `ml/src/surprisal-service`.
3. **Tier 2 — FTaaS-Trained LoRA Triage (SmolLM2 First, Gemma 2B Phase 5):** Evaluates only rule-flagged or high-surprisal event windows using a locally fine-tuned LoRA adapter, classifies the threat pattern, and writes structured alerts back into Genesis (`service=sentinel`) so they appear directly in Genesis's Web UI.
4. **Adaptive Feedback Loop ("Definition Updates", Phase 3):** Operator labels (`true positive` / `false positive`) accumulate into a redacted JSONL dataset and trigger periodic async FTaaS LoRA jobs—starting on **SmolLM2-Instruct** (`HuggingFaceTB/SmolLM2-135M-Instruct` default, `SmolLM2-360M-Instruct` optional step-up) for rapid local turnaround, and graduating to **Gemma 2 2B IT** in Phase 5. Experimental **BitNet b1.58** models are explicitly excluded pending upstream toolchain maturity.

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
* **Claims Are Measured, Not Asserted:** No Sentinel throughput, latency, or detection accuracy metrics will be published until produced by committed benchmarks in `docs/benchmarks/`.

---

## CLI Usage

```text
Genesis Sentinel - Local-First Tiered Log Triage & Anomaly Sidecar

Usage:
  sentinel [command] [flags]

Commands:
  watch     Watch Genesis .seg files (or /query windows) through Tier 0 -> 1 -> 2 (Phase 1+)
  scan      Run an offline scan over Genesis .seg files or JSONL exports (Phase 1+)
  feedback  Label alerts as true/false positives and export redacted JSONL (Phase 3)
  train     Submit a redacted feedback dataset to local FTaaS (SmolLM2-Instruct) (Phase 3)
  stats     Display live pipeline throughput, surprisal, and alert metrics (Phase 1+)
  burn      Purge Sentinel disk state, baselines, and unexported local queues (Phase 1+)
  data      Inspect or open Sentinel's local data directory (path | status | open)
  config    Validate and print the resolved Sentinel configuration
  version   Print the Genesis Sentinel version
  help      Show help for Genesis Sentinel
```

### Phase 0 Commands Available Today

```bash
# Build the pure-Go binary
make build

# Print version
./bin/sentinel version

# Validate and inspect resolved configuration (with auth tokens redacted)
./bin/sentinel config

# Inspect or open Sentinel's local data directory without hunting for hidden folders
./bin/sentinel data path
./bin/sentinel data status
./bin/sentinel data open
```

---

## Documentation Index

* [Execution Roadmap & Model Inventory](docs/ROADMAP.md)
* [Architecture Specification & Invariants](docs/ARCHITECTURE.md)
* [Architecture Decision Records (ADRs)](docs/DECISIONS.md)
* [Security Policy & Hostile-Log Threat Model](SECURITY.md)
* [Governance & Third-Party Attribution Notice](NOTICE.md)
* [Contributing Guidelines](CONTRIBUTING.md)
* [Changelog](CHANGELOG.md)

---

## Verification & Testing

```bash
# Run unit tests
make test

# Run race detector tests
make race

# Run linter
make lint
```

---

## License

[MIT](LICENSE)
