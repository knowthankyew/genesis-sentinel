<!-- diagram-meta
last-validated: 2026-11-24
validated-commit: initial-scaffold
covers: [cmd/, internal/]
-->

# Genesis Sentinel Architecture Specification (`knowthankyew/genesis-sentinel`)

**Genesis Sentinel** is a standalone, pure-Go standard library sidecar (`go.mod` contains zero external dependencies) that monitors Project Genesis log streams through a three-tier local detection funnel—deterministic rules and template collapsing, Laplace-LK surprisal anomaly scoring, and FTaaS-trained LoRA triage—with zero external network egress.

---

## 1. End-to-End Detection & Feedback Pipeline

```mermaid
flowchart TD
    subgraph GenesisHost["Project Genesis (127.0.0.1)"]
        Segs["Genesis Disk Segments (.seg)<br/>or HTTP /query Window"]
        GenSink["Genesis TCP Ingest (:9000)<br/>service=sentinel Alerts"]
    end

    subgraph SentinelCore["Genesis Sentinel Sidecar (Pure Go Stdlib)"]
        Entry["CLI Entrypoint<br/><code>cmd/sentinel/main.go</code>"]
        CLI["Subcommand Router<br/><code>internal/cli/cli.go</code>"]
        Cfg["Config & Invariant Guard<br/><code>internal/config/config.go</code>"]
        Sec["Loopback, Auth & Prompt Sanitizer<br/><code>internal/security/security.go</code>"]
        Types["Tier Contracts & Model Allowlist<br/><code>internal/model/types.go</code>"]
        T0["Tier 0: Ingest, Rules & Drain Templates<br/>(Planned: Phase 1)"]
        T1["Tier 1: Laplace-LK Log Surprisal<br/>(Planned: Phase 2)"]
        T2["Tier 2: Triage Client & Feedback Queue<br/>(Planned: Phase 3)"]
    end

    subgraph MLHost["Event-Driven FTaaS / ml (127.0.0.1)"]
        SurpSvc["surprisal-service (:5200)<br/>Preflight Ablation & Parity"]
        FTaaS["FTaaS API & PyTorch Worker (:5100)<br/>SmolLM2 LoRA (Ph. 3) / Gemma 2B (Ph. 5)"]
        Infer["Local Inference Engine (:8000)<br/>Dynamic LoRA / Edge ONNX"]
    end

    Entry --> CLI --> Cfg --> Sec
    Cfg --> Types
    Segs -->|"Lossless .seg / /query"| T0
    T0 -->|"TemplateWindow + RuleHits"| T1
    T1 <-->|"Optional HTTP Parity"| SurpSvc
    T1 -->|"Anomalous / Flagged Windows"| Sec
    Sec -->|"Sanitized Framed Prompt"| T2
    T2 <-->|"Local Loopback Triage"| Infer
    T2 -->|"Structured Alert (Alert-Only)"| GenSink
    T2 -->|"Redacted Feedback JSONL"| FTaaS
    FTaaS <-->|"Dataset Preflight Ablation"| SurpSvc
    FTaaS -.->|"Refreshed LoRA Adapter"| Infer
```

---

## 2. Phase 0 Implemented Subsystems

1. **CLI & Configuration Hierarchy (`cmd/sentinel/main.go`, `internal/cli/cli.go`, `internal/config/config.go`):**
   - Mirrors Genesis's single-binary subcommand router (`watch`, `scan`, `feedback`, `train`, `stats`, `burn`, `config`, `version`, `help`).
   - Merges compiled safe defaults -> `sentinel.json` -> `SENTINEL_*` environment variables -> CLI flags.
   - Redacts sensitive auth tokens automatically when rendering resolved config via `sentinel config`.
2. **Domain Contracts & Model Governance (`internal/model/types.go`):**
   - Mirrors Genesis's `parser.LogEntry` JSON contract via `LogEvent`.
   - Defines explicit wire contracts between tiers: `TemplateWindow`, `RuleHit`, `SurprisalScore`, `TriageVerdict`, and `FeedbackRecord`.
   - Enforces a fail-closed base model allowlist (`ValidateBaseModel`): SmolLM2 (`HuggingFaceTB/SmolLM2-135M`, `SmolLM2-135M-Instruct`, `SmolLM2-360M-Instruct`) for Phases 0–4, `google/gemma-2-2b-it` reserved for Phase 5, and explicit rejection (`ErrExperimentalModelExcluded`) of experimental BitNet models.
3. **Zero-Egress & Hostile-Log Security Layer (`internal/security/security.go`):**
   - Constant-time Bearer token middleware (`crypto/subtle.ConstantTimeCompare`) matching Genesis's HTTP authentication posture.
   - Strict loopback endpoint validator (`IsLoopbackEndpoint`) blocking non-loopback upstream URLs (`genesis`, `surprisal-service`, `ftaas`, `inference`) unless `allow_remote_endpoints=true` is explicitly configured.
   - Untrusted log sanitizer (`SanitizeUntrustedLogText`) neutralizing LLM chat-template delimiters (`<|...|>`, `<start_of_turn>`, `<end_of_turn>`, `<s>`, `</s>`), stripping unsafe ASCII control bytes, bounding UTF-8 byte length, and surfacing semantic prompt-injection heuristic signals as structured verdict metadata.

---

## 3. Feedback & Adapter Refresh Sequence (Phase 3 Target)

```mermaid
sequenceDiagram
    participant Op as Local Operator
    participant Sent as Genesis Sentinel
    participant Surp as surprisal-service (:5200)
    participant FTaaS as FTaaS API & Worker (:5100)
    participant Inf as Local Inference (:8000)

    Op->>Sent: sentinel feedback --alert-id ID --label BENIGN_CRON
    Sent->>Sent: Scrub secrets/PII (RequireRedaction=true) & append JSONL
    Op->>Sent: sentinel train --base-model HuggingFaceTB/SmolLM2-135M
    Sent->>FTaaS: POST /api/v1/jobs (redacted JSONL, surprisalPreflight=true)
    FTaaS->>Surp: POST /v1/audit/dataset (redundancy ablation & anomaly audit)
    Surp-->>FTaaS: Cleaned weighted records
    FTaaS->>FTaaS: Async PyTorch PEFT LoRA training (~2-4 min on SmolLM2)
    FTaaS-->>Sent: Job Completed (adapterPath + SHA-256)
    Sent->>Inf: Mount refreshed adapter for subsequent Tier 2 triage
```

---

## 4. Non-Negotiable Architectural Invariants

1. **Zero External Go Dependencies:** `go.mod` maintains zero `require` directives for the core Sentinel binary.
2. **Localhost-by-Default Zero Egress:** All listeners and upstream service URLs enforce loopback (`127.0.0.1` / `localhost` / `::1`) unless explicitly overridden.
3. **Alert-Only Safety Boundary:** Sentinel classifies, alerts, and explains. It never executes destructive host containment commands from model output.
4. **Loop Prevention:** Sentinel emits alerts back to Genesis under `service=sentinel` (configurable) and strictly drops incoming events from its own alert service before Tier 0 processing.
5. **Claims Are Measured, Not Asserted:** No throughput, latency, memory, or detection-accuracy figures are stated for Sentinel until produced by committed benchmarks in `docs/benchmarks/`.
