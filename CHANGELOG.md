# Changelog

All notable changes to **Genesis Sentinel** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.4.0-phase3] - 2026-11-24

### Added
- **Tier 2 Local LoRA Triage Engine (`internal/triage`):** Added the 8-class starter security triage taxonomy (`[BENIGN-NOISE]`, `[RECON-SCAN]`, `[AUTH-BRUTEFORCE]`, `[INJECTION-ATTEMPT]`, `[EXFIL-SUSPECT]`, `[PRIV-ESC]`, `[POLICY-ANOMALY]`, `[NEEDS-REVIEW]`), prompt-injection-resistant data framing (`BEGIN_UNTRUSTED_LOG_TELEMETRY` / `END_UNTRUSTED_LOG_TELEMETRY`), fail-closed completion parsing with automatic override of `[BENIGN-NOISE]` back to `[NEEDS-REVIEW]` (`HIGH`) on injection-flagged payloads, and a loopback HTTP client targeting `ml/src/FtaaSService.Inference` (`/api/v1/inference/generate`, `/healthz`) with generation-tracked circuit breaking and dynamic adapter hot-swapping.
- **Mandatory PII/Secret Redaction, Synthetic Seed Generator & Curated Feedback Store (`internal/feedback`):** Added pure-Go stdlib scrubbing and fail-closed scanning for PEM private keys, JWTs, Bearer tokens, cloud/VCS API keys, credential key-value pairs, emails, SSA-valid SSNs, and Luhn-valid payment cards (matching FTaaS `DatasetService.cs`), balanced deterministic synthetic seed + validation split generation (`GenerateSeedSplit`), FTaaS-compliant JSONL export enforcing `50,000`-record / `25 MB` ceilings, and a bounded local `alerts.jsonl` journal (`MaxAlertJournalRecords = 2000`) wiped cleanly by `sentinel burn`.
- **FTaaS Training Client & Active Adapter Persistence (`internal/train`):** Added loopback multipart HTTP client targeting `ml/src/FtaaSService.Api` (`POST /api/v1/jobs`, `POST /api/v1/jobs/audit`, `GET /api/v1/jobs/{id}`, `GET /api/v1/jobs`) with BitNet exclusion, hyperparameter validation, pre-upload PII verification, job polling, `active-adapter.json` persistence, and `POST /adapter` daemon hot-reload notifications.
- **Pipeline, Alert & Phase 3 CLI Wiring (`internal/pipeline`, `internal/emit`, `internal/config`, `internal/cli`):** Implemented `sentinel feedback` (`add`, `seed`, `export`, `stats`, `alerts`) and `sentinel train` (`submit`, `status`, `list`, `activate`), added `--triage-mode`, `--inference-http`, `--base-model`, and `--adapter-path` to `watch` and `scan`, added Tier 2 enrichment fields on `emit.Alert`, exposed `POST /adapter` on the sidecar HTTP server, extended `sentinel burn` to remove `alerts.jsonl` and `active-adapter.json`, and redacted `ftaas_api_key` in `sentinel config`.

---

## [0.3.0-phase2] - 2026-11-24

### Added
- **Tier 1 Clean-Room Laplace-LK Log Surprisal Engine (`internal/surprisal`):** Pure-Go stdlib implementation of Equations 4, 6, 7, and 8 (`arXiv:2510.22809`) with MAD substitutability deviations (`MinDeviationFloor = 0.25`), nominal mismatch penalty (`2.5 nats`), strided same-service/global $k$-NN neighborhood scoring (`DefaultMaxCandidateCases = 120`), and numerical parity tests against `ml/src/surprisal-service/service.py` within `1e-6` nats.
- **Log-Domain Feature Extractor & Poisoning-Resistant Rolling Baseline (`features.go`, `engine.go`, `baseline.go`):** Linear-time extraction of 8 well-conditioned continuous features and 4 structural nominal features (`service`, `level`, `template_class`, HTTP status family / syslog `<PRI>` facility), cold-start warmup guard (`DefaultWarmupMinCases = 20`), baseline poisoning prevention, and atomic `baseline.json` persistence (`0600`, 16 MiB load cap) wiped cleanly by `sentinel burn`.
- **Loopback HTTP Parity Client (`http_client.go`):** Optional `surprisal_mode=http|hybrid` client targeting local `ml/src/surprisal-service` (`:5200`) with dial-time loopback enforcement and automatic fallback to in-process scoring.
- **Pipeline, Alert & CLI Wiring (`internal/pipeline`, `internal/emit`, `internal/cli`):** Unified `tier0+tier1` alert enrichment, standalone `tier1` (`SURPRISAL-001`) anomaly alerts for unseen traffic, Tier 1 telemetry on `/stats`, and `--surprisal-mode` / `--surprisal-threshold` / `--baseline` / `--window-events` CLI flags on `watch` and `scan`.

---

## [0.2.0-phase1] - 2026-11-24

### Added
- **Genesis Ingestion Bridge (`internal/ingest`):** Read-only lossless follower for Genesis `--data-dir` CRC32 `.seg` files (`segreader.go`) with atomic cursor persistence (`cursor.json`), rotation handling, partial-write waiting, corrupted-tail recovery, and `genesis burn` rewind detection; secondary `/query` fallback poller (`querypoller.go`) tracking monotonic ID eviction gaps; Genesis-compatible multi-format parser (`parser.go`); and Track A deterministic synthetic attack/noise corpus generator (`synthetic.go`).
- **Tier 0 Template Collapse & Deterministic Rules (`internal/template`, `internal/rules`):** Bounded pure-Go Drain-style prefix-tree template collapser (`DefaultMaxClusters = 4096`) with linear ASCII token masking and peak Shannon entropy tracking; precompiled RE2 rule engine (`rules.json` or built-in starter pack `SENT-001`..`SENT-008`) with operator allowlist suppressions.
- **Alert Sink & Phase 1 Pipeline (`internal/emit`, `internal/pipeline`):** Loopback TCP JSONL alert sink emitting alerts back into Genesis under `service=sentinel` (mapping `CRITICAL`/`HIGH` to Genesis `FATAL`/`ERROR` priority lanes) with strict self-alert loop prevention, HTTP `/healthz` + `/stats` + `DELETE /burn`, and local disk state burn.
- **Phase 1 CLI (`internal/cli`):** Implemented `sentinel watch`, `sentinel scan` (`--seg-dir`, `--file`, `--synthetic`), `sentinel stats`, and `sentinel burn -y`.
- **Portfolio Claims Governance, SBOM & CI (`scripts/`, `tests/`, `.github/`):** Added `docs/claims_registry.json`, `scripts/sync_docs.py`, `scripts/audit-claims.py`, `tests/test_claims_linter.py`, deterministic CycloneDX 1.5 SBOM generator (`scripts/generate-sbom.py` + `bom.json`), GitHub Actions CI + SLSA build provenance (`.github/workflows/ci.yml`), and grouped Dependabot configuration (`.github/dependabot.yml`).

---

## [0.1.0-scaffold] - 2026-11-24

### Added
- **Phase 0 Pure-Go Scaffold:** Initialized local Git repository following Project Genesis coding standards (`go.mod` Go 1.24, zero external dependencies, `Makefile`, `LICENSE`, `NOTICE.md`, `SECURITY.md`, `CONTRIBUTING.md`).
- **CLI & Configuration (`cmd/sentinel`, `internal/cli`, `internal/config`):** Subcommand dispatch (`watch`, `scan`, `feedback`, `train`, `stats`, `burn`, `data`, `config`, `version`, `help`) and Defaults -> `sentinel.json` -> `SENTINEL_*` env config hierarchy with fail-closed validation, secret redaction, and `sentinel data path|status|open` commands for transparent access to `~/.genesis-sentinel/`.
- **Tier Domain Contracts & Model Governance (`internal/model`):** Wire contracts matching Genesis `parser.LogEntry` (`LogEvent`), `TemplateWindow`, `RuleHit`, `SurprisalScore`, `TriageVerdict`, `FeedbackRecord`, and fail-closed model allowlist defaulting to `SmolLM2-135M-Instruct` (with `SmolLM2-360M-Instruct` step-up), `Gemma 2 2B IT` in Phase 5, and explicit exclusion of experimental BitNet models.
- **Security Foundations (`internal/security`):** Constant-time Bearer auth middleware, loopback-only endpoint validation, and untrusted-log control-token & prompt-injection sanitizer.
- **Planning & Architecture Docs (`docs/`):** Committed `docs/ROADMAP.md`, `docs/DECISIONS.md` (ADRs 1–7, including intentional Portfolio Pillar 1 disk-persistence variance and performance-first in-process Laplace-LK surprisal), and `docs/ARCHITECTURE.md`.
