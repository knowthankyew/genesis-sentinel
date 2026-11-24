# Changelog

All notable changes to **Genesis Sentinel** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0-scaffold] - 2026-11-24

### Added
- **Phase 0 Pure-Go Scaffold:** Initialized local Git repository following Project Genesis coding standards (`go.mod` Go 1.24, zero external dependencies, `Makefile`, `LICENSE`, `NOTICE.md`, `SECURITY.md`, `CONTRIBUTING.md`).
- **CLI & Configuration (`cmd/sentinel`, `internal/cli`, `internal/config`):** Subcommand dispatch (`watch`, `scan`, `feedback`, `train`, `stats`, `burn`, `config`, `version`, `help`) and Defaults -> `sentinel.json` -> `SENTINEL_*` env config hierarchy with fail-closed validation and secret redaction.
- **Tier Domain Contracts & Model Governance (`internal/model`):** Wire contracts matching Genesis `parser.LogEntry` (`LogEvent`), `TemplateWindow`, `RuleHit`, `SurprisalScore`, `TriageVerdict`, `FeedbackRecord`, and fail-closed model allowlist targeting SmolLM2 first, Gemma 2 2B IT in Phase 5, and explicitly excluding experimental BitNet models.
- **Security Foundations (`internal/security`):** Constant-time Bearer auth middleware, loopback-only endpoint validation, and untrusted-log control-token & prompt-injection sanitizer.
- **Planning & Architecture Docs (`docs/`):** Committed `docs/ROADMAP.md`, `docs/DECISIONS.md` (ADRs 1–7), and `docs/ARCHITECTURE.md`.
