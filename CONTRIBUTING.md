# Contributing to Genesis Sentinel

Thank you for contributing to **Genesis Sentinel**!

Sentinel follows the same engineering discipline and privacy-first invariants as Project Genesis.

---

## 1. The Non-Negotiable Rule: Claims Are Measured, Not Asserted

We do not commit unmeasured performance or detection claims:
1. **Benchmark before claiming:** Any throughput, latency, memory footprint, or precision/recall figure added to `README.md` or `docs/` must come from a reproducible benchmark committed under `docs/benchmarks/` recording CPU, RAM, OS, Go version, model ID, and git commit SHA.
2. **Never weaken a test to make it pass:** Explain mathematically or architecturally in the commit message if an existing expectation changes. Report missed targets honestly.

---

## 2. Standard Library Only for the Go Core

The `genesis-sentinel` binary maintains **zero external Go dependencies** (`go.mod` has zero `require` directives).
* Use standard library packages (`net/http`, `encoding/json`, `encoding/binary`, `hash/crc32`, `regexp`, `math`, `crypto/subtle`) for all sidecar code.
* ML training and neural inference remain out-of-process in the companion `ml` (`event-driven-ftaas`) stack over loopback HTTP.
* Any proposed Go dependency requires an Architecture Decision Record in `docs/DECISIONS.md` prior to implementation.

---

## 3. Security & Privacy Invariants

* **Localhost-by-Default Zero Egress:** Keep all listeners and upstream clients loopback-only by default.
* **Hostile-Log Defenses:** Untrusted log payloads must pass through `internal/security.SanitizeUntrustedLogText` before prompt framing.
* **Alert-Only Boundary:** Never add autonomous destructive host actions triggered by model output.
* **Model Governance:** Keep SmolLM2 as the active Tier 2 target through Phase 4, Gemma 2 2B IT for Phase 5, and BitNet excluded unless superseded by a formal ADR.

---

## 4. Development & Testing Workflow

Before committing:

```bash
# Format code
make fmt

# Run unit tests
make test

# Run race detector
make race

# Run linter
make lint

# Regenerate deterministic CycloneDX 1.5 SBOM (when version or internal/* packages change)
make sbom

# Run claims, benchmark math recomputation, diagram freshness, landscape & security invariant audit
make audit
```

Use conventional commit prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
