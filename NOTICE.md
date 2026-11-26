# NOTICE & PRIVACY GOVERNANCE DISCLOSURE — GENESIS SENTINEL (`knowthankyew/genesis-sentinel`)

**Genesis Sentinel** is a local-first log triage and anomaly detection sidecar for Project Genesis written in pure Go standard library (`go.mod` contains zero external dependencies) as part of the [`knowthankyew`](https://github.com/knowthankyew) open-source portfolio.

This repository is licensed in its entirety under the **MIT License** (`SPDX-License-Identifier: MIT`). See [LICENSE](LICENSE).

---

## 1. Core Architectural & Privacy Invariants

| Invariant | Default Posture | Enforcement Mechanism |
| :--- | :--- | :--- |
| **1. Zero External Go Dependencies** | `go.mod` contains zero `require` directives. No third-party Go SDKs or telemetry exporters are linked into the binary. | Enforced fail-closed by `scripts/audit-claims.py`, `go vet ./...`, and CI. |
| **2. Localhost-by-Default Zero Egress** | All listen addresses and upstream endpoints (`genesis`, `surprisal-service`, `ftaas-api`, `inference`) must target loopback (`127.0.0.1` / `localhost` / `::1`) unless explicitly overridden. | Enforced fail-closed by `internal/config.(*Config).Validate`, `internal/security.IsLoopbackEndpoint`, and `scripts/audit-claims.py`. |
| **3. Alert-Only Safety Boundary** | Sentinel classifies, alerts, and explains. It never executes destructive host containment commands from model output. | Architectural invariant documented in `SECURITY.md` and `docs/DECISIONS.md` (ADR-6). |
| **4. Model Governance (Smol-Instruct First, Gemma Phase 5, BitNet Excluded)** | Active allowlist defaults to <!-- claim:default_base_model -->`HuggingFaceTB/SmolLM2-135M-Instruct`<!-- /claim --> (with <!-- claim:stepup_base_model -->`HuggingFaceTB/SmolLM2-360M-Instruct`<!-- /claim --> step-up) through Phase 4 and <!-- claim:phase5_base_model -->`google/gemma-2-2b-it`<!-- /claim --> in Phase 5. Experimental BitNet models are rejected fail-closed. | Enforced by `internal/model.ValidateBaseModel`, `TestValidateBaseModel`, and `scripts/audit-claims.py`. |
| **5. Mandatory Pre-Training Redaction** | `require_redaction` defaults to `true`; auth tokens are redacted from CLI config dumps. | Enforced by `internal/config` and `TestExecuteConfigRedactsTokens`. |
| **6. Intentional Pillar 1 Variance (Transparent Local Disk State)** | Unlike volatile-only client engines, Sentinel prioritizes lossless Genesis `.seg` tailing and bounded local state in `~/.genesis-sentinel/` so bursts cannot blind detection. Surfacing and access require zero hidden-folder gymnastics (`sentinel data path\|status\|open` and `sentinel burn`). | Documented in `README.md`, `SECURITY.md`, and `docs/DECISIONS.md` (ADR-4); tested by `TestExecuteDataSubcommands`. |

---

## 2. Clean-Room Laplace-LK Surprisal Provenance (Tier 1 & `surprisal-service`)

Tier 1 anomaly scoring (Phase 2) and FTaaS preflight auditing leverage clean-room Laplace-LK information-theoretic surprisal routines derived strictly from the published equations and algorithmic descriptions (Equations 4, 6, 7, 8, 10 and Sections 8.1, 9.4) in:

> Christopher J. Hazard et al., *"A Theory of the Mechanics of Information: Generalization Through Measurement of Uncertainty (Learning is Measuring)"*, `arXiv:2510.22809`.

* **Clean-Room Isolation:** No source code, functions, binaries, or packages from Howso or Amalgam repositories are included, linked, or imported.
* **Adaptation Scope & Fidelity:** Sentinel adapts these equations with original log-domain engineering heuristics (Drain-style template collapsing, Shannon entropy features, rolling baseline windows, and fixed alert thresholds). This is an independent adaptation, not a validated reproduction of the paper's methods; results should not be attributed to the paper's authors or to Howso.
* **Academic Citation:** References to Hazard et al. are citations to published research and imply no endorsement by the authors.
* **Trademarks & Non-Affiliation:** Howso® and Amalgam™ are trademarks or registered trademarks of Howso Incorporated. They appear in this notice solely for provenance and attribution. This project is independent and is not affiliated with, endorsed by, or sponsored by Howso Incorporated.
* **Patents:** The MIT License does not grant, and this repository does not claim to grant, any license under third-party patents. Operators deploying this software commercially are responsible for their own patent and freedom-to-operate review.

---

## 3. Third-Party Foundation Models Attribution

When paired with the companion `ml` (`event-driven-ftaas`) training and inference stack, Sentinel targets third-party foundation models under their respective licenses:

* **`HuggingFaceTB/SmolLM2-135M`** (and optional **<!-- claim:default_base_model -->`HuggingFaceTB/SmolLM2-135M-Instruct`<!-- /claim -->** / **<!-- claim:stepup_base_model -->`HuggingFaceTB/SmolLM2-360M-Instruct`<!-- /claim -->**): Licensed under the Apache License 2.0 by Hugging Face, Inc.
* **<!-- claim:phase5_base_model -->`google/gemma-2-2b-it`<!-- /claim -->** *(Phase 5 reasoning upgrade)*: Developed and published by Google LLC. Available under the Google Gemma Terms of Use. Operators must accept Google's terms and adhere to the Gemma Prohibited Use Policy prior to fine-tuning or serving Gemma weights.
* **`sentence-transformers/all-MiniLM-L6-v2`** *(optional Phase 4 offline evaluation)*: Licensed under the Apache License 2.0.

---

## 4. Supply-Chain & SBOM Governance

* **License:** Permissive **MIT License** (`SPDX-License-Identifier: MIT`). See [LICENSE](LICENSE).
* **Third-Party Go Runtime Dependencies:** `0` (Pure Go 1.24+ Standard Library).
* **CycloneDX 1.5 SBOM:** Generated deterministically via `scripts/generate-sbom.py` (`bom.json`), checked by `scripts/audit-claims.py`, and attested via SLSA build provenance in GitHub Actions CI.
