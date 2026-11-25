#!/usr/bin/env python3
"""
audit-claims.py - Unified Architectural, Privacy & Claims Governance Linter
for Genesis Sentinel (`knowthankyew/genesis-sentinel`).

Provides portfolio-standard CLI discoverability (scripts/audit-claims.py) matching `genesis` and `ml`:
1. Claims & Go constant bound unit tests (tests/test_claims_linter.py)
2. Document Claims & Constant Sync Check across all registered docs (scripts/sync_docs.py --check)
3. Prohibited & Guarded Vocabulary + Personal Path Audit across README.md, NOTICE.md, SECURITY.md,
   CHANGELOG.md, CONTRIBUTING.md, and docs/**/*.md
4. Architecture Diagram Freshness & Path Existence Audit (diagram-meta covers & code paths)
5. Canonical MIT License, SPDX, NOTICE.md (including Pillar 1 Variance & arXiv:2510.22809 Attribution),
   and CycloneDX 1.5 SBOM (bom.json) Governance Gate
6. Pure-Go Stdlib Zero-Dependency, Model Governance (Smol-First / BitNet Excluded), Loopback-Only,
   Prompt Sanitizer & Local Burn Security Invariant Verification
"""

import hashlib
import json
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import sync_docs  # noqa: E402

DIAGRAM_META_RE = re.compile(r"<!--\s*diagram-meta\b(.*?)-->", re.DOTALL)
DIAGRAM_CODE_PATH_RE = re.compile(r"<code>([^<>\s]+)</code>")
DIAGRAM_PATH_PREFIXES = ("cmd/", "internal/", "scripts/", "docs/", ".github/", "tests/")
REQUIRED_DIAGRAM_DOC = "docs/ARCHITECTURE.md"

CANONICAL_MIT_SHA256 = "49f4b2686067fc56489ee83e4280c72a38b5c09d275bf352f5247d90572c8b9b"
SPDX_PREFIX = "SPDX" + "-License-Identifier:"
SPDX_RE = re.compile(re.escape(SPDX_PREFIX) + r"\s*([^\r\n]+)")


def clean_spdx_identifier(raw: str) -> str:
    cleaned = re.sub(r"(-->|\*\/|\*|#|\/|\"|'|`)[\s\S]*$", "", raw).strip()
    return cleaned.rstrip(";`).,").strip()


def _git(*args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["git", *args], cwd=str(REPO_ROOT), capture_output=True, text=True)
    except FileNotFoundError as ex:
        return subprocess.CompletedProcess(
            args=["git", *args],
            returncode=127,
            stdout="",
            stderr=f"git executable not found: {ex}",
        )


def get_docs_to_scan() -> list[Path]:
    docs = [
        REPO_ROOT / "README.md",
        REPO_ROOT / "NOTICE.md",
        REPO_ROOT / "SECURITY.md",
        REPO_ROOT / "CHANGELOG.md",
        REPO_ROOT / "CONTRIBUTING.md",
    ]
    docs_dir = REPO_ROOT / "docs"
    if docs_dir.is_dir():
        for md in sorted(docs_dir.rglob("*.md")):
            docs.append(md)
    return [d for d in dict.fromkeys(docs) if d.is_file()]


def audit_vocabulary(errors: list[str]) -> None:
    registry_path = REPO_ROOT / "docs" / "claims_registry.json"
    for doc in get_docs_to_scan():
        content = doc.read_text(encoding="utf-8")
        rel_name = str(doc.relative_to(REPO_ROOT)).replace("\\", "/")
        ok, word_errs = sync_docs.lint_prose_and_words(
            content, rel_name, registry_path=registry_path, repo_root=REPO_ROOT
        )
        if not ok:
            for e in word_errs:
                errors.append(f"Vocabulary/Path violation: {e}")


def parse_diagram_meta(text: str) -> dict | None:
    m = DIAGRAM_META_RE.search(text)
    if not m:
        return None
    meta: dict = {}
    for line in m.group(1).splitlines():
        key, sep, val = line.partition(":")
        if sep:
            meta[key.strip()] = val.strip()
    covers = meta.get("covers", "")
    if covers.startswith("[") and covers.endswith("]"):
        meta["covers"] = [c.strip() for c in covers[1:-1].split(",") if c.strip()]
    else:
        meta["covers"] = []
    return meta


def _audit_diagram_doc(doc: Path, errors: list[str]) -> None:
    try:
        rel = doc.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        rel = doc.name
    label = f"Architecture diagram ({rel})"
    text = doc.read_text(encoding="utf-8")

    meta = parse_diagram_meta(text)
    if meta is None:
        errors.append(f"{label}: missing <!-- diagram-meta ... --> header")
        return

    raw_date = meta.get("last-validated", "")
    try:
        max_allowed_date = datetime.now(timezone.utc).date() + timedelta(days=1)
        if date.fromisoformat(raw_date) > max_allowed_date:
            errors.append(f"{label}: last-validated {raw_date} is in the future")
    except ValueError:
        errors.append(f"{label}: last-validated '{raw_date}' is not an ISO date (YYYY-MM-DD)")

    commit = meta.get("validated-commit", "")
    covers: list[str] = meta["covers"]
    if not commit:
        errors.append(f"{label}: validated-commit is missing")
    elif not re.fullmatch(r"[0-9a-fA-F]{7,40}", commit):
        errors.append(f"{label}: validated-commit '{commit}' must be a valid hex git commit hash")
    if not covers:
        errors.append(f"{label}: covers is missing or not a [a, b, c] list")

    if commit and re.fullmatch(r"[0-9a-fA-F]{7,40}", commit) and covers:
        resolved = _git("rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}")
        if resolved.returncode != 0:
            errors.append(
                f"{label}: validated-commit '{commit}' not found in this clone "
                f"(shallow checkout? use fetch-depth: 0)"
            )
        elif _git("merge-base", "--is-ancestor", commit, "HEAD").returncode != 0:
            errors.append(f"{label}: validated-commit '{commit}' is not an ancestor of HEAD")
        else:
            pathspecs = [f":(glob){c}" for c in covers] + [
                f":(exclude){rel}",
                ":(exclude)scripts/audit-claims.py",
                ":(exclude)scripts/sync_docs.py",
                ":(exclude)tests/test_claims_linter.py",
            ]
            diff = _git("diff", "--name-only", commit, "--", *pathspecs)
            if diff.returncode != 0:
                errors.append(f"{label}: git diff failed: {diff.stderr.strip()}")
            else:
                changed = [f for f in diff.stdout.splitlines() if f.strip()]
                if changed:
                    last = _git("log", "-1", "--format=%h", "HEAD", "--", *pathspecs).stdout.strip()
                    shown = ", ".join(changed[:10]) + (" ..." if len(changed) > 10 else "")
                    errors.append(
                        f"{label}: STALE. {len(changed)} covered file(s) changed since "
                        f"{commit}: {shown}. Re-validate the diagram, then set "
                        f"validated-commit to {last} and update last-validated."
                    )

    for raw in dict.fromkeys(DIAGRAM_CODE_PATH_RE.findall(text)):
        p = raw.split("#", 1)[0]
        p = re.sub(r":\d+(-\d+)?$", "", p)
        if not p.startswith(DIAGRAM_PATH_PREFIXES) or any(ch in p for ch in "*{}<>$"):
            continue
        if not (REPO_ROOT / p).exists():
            errors.append(f"{label}: referenced path does not exist: {p}")


def audit_architecture_diagrams(errors: list[str]) -> None:
    required = REPO_ROOT / REQUIRED_DIAGRAM_DOC
    targets: list[Path] = []
    if required.is_file():
        targets.append(required)
    else:
        errors.append(f"Architecture diagram: required doc {REQUIRED_DIAGRAM_DOC} not found")
    for doc in get_docs_to_scan():
        if doc != required and "<!-- diagram-meta" in doc.read_text(encoding="utf-8"):
            targets.append(doc)
    for doc in targets:
        _audit_diagram_doc(doc, errors)


def audit_license_and_sbom(errors: list[str]) -> None:
    license_file = REPO_ROOT / "LICENSE"
    if not license_file.is_file():
        errors.append("License gate: root LICENSE file is missing")
    else:
        license_sha = hashlib.sha256(license_file.read_bytes()).hexdigest()
        if license_sha != CANONICAL_MIT_SHA256:
            errors.append(
                f"License gate: root LICENSE SHA-256 mismatch. Expected {CANONICAL_MIT_SHA256}, got {license_sha}."
            )

    ls_files = _git("ls-files", "-z")
    if ls_files.returncode == 0:
        for rel_path in ls_files.stdout.split("\0"):
            if not rel_path or rel_path == "scripts/audit-claims.py":
                continue
            p = REPO_ROOT / rel_path
            if not p.is_file():
                continue
            try:
                content = p.read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                continue
            for spdx_raw in SPDX_RE.findall(content):
                spdx = clean_spdx_identifier(spdx_raw)
                if spdx != "MIT":
                    errors.append(
                        f"License gate: non-MIT SPDX identifier '{spdx}' found in {rel_path}. Only 'MIT' is permitted."
                    )

    notice_path = REPO_ROOT / "NOTICE.md"
    if not notice_path.is_file():
        errors.append("Governance gate: NOTICE.md is missing")
    else:
        notice = notice_path.read_text(encoding="utf-8")
        required_phrases = (
            "Zero External Go Dependencies",
            "Localhost-by-Default Zero Egress",
            "Alert-Only Safety Boundary",
            "Intentional Pillar 1 Variance",
            "arXiv:2510.22809",
            "MIT License",
        )
        for phrase in required_phrases:
            if phrase not in notice:
                errors.append(f"NOTICE.md missing required disclosure phrase '{phrase}'")

    bom_path = REPO_ROOT / "bom.json"
    if not bom_path.is_file():
        errors.append("Governance gate: bom.json is missing")
    else:
        raw_bom = bom_path.read_text(encoding="utf-8")
        if "/Users/" in raw_bom:
            errors.append("bom.json contains leaked '/Users/' path")
        try:
            bom = json.loads(raw_bom)
            if bom.get("bomFormat") != "CycloneDX" or bom.get("specVersion") != "1.5":
                errors.append("bom.json must be CycloneDX specVersion 1.5")
            comp = bom.get("metadata", {}).get("component", {})
            if comp.get("name") != "genesis-sentinel":
                errors.append(f"bom.json component name expected 'genesis-sentinel', got {comp.get('name')!r}")

            expected_ver = sync_docs.extract_go_constant(REPO_ROOT / "internal" / "cli" / "cli.go", "Version")
            if comp.get("version") != expected_ver:
                errors.append(
                    f"bom.json version drift: expected {expected_ver!r} (from internal/cli/cli.go), "
                    f"got {comp.get('version')!r}"
                )

            props = {p.get("name"): p.get("value") for p in comp.get("properties", [])}
            expected_props = {
                "knowthankyew:privacy:network_egress": "deny",
                "knowthankyew:privacy:telemetry_mode": "local_disk_state",
                "knowthankyew:privacy:pillar1_variance": "intentional_lossless_seg_tailing_and_burnable_local_state",
                "knowthankyew:privacy:burn_enabled": "true",
                "knowthankyew:privacy:third_party_dependencies": "0",
                "knowthankyew:security:localhost_default_bind": "true",
                "knowthankyew:security:alert_only": "true",
                "knowthankyew:ml:default_base_model": "HuggingFaceTB/SmolLM2-135M-Instruct",
                "knowthankyew:ml:excluded_families": "bitnet",
            }
            for k, v in expected_props.items():
                if props.get(k) != v:
                    errors.append(f"bom.json property '{k}' expected '{v}', got {props.get(k)!r}")

            internal_dir = REPO_ROOT / "internal"
            actual_pkgs = {
                f"internal/{d.name}"
                for d in internal_dir.iterdir()
                if d.is_dir() and any(d.glob("*.go"))
            }
            sbom_pkgs = {c.get("name") for c in bom.get("components", []) if c.get("name")}
            missing_pkgs = sorted(actual_pkgs - sbom_pkgs)
            extra_pkgs = sorted(sbom_pkgs - actual_pkgs)
            if missing_pkgs or extra_pkgs:
                errors.append(
                    f"bom.json internal package parity drift: missing={missing_pkgs}, extra={extra_pkgs}"
                )
        except Exception as exc:
            errors.append(f"bom.json invalid JSON or schema error: {exc}")


def audit_sentinel_invariants(errors: list[str]) -> None:
    # 1. Zero external Go dependencies
    gomod_path = REPO_ROOT / "go.mod"
    if not gomod_path.is_file():
        errors.append("go.mod is missing")
    else:
        gomod = gomod_path.read_text(encoding="utf-8")
        if "module github.com/knowthankyew/genesis-sentinel" not in gomod:
            errors.append("go.mod does not declare 'module github.com/knowthankyew/genesis-sentinel'")
        if re.search(r"^\s*require\b", gomod, flags=re.MULTILINE):
            errors.append("go.mod contains external 'require' directives (violates stdlib-only invariant)")
    gosum_path = REPO_ROOT / "go.sum"
    if gosum_path.is_file() and gosum_path.read_text(encoding="utf-8").strip():
        errors.append("go.sum is non-empty (violates stdlib-only invariant)")

    # 2. Security, Model Governance (BitNet excluded), Config Redaction, Tier 2/Feedback & Burn Invariant Go Tests
    expected_invariant_tests = [
        ("github.com/knowthankyew/genesis-sentinel/internal/security", "TestIsLoopbackEndpoint"),
        ("github.com/knowthankyew/genesis-sentinel/internal/security", "TestIsBindingAllInterfaces"),
        ("github.com/knowthankyew/genesis-sentinel/internal/security", "TestAuthMiddleware"),
        ("github.com/knowthankyew/genesis-sentinel/internal/security", "TestSanitizeUntrustedLogText"),
        ("github.com/knowthankyew/genesis-sentinel/internal/security", "TestNewLoopbackHTTPClientRedirectPolicies"),
        ("github.com/knowthankyew/genesis-sentinel/internal/model", "TestValidateBaseModel"),
        ("github.com/knowthankyew/genesis-sentinel/internal/config", "TestDefaultConfigValidates"),
        ("github.com/knowthankyew/genesis-sentinel/internal/config", "TestConfigRejectsBitNetAndNonLoopback"),
        ("github.com/knowthankyew/genesis-sentinel/internal/cli", "TestExecuteConfigRedactsTokens"),
        ("github.com/knowthankyew/genesis-sentinel/internal/cli", "TestExecuteDataSubcommands"),
        ("github.com/knowthankyew/genesis-sentinel/internal/pipeline", "TestBurnLocalStateRejectsFeedbackSymlinkEscape"),
        ("github.com/knowthankyew/genesis-sentinel/internal/pipeline", "TestPipelineCountsOnlySuccessfulSinkEmissions"),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/pipeline",
            "TestAsyncTier2EmitsDeterministicAlertImmediatelyAndEnrichesCorrelatedUpdate",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/pipeline",
            "TestAdversarialPromptInjectionAndDelimiterEscapeCampaign",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/pipeline",
            "TestAdversarialLogFloodLosslessSegAndBoundedMemory",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/pipeline",
            "TestAdversarialCorruptedSegTailAndBurnRewindRecovery",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/pipeline",
            "TestAdversarialSelfAlertLoopImmunityAndBaselinePoisoningResistance",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/pipeline",
            "TestAdversarialPIIAndSecretExfiltrationEndToEnd",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/cmd/sentinel-bench",
            "TestRunBenchmarksOfflineAndMarkdownParity",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/cmd/sentinel-bench",
            "TestBenchmarkRejectsBitNetModel",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/triage",
            "TestClientValidationRejectsBitNetOffLoopbackTraversalAndBadURLCredentials",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/triage",
            "TestClientRejectsExplicitEmptyAdapterAndTripsOnFlushDeadline",
        ),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/triage",
            "TestClientDiscardsStaleVerdictOnAdapterHotSwapOrReset",
        ),
        ("github.com/knowthankyew/genesis-sentinel/internal/triage", "TestParseCompletionFailClosedAndInjectionOverride"),
        ("github.com/knowthankyew/genesis-sentinel/internal/feedback", "TestRedactTextAndScanForPII"),
        (
            "github.com/knowthankyew/genesis-sentinel/internal/train",
            "TestFTaaSClientRejectsBitNetNonLoopbackBadURLAndUnredactedPIIWithoutUpload",
        ),
    ]
    test_names = sorted({t for _, t in expected_invariant_tests})
    ok_inv, inv_out = run_check(
        [
            "go",
            "test",
            "-json",
            "./internal/security",
            "./internal/model",
            "./internal/config",
            "./internal/cli",
            "./internal/pipeline",
            "./internal/triage",
            "./internal/feedback",
            "./internal/train",
            "./cmd/sentinel-bench",
            "-run",
            "^(" + "|".join(test_names) + ")$",
        ],
        "Go Security, Model Governance, Redaction & Burn Invariant Tests",
        errors,
    )
    if ok_inv:
        passed_pairs: set[tuple[str, str]] = set()
        for line in inv_out.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (
                ev.get("Action") == "pass"
                and isinstance(ev.get("Package"), str)
                and isinstance(ev.get("Test"), str)
            ):
                passed_pairs.add((ev["Package"], ev["Test"]))
        missing_tests = [f"{pkg}::{t}" for pkg, t in expected_invariant_tests if (pkg, t) not in passed_pairs]
        if missing_tests:
            errors.append(
                f"Invariant Go test audit missed expected tests (renamed or skipped?): {', '.join(missing_tests)}"
            )


def run_check(cmd: list[str], label: str, errors: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True)
    except FileNotFoundError as exc:
        msg = f"{label} failed: executable not found ({exc})"
        errors.append(msg)
        return False, msg
    combined = f"{proc.stdout}\n{proc.stderr}"
    if proc.returncode != 0:
        errors.append(f"{label} failed (exit {proc.returncode}):\n{combined}")
        return False, combined
    return True, combined


def main() -> int:
    print("\n=== Genesis Sentinel Architectural, Privacy & Claims Governance Audit ===")
    errors: list[str] = []

    # 1. Run claims linter unit test suite
    test_cmd = [sys.executable, "-m", "unittest", "tests/test_claims_linter.py"]
    ok_tests, test_out = run_check(test_cmd, "Claims Linter Test Suite (test_claims_linter.py)", errors)
    if ok_tests:
        m = re.search(r"Ran\s+(\d+)\s+tests?", test_out)
        count_str = f"{m.group(1)} test cases" if m else "all test cases"
        print(f"  ✓ Claims & Go constant bound tests passed ({count_str})")

    # 2. Run sync_docs claims and empirical constraint check
    sync_cmd = [sys.executable, "scripts/sync_docs.py", "--check"]
    ok_sync, _ = run_check(sync_cmd, "Document Claims Sync Check (sync_docs.py --check)", errors)
    if ok_sync:
        print("  ✓ Multi-doc Go constant claims and empirical guardrails synchronized (sync_docs.py)")

    # 3. Audit prohibited and guarded vocabulary + personal path leaks across docs
    before_vocab = len(errors)
    audit_vocabulary(errors)
    if len(errors) == before_vocab:
        print("  ✓ README.md, NOTICE.md, SECURITY.md, CHANGELOG.md, CONTRIBUTING.md, and docs/*.md clean of prohibited/unguarded vocabulary & /Users/ leaks")

    # 4. Architecture diagram freshness & path existence
    before_diagram = len(errors)
    audit_architecture_diagrams(errors)
    if len(errors) == before_diagram:
        print("  ✓ Architecture diagram metadata is fresh and every referenced path exists")

    # 5. Canonical MIT license, SPDX, Pillar 1 variance NOTICE & CycloneDX SBOM governance gate
    before_license = len(errors)
    audit_license_and_sbom(errors)
    if len(errors) == before_license:
        print("  ✓ MIT canonical license integrity, SPDX identifiers, NOTICE.md & CycloneDX 1.5 SBOM verified")

    # 6. Pure-Go stdlib zero-dep, loopback, prompt sanitizer, BitNet exclusion & burn invariants
    before_inv = len(errors)
    audit_sentinel_invariants(errors)
    if len(errors) == before_inv:
        print("  ✓ Zero external Go dependencies, loopback enforcement, BitNet exclusion, prompt sanitizer & burn invariants verified")

    if errors:
        print(f"\n[FAIL] {len(errors)} invariant violation(s) detected:", file=sys.stderr)
        for err in errors:
            print(f"  ✗ {err}", file=sys.stderr)
        return 1

    print("\nAll Genesis Sentinel claims, registry schemas, and governance gates passed.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
