#!/usr/bin/env python3
"""
sync_docs.py: Claims Registry Documentation Synchronizer & Linter v2 for Genesis Sentinel.

Enforces:
1. Documentation claim markers `<!-- claim:<id> -->...<!-- /claim -->` strictly match
   Go source constants (or empirical JSON artifacts once Phase 4 benchmarks land)
   registered in docs/claims_registry.json.
2. Inside regions marked as empirical (`<!-- BEGIN_EMPIRICAL -->` ... `<!-- END_EMPIRICAL -->`),
   any unmanaged digit in metric cells outside a claim marker fails the check, and every
   table row status cell must be governed by a registered status claim marker.
3. Word lint: adjectives such as 'bulletproof', 'rock solid', 'conclusive', 'definitive',
   and 'infinitely scalable' are prohibited. Guarded terms ('verified', 'authentic',
   'proves', 'zero hallucination', '100%') are allowed only when tied to a registered claim
   marker whose evidence exists on disk.
4. Personal host path leak guard: fails closed if '/Users/' appears in checked docs or JSON.

Modes:
  --check (DEFAULT): Validates documentation and artifacts; exits 0 on match, 1 on failure.
  --write (EXPLICIT): Renders resolved claim values into documentation markers.
"""

import argparse
import ast
import json
import math
import operator
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY_PATH = REPO_ROOT / "docs" / "claims_registry.json"
DEFAULT_README_PATH = REPO_ROOT / "README.md"

EMPIRICAL_BLOCK_DELIMITERS = [
    ("<!-- BEGIN_EMPIRICAL -->", "<!-- END_EMPIRICAL -->"),
]

PROHIBITED_WORDS = [
    re.compile(r"\bbullet-?proof\b", re.IGNORECASE),
    re.compile(r"\brock\s+solid\b", re.IGNORECASE),
    re.compile(r"\bconclusive\b", re.IGNORECASE),
    re.compile(r"\bdefinitive\b", re.IGNORECASE),
    re.compile(r"\binfinitely\s+scalable\b", re.IGNORECASE),
]

GUARDED_WORDS = [
    re.compile(r"\bverified\b", re.IGNORECASE),
    re.compile(r"\bauthentic\b", re.IGNORECASE),
    re.compile(r"\bproves\b", re.IGNORECASE),
    re.compile(r"\bzero\s+hallucination\b", re.IGNORECASE),
    re.compile(r"100%"),
]

_BINARY_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
}


def _eval_numeric_expr(expr_str: str, const_name: str) -> int | float:
    """Safely evaluate a constant numeric Go expression (e.g. '16 * 1024 * 1024') via AST."""
    tree = ast.parse(expr_str.strip(), mode="eval")

    def _eval(node: ast.AST) -> int | float:
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
            return node.value
        if isinstance(node, ast.BinOp) and type(node.op) in _BINARY_OPS:
            return _BINARY_OPS[type(node.op)](_eval(node.left), _eval(node.right))
        raise ValueError(f"Unsupported expression in Go constant {const_name}: {expr_str!r}")

    return _eval(tree)


def extract_go_constant(file_path: Path, const_name: str) -> int | float | str:
    """Extract a package-level Go constant from a .go source file without executing code."""
    if not file_path.is_file():
        raise FileNotFoundError(f"Go source file not found: {file_path}")
    text = file_path.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"^\s*(?:const\s+)?{re.escape(const_name)}(?:\s+[A-Za-z0-9_]+)?\s*=\s*([^\r\n]+)",
        re.MULTILINE,
    )
    m = pattern.search(text)
    if not m:
        raise ValueError(f"Go constant {const_name!r} not found in {file_path}")
    raw_expr = m.group(1).strip()
    if raw_expr.startswith('"'):
        # Extract quoted string literal (allowing '/' inside model IDs like "HuggingFaceTB/SmolLM2-135M-Instruct")
        str_match = re.match(r'^"((?:[^"\\]|\\.)*)"(?:\s*//.*)?$', raw_expr)
        if not str_match:
            raise ValueError(f"Unsupported string expression in Go constant {const_name}: {raw_expr!r}")
        return str_match.group(1)
    # Strip trailing inline comment for numeric expressions
    raw_expr = re.sub(r"//.*$", "", raw_expr).strip()
    return _eval_numeric_expr(raw_expr, const_name)


NAMED_FORMAT_RULES = {
    "bytes_to_mb": lambda v: f"{int(v) // (1024 * 1024)} MB",
    "bytes_to_kb": lambda v: f"{int(v) // 1024} KB",
}


def apply_format_rule(claim_id: str, fmt: str, value) -> str:
    """Render a resolved value using named format rules or str.format."""
    if fmt in NAMED_FORMAT_RULES:
        try:
            return NAMED_FORMAT_RULES[fmt](value)
        except Exception as exc:
            raise ValueError(f"Claim '{claim_id}': named format_rule {fmt!r} failed on {value!r}: {exc}") from exc
    if isinstance(value, (list, tuple, dict)):
        raise ValueError(f"Claim '{claim_id}': format_rule {fmt!r} cannot render {type(value).__name__}")
    try:
        return fmt.format(value=value)
    except Exception as exc:
        raise ValueError(f"Claim '{claim_id}': invalid format_rule {fmt!r}: {exc}") from exc


def resolve_claim_value(claim_id: str, claim_cfg: dict, repo_root: Path = REPO_ROOT) -> str:
    """Resolve and format a registered claim value from its Go source or empirical JSON artifact."""
    artifact_rel = claim_cfg.get("source_artifact")
    if not artifact_rel:
        raise ValueError(f"Claim '{claim_id}' missing 'source_artifact'")
    artifact_path = repo_root / artifact_rel
    if not artifact_path.is_file():
        raise FileNotFoundError(f"Source artifact not found for claim '{claim_id}': {artifact_path}")

    fmt = claim_cfg.get("format_rule", "{value}")

    if "go_const" in claim_cfg:
        val = extract_go_constant(artifact_path, claim_cfg["go_const"])
        return apply_format_rule(claim_id, fmt, val)

    if "json_path" in claim_cfg:
        data = json.loads(artifact_path.read_text(encoding="utf-8"))
        cur = data
        for part in claim_cfg["json_path"].split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
                cur = cur[int(part)]
            else:
                raise KeyError(f"Path '{claim_cfg['json_path']}' part '{part}' not found in {artifact_path.name}")
        return apply_format_rule(claim_id, fmt, cur)

    raise ValueError(f"Claim '{claim_id}' has neither 'go_const' nor 'json_path'")


MAX_SAFE_INT64 = (1 << 63) - 1


def _reject_nonfinite_json_constant(const: str) -> None:
    raise ValueError(f"Non-standard non-finite JSON constant not permitted: {const!r}")


def _loads_strict_json(raw: str):
    return json.loads(raw, parse_constant=_reject_nonfinite_json_constant)


def _contains_personal_host_path(obj) -> bool:
    """Recursively check decoded JSON strings for personal host prefixes (catching JSON-escaped slashes)."""
    if isinstance(obj, str):
        return "/Users/" in obj or "/home/" in obj
    if isinstance(obj, dict):
        return any(_contains_personal_host_path(k) or _contains_personal_host_path(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contains_personal_host_path(v) for v in obj)
    return False


def _is_int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_finite_num(v) -> bool:
    if not isinstance(v, (int, float)) or isinstance(v, bool):
        return False
    try:
        return math.isfinite(float(v))
    except (OverflowError, ValueError, TypeError):
        return False


def _req_dict(parent: dict, key: str, errors: list[str], prefix: str) -> dict:
    val = parent.get(key)
    if not isinstance(val, dict):
        errors.append(f"{prefix}.{key} must be a JSON object, got {type(val).__name__}")
        return {}
    return val


def _req_int(
    section: dict,
    key: str,
    errors: list[str],
    prefix: str,
    min_val: int | None = None,
    max_val: int = MAX_SAFE_INT64,
) -> int | None:
    val = section.get(key)
    if not _is_int(val):
        errors.append(f"{prefix}.{key} must be an integer, got {val!r}")
        return None
    if min_val is not None and val < min_val:
        errors.append(f"{prefix}.{key} must be >= {min_val}, got {val}")
        return None
    if val > max_val:
        errors.append(f"{prefix}.{key} exceeds maximum safe int64 bound ({max_val}), got {val}")
        return None
    return val


def _req_num(section: dict, key: str, errors: list[str], prefix: str) -> float | None:
    val = section.get(key)
    if not _is_finite_num(val):
        errors.append(f"{prefix}.{key} must be a finite number, got {val!r}")
        return None
    return float(val)


def _extract_published_markdown_table_rows(md_text: str) -> tuple[set[str], list[str]]:
    """
    Strip HTML comments and fenced code blocks, then return (published_table_rows, duplicate_labels)
    so hidden comments or stale duplicate metric rows cannot satisfy parity verification.
    """
    cleaned = re.sub(r"<!--.*?-->", "", md_text, flags=re.DOTALL)
    cleaned = re.sub(r"```.*?```", "", cleaned, flags=re.DOTALL)
    rows: set[str] = set()
    seen_labels: set[str] = set()
    dup_labels: list[str] = []
    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not (line.startswith("|") and line.endswith("|")):
            continue
        rows.add(line)
        parts = [p.strip() for p in line.split("|")[1:-1]]
        if len(parts) >= 2 and parts[0].startswith("**") and parts[0].endswith("**"):
            lbl = parts[0]
            if lbl in seen_labels:
                dup_labels.append(lbl)
            else:
                seen_labels.add(lbl)
    return rows, dup_labels


def independent_recompute_metrics(benchmark_json_path: Path, repo_root: Path = REPO_ROOT) -> tuple[bool, list[str]]:
    """
    Independently verify mathematical consistency of docs/benchmarks/empirical_benchmarks.json,
    strict schema & finite-number bounds, status gate derivations from recomputed metrics,
    and exact published-table row parity against the committed Markdown benchmark report.
    """
    errors: list[str] = []
    if not benchmark_json_path.is_file():
        return False, [f"Missing empirical benchmark JSON: {benchmark_json_path}"]

    try:
        raw_json = benchmark_json_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, [f"Failed to read {benchmark_json_path}: {exc}"]
    if "/Users/" in raw_json or "/home/" in raw_json:
        errors.append("Empirical benchmark JSON contains leaked personal host path")

    try:
        data = _loads_strict_json(raw_json)
    except Exception as exc:
        return False, [f"Failed to parse {benchmark_json_path}: {exc}"]

    if not isinstance(data, dict):
        return False, [f"Empirical benchmark JSON root must be an object, got {type(data).__name__}"]
    if _contains_personal_host_path(data):
        errors.append("Empirical benchmark JSON contains leaked personal host path in decoded strings")

    meta = _req_dict(data, "metadata", errors, "benchmark")
    gates = _req_dict(data, "acceptance_gates", errors, "benchmark")
    t0 = _req_dict(data, "tier0_replay", errors, "benchmark")
    t1 = _req_dict(data, "tier1_surprisal", errors, "benchmark")
    det = _req_dict(data, "detection_accuracy", errors, "benchmark")
    t2 = _req_dict(data, "tier2_triage", errors, "benchmark")
    mem = _req_dict(data, "memory_profile", errors, "benchmark")
    adv = _req_dict(data, "adversarial_checks", errors, "benchmark")
    if errors:
        return False, errors

    # 1. Verify Sentinel version metadata against internal/cli/cli.go (when present in repo_root)
    cli_go = repo_root / "internal" / "cli" / "cli.go"
    if cli_go.is_file():
        try:
            expected_ver = extract_go_constant(cli_go, "Version")
            if meta.get("sentinel_version") != expected_ver:
                errors.append(
                    f"Benchmark sentinel_version mismatch: expected {expected_ver!r}, got {meta.get('sentinel_version')!r}"
                )
        except Exception as exc:
            errors.append(f"Failed to extract CLI Version for benchmark check: {exc}")

    # 2. Tier 0 replay throughput, lossless drop count, digest identity, and collapse ratio
    tps_target = _req_num(gates, "throughput_target_lps", errors, "acceptance_gates")
    drop_target = _req_int(gates, "lossless_dropped_target", errors, "acceptance_gates", min_val=0)
    lines_written = _req_int(t0, "lines_written", errors, "tier0_replay", min_val=1)
    lines_read = _req_int(t0, "lines_read", errors, "tier0_replay", min_val=1)
    lines_dropped = _req_int(t0, "lines_dropped", errors, "tier0_replay", min_val=0)
    digest_matched = t0.get("content_digest_matched")
    if not isinstance(digest_matched, bool):
        errors.append(f"tier0_replay.content_digest_matched must be a boolean, got {digest_matched!r}")
    dur_sec = _req_num(t0, "duration_seconds", errors, "tier0_replay")
    stored_tps = _req_num(t0, "throughput_lps", errors, "tier0_replay")
    tmpls = _req_int(t0, "templates_emitted", errors, "tier0_replay", min_val=1)
    stored_collapse = _req_num(t0, "collapse_ratio", errors, "tier0_replay")

    calc_tps = None
    calc_collapse = None
    if lines_written is not None and lines_read is not None and lines_dropped is not None and dur_sec is not None and stored_tps is not None:
        if dur_sec <= 0:
            errors.append("tier0_replay.duration_seconds must be positive")
        else:
            exp_dropped = max(0, lines_written - lines_read)
            if lines_dropped != exp_dropped:
                errors.append(f"tier0_replay lines_dropped mismatch: stored {lines_dropped}, expected {exp_dropped}")

            calc_tps = round(lines_read / dur_sec, 2)
            # Require stored and recomputed throughput to match at the published 2-decimal precision.
            if f"{stored_tps:.2f}" != f"{calc_tps:.2f}":
                errors.append(
                    f"Tier 0 throughput recomputation mismatch: stored {stored_tps:.2f}, calculated {calc_tps:.2f} "
                    f"({lines_read} / {dur_sec})"
                )
            if tps_target is not None:
                exp_tps_status = "PASSED" if calc_tps >= tps_target else "MISSED TARGET"
                if t0.get("throughput_gate_status") != exp_tps_status:
                    errors.append(
                        f"tier0_replay throughput_gate_status mismatch: expected {exp_tps_status!r} "
                        f"for recomputed throughput {calc_tps:.2f} vs target {tps_target:.2f}"
                    )

        if tmpls is not None and stored_collapse is not None:
            calc_collapse = round(lines_read / tmpls, 2)
            if f"{stored_collapse:.2f}" != f"{calc_collapse:.2f}":
                errors.append(
                    f"Tier 0 collapse_ratio recomputation mismatch: stored {stored_collapse:.2f}, calculated {calc_collapse:.2f}"
                )

        if drop_target is not None and isinstance(digest_matched, bool):
            exp_lossless_status = (
                "PASSED"
                if lines_dropped <= drop_target and lines_read == lines_written and digest_matched
                else "FAILED"
            )
            if t0.get("lossless_gate_status") != exp_lossless_status:
                errors.append(f"tier0_replay lossless_gate_status mismatch: expected {exp_lossless_status!r}")

    # 3. Tier 1 surprisal latency percentile monotonicity and benign/anomalous separation
    p99_target_us = _req_num(gates, "tier1_p99_target_us", errors, "acceptance_gates")
    _req_int(t1, "evaluations", errors, "tier1_surprisal", min_val=1)
    _req_int(t1, "baseline_cases", errors, "tier1_surprisal", min_val=1)
    p50_us = _req_num(t1, "p50_us", errors, "tier1_surprisal")
    p90_us = _req_num(t1, "p90_us", errors, "tier1_surprisal")
    p99_us = _req_num(t1, "p99_us", errors, "tier1_surprisal")
    max_us = _req_num(t1, "max_us", errors, "tier1_surprisal")
    benign_mean = _req_num(t1, "benign_mean_nats", errors, "tier1_surprisal")
    anom_mean = _req_num(t1, "anomalous_mean_nats", errors, "tier1_surprisal")
    stored_sep = _req_num(t1, "separation_nats", errors, "tier1_surprisal")

    if p50_us is not None and p90_us is not None and p99_us is not None and max_us is not None:
        if not (0 < p50_us <= p90_us <= p99_us <= max_us):
            errors.append(
                f"Tier 1 latency percentile monotonicity violated: "
                f"p50={p50_us}us, p90={p90_us}us, p99={p99_us}us, max={max_us}us"
            )
        if p99_target_us is not None:
            exp_p99_status = "PASSED" if p99_us < p99_target_us else "MISSED TARGET"
            if t1.get("p99_gate_status") != exp_p99_status:
                errors.append(f"tier1_surprisal p99_gate_status mismatch: expected {exp_p99_status!r}")

    if benign_mean is not None and anom_mean is not None and stored_sep is not None:
        calc_sep = round(anom_mean - benign_mean, 4)
        if abs(calc_sep - stored_sep) > 0.001:
            errors.append(f"Tier 1 separation_nats mismatch: stored {stored_sep}, calculated {calc_sep}")

    # 4. Labeled detection confusion matrix and raw-count Precision/Recall/F1 recomputation
    f1_target = _req_num(gates, "detection_f1_target", errors, "acceptance_gates")
    tot_win = _req_int(det, "total_windows", errors, "detection_accuracy", min_val=1)
    pos_win = _req_int(det, "positive_windows", errors, "detection_accuracy", min_val=0)
    neg_win = _req_int(det, "negative_windows", errors, "detection_accuracy", min_val=0)
    tp = _req_int(det, "true_positives", errors, "detection_accuracy", min_val=0)
    fp = _req_int(det, "false_positives", errors, "detection_accuracy", min_val=0)
    fn = _req_int(det, "false_negatives", errors, "detection_accuracy", min_val=0)
    tn = _req_int(det, "true_negatives", errors, "detection_accuracy", min_val=0)
    t0_det = _req_int(det, "tier0_detections", errors, "detection_accuracy", min_val=0)
    t1_det = _req_int(det, "tier1_only_detections", errors, "detection_accuracy", min_val=0)
    stored_prec = _req_num(det, "precision", errors, "detection_accuracy")
    stored_rec = _req_num(det, "recall", errors, "detection_accuracy")
    stored_f1 = _req_num(det, "f1_score", errors, "detection_accuracy")

    calc_prec = calc_rec = calc_f1 = None
    if None not in (tot_win, pos_win, neg_win, tp, fp, fn, tn, t0_det, t1_det, stored_prec, stored_rec, stored_f1):
        if tot_win != pos_win + neg_win or tot_win != tp + fp + fn + tn:
            errors.append(
                f"Detection confusion matrix totals inconsistent: total={tot_win}, pos+neg={pos_win + neg_win}, sum={tp + fp + fn + tn}"
            )
        if tp + fn != pos_win or tn + fp != neg_win:
            errors.append(
                f"Detection class partition mismatch: tp+fn={tp + fn} vs pos={pos_win}, tn+fp={tn + fp} vs neg={neg_win}"
            )
        if t0_det + t1_det != tp:
            errors.append(f"Detection tier breakdown mismatch: tier0({t0_det}) + tier1_only({t1_det}) != tp({tp})")

        calc_prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        calc_rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        calc_f1 = round((2 * tp) / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) > 0 else 0.0
        if abs(calc_prec - stored_prec) > 0.0005:
            errors.append(f"Detection precision mismatch: stored {stored_prec}, calculated {calc_prec}")
        if abs(calc_rec - stored_rec) > 0.0005:
            errors.append(f"Detection recall mismatch: stored {stored_rec}, calculated {calc_rec}")
        if abs(calc_f1 - stored_f1) > 0.0005:
            errors.append(f"Detection f1_score mismatch: stored {stored_f1}, calculated {calc_f1}")
        if f1_target is not None:
            exp_f1_status = "PASSED" if calc_f1 >= f1_target else "MISSED TARGET"
            if det.get("f1_gate_status") != exp_f1_status:
                errors.append(f"detection_accuracy f1_gate_status mismatch: expected {exp_f1_status!r}")

    # 5. Tier 2 triage latency & defensive injection-safety checks (when enabled)
    # Note: injection_overrides_actual counts defensive fail-closed overrides where Sentinel
    # forced a coerced BENIGN-NOISE model output back to NEEDS-REVIEW (HIGH).
    t2_enabled = t2.get("enabled")
    if not isinstance(t2_enabled, bool):
        errors.append(f"tier2_triage.enabled must be a boolean, got {t2_enabled!r}")
    elif t2_enabled:
        t2_p50 = _req_num(t2, "p50_ms", errors, "tier2_triage")
        t2_p90 = _req_num(t2, "p90_ms", errors, "tier2_triage")
        t2_p99 = _req_num(t2, "p99_ms", errors, "tier2_triage")
        t2_max = _req_num(t2, "max_ms", errors, "tier2_triage")
        if None not in (t2_p50, t2_p90, t2_p99, t2_max):
            if not (0 < t2_p50 <= t2_p90 <= t2_p99 <= t2_max):
                errors.append(
                    f"Tier 2 latency percentile monotonicity violated: "
                    f"p50={t2_p50}ms, p90={t2_p90}ms, p99={t2_p99}ms, max={t2_max}ms"
                )
        inj_attempted = _req_int(t2, "injection_probes_attempted", errors, "tier2_triage", min_val=0)
        inj_failed = _req_int(t2, "injection_probes_failed", errors, "tier2_triage", min_val=0)
        inj_safe = _req_int(t2, "injection_probes_safe", errors, "tier2_triage", min_val=0)
        inj_actual = _req_int(t2, "injection_overrides_actual", errors, "tier2_triage", min_val=0)
        if None not in (inj_attempted, inj_failed, inj_safe, inj_actual):
            if inj_safe + inj_failed > inj_attempted:
                errors.append(
                    f"tier2_triage probe accounting inconsistent: safe({inj_safe}) + failed({inj_failed}) > attempted({inj_attempted})"
                )
            if inj_actual > inj_safe:
                errors.append(f"tier2_triage injection_overrides_actual ({inj_actual}) > injection_probes_safe ({inj_safe})")
            if inj_attempted == 0 or inj_failed > 0:
                exp_inj_status = "INCOMPLETE"
            elif inj_safe == inj_attempted:
                exp_inj_status = "PASSED"
            else:
                exp_inj_status = "FAILED"
            if t2.get("injection_override_gate_status") != exp_inj_status:
                errors.append(f"tier2_triage injection_override_gate_status mismatch: expected {exp_inj_status!r}")
    else:
        if t2.get("injection_override_gate_status") != "SKIPPED":
            errors.append("tier2_triage disabled run must report injection_override_gate_status='SKIPPED'")

    # 6. Memory bounds and RSS parity
    ceiling_mb = _req_num(gates, "memory_ceiling_mb", errors, "acceptance_gates")
    plateau_mb = _req_num(mem, "heap_alloc_plateau_mb", errors, "memory_profile")
    peak_mb = _req_num(mem, "heap_alloc_peak_mb", errors, "memory_profile")
    rss_kb = _req_int(mem, "rss_peak_kb", errors, "memory_profile", min_val=1)
    rss_mb = _req_num(mem, "rss_peak_mb", errors, "memory_profile")
    calc_rss_mb = None
    if plateau_mb is not None and peak_mb is not None:
        if not (0 < plateau_mb <= peak_mb):
            errors.append(f"Memory heap invariant violated: plateau={plateau_mb}MB, peak={peak_mb}MB")
        if ceiling_mb is not None:
            exp_heap_status = "PASSED" if plateau_mb <= ceiling_mb and peak_mb <= ceiling_mb else "MISSED TARGET"
            if mem.get("heap_gate_status") != exp_heap_status:
                errors.append(f"memory_profile heap_gate_status mismatch: expected {exp_heap_status!r}")
    if rss_kb is not None and rss_mb is not None:
        calc_rss_mb = round(rss_kb / 1024.0, 2)
        if f"{rss_mb:.2f}" != f"{calc_rss_mb:.2f}":
            errors.append(f"rss_peak_mb mismatch: stored {rss_mb:.2f}, calculated {calc_rss_mb:.2f}")

    # 7. Adversarial inline checks
    adv_target = _req_num(gates, "adversarial_pass_target_pct", errors, "acceptance_gates")
    adv_total = _req_int(adv, "total_checks", errors, "adversarial_checks", min_val=1)
    adv_passed = _req_int(adv, "passed_checks", errors, "adversarial_checks", min_val=0)
    adv_pct = _req_num(adv, "pass_rate_pct", errors, "adversarial_checks")
    calc_adv_pct = None
    if adv_total is not None and adv_passed is not None and adv_pct is not None:
        if adv_passed > adv_total:
            errors.append(f"adversarial_checks passed_checks ({adv_passed}) > total_checks ({adv_total})")
        else:
            calc_adv_pct = round(adv_passed * 100.0 / adv_total, 2)
            if f"{adv_pct:.2f}" != f"{calc_adv_pct:.2f}":
                errors.append(f"adversarial_checks pass_rate_pct mismatch: stored {adv_pct:.2f}, calculated {calc_adv_pct:.2f}")
            if adv_target is not None:
                exp_adv_status = "PASSED" if calc_adv_pct >= adv_target else "FAILED"
                if adv.get("gate_status") != exp_adv_status:
                    errors.append(f"adversarial_checks gate_status mismatch: expected {exp_adv_status!r}")

    # 8. Published-table row parity cross-check against repo-confined Markdown benchmark report
    report_rel = meta.get("report_markdown", "")
    report_path: Path | None = None
    if not isinstance(report_rel, str) or not report_rel.strip():
        errors.append(f"Referenced markdown benchmark report path is missing or invalid: {report_rel!r}")
    elif Path(report_rel).is_absolute():
        errors.append(f"Referenced markdown benchmark report must be repository-relative, got absolute path: {report_rel!r}")
    else:
        cand = (repo_root / report_rel).resolve()
        try:
            cand.relative_to(repo_root.resolve())
        except ValueError:
            errors.append(f"Referenced markdown benchmark report escapes repository root: {report_rel!r}")
        else:
            if not cand.is_file():
                errors.append(f"Referenced markdown benchmark report not found: {report_rel!r}")
            else:
                report_path = cand

    if report_path is not None and not errors:
        try:
            md_text = report_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return False, [f"Failed to read markdown benchmark report {report_rel}: {exc}"]
        if "/Users/" in md_text or "/home/" in md_text:
            errors.append(f"Markdown benchmark report {report_rel} contains leaked personal host path")

        published_rows, dup_labels = _extract_published_markdown_table_rows(md_text)
        if dup_labels:
            errors.append(f"Markdown benchmark report {report_rel} contains duplicate metric row labels: {dup_labels}")

        expected_rows = [
            f"| **Lines Written / Read** | `{lines_written}` written / `{lines_read}` read (`{lines_dropped}` dropped, digest matched=`{'true' if digest_matched else 'false'}`) | `{t0['lossless_gate_status']}` |",
            f"| **Tier 0+1 Throughput** | `{calc_tps:.2f} lines/sec` (target >= {tps_target:.0f} lines/sec) | `{t0['throughput_gate_status']}` |",
            f"| **Templates Emitted / Collapse Ratio** | `{tmpls}` windows (`{calc_collapse:.2f}x` collapse, `{t0.get('clusters_active', 0)}` active clusters) | — |",
            f"| **Latency P50 / P90 / P99 / Max** | `{p50_us:.3f} us` / `{p90_us:.3f} us` / `{p99_us:.3f} us` / `{max_us:.3f} us` | `{t1['p99_gate_status']}` |",
            f"| **Precision / Recall / F1** | `{calc_prec:.4f}` / `{calc_rec:.4f}` / `{calc_f1:.4f}` (target F1 >= {f1_target:.2f}) | `{det['f1_gate_status']}` |",
            f"| **Sampled Go Heap Plateau / Peak** | `{plateau_mb:.2f} MB` plateau / `{peak_mb:.2f} MB` sampled peak (ceiling `{ceiling_mb:.0f} MB`, method=`{mem.get('heap_sampling_method', '')}`) | `{mem['heap_gate_status']}` |",
            f"| **Process Peak RSS** | `{rss_kb} KB` (`{calc_rss_mb:.2f} MB`) | — |",
            f"| **Adversarial Hostile-Log Self-Checks** | `{adv_passed}/{adv_total}` passed (`{calc_adv_pct:.2f}%`) | `{adv['gate_status']}` |",
        ]
        if t2_enabled:
            expected_rows.extend([
                f"| **Inference Latency P50 / P90 / P99 / Max** | `{t2['p50_ms']:.3f} ms` / `{t2['p90_ms']:.3f} ms` / `{t2['p99_ms']:.3f} ms` / `{t2['max_ms']:.3f} ms` | — |",
                f"| **Hostile Injection Safety** | `{t2['injection_probes_safe']}/{t2['injection_probes_attempted']}` safe non-benign verdicts (`{t2['injection_overrides_actual']}` actual overrides, `{t2['injection_probes_failed']}` failed) | `{t2['injection_override_gate_status']}` |",
            ])
        for row in expected_rows:
            if row not in published_rows:
                errors.append(f"Benchmark JSON/Markdown published-table parity error: expected row {row!r} missing from {report_rel}")

    return len(errors) == 0, errors


def independent_recompute_embedding_comparison(embedding_json_path: Path) -> tuple[bool, list[str]]:
    """Independently verify mathematical consistency of docs/benchmarks/embedding_comparison.json."""
    errors: list[str] = []
    if not embedding_json_path.exists():
        return True, []
    if not embedding_json_path.is_file():
        return False, [f"Embedding comparison path is not a regular file: {embedding_json_path}"]

    try:
        raw = embedding_json_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, [f"Failed to read {embedding_json_path}: {exc}"]
    if "/Users/" in raw or "/home/" in raw:
        errors.append("Embedding comparison JSON contains leaked personal host path")
    try:
        data = _loads_strict_json(raw)
    except Exception as exc:
        return False, [f"Failed to parse {embedding_json_path}: {exc}"]
    if not isinstance(data, dict):
        return False, [f"Embedding comparison JSON root must be an object, got {type(data).__name__}"]
    if _contains_personal_host_path(data):
        errors.append("Embedding comparison JSON contains leaked personal host path in decoded strings")

    ds = _req_dict(data, "dataset", errors, "embedding_comparison")
    lk = _req_dict(data, "pure_laplace_lk", errors, "embedding_comparison")
    hyb = _req_dict(data, "hybrid_laplace_lk_minilm", errors, "embedding_comparison")
    cmp_sec = _req_dict(data, "comparison", errors, "embedding_comparison")
    if errors:
        return False, errors

    eval_total = _req_int(ds, "eval_total_windows", errors, "dataset", min_val=1)
    eval_benign = _req_int(ds, "eval_benign_windows", errors, "dataset", min_val=0)
    eval_struct = _req_int(ds, "eval_structural_attack_windows", errors, "dataset", min_val=0)
    eval_disg = _req_int(ds, "eval_disguised_semantic_windows", errors, "dataset", min_val=0)
    if None not in (eval_total, eval_benign, eval_struct, eval_disg):
        eval_attacks = eval_struct + eval_disg
        if eval_benign + eval_attacks != eval_total:
            errors.append(
                f"embedding_comparison dataset totals inconsistent: benign({eval_benign}) + attacks({eval_attacks}) != total({eval_total})"
            )
    else:
        return False, errors

    recomputed: dict[str, dict[str, float | int]] = {}
    for key, sec in (("pure_laplace_lk", lk), ("hybrid_laplace_lk_minilm", hyb)):
        tp = _req_int(sec, "tp", errors, key, min_val=0)
        fp = _req_int(sec, "fp", errors, key, min_val=0)
        fn = _req_int(sec, "fn", errors, key, min_val=0)
        tn = _req_int(sec, "tn", errors, key, min_val=0)
        struct_tp = _req_int(sec, "structural_tp", errors, key, min_val=0)
        disg_tp = _req_int(sec, "disguised_semantic_tp", errors, key, min_val=0)
        stored_prec = _req_num(sec, "precision", errors, key)
        stored_rec = _req_num(sec, "recall", errors, key)
        stored_f1 = _req_num(sec, "f1", errors, key)
        stored_struct_rec = _req_num(sec, "structural_recall", errors, key)
        stored_disg_rec = _req_num(sec, "disguised_semantic_recall", errors, key)
        p50 = _req_num(sec, "latency_p50_ms", errors, key)
        p99 = _req_num(sec, "latency_p99_ms", errors, key)
        if None in (tp, fp, fn, tn, struct_tp, disg_tp, stored_prec, stored_rec, stored_f1, stored_struct_rec, stored_disg_rec, p50, p99):
            continue

        if tp + fp + fn + tn != eval_total:
            errors.append(f"embedding_comparison {key}: confusion sum {tp + fp + fn + tn} != eval_total {eval_total}")
        if tp + fn != eval_attacks:
            errors.append(f"embedding_comparison {key}: tp+fn ({tp + fn}) != attack windows ({eval_attacks})")
        if tn + fp != eval_benign:
            errors.append(f"embedding_comparison {key}: tn+fp ({tn + fp}) != benign windows ({eval_benign})")
        if struct_tp + disg_tp != tp:
            errors.append(f"embedding_comparison {key}: structural_tp({struct_tp}) + disguised_semantic_tp({disg_tp}) != tp({tp})")
        if struct_tp > eval_struct or disg_tp > eval_disg:
            errors.append(f"embedding_comparison {key}: subgroup tp exceeds subgroup window count")

        prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round((2 * tp) / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) > 0 else 0.0
        struct_rec = round(struct_tp / max(eval_struct, 1), 4)
        disg_rec = round(disg_tp / max(eval_disg, 1), 4)
        if abs(prec - stored_prec) > 0.0005:
            errors.append(f"embedding_comparison {key} precision mismatch: stored {stored_prec}, calc {prec}")
        if abs(rec - stored_rec) > 0.0005:
            errors.append(f"embedding_comparison {key} recall mismatch: stored {stored_rec}, calc {rec}")
        if abs(f1 - stored_f1) > 0.0005:
            errors.append(f"embedding_comparison {key} f1 mismatch: stored {stored_f1}, calc {f1}")
        if abs(struct_rec - stored_struct_rec) > 0.0005:
            errors.append(f"embedding_comparison {key} structural_recall mismatch: stored {stored_struct_rec}, calc {struct_rec}")
        if abs(disg_rec - stored_disg_rec) > 0.0005:
            errors.append(f"embedding_comparison {key} disguised_semantic_recall mismatch: stored {stored_disg_rec}, calc {disg_rec}")
        if not (0 < p50 <= p99):
            errors.append(f"embedding_comparison {key} latency ordering invalid: p50={p50}, p99={p99}")
        recomputed[key] = {"f1": f1, "disg_rec": disg_rec, "fp": fp}

    if "pure_laplace_lk" in recomputed and "hybrid_laplace_lk_minilm" in recomputed:
        stored_f1_delta = _req_num(cmp_sec, "f1_delta", errors, "comparison")
        stored_disg_delta = _req_num(cmp_sec, "disguised_semantic_recall_delta", errors, "comparison")
        if stored_f1_delta is not None:
            exp_f1_delta = round(recomputed["hybrid_laplace_lk_minilm"]["f1"] - recomputed["pure_laplace_lk"]["f1"], 4)
            if abs(exp_f1_delta - stored_f1_delta) > 0.0005:
                errors.append(f"embedding_comparison f1_delta mismatch: stored {stored_f1_delta}, calc {exp_f1_delta}")
        if stored_disg_delta is not None:
            exp_disg_delta = round(recomputed["hybrid_laplace_lk_minilm"]["disg_rec"] - recomputed["pure_laplace_lk"]["disg_rec"], 4)
            if abs(exp_disg_delta - stored_disg_delta) > 0.0005:
                errors.append(
                    f"embedding_comparison disguised_semantic_recall_delta mismatch: "
                    f"stored {stored_disg_delta}, calc {exp_disg_delta}"
                )

    return len(errors) == 0, errors


def _verify_claim_term_evidence(term_id: str, term_cfg: dict, repo_root: Path) -> list[str]:
    """Verify that a claim_term entry declares non-empty evidence files/symbols that exist in repo_root."""
    errs: list[str] = []
    evidence_list = term_cfg.get("evidence", [])
    if not isinstance(evidence_list, list) or not evidence_list:
        return [f"claim_term '{term_id}' is missing required non-empty 'evidence' list in claims_registry.json"]

    for item in evidence_list:
        file_part, sep, symbol_part = str(item).partition(":")
        target = repo_root / file_part
        if not target.is_file():
            errs.append(f"claim_term '{term_id}' evidence file does not exist: {file_part}")
            continue
        if sep and symbol_part:
            text = target.read_text(encoding="utf-8")
            if symbol_part not in text:
                errs.append(f"claim_term '{term_id}' evidence symbol {symbol_part!r} not found in {file_part}")
    return errs


def lint_prose_and_words(
    content: str,
    doc_name: str = "document",
    registry_path: Path | None = None,
    repo_root: Path = REPO_ROOT,
) -> tuple[bool, list[str]]:
    """
    Word & personal-path lint:
    - Prohibit 'bulletproof', 'rock solid', 'conclusive', 'definitive', 'infinitely scalable'.
    - Guarded words ('verified', 'authentic', 'proves', 'zero hallucination', '100%')
      allowed only when tied to a registered claim marker <!-- claim:... --> or <!-- claim_term:... -->
      whose evidence exists on disk.
    - Prohibit leaked '/Users/' host paths.
    """
    errors: list[str] = []

    for idx, line in enumerate(content.splitlines(), 1):
        if "/Users/" in line:
            errors.append(f"Personal path leak in {doc_name}:{idx}: found '/Users/' host path.")
        lower = line.lower()
        if (
            "prohibits unprovable" in lower
            or "prohibited word" in lower
            or "prohibited marketing" in lower
            or "banned vocabulary" in lower
        ):
            continue
        for pat in PROHIBITED_WORDS:
            m = pat.search(line)
            if m:
                errors.append(
                    f"Word lint failure in {doc_name}:{idx}: prohibited adjective '{m.group(0)}' found."
                )

    if registry_path is None:
        registry_path = DEFAULT_REGISTRY_PATH
    claim_terms = {}
    if registry_path and registry_path.is_file():
        try:
            claim_terms = json.loads(registry_path.read_text(encoding="utf-8")).get("claim_terms", {})
        except Exception as exc:
            errors.append(f"Failed to load claim_terms from {registry_path.name}: {exc}")

    verified_term_ids: set[str] = set()
    claim_term_pat = re.compile(r"<!--\s*claim_term:([a-zA-Z0-9_\-]+)\s*-->(.*?)<!--\s*/claim_term\s*-->", re.DOTALL)
    for m in claim_term_pat.finditer(content):
        term_id = m.group(1)
        wrapped_text = m.group(2).strip()
        if term_id not in claim_terms:
            errors.append(f"Word lint failure in {doc_name}: unknown claim_term ID '{term_id}'.")
        else:
            expected_term = claim_terms[term_id].get("term", "")
            if wrapped_text.lower() != expected_term.lower():
                errors.append(
                    f"Word lint failure in {doc_name}: claim_term '{term_id}' wrapped text {wrapped_text!r} "
                    f"does not match registered term {expected_term!r}."
                )
            if term_id not in verified_term_ids:
                verified_term_ids.add(term_id)
                errors.extend(_verify_claim_term_evidence(term_id, claim_terms[term_id], repo_root))

    masked = re.sub(r"<!--\s*claim:[^>]+-->.*?<!--\s*/claim\s*-->", " ", content, flags=re.DOTALL)
    masked = re.sub(r"<!--\s*claim_term:[^>]+-->.*?<!--\s*/claim_term\s*-->", " ", masked, flags=re.DOTALL)

    for pat in GUARDED_WORDS:
        for match in pat.finditer(masked):
            line_no = masked[: match.start()].count("\n") + 1
            errors.append(
                f"Word lint failure in {doc_name} line {line_no}: guarded term '{match.group(0)}' "
                f"used in bare text without being tied to a registered claim marker."
            )

    return len(errors) == 0, errors


def check_empirical_regions(content: str, doc_name: str = "document") -> tuple[bool, list[str]]:
    """
    Verify that inside regions marked as empirical:
    1. Any empirical metric digit outside a claim marker in Target/Result/Status cells fails.
    2. Every data row's Status cell (last column) contains a registered `<!-- claim:... -->` marker.
    """
    errors: list[str] = []
    claim_marker_re = re.compile(r"<!--\s*claim:[a-zA-Z0-9_\-]+\s*-->.*?<!--\s*/claim\s*-->", re.DOTALL)

    for begin_marker, end_marker in EMPIRICAL_BLOCK_DELIMITERS:
        pattern = re.escape(begin_marker) + r"(.*?)" + re.escape(end_marker)
        for match in re.finditer(pattern, content, re.DOTALL):
            block_text = match.group(1)
            line_offset = content[: match.start()].count("\n") + 1
            filtered_lines = []
            for row_idx, line in enumerate(block_text.splitlines(), 1):
                line_str = line.strip()
                if not line_str:
                    continue
                if line_str.startswith("|") and (":---" in line_str or "Measured Result" in line_str):
                    continue
                if line_str.startswith("|") and line_str.endswith("|"):
                    parts = [p.strip() for p in line_str.split("|")[1:-1]]
                    if len(parts) >= 3:
                        status_cell = parts[-1]
                        if not claim_marker_re.search(status_cell):
                            errors.append(
                                f"Empirical block lint in {doc_name} (line {line_offset + row_idx - 1}): "
                                f"status cell {status_cell!r} must be governed by a <!-- claim:... --> marker"
                            )
                        metric_cells = " | ".join(parts[1:])
                        filtered_lines.append(metric_cells)
                        continue
                filtered_lines.append(line_str)
            block_to_check = "\n".join(filtered_lines)

            stripped = re.sub(r"<!--\s*claim:[^>]+-->.*?<!--\s*/claim\s*-->", " ", block_to_check, flags=re.DOTALL)
            stripped = re.sub(r"<!--.*?-->", " ", stripped, flags=re.DOTALL)

            digits = re.findall(r"\d+", stripped)
            if digits:
                errors.append(
                    f"Empirical block lint in {doc_name} (around line {line_offset}): "
                    f"found unmanaged digits outside claim marker in empirical block: {digits[:5]}"
                )

    return len(errors) == 0, errors


def sync_document(
    doc_path: Path,
    registry_path: Path,
    write: bool = False,
    repo_root: Path = REPO_ROOT,
) -> tuple[bool, list[str]]:
    """Verify or update claim markers in doc_path against registry_path."""
    messages: list[str] = []
    errors: list[str] = []

    if not registry_path.is_file():
        return False, [f"Registry not found: {registry_path}"]
    if not doc_path.is_file():
        return False, [f"Target doc not found: {doc_path}"]

    raw_reg = registry_path.read_text(encoding="utf-8")
    if "/Users/" in raw_reg:
        errors.append(f"Registry {registry_path.name} contains leaked '/Users/' path")
    registry = json.loads(raw_reg)
    claims = registry.get("claims", {})
    resolved_values: dict[str, str] = {}

    for claim_id, claim_cfg in claims.items():
        try:
            resolved_values[claim_id] = resolve_claim_value(claim_id, claim_cfg, repo_root=repo_root)
        except Exception as exc:
            errors.append(f"Failed to resolve claim '{claim_id}': {exc}")

    content = doc_path.read_text(encoding="utf-8")
    claim_pat = re.compile(r"<!--\s*claim:([a-zA-Z0-9_\-]+)\s*-->(.*?)<!--\s*/claim\s*-->", re.DOTALL)

    found_claims: set[str] = set()
    for m in claim_pat.finditer(content):
        cid = m.group(1)
        current_val = m.group(2)
        found_claims.add(cid)

        if cid not in resolved_values:
            errors.append(f"Unknown claim ID '{cid}' used in {doc_path.name}")
            continue

        expected_val = resolved_values[cid]
        if current_val != expected_val:
            if write:
                messages.append(f"Updated claim '{cid}' from {current_val!r} to {expected_val!r}")
            else:
                errors.append(
                    f"Claim drift for '{cid}' in {doc_path.name}: "
                    f"expected {expected_val!r}, found {current_val!r}"
                )

    try:
        doc_rel = str(doc_path.resolve().relative_to(repo_root.resolve())).replace("\\", "/")
    except ValueError:
        doc_rel = None

    if doc_rel:
        for claim_id, claim_cfg in claims.items():
            used_in = [u.replace("\\", "/") for u in claim_cfg.get("used_in", [])]
            if doc_rel in used_in and claim_id not in found_claims:
                errors.append(
                    f"Missing required claim marker '<!-- claim:{claim_id} -->' in {doc_rel} "
                    f"(registered in claims_registry.json 'used_in')"
                )

    if write:
        def repl(match):
            cid = match.group(1)
            if cid in resolved_values:
                return f"<!-- claim:{cid} -->{resolved_values[cid]}<!-- /claim -->"
            return match.group(0)

        updated_content = claim_pat.sub(repl, content)
        if updated_content != content:
            doc_path.write_text(updated_content, encoding="utf-8")
            messages.append(f"Wrote updated claims to {doc_path.name}")

    latest_text = doc_path.read_text(encoding="utf-8")
    emp_ok, emp_errors = check_empirical_regions(latest_text, doc_path.name)
    if not emp_ok:
        errors.extend(emp_errors)

    word_ok, word_errors = lint_prose_and_words(
        latest_text, doc_path.name, registry_path=registry_path, repo_root=repo_root
    )
    if not word_ok:
        errors.extend(word_errors)

    if errors:
        return False, errors
    return True, messages


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronize and lint Genesis Sentinel documentation claims.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="Check documentation claims without modifying files")
    mode.add_argument("--write", action="store_true", help="Overwrite documentation claim markers with ground truth")
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY_PATH, help="Path to claims_registry.json")
    parser.add_argument("--doc", type=Path, default=None, help="Specific markdown document to check/sync")

    args = parser.parse_args()
    do_write = args.write

    print(f"=== Genesis Sentinel Claims Synchronizer & Linter v2 (mode: {'WRITE' if do_write else 'CHECK'}) ===")
    overall_success = True

    bench_json = REPO_ROOT / "docs" / "benchmarks" / "empirical_benchmarks.json"
    metrics_ok, metrics_errs = independent_recompute_metrics(bench_json, repo_root=REPO_ROOT)
    if not metrics_ok:
        overall_success = False
        for err in metrics_errs:
            print(f"[FAIL] {err}", file=sys.stderr)
    else:
        print("[PASS] Independent benchmark math recomputation & Markdown parity verified.")

    emb_json = REPO_ROOT / "docs" / "benchmarks" / "embedding_comparison.json"
    if emb_json.exists():
        emb_ok, emb_errs = independent_recompute_embedding_comparison(emb_json)
        if not emb_ok:
            overall_success = False
            for err in emb_errs:
                print(f"[FAIL] {err}", file=sys.stderr)
        else:
            print("[PASS] Independent semantic embedding comparison math verified.")

    if do_write and not overall_success:
        print("\nAborting --write because benchmark artifact recomputation failed.", file=sys.stderr)
        return 1

    if args.doc is not None:
        target_docs = [args.doc]
    else:
        target_docs = [DEFAULT_README_PATH]
        if args.registry.is_file():
            try:
                reg_data = json.loads(args.registry.read_text(encoding="utf-8"))
                for c_cfg in reg_data.get("claims", {}).values():
                    for rel_p in c_cfg.get("used_in", []):
                        candidate = REPO_ROOT / rel_p
                        if candidate not in target_docs:
                            target_docs.append(candidate)
            except Exception as exc:
                overall_success = False
                print(f"[FAIL] Failed to parse {args.registry}: {exc}", file=sys.stderr)

    for doc_target in target_docs:
        doc_ok, doc_msgs = sync_document(doc_target, args.registry, write=do_write, repo_root=REPO_ROOT)
        if not doc_ok:
            overall_success = False
            for err in doc_msgs:
                print(f"[FAIL] {err}", file=sys.stderr)
        else:
            for msg in doc_msgs:
                print(f"[INFO] {msg}")
            print(f"[PASS] Document claims and constraints verified for {doc_target.name}.")

    if overall_success:
        print("\nAll Genesis Sentinel claims and empirical guardrails verified successfully.")
        return 0
    print("\nClaims synchronization / lint failed.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
