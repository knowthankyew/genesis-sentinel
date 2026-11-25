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


def independent_recompute_metrics(benchmark_json_path: Path, repo_root: Path = REPO_ROOT) -> tuple[bool, list[str]]:
    """
    Independently verify mathematical consistency of docs/benchmarks/empirical_benchmarks.json,
    status gate derivations, and exact parity against the committed Markdown benchmark report.
    """
    errors: list[str] = []
    if not benchmark_json_path.is_file():
        return False, [f"Missing empirical benchmark JSON: {benchmark_json_path}"]

    raw_json = benchmark_json_path.read_text(encoding="utf-8")
    if "/Users/" in raw_json:
        errors.append("Empirical benchmark JSON contains leaked personal '/Users/' path")

    try:
        data = json.loads(raw_json)
    except Exception as exc:
        return False, [f"Failed to parse {benchmark_json_path}: {exc}"]

    meta = data.get("metadata", {})
    gates = data.get("acceptance_gates", {})
    t0 = data.get("tier0_replay", {})
    t1 = data.get("tier1_surprisal", {})
    det = data.get("detection_accuracy", {})
    t2 = data.get("tier2_triage", {})
    mem = data.get("memory_profile", {})
    adv = data.get("adversarial_checks", {})

    # 1. Verify Sentinel version metadata against internal/cli/cli.go (when running against repo_root)
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

    # 2. Tier 0 replay throughput, lossless drop count, and template collapse ratio
    lines_written = t0.get("lines_written", 0)
    lines_read = t0.get("lines_read", 0)
    lines_dropped = t0.get("lines_dropped", -1)
    dur_sec = t0.get("duration_seconds", 0.0)
    stored_tps = t0.get("throughput_lps", 0.0)
    tmpls = t0.get("templates_emitted", 0)
    stored_collapse = t0.get("collapse_ratio", 0.0)

    if lines_written <= 0 or lines_read <= 0 or dur_sec <= 0:
        errors.append("tier0_replay must have positive lines_written, lines_read, and duration_seconds")
    else:
        exp_dropped = max(0, lines_written - lines_read)
        if lines_dropped != exp_dropped:
            errors.append(f"tier0_replay lines_dropped mismatch: stored {lines_dropped}, expected {exp_dropped}")

        calc_tps = round(lines_read / dur_sec, 2)
        if abs(calc_tps - stored_tps) > 0.05:
            errors.append(
                f"Tier 0 throughput recomputation mismatch: stored {stored_tps}, calculated {calc_tps} "
                f"({lines_read} / {dur_sec})"
            )

        if tmpls > 0:
            calc_collapse = round(lines_read / tmpls, 2)
            if abs(calc_collapse - stored_collapse) > 0.05:
                errors.append(
                    f"Tier 0 collapse_ratio recomputation mismatch: stored {stored_collapse}, calculated {calc_collapse}"
                )
        else:
            errors.append("tier0_replay templates_emitted must be positive")

    exp_tps_status = "PASSED" if stored_tps >= gates.get("throughput_target_lps", 50000) else "MISSED TARGET"
    if t0.get("throughput_gate_status") != exp_tps_status:
        errors.append(f"tier0_replay throughput_gate_status mismatch: expected {exp_tps_status!r}")

    exp_lossless_status = (
        "PASSED"
        if lines_dropped <= gates.get("lossless_dropped_target", 0) and lines_read == lines_written
        else "FAILED"
    )
    if t0.get("lossless_gate_status") != exp_lossless_status:
        errors.append(f"tier0_replay lossless_gate_status mismatch: expected {exp_lossless_status!r}")

    # 3. Tier 1 surprisal latency percentile monotonicity and benign/anomalous separation
    p50_us = t1.get("p50_us", 0.0)
    p90_us = t1.get("p90_us", 0.0)
    p99_us = t1.get("p99_us", 0.0)
    max_us = t1.get("max_us", 0.0)
    if not (0 < p50_us <= p90_us <= p99_us <= max_us):
        errors.append(
            f"Tier 1 latency percentile monotonicity violated: "
            f"p50={p50_us}us, p90={p90_us}us, p99={p99_us}us, max={max_us}us"
        )

    exp_p99_status = "PASSED" if p99_us < gates.get("tier1_p99_target_us", 2000.0) else "MISSED TARGET"
    if t1.get("p99_gate_status") != exp_p99_status:
        errors.append(f"tier1_surprisal p99_gate_status mismatch: expected {exp_p99_status!r}")

    benign_mean = t1.get("benign_mean_nats", 0.0)
    anom_mean = t1.get("anomalous_mean_nats", 0.0)
    stored_sep = t1.get("separation_nats", 0.0)
    calc_sep = round(anom_mean - benign_mean, 4)
    if abs(calc_sep - stored_sep) > 0.001:
        errors.append(f"Tier 1 separation_nats mismatch: stored {stored_sep}, calculated {calc_sep}")

    # 4. Labeled detection confusion matrix and precision/recall/F1 recomputation
    tot_win = det.get("total_windows", 0)
    pos_win = det.get("positive_windows", 0)
    neg_win = det.get("negative_windows", 0)
    tp = det.get("true_positives", 0)
    fp = det.get("false_positives", 0)
    fn = det.get("false_negatives", 0)
    tn = det.get("true_negatives", 0)
    t0_det = det.get("tier0_detections", 0)
    t1_det = det.get("tier1_only_detections", 0)

    if tot_win <= 0 or tot_win != pos_win + neg_win or tot_win != tp + fp + fn + tn:
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
    calc_f1 = round((2 * calc_prec * calc_rec) / (calc_prec + calc_rec), 4) if (calc_prec + calc_rec) > 0 else 0.0
    if abs(calc_prec - det.get("precision", -1.0)) > 0.0005:
        errors.append(f"Detection precision mismatch: stored {det.get('precision')}, calculated {calc_prec}")
    if abs(calc_rec - det.get("recall", -1.0)) > 0.0005:
        errors.append(f"Detection recall mismatch: stored {det.get('recall')}, calculated {calc_rec}")
    if abs(calc_f1 - det.get("f1_score", -1.0)) > 0.0005:
        errors.append(f"Detection f1_score mismatch: stored {det.get('f1_score')}, calculated {calc_f1}")

    exp_f1_status = "PASSED" if det.get("f1_score", 0.0) >= gates.get("detection_f1_target", 0.90) else "MISSED TARGET"
    if det.get("f1_gate_status") != exp_f1_status:
        errors.append(f"detection_accuracy f1_gate_status mismatch: expected {exp_f1_status!r}")

    # 5. Tier 2 triage latency & injection-override checks (when enabled)
    t2_enabled = bool(t2.get("enabled", False))
    if t2_enabled:
        t2_p50 = t2.get("p50_ms", 0.0)
        t2_p90 = t2.get("p90_ms", 0.0)
        t2_p99 = t2.get("p99_ms", 0.0)
        t2_max = t2.get("max_ms", 0.0)
        if not (0 < t2_p50 <= t2_p90 <= t2_p99 <= t2_max):
            errors.append(
                f"Tier 2 latency percentile monotonicity violated: "
                f"p50={t2_p50}ms, p90={t2_p90}ms, p99={t2_p99}ms, max={t2_max}ms"
            )
        inj_tested = t2.get("injection_probes_tested", 0)
        inj_safe = t2.get("injection_overrides_enforced", 0)
        exp_inj_status = "PASSED" if inj_tested > 0 and inj_safe == inj_tested else "FAILED"
        if t2.get("injection_override_gate_status") != exp_inj_status:
            errors.append(f"tier2_triage injection_override_gate_status mismatch: expected {exp_inj_status!r}")
    else:
        if t2.get("injection_override_gate_status") != "SKIPPED":
            errors.append("tier2_triage disabled run must report injection_override_gate_status='SKIPPED'")

    # 6. Memory bounds and RSS parity
    plateau_mb = mem.get("heap_alloc_plateau_mb", 0.0)
    peak_mb = mem.get("heap_alloc_peak_mb", 0.0)
    ceiling_mb = gates.get("memory_ceiling_mb", 256.0)
    if not (0 < plateau_mb <= peak_mb):
        errors.append(f"Memory heap invariant violated: plateau={plateau_mb}MB, peak={peak_mb}MB")
    exp_heap_status = "PASSED" if plateau_mb <= ceiling_mb and peak_mb <= ceiling_mb else "MISSED TARGET"
    if mem.get("heap_gate_status") != exp_heap_status:
        errors.append(f"memory_profile heap_gate_status mismatch: expected {exp_heap_status!r}")

    rss_kb = mem.get("rss_peak_kb", 0)
    rss_mb = mem.get("rss_peak_mb", 0.0)
    if rss_kb <= 0:
        errors.append(f"rss_peak_kb must be positive, got {rss_kb}")
    elif abs(round(rss_kb / 1024.0, 2) - rss_mb) > 0.05:
        errors.append(f"rss_peak_mb mismatch: stored {rss_mb}, calculated {round(rss_kb / 1024.0, 2)}")

    # 7. Adversarial inline checks
    adv_total = adv.get("total_checks", 0)
    adv_passed = adv.get("passed_checks", 0)
    adv_pct = adv.get("pass_rate_pct", 0.0)
    if adv_total <= 0 or adv_passed < 0 or adv_passed > adv_total:
        errors.append(f"adversarial_checks counts invalid: {adv_passed}/{adv_total}")
    else:
        calc_adv_pct = round(adv_passed * 100.0 / adv_total, 2)
        if abs(calc_adv_pct - adv_pct) > 0.02:
            errors.append(f"adversarial_checks pass_rate_pct mismatch: stored {adv_pct}, calculated {calc_adv_pct}")
    exp_adv_status = "PASSED" if adv_pct >= gates.get("adversarial_pass_target_pct", 100.0) else "FAILED"
    if adv.get("gate_status") != exp_adv_status:
        errors.append(f"adversarial_checks gate_status mismatch: expected {exp_adv_status!r}")

    # 8. Cross-verify against referenced Markdown benchmark report
    report_rel = meta.get("report_markdown", "")
    report_path = repo_root / report_rel if report_rel else None
    if not report_path or not report_path.is_file():
        errors.append(f"Referenced markdown benchmark report not found: {report_rel}")
    else:
        md_text = report_path.read_text(encoding="utf-8")
        if "/Users/" in md_text:
            errors.append(f"Markdown benchmark report {report_rel} contains leaked '/Users/' path")
        expected_tokens = [
            f"{stored_tps:.2f} lines/sec",
            f"{stored_collapse:.2f}x",
            f"{p50_us:.3f} us",
            f"{p90_us:.3f} us",
            f"{p99_us:.3f} us",
            f"{det.get('precision', 0.0):.4f}",
            f"{det.get('recall', 0.0):.4f}",
            f"{det.get('f1_score', 0.0):.4f}",
            f"{plateau_mb:.2f} MB",
            f"{peak_mb:.2f} MB",
            f"{rss_kb} KB",
            f"{adv_passed}/{adv_total}",
        ]
        if t2_enabled:
            expected_tokens.extend([
                f"{t2.get('p50_ms', 0.0):.3f} ms",
                f"{t2.get('p99_ms', 0.0):.3f} ms",
                f"{t2.get('injection_overrides_enforced', 0)}/{t2.get('injection_probes_tested', 0)}",
            ])
        for tok in expected_tokens:
            if tok not in md_text:
                errors.append(f"Benchmark JSON/Markdown parity error: token {tok!r} missing from {report_rel}")

    return len(errors) == 0, errors


def independent_recompute_embedding_comparison(embedding_json_path: Path) -> tuple[bool, list[str]]:
    """Independently verify mathematical consistency of docs/benchmarks/embedding_comparison.json."""
    errors: list[str] = []
    if not embedding_json_path.is_file():
        return True, []

    raw = embedding_json_path.read_text(encoding="utf-8")
    if "/Users/" in raw:
        errors.append("Embedding comparison JSON contains leaked personal '/Users/' path")
    try:
        data = json.loads(raw)
    except Exception as exc:
        return False, [f"Failed to parse {embedding_json_path}: {exc}"]

    ds = data.get("dataset", {})
    eval_total = ds.get("eval_total_windows", 0)
    for key in ("pure_laplace_lk", "hybrid_laplace_lk_minilm"):
        sec = data.get(key, {})
        tp, fp, fn, tn = sec.get("tp", 0), sec.get("fp", 0), sec.get("fn", 0), sec.get("tn", 0)
        if eval_total <= 0 or tp + fp + fn + tn != eval_total:
            errors.append(f"embedding_comparison {key}: confusion sum {tp + fp + fn + tn} != eval_total {eval_total}")
        prec = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        rec = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        f1 = round((2 * prec * rec) / (prec + rec), 4) if (prec + rec) > 0 else 0.0
        if abs(prec - sec.get("precision", -1.0)) > 0.0005:
            errors.append(f"embedding_comparison {key} precision mismatch: stored {sec.get('precision')}, calc {prec}")
        if abs(rec - sec.get("recall", -1.0)) > 0.0005:
            errors.append(f"embedding_comparison {key} recall mismatch: stored {sec.get('recall')}, calc {rec}")
        if abs(f1 - sec.get("f1", -1.0)) > 0.0005:
            errors.append(f"embedding_comparison {key} f1 mismatch: stored {sec.get('f1')}, calc {f1}")
        p50 = sec.get("latency_p50_ms", 0.0)
        p99 = sec.get("latency_p99_ms", 0.0)
        if not (0 < p50 <= p99):
            errors.append(f"embedding_comparison {key} latency ordering invalid: p50={p50}, p99={p99}")

    lk = data.get("pure_laplace_lk", {})
    hyb = data.get("hybrid_laplace_lk_minilm", {})
    cmp_sec = data.get("comparison", {})
    exp_f1_delta = round(hyb.get("f1", 0.0) - lk.get("f1", 0.0), 4)
    if abs(exp_f1_delta - cmp_sec.get("f1_delta", -99.0)) > 0.0005:
        errors.append(f"embedding_comparison f1_delta mismatch: stored {cmp_sec.get('f1_delta')}, calc {exp_f1_delta}")

    exp_disg_delta = round(hyb.get("disguised_semantic_recall", 0.0) - lk.get("disguised_semantic_recall", 0.0), 4)
    if abs(exp_disg_delta - cmp_sec.get("disguised_semantic_recall_delta", -99.0)) > 0.0005:
        errors.append(
            f"embedding_comparison disguised_semantic_recall_delta mismatch: "
            f"stored {cmp_sec.get('disguised_semantic_recall_delta')}, calc {exp_disg_delta}"
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
    if emb_json.is_file():
        emb_ok, emb_errs = independent_recompute_embedding_comparison(emb_json)
        if not emb_ok:
            overall_success = False
            for err in emb_errs:
                print(f"[FAIL] {err}", file=sys.stderr)
        else:
            print("[PASS] Independent semantic embedding comparison math verified.")

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
