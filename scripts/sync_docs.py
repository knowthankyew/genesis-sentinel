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
