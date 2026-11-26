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
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REGISTRY_PATH = REPO_ROOT / "docs" / "claims_registry.json"
DEFAULT_README_PATH = REPO_ROOT / "README.md"

EMPIRICAL_BLOCK_DELIMITERS = [
    ("<!-- BEGIN_EMPIRICAL -->", "<!-- END_EMPIRICAL -->"),
]

REQUIRED_CONCLUSION_SCRIPTS = (
    "eval_embedding_comparison.py",
)

_PERSONAL_HOST_PATH_RE = re.compile(r"(?:/Users/|/home/|[A-Za-z]:(?:\\|/)[Uu]sers(?:\\|/))")
_ALLOWED_PERCENTILE_TOKEN_RE = re.compile(r"\bP(?:50|90|95|99)\b")

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


def resolve_claim_value(
    claim_id: str,
    claim_cfg: dict,
    repo_root: Path = REPO_ROOT,
    validated_json_cache: dict[Path, dict] | None = None,
) -> str:
    """Resolve and format a registered claim value from its Go source or validated JSON snapshot."""
    artifact_rel = claim_cfg.get("source_artifact")
    if not isinstance(artifact_rel, str) or not artifact_rel.strip():
        raise ValueError(f"Claim '{claim_id}' missing 'source_artifact'")
    if Path(artifact_rel).is_absolute():
        raise ValueError(f"Claim '{claim_id}' source_artifact must be repository-relative: {artifact_rel!r}")
    artifact_path = repo_root / artifact_rel
    try:
        resolved_artifact = artifact_path.resolve()
        resolved_root = repo_root.resolve()
    except (ValueError, OSError) as exc:
        raise ValueError(f"Claim '{claim_id}' has invalid source_artifact {artifact_rel!r}: {exc}") from exc
    try:
        resolved_artifact.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"Claim '{claim_id}' source_artifact escapes repository root: {artifact_rel!r}") from exc

    fmt = claim_cfg.get("format_rule", "{value}")

    if "go_const" in claim_cfg:
        if not artifact_path.is_file():
            raise FileNotFoundError(f"Source artifact not found for claim '{claim_id}': {artifact_path}")
        val = extract_go_constant(artifact_path, claim_cfg["go_const"])
        return apply_format_rule(claim_id, fmt, val)

    if "json_path" in claim_cfg:
        if validated_json_cache is not None and resolved_artifact in validated_json_cache:
            data = validated_json_cache[resolved_artifact]
        else:
            if not artifact_path.is_file():
                raise FileNotFoundError(f"Source artifact not found for claim '{claim_id}': {artifact_path}")
            data = _loads_strict_json(artifact_path.read_text(encoding="utf-8"))
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


def _parse_finite_json_float(raw: str) -> float:
    val = float(raw)
    if not math.isfinite(val):
        raise ValueError(f"Non-finite JSON floating-point value not permitted: {raw!r}")
    return val


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"Duplicate JSON object member not permitted: {k!r}")
        out[k] = v
    return out


def _loads_strict_json(raw: str):
    return json.loads(
        raw,
        parse_float=_parse_finite_json_float,
        parse_constant=_reject_nonfinite_json_constant,
        object_pairs_hook=_reject_duplicate_json_keys,
    )


def _round_go(val: float, digits: int) -> float:
    """Match Go's math.Round(v * 10^digits) / 10^digits (IEEE 754 half away from zero)."""
    scale = 10 ** digits
    scaled = val * scale
    frac, whole = math.modf(abs(scaled))
    rounded = whole + (1.0 if frac >= 0.5 else 0.0)
    return math.copysign(rounded / scale, scaled)


def _nearest_rank_percentile(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    if p <= 0:
        return sorted_vals[0]
    if p >= 100:
        return sorted_vals[-1]
    idx = max(0, min(len(sorted_vals) - 1, math.ceil((p / 100.0) * len(sorted_vals)) - 1))
    return sorted_vals[idx]


def _req_sample_array(
    section: dict,
    key: str,
    expected_len: int,
    errors: list[str],
    prefix: str,
) -> list[float] | None:
    val = section.get(key)
    if not isinstance(val, list):
        errors.append(f"{prefix}.{key} must be a JSON array of raw timing samples, got {type(val).__name__}")
        return None
    if len(val) != expected_len:
        errors.append(f"{prefix}.{key} length mismatch: expected {expected_len} samples, got {len(val)}")
        return None
    out: list[float] = []
    for idx, item in enumerate(val):
        if not _is_finite_num(item) or float(item) <= 0:
            errors.append(f"{prefix}.{key}[{idx}] must be a positive finite number, got {item!r}")
            return None
        out.append(float(item))
    return out


def _has_personal_host_path_text(text: str) -> bool:
    """Detect leaked macOS (/Users/), Linux (/home/), or Windows (C:\\Users\\) personal paths."""
    return _PERSONAL_HOST_PATH_RE.search(text) is not None


def _contains_personal_host_path(obj) -> bool:
    """Recursively check decoded JSON strings for personal host prefixes (catching JSON-escaped slashes)."""
    if isinstance(obj, str):
        return _has_personal_host_path_text(obj)
    if isinstance(obj, dict):
        return any(_contains_personal_host_path(k) or _contains_personal_host_path(v) for k, v in obj.items())
    if isinstance(obj, list):
        return any(_contains_personal_host_path(v) for v in obj)
    return False


def _verify_git_commit_ancestry(commit: object, repo_root: Path, label: str, errors: list[str]) -> bool:
    """Verify git_commit metadata is a clean 7-40 hex hash (never 'unknown' or '-dirty') and an ancestor of HEAD."""
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{7,40}", commit):
        errors.append(
            f"{label}: git_commit {commit!r} must be a clean 7-40 hex git commit hash (dirty/unknown builds not permitted)"
        )
        return False
    if (repo_root / ".git").exists():
        try:
            rev = subprocess.run(
                ["git", "rev-parse", "--verify", "--quiet", f"{commit}^{{commit}}"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
            )
            if rev.returncode != 0:
                errors.append(f"{label}: git_commit '{commit}' not found in repository git history")
                return False
            anc = subprocess.run(
                ["git", "merge-base", "--is-ancestor", commit, "HEAD"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
            )
            if anc.returncode != 0:
                errors.append(f"{label}: git_commit '{commit}' is not an ancestor of HEAD")
                return False
        except FileNotFoundError as exc:
            errors.append(f"{label}: git executable not found while verifying commit ancestry ({exc})")
            return False
    return True


def lint_script_conclusions(scripts_dir: Path) -> tuple[bool, list[str]]:
    """
    AST check (ported from companion `ml`) verifying that functions building narrative
    conclusion/recommendation prose contain zero hardcoded numeric literals or digit-bearing
    string fragments (other than standard P50/P90/P95/P99 percentile labels and format specs),
    and that governed benchmark scripts define a `*conclusion*` builder function.
    """
    errors: list[str] = []
    if not scripts_dir.is_dir():
        return True, []

    def _walk_excluding_format_specs(node: ast.AST):
        yield node
        for field_name, field_val in ast.iter_fields(node):
            if isinstance(node, ast.FormattedValue) and field_name == "format_spec":
                continue
            if isinstance(field_val, list):
                for item in field_val:
                    if isinstance(item, ast.AST):
                        yield from _walk_excluding_format_specs(item)
            elif isinstance(field_val, ast.AST):
                yield from _walk_excluding_format_specs(field_val)

    for py_file in sorted(scripts_dir.glob("*.py")):
        if py_file.name in ("sync_docs.py", "audit-claims.py", "generate-sbom.py"):
            continue
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except Exception as exc:
            errors.append(f"Failed to parse AST for {py_file.name}: {exc}")
            continue

        found_conclusion_fn = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and "conclusion" in node.name.lower():
                found_conclusion_fn = True
                docstring_node = (
                    node.body[0].value
                    if (
                        node.body
                        and isinstance(node.body[0], ast.Expr)
                        and isinstance(node.body[0].value, ast.Constant)
                        and isinstance(node.body[0].value.value, str)
                    )
                    else None
                )
                for stmt in node.body:
                    for child in _walk_excluding_format_specs(stmt):
                        if child is docstring_node:
                            continue
                        if isinstance(child, ast.Constant) and isinstance(child.value, str):
                            scrubbed = _ALLOWED_PERCENTILE_TOKEN_RE.sub("", child.value)
                            if re.search(r"\d", scrubbed):
                                errors.append(
                                    f"Script AST lint: {py_file.name}::{node.name} line {getattr(child, 'lineno', '?')} "
                                    f"contains hardcoded digit in string fragment: {child.value!r}"
                                )
                        elif (
                            isinstance(child, ast.Constant)
                            and isinstance(child.value, (int, float))
                            and not isinstance(child.value, bool)
                        ):
                            errors.append(
                                f"Script AST lint: {py_file.name}::{node.name} line {getattr(child, 'lineno', '?')} "
                                f"contains hardcoded numeric literal: {child.value!r}"
                            )

        if py_file.name in REQUIRED_CONCLUSION_SCRIPTS and not found_conclusion_fn:
            errors.append(
                f"Script AST lint: {py_file.name} must define a conclusion builder function (*conclusion*) governed by AST lint."
            )

    return len(errors) == 0, errors


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


_HTML_TYPE1_OPEN_RE = re.compile(r"^ {0,3}<(pre|script|style|textarea)(?:[\s>]|$)", re.IGNORECASE)
_HTML_TYPE3_OPEN_RE = re.compile(r"^ {0,3}<\?")
_HTML_TYPE5_OPEN_RE = re.compile(r"^ {0,3}<!\[CDATA\[")
_HTML_TYPE6_OPEN_RE = re.compile(
    r"^ {0,3}</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|"
    r"dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|"
    r"head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|"
    r"p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:[\s/>]|$)",
    re.IGNORECASE,
)


def _parse_gfm_row(
    raw_line: str,
    require_outer_pipes: bool = False,
    min_cells: int = 2,
) -> tuple[str, list[str]] | None:
    """Parse a GFM table row outside 4-space/tab indented code blocks (optional outer pipes)."""
    if raw_line.startswith("    ") or raw_line.startswith("\t"):
        return None
    line = raw_line.strip()
    if not line or "|" not in line:
        return None
    if require_outer_pipes and not (line.startswith("|") and line.endswith("|") and len(line) >= 3):
        return None
    inner = line
    if inner.startswith("|"):
        inner = inner[1:]
    if inner.endswith("|") and not inner.endswith(r"\|"):
        inner = inner[:-1]
    cells = [c.strip() for c in re.split(r"(?<!\\)\|", inner)]
    if len(cells) < min_cells:
        return None
    return line, cells


def _is_gfm_delimiter_row(cells: list[str]) -> bool:
    return len(cells) >= 2 and all(re.fullmatch(r":?-{1,}:?", c) is not None for c in cells)


def _extract_published_markdown_table_rows(md_text: str) -> tuple[set[str], set[str], list[str]]:
    """
    Strip CommonMark fenced code blocks (backticks and tildes >= 3), 4-space/tab indented code
    blocks (before scanning for HTML comments), raw HTML blocks (Type 1 <pre>/<script>/<style>/
    <textarea>, Type 3 <? ... ?>, Type 5 <![CDATA[...]]>, and Type 6 block tags), and HTML
    comments (including unclosed '<!--' through EOF), then collect rendered body rows strictly
    from valid GFM tables (header row immediately followed by a matching-column delimiter row,
    supporting optional outer pipes, 1-cell body rows, and honoring GFM column-width truncation).
    Returns (published_table_rows, seen_bold_labels, duplicate_bold_labels).
    """
    cleaned_lines: list[str] = []
    fence_char: str | None = None
    fence_len = 0
    in_comment = False
    html_type1_end: re.Pattern[str] | None = None
    in_html_type3 = False
    in_html_type5 = False
    in_html_type6 = False
    can_start_indented_code = True

    for raw_line in md_text.splitlines():
        if fence_char is not None:
            close_m = re.match(r"^ {0,3}(" + re.escape(fence_char) + r"{3,})[ \t]*$", raw_line)
            if close_m and len(close_m.group(1)) >= fence_len:
                fence_char = None
                fence_len = 0
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        if html_type1_end is not None:
            if html_type1_end.search(raw_line):
                html_type1_end = None
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        if in_html_type3:
            if "?>" in raw_line:
                in_html_type3 = False
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        if in_html_type5:
            if "]]>" in raw_line:
                in_html_type5 = False
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        if in_html_type6:
            if raw_line.strip() == "":
                in_html_type6 = False
                can_start_indented_code = True
            cleaned_lines.append("")
            continue

        line = raw_line
        if in_comment:
            end_idx = line.find("-->")
            if end_idx == -1:
                cleaned_lines.append("")
                continue
            in_comment = False
            line = line[end_idx + 3:]
            if line.strip() == "":
                cleaned_lines.append("")
                can_start_indented_code = True
                continue

        if line.strip() == "":
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        # Classify 4-space / tab indented code blocks BEFORE scanning for HTML comments or fences.
        if can_start_indented_code and (line.startswith("    ") or line.startswith("\t")):
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        open_m = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if open_m:
            marker, info = open_m.group(1), open_m.group(2)
            # CommonMark §4.5: backtick info strings may not contain backticks.
            if marker[0] == "~" or "`" not in info:
                fence_char = marker[0]
                fence_len = len(marker)
                cleaned_lines.append("")
                can_start_indented_code = True
                continue

        # CommonMark §4.6 Type 1 raw HTML blocks (<pre>, <script>, <style>, <textarea>)
        m1 = _HTML_TYPE1_OPEN_RE.match(line)
        if m1:
            end_re = re.compile(rf"</{m1.group(1)}>", re.IGNORECASE)
            if not end_re.search(line):
                html_type1_end = end_re
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        # CommonMark §4.6 Type 3 raw HTML blocks (<? ... ?> processing instructions)
        if _HTML_TYPE3_OPEN_RE.match(line):
            if "?>" not in line:
                in_html_type3 = True
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        # CommonMark §4.6 Type 5 raw HTML blocks (<![CDATA[ ... ]]>)
        if _HTML_TYPE5_OPEN_RE.match(line):
            if "]]>" not in line:
                in_html_type5 = True
            cleaned_lines.append("")
            can_start_indented_code = True
            continue

        # CommonMark §4.6 Type 6 raw HTML blocks (<div>, <table>, etc., terminated by blank line)
        if _HTML_TYPE6_OPEN_RE.match(line):
            in_html_type6 = True
            cleaned_lines.append("")
            can_start_indented_code = False
            continue

        out_parts: list[str] = []
        pos = 0
        while True:
            start_idx = line.find("<!--", pos)
            if start_idx == -1:
                out_parts.append(line[pos:])
                break
            out_parts.append(line[pos:start_idx])
            end_idx = line.find("-->", start_idx + 4)
            if end_idx == -1:
                in_comment = True
                break
            pos = end_idx + 3
        cleaned = "".join(out_parts)
        cleaned_lines.append(cleaned)
        can_start_indented_code = cleaned.strip() == ""

    rows: set[str] = set()
    seen_labels: set[str] = set()
    dup_labels: list[str] = []
    i = 0
    total_lines = len(cleaned_lines)
    while i < total_lines:
        hdr = _parse_gfm_row(cleaned_lines[i], require_outer_pipes=False)
        if hdr is not None and i + 1 < total_lines:
            delim = _parse_gfm_row(cleaned_lines[i + 1], require_outer_pipes=False)
            if delim is not None and len(delim[1]) == len(hdr[1]) and _is_gfm_delimiter_row(delim[1]):
                header_cols = len(hdr[1])
                i += 2
                while i < total_lines:
                    body = _parse_gfm_row(cleaned_lines[i], require_outer_pipes=False, min_cells=1)
                    if body is None:
                        break
                    line, parts = body
                    # GFM §4.10 discards body cells beyond the header column width.
                    if len(parts) > header_cols:
                        rendered_parts = parts[:header_cols]
                        rendered_line = "| " + " | ".join(rendered_parts) + " |"
                    else:
                        rendered_parts = parts
                        rendered_line = line
                    rows.add(rendered_line)
                    if rendered_parts[0].startswith("**") and rendered_parts[0].endswith("**"):
                        lbl = rendered_parts[0]
                        if lbl in seen_labels:
                            dup_labels.append(lbl)
                        else:
                            seen_labels.add(lbl)
                    i += 1
                continue
        i += 1
    return rows, seen_labels, dup_labels


def independent_recompute_metrics(
    benchmark_json_path: Path,
    repo_root: Path = REPO_ROOT,
    validated_json_cache: dict[Path, dict] | None = None,
) -> tuple[bool, list[str]]:
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
    if _has_personal_host_path_text(raw_json):
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

    # 1. Verify Sentinel version, git_commit provenance, and Go code-constant gate pinning (when present in repo_root)
    git_commit = meta.get("git_commit")
    commit_valid = _verify_git_commit_ancestry(git_commit, repo_root, "Empirical benchmark metadata", errors)

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

    config_go = repo_root / "internal" / "config" / "config.go"
    if config_go.is_file():
        try:
            expected_mem_mb = extract_go_constant(config_go, "DefaultMaxMemMB")
            if gates.get("memory_ceiling_mb") != expected_mem_mb:
                errors.append(
                    f"Benchmark acceptance_gates.memory_ceiling_mb ({gates.get('memory_ceiling_mb')!r}) drifted from "
                    f"DefaultMaxMemMB ({expected_mem_mb!r}) in internal/config/config.go"
                )
        except Exception as exc:
            errors.append(f"Failed to extract DefaultMaxMemMB for gate check: {exc}")

    math_go = repo_root / "internal" / "surprisal" / "math.go"
    if math_go.is_file():
        try:
            expected_thresh = extract_go_constant(math_go, "DefaultThresholdNats")
            stored_thresh = t1.get("threshold_nats")
            if not _is_finite_num(stored_thresh) or float(stored_thresh) != float(expected_thresh):
                errors.append(
                    f"Benchmark tier1_surprisal.threshold_nats ({stored_thresh!r}) drifted from "
                    f"DefaultThresholdNats ({expected_thresh!r}) in internal/surprisal/math.go"
                )
        except Exception as exc:
            errors.append(f"Failed to extract DefaultThresholdNats for gate check: {exc}")

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
    clusters_active = _req_int(t0, "clusters_active", errors, "tier0_replay", min_val=0)

    calc_tps = None
    calc_collapse = None
    if lines_written is not None and lines_read is not None and lines_dropped is not None and dur_sec is not None and stored_tps is not None:
        if dur_sec <= 0:
            errors.append("tier0_replay.duration_seconds must be positive")
        else:
            exp_dropped = max(0, lines_written - lines_read)
            if lines_dropped != exp_dropped:
                errors.append(f"tier0_replay lines_dropped mismatch: stored {lines_dropped}, expected {exp_dropped}")

            # Match cmd/sentinel-bench/main.go exactly: durSec is rounded to 6 decimals before dividing,
            # tps is rounded half-away-from-zero to 2 decimals, and the gate compares that rounded tps.
            calc_tps = _round_go(lines_read / dur_sec, 2)
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
            calc_collapse = _round_go(lines_read / tmpls, 2)
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

    # 3. Tier 1 surprisal latency percentile recomputation from raw samples & benign/anomalous separation
    p99_target_us = _req_num(gates, "tier1_p99_target_us", errors, "acceptance_gates")
    t1_evals = _req_int(t1, "evaluations", errors, "tier1_surprisal", min_val=2)
    _req_int(t1, "baseline_cases", errors, "tier1_surprisal", min_val=1)
    p50_us = _req_num(t1, "p50_us", errors, "tier1_surprisal")
    p90_us = _req_num(t1, "p90_us", errors, "tier1_surprisal")
    p99_us = _req_num(t1, "p99_us", errors, "tier1_surprisal")
    max_us = _req_num(t1, "max_us", errors, "tier1_surprisal")
    benign_mean = _req_num(t1, "benign_mean_nats", errors, "tier1_surprisal")
    anom_mean = _req_num(t1, "anomalous_mean_nats", errors, "tier1_surprisal")
    stored_sep = _req_num(t1, "separation_nats", errors, "tier1_surprisal")
    raw_t1_samples = _req_sample_array(t1, "raw_samples_us", t1_evals, errors, "tier1_surprisal") if t1_evals is not None else None

    calc_t1: dict[str, float] = {}
    if p50_us is not None and p90_us is not None and p99_us is not None and max_us is not None:
        if not (0 < p50_us <= p90_us <= p99_us <= max_us):
            errors.append(
                f"Tier 1 latency percentile monotonicity violated: "
                f"p50={p50_us}us, p90={p90_us}us, p99={p99_us}us, max={max_us}us"
            )
        if raw_t1_samples is not None:
            sorted_t1 = sorted(raw_t1_samples)
            for lbl, stored_v, p_rank in (
                ("p50_us", p50_us, 50.0),
                ("p90_us", p90_us, 90.0),
                ("p99_us", p99_us, 99.0),
                ("max_us", max_us, 100.0),
            ):
                calc_v = _round_go(_nearest_rank_percentile(sorted_t1, p_rank), 3)
                calc_t1[lbl] = calc_v
                if f"{stored_v:.3f}" != f"{calc_v:.3f}":
                    errors.append(f"Tier 1 {lbl} raw-sample recomputation mismatch: stored {stored_v:.3f}, calculated {calc_v:.3f}")
        if p99_target_us is not None:
            gate_p99 = calc_t1.get("p99_us", p99_us)
            exp_p99_status = "PASSED" if gate_p99 < p99_target_us else "MISSED TARGET"
            if t1.get("p99_gate_status") != exp_p99_status:
                errors.append(
                    f"tier1_surprisal p99_gate_status mismatch: expected {exp_p99_status!r} "
                    f"for recomputed P99 {gate_p99:.3f}us vs target {p99_target_us:.3f}us"
                )

    if benign_mean is not None and anom_mean is not None and stored_sep is not None:
        calc_sep = _round_go(anom_mean - benign_mean, 4)
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

        calc_prec = _round_go(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        calc_rec = _round_go(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        calc_f1 = _round_go((2 * tp) / (2 * tp + fp + fn), 4) if (2 * tp + fp + fn) > 0 else 0.0
        for score_lbl, s_val, c_val in (
            ("precision", stored_prec, calc_prec),
            ("recall", stored_rec, calc_rec),
            ("f1_score", stored_f1, calc_f1),
        ):
            if not (0.0 <= s_val <= 1.0):
                errors.append(f"Detection {score_lbl} out of [0, 1] range: {s_val}")
            elif f"{s_val:.4f}" != f"{c_val:.4f}":
                errors.append(f"Detection {score_lbl} mismatch: stored {s_val:.4f}, calculated {c_val:.4f}")
        if f1_target is not None:
            exp_f1_status = "PASSED" if calc_f1 >= f1_target else "MISSED TARGET"
            if det.get("f1_gate_status") != exp_f1_status:
                errors.append(f"detection_accuracy f1_gate_status mismatch: expected {exp_f1_status!r}")

    # 5. Tier 2 triage latency & defensive injection-safety checks (when enabled)
    # Note: injection_overrides_actual counts defensive fail-closed overrides where Sentinel
    # forced a coerced BENIGN-NOISE model output back to NEEDS-REVIEW (HIGH).
    calc_t2: dict[str, float] = {}
    t2_enabled = t2.get("enabled")
    if not isinstance(t2_enabled, bool):
        errors.append(f"tier2_triage.enabled must be a boolean, got {t2_enabled!r}")
    elif t2_enabled:
        t2_samples = _req_int(t2, "samples_evaluated", errors, "tier2_triage", min_val=1)
        t2_p50 = _req_num(t2, "p50_ms", errors, "tier2_triage")
        t2_p90 = _req_num(t2, "p90_ms", errors, "tier2_triage")
        t2_p99 = _req_num(t2, "p99_ms", errors, "tier2_triage")
        t2_max = _req_num(t2, "max_ms", errors, "tier2_triage")
        raw_t2_samples = _req_sample_array(t2, "raw_samples_ms", t2_samples, errors, "tier2_triage") if t2_samples is not None else None
        if None not in (t2_p50, t2_p90, t2_p99, t2_max):
            if not (0 < t2_p50 <= t2_p90 <= t2_p99 <= t2_max):
                errors.append(
                    f"Tier 2 latency percentile monotonicity violated: "
                    f"p50={t2_p50}ms, p90={t2_p90}ms, p99={t2_p99}ms, max={t2_max}ms"
                )
            if raw_t2_samples is not None:
                sorted_t2 = sorted(raw_t2_samples)
                for lbl, stored_v, p_rank in (
                    ("p50_ms", t2_p50, 50.0),
                    ("p90_ms", t2_p90, 90.0),
                    ("p99_ms", t2_p99, 99.0),
                    ("max_ms", t2_max, 100.0),
                ):
                    calc_v = _round_go(_nearest_rank_percentile(sorted_t2, p_rank), 3)
                    calc_t2[lbl] = calc_v
                    if f"{stored_v:.3f}" != f"{calc_v:.3f}":
                        errors.append(f"Tier 2 {lbl} raw-sample recomputation mismatch: stored {stored_v:.3f}, calculated {calc_v:.3f}")
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
        calc_rss_mb = _round_go(rss_kb / 1024.0, 2)
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
            calc_adv_pct = _round_go(adv_passed * 100.0 / adv_total, 2)
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
        try:
            cand = (repo_root / report_rel).resolve()
            resolved_root = repo_root.resolve()
        except (ValueError, OSError) as exc:
            errors.append(f"Referenced markdown benchmark report path is invalid: {report_rel!r} ({exc})")
        else:
            try:
                cand.relative_to(resolved_root)
            except ValueError:
                errors.append(f"Referenced markdown benchmark report escapes repository root: {report_rel!r}")
            else:
                if not cand.is_file():
                    errors.append(f"Referenced markdown benchmark report not found: {report_rel!r}")
                else:
                    report_path = cand
                    if commit_valid and isinstance(git_commit, str):
                        if not re.fullmatch(rf"\d{{4}}-\d{{2}}-\d{{2}}-{re.escape(git_commit)}(?:-r[2-9]\d*)?\.md", cand.name):
                            errors.append(
                                f"Benchmark report_markdown filename {cand.name!r} must match "
                                f"'YYYY-MM-DD-{git_commit}[-rN].md' for metadata.git_commit={git_commit!r}"
                            )

    if report_path is not None and not errors:
        try:
            md_text = report_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return False, [f"Failed to read markdown benchmark report {report_rel}: {exc}"]
        if _has_personal_host_path_text(md_text):
            errors.append(f"Markdown benchmark report {report_rel} contains leaked personal host path")

        published_rows, seen_labels, dup_labels = _extract_published_markdown_table_rows(md_text)
        if dup_labels:
            errors.append(f"Markdown benchmark report {report_rel} contains duplicate metric row labels: {dup_labels}")

        row_t1_p50 = calc_t1.get("p50_us", p50_us)
        row_t1_p90 = calc_t1.get("p90_us", p90_us)
        row_t1_p99 = calc_t1.get("p99_us", p99_us)
        row_t1_max = calc_t1.get("max_us", max_us)
        expected_rows = [
            f"| **Lines Written / Read** | `{lines_written}` written / `{lines_read}` read (`{lines_dropped}` dropped, digest matched=`{'true' if digest_matched else 'false'}`) | `{t0['lossless_gate_status']}` |",
            f"| **Tier 0+1 Throughput** | `{calc_tps:.2f} lines/sec` (target >= {tps_target:.0f} lines/sec) | `{t0['throughput_gate_status']}` |",
            f"| **Templates Emitted / Collapse Ratio** | `{tmpls}` windows (`{calc_collapse:.2f}x` collapse, `{clusters_active}` active clusters) | — |",
            f"| **Latency P50 / P90 / P99 / Max** | `{row_t1_p50:.3f} us` / `{row_t1_p90:.3f} us` / `{row_t1_p99:.3f} us` / `{row_t1_max:.3f} us` | `{t1['p99_gate_status']}` |",
            f"| **Precision / Recall / F1** | `{calc_prec:.4f}` / `{calc_rec:.4f}` / `{calc_f1:.4f}` (target F1 >= {f1_target:.2f}) | `{det['f1_gate_status']}` |",
            f"| **Sampled Go Heap Plateau / Peak** | `{plateau_mb:.2f} MB` plateau / `{peak_mb:.2f} MB` sampled peak (ceiling `{ceiling_mb:.0f} MB`, method=`{mem.get('heap_sampling_method', '')}`) | `{mem['heap_gate_status']}` |",
            f"| **Process Peak RSS** | `{rss_kb} KB` (`{calc_rss_mb:.2f} MB`) | — |",
            f"| **Adversarial Hostile-Log Self-Checks** | `{adv_passed}/{adv_total}` passed (`{calc_adv_pct:.2f}%`) | `{adv['gate_status']}` |",
        ]
        if t2_enabled:
            row_t2_p50 = calc_t2.get("p50_ms", t2["p50_ms"])
            row_t2_p90 = calc_t2.get("p90_ms", t2["p90_ms"])
            row_t2_p99 = calc_t2.get("p99_ms", t2["p99_ms"])
            row_t2_max = calc_t2.get("max_ms", t2["max_ms"])
            expected_rows.extend([
                f"| **Inference Latency P50 / P90 / P99 / Max** | `{row_t2_p50:.3f} ms` / `{row_t2_p90:.3f} ms` / `{row_t2_p99:.3f} ms` / `{row_t2_max:.3f} ms` | — |",
                f"| **Hostile Injection Safety** | `{t2['injection_probes_safe']}/{t2['injection_probes_attempted']}` safe non-benign verdicts (`{t2['injection_overrides_actual']}` actual overrides, `{t2['injection_probes_failed']}` failed) | `{t2['injection_override_gate_status']}` |",
            ])
        else:
            for stale_lbl in (
                "**Model / Adapter**",
                "**Samples / Structured / Fallbacks**",
                "**Inference Latency P50 / P90 / P99 / Max**",
                "**Hostile Injection Safety**",
            ):
                if stale_lbl in seen_labels:
                    errors.append(
                        f"Benchmark Markdown report {report_rel} contains stale Tier 2 row {stale_lbl!r} while tier2_triage.enabled is false"
                    )
        for row in expected_rows:
            if row not in published_rows:
                errors.append(f"Benchmark JSON/Markdown published-table parity error: expected row {row!r} missing from {report_rel}")

    if not errors and validated_json_cache is not None:
        validated_json_cache[benchmark_json_path.resolve()] = data
    return len(errors) == 0, errors


def _format_expected_embedding_recommendation(
    model_short_name: str,
    threshold_nats: float,
    semantic_weight: float,
    recall_delta: float,
    lk_disg_recall: float,
    hyb_disg_recall: float,
    fp_delta: int,
    lk_fp: int,
    hyb_fp: int,
    lk_p50: float,
    hyb_p50: float,
    latency_ratio: float,
    rss_delta: float,
) -> str:
    if recall_delta > 0:
        recall_summary = (
            f"On this synthetic corpus at fixed threshold {threshold_nats:.1f} nats "
            f"(semantic_weight={semantic_weight:g}), disguised-semantic recall changed by "
            f"{recall_delta:+.4f} ({lk_disg_recall:.4f} -> "
            f"{hyb_disg_recall:.4f}) with FP delta {fp_delta:+d} "
            f"({lk_fp} -> {hyb_fp})."
        )
    else:
        recall_summary = (
            f"On this synthetic corpus at fixed threshold {threshold_nats:.1f} nats "
            f"(semantic_weight={semantic_weight:g}), disguised-semantic recall showed "
            f"{recall_delta:+.4f} change ({lk_disg_recall:.4f} -> "
            f"{hyb_disg_recall:.4f}) with FP delta {fp_delta:+d}."
        )
    return (
        f"In this Python proxy comparison, the Laplace-LK baseline scored P50 {lk_p50:.4f} ms vs hybrid "
        f"{model_short_name} P50 {hyb_p50:.4f} ms (~{latency_ratio}x slower in Python, +{rss_delta:.2f} MB peak "
        f"process RSS delta after PyTorch/Transformers imports). {recall_summary} Because neural embedding "
        f"inference measured {hyb_p50:.4f} ms P50 latency and +{rss_delta:.2f} MB post-import peak process RSS "
        f"overhead in this benchmark, semantic embeddings remain optional for sidecar or offline evaluation "
        f"rather than embedded in the zero-dependency Go binary."
    )


def independent_recompute_embedding_comparison(
    embedding_json_path: Path,
    repo_root: Path = REPO_ROOT,
    validated_json_cache: dict[Path, dict] | None = None,
    require_governed_fields: bool = False,
) -> tuple[bool, list[str]]:
    """Independently verify mathematical consistency and narrative parity of docs/benchmarks/embedding_comparison.json."""
    errors: list[str] = []
    if not embedding_json_path.exists():
        if require_governed_fields:
            return False, [f"Missing required embedding comparison JSON: {embedding_json_path}"]
        return True, []
    if not embedding_json_path.is_file():
        return False, [f"Embedding comparison path is not a regular file: {embedding_json_path}"]

    try:
        raw = embedding_json_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, [f"Failed to read {embedding_json_path}: {exc}"]
    if _has_personal_host_path_text(raw):
        errors.append("Embedding comparison JSON contains leaked personal host path")
    try:
        data = _loads_strict_json(raw)
    except Exception as exc:
        return False, [f"Failed to parse {embedding_json_path}: {exc}"]
    if not isinstance(data, dict):
        return False, [f"Embedding comparison JSON root must be an object, got {type(data).__name__}"]
    if _contains_personal_host_path(data):
        errors.append("Embedding comparison JSON contains leaked personal host path in decoded strings")

    meta = _req_dict(data, "metadata", errors, "embedding_comparison")
    ds = _req_dict(data, "dataset", errors, "embedding_comparison")
    lk = _req_dict(data, "pure_laplace_lk", errors, "embedding_comparison")
    hyb = _req_dict(data, "hybrid_laplace_lk_minilm", errors, "embedding_comparison")
    cmp_sec = _req_dict(data, "comparison", errors, "embedding_comparison")
    if errors:
        return False, errors

    if require_governed_fields or "git_commit" in meta:
        _verify_git_commit_ancestry(meta.get("git_commit"), repo_root, "Embedding comparison metadata", errors)
    if require_governed_fields and meta.get("offline_mode") is not True:
        errors.append(f"embedding_comparison metadata.offline_mode must be true, got {meta.get('offline_mode')!r}")

    calc_rss_delta: float | None = None
    if require_governed_fields or any(k in meta for k in ("rss_before_model_mb", "rss_after_model_mb", "rss_delta_mb")):
        rss_before = _req_num(meta, "rss_before_model_mb", errors, "metadata")
        rss_after = _req_num(meta, "rss_after_model_mb", errors, "metadata")
        rss_delta = _req_num(meta, "rss_delta_mb", errors, "metadata")
        if None not in (rss_before, rss_after, rss_delta):
            if not (0 < rss_before <= rss_after):
                errors.append(
                    f"embedding_comparison RSS ordering invalid: before={rss_before}MB, after={rss_after}MB"
                )
            else:
                calc_rss_delta = round(max(rss_after - rss_before, 0.0), 2)
                if f"{rss_delta:.2f}" != f"{calc_rss_delta:.2f}":
                    errors.append(
                        f"embedding_comparison metadata.rss_delta_mb mismatch: stored {rss_delta:.2f}, calc {calc_rss_delta:.2f}"
                    )

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
        for score_lbl, s_val, c_val in (
            ("precision", stored_prec, prec),
            ("recall", stored_rec, rec),
            ("f1", stored_f1, f1),
            ("structural_recall", stored_struct_rec, struct_rec),
            ("disguised_semantic_recall", stored_disg_rec, disg_rec),
        ):
            if not (0.0 <= s_val <= 1.0):
                errors.append(f"embedding_comparison {key} {score_lbl} out of [0, 1] range: {s_val}")
            elif f"{s_val:.4f}" != f"{c_val:.4f}":
                errors.append(f"embedding_comparison {key} {score_lbl} mismatch: stored {s_val:.4f}, calc {c_val:.4f}")
        if not (0 < p50 <= p99):
            errors.append(f"embedding_comparison {key} latency ordering invalid: p50={p50}, p99={p99}")
        raw_emb_samples = _req_sample_array(sec, "raw_samples_ms", eval_total, errors, key)
        eff_p50 = p50
        if raw_emb_samples is not None:
            sorted_emb = sorted(raw_emb_samples)
            calc_p50 = round(_nearest_rank_percentile(sorted_emb, 50.0), 4)
            calc_p99 = round(_nearest_rank_percentile(sorted_emb, 99.0), 4)
            eff_p50 = calc_p50
            if f"{p50:.4f}" != f"{calc_p50:.4f}":
                errors.append(f"embedding_comparison {key} latency_p50_ms raw-sample mismatch: stored {p50:.4f}, calc {calc_p50:.4f}")
            if f"{p99:.4f}" != f"{calc_p99:.4f}":
                errors.append(f"embedding_comparison {key} latency_p99_ms raw-sample mismatch: stored {p99:.4f}, calc {calc_p99:.4f}")
        recomputed[key] = {"f1": f1, "disg_rec": disg_rec, "fp": fp, "p50": eff_p50}

    if "pure_laplace_lk" in recomputed and "hybrid_laplace_lk_minilm" in recomputed:
        stored_f1_delta = _req_num(cmp_sec, "f1_delta", errors, "comparison")
        stored_fp_delta = _req_int(cmp_sec, "fp_delta", errors, "comparison")
        stored_disg_delta = _req_num(cmp_sec, "disguised_semantic_recall_delta", errors, "comparison")
        stored_slowdown = _req_num(cmp_sec, "p50_latency_slowdown_x", errors, "comparison")
        exp_fp_delta = int(recomputed["hybrid_laplace_lk_minilm"]["fp"]) - int(recomputed["pure_laplace_lk"]["fp"])
        exp_disg_delta = round(recomputed["hybrid_laplace_lk_minilm"]["disg_rec"] - recomputed["pure_laplace_lk"]["disg_rec"], 4)
        lk_p50_v = float(recomputed["pure_laplace_lk"]["p50"])
        hyb_p50_v = float(recomputed["hybrid_laplace_lk_minilm"]["p50"])
        exp_slowdown = round(hyb_p50_v / max(lk_p50_v, 0.0001), 1)

        if stored_f1_delta is not None:
            exp_f1_delta = round(recomputed["hybrid_laplace_lk_minilm"]["f1"] - recomputed["pure_laplace_lk"]["f1"], 4)
            if f"{stored_f1_delta:.4f}" != f"{exp_f1_delta:.4f}":
                errors.append(f"embedding_comparison f1_delta mismatch: stored {stored_f1_delta:.4f}, calc {exp_f1_delta:.4f}")
        if stored_fp_delta is not None and stored_fp_delta != exp_fp_delta:
            errors.append(f"embedding_comparison fp_delta mismatch: stored {stored_fp_delta}, calc {exp_fp_delta}")
        if stored_disg_delta is not None:
            if f"{stored_disg_delta:.4f}" != f"{exp_disg_delta:.4f}":
                errors.append(
                    f"embedding_comparison disguised_semantic_recall_delta mismatch: "
                    f"stored {stored_disg_delta:.4f}, calc {exp_disg_delta:.4f}"
                )
        if stored_slowdown is not None:
            if f"{stored_slowdown:.1f}" != f"{exp_slowdown:.1f}":
                errors.append(
                    f"embedding_comparison p50_latency_slowdown_x mismatch: stored {stored_slowdown:.1f}, calc {exp_slowdown:.1f}"
                )

        if require_governed_fields or "recommendation" in cmp_sec:
            rec_text = cmp_sec.get("recommendation")
            model_id = meta.get("model_id")
            thresh_nats = _req_num(ds, "threshold_nats", errors, "dataset")
            sem_weight = _req_num(ds, "semantic_weight_nats", errors, "dataset")
            if not isinstance(rec_text, str) or not rec_text.strip():
                errors.append("embedding_comparison comparison.recommendation must be a non-empty string")
            elif not isinstance(model_id, str) or not model_id.strip():
                errors.append("embedding_comparison metadata.model_id must be a non-empty string")
            elif calc_rss_delta is None:
                errors.append("embedding_comparison recommendation check requires metadata.rss_before_model_mb/rss_after_model_mb/rss_delta_mb")
            elif thresh_nats is not None and sem_weight is not None:
                exp_rec = _format_expected_embedding_recommendation(
                    model_short_name=model_id.split("/")[-1],
                    threshold_nats=thresh_nats,
                    semantic_weight=sem_weight,
                    recall_delta=exp_disg_delta,
                    lk_disg_recall=float(recomputed["pure_laplace_lk"]["disg_rec"]),
                    hyb_disg_recall=float(recomputed["hybrid_laplace_lk_minilm"]["disg_rec"]),
                    fp_delta=exp_fp_delta,
                    lk_fp=int(recomputed["pure_laplace_lk"]["fp"]),
                    hyb_fp=int(recomputed["hybrid_laplace_lk_minilm"]["fp"]),
                    lk_p50=lk_p50_v,
                    hyb_p50=hyb_p50_v,
                    latency_ratio=exp_slowdown,
                    rss_delta=calc_rss_delta,
                )
                if rec_text != exp_rec:
                    errors.append(
                        f"embedding_comparison comparison.recommendation narrative drifted from recomputed metrics:\n"
                        f"  stored  : {rec_text!r}\n  expected: {exp_rec!r}"
                    )

    if not errors and validated_json_cache is not None:
        validated_json_cache[embedding_json_path.resolve()] = data
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
        if _has_personal_host_path_text(line):
            errors.append(f"Personal path leak in {doc_name}:{idx}: found personal host path.")
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
            claim_terms = _loads_strict_json(registry_path.read_text(encoding="utf-8")).get("claim_terms", {})
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


def _strip_fenced_code_blocks_preserve_lines(content: str) -> str:
    """Blank out CommonMark backtick/tilde fenced code blocks while preserving 1-based line numbers."""
    out: list[str] = []
    fence_char: str | None = None
    fence_len = 0
    for raw_line in content.splitlines():
        if fence_char is not None:
            close_m = re.match(r"^ {0,3}(" + re.escape(fence_char) + r"{3,})[ \t]*$", raw_line)
            if close_m and len(close_m.group(1)) >= fence_len:
                fence_char = None
                fence_len = 0
            out.append("")
            continue
        open_m = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", raw_line)
        if open_m and (open_m.group(1)[0] == "~" or "`" not in open_m.group(2)):
            fence_char = open_m.group(1)[0]
            fence_len = len(open_m.group(1))
            out.append("")
            continue
        out.append(raw_line)
    return "\n".join(out)


def _find_inline_code_spans(line: str) -> list[str]:
    """Extract CommonMark §6.1 inline backtick code spans from a single line."""
    spans: list[str] = []
    i = 0
    n = len(line)
    while i < n:
        if line[i] == "`":
            j = i
            while j < n and line[j] == "`":
                j += 1
            ticks = j - i
            k = j
            found = -1
            while k < n:
                if line[k] == "`":
                    m = k
                    while m < n and line[m] == "`":
                        m += 1
                    if m - k == ticks:
                        found = k
                        break
                    k = m
                else:
                    k += 1
            if found != -1:
                spans.append(line[j:found])
                i = found + ticks
            else:
                i = j
        else:
            i += 1
    return spans


def lint_claim_markers_and_regions(
    content: str,
    doc_name: str = "document",
    registry_path: Path | None = None,
) -> tuple[bool, list[str]]:
    """
    Validate structural integrity of `<!-- claim:... -->`, `<!-- claim_term:... -->`, and
    `<!-- BEGIN_EMPIRICAL -->` markers across ANY scanned Markdown file (even docs outside `used_in`).
    Catches unknown IDs, unclosed HTML comments, mismatched/nested closing tags, inline-backtick-wrapped
    markers that render visibly on GitHub, and ungoverned empirical blocks.
    """
    errors: list[str] = []
    if registry_path is None:
        registry_path = DEFAULT_REGISTRY_PATH

    known_claims: set[str] = set()
    known_terms: set[str] = set()
    if registry_path and registry_path.is_file():
        try:
            reg = _loads_strict_json(registry_path.read_text(encoding="utf-8"))
            known_claims = set(reg.get("claims", {}).keys())
            known_terms = set(reg.get("claim_terms", {}).keys())
        except Exception as exc:
            errors.append(f"Failed to parse {registry_path.name}: {exc}")
            return False, errors

    stripped = _strip_fenced_code_blocks_preserve_lines(content)

    # 0. Reject claim markers wrapped inside inline backtick code spans (rendered visibly as literal text in GFM)
    inline_claim_re = re.compile(r"<!--\s*/?claim(?:_term)?\b")
    for line_no, raw_line in enumerate(stripped.splitlines(), 1):
        if "`" in raw_line and "<!--" in raw_line:
            for span in _find_inline_code_spans(raw_line):
                if inline_claim_re.search(span):
                    errors.append(
                        f"Marker lint failure in {doc_name}:{line_no}: claim marker inside inline backtick code "
                        f"span renders visibly on GitHub (keep '<!-- claim:... -->' outside backticks): `{span}`"
                    )

    # 1. Balanced BEGIN_EMPIRICAL / END_EMPIRICAL delimiters
    for begin_marker, end_marker in EMPIRICAL_BLOCK_DELIMITERS:
        b_count = stripped.count(begin_marker)
        e_count = stripped.count(end_marker)
        if b_count != e_count:
            errors.append(
                f"Marker lint failure in {doc_name}: unbalanced empirical delimiters "
                f"({b_count} '{begin_marker}' vs {e_count} '{end_marker}')"
            )

    # 2. Scan all HTML comments starting with claim / /claim / claim_term / /claim_term
    pos = 0
    open_tag: tuple[str, str, int] | None = None  # (kind, id, line_no)
    tag_start_re = re.compile(r"<!--\s*(/?claim(?:_term)?)\b")
    full_open_re = re.compile(r"^<!--\s*(claim|claim_term):([a-zA-Z0-9_\-]+)\s*-->$")
    full_close_re = re.compile(r"^<!--\s*/(claim|claim_term)\s*-->$")

    while True:
        m = tag_start_re.search(stripped, pos)
        if not m:
            break
        start = m.start()
        line_no = stripped[:start].count("\n") + 1
        end = stripped.find("-->", start + 4)
        if end == -1:
            errors.append(f"Marker lint failure in {doc_name}:{line_no}: unclosed HTML claim marker comment")
            break
        raw_comment = stripped[start : end + 3]
        pos = end + 3

        mo = full_open_re.match(raw_comment)
        mc = full_close_re.match(raw_comment)
        if mo:
            kind, cid = mo.group(1), mo.group(2)
            if open_tag is not None:
                errors.append(
                    f"Marker lint failure in {doc_name}:{line_no}: nested or unclosed "
                    f"'{open_tag[0]}:{open_tag[1]}' (opened at line {open_tag[2]}) before '{kind}:{cid}'"
                )
            open_tag = (kind, cid, line_no)
            if kind == "claim" and known_claims and cid not in known_claims:
                errors.append(f"Marker lint failure in {doc_name}:{line_no}: unknown claim ID '{cid}'")
            elif kind == "claim_term" and known_terms and cid not in known_terms:
                errors.append(f"Marker lint failure in {doc_name}:{line_no}: unknown claim_term ID '{cid}'")
        elif mc:
            close_kind = mc.group(1)
            if open_tag is None:
                errors.append(
                    f"Marker lint failure in {doc_name}:{line_no}: orphan closing '<!-- /{close_kind} -->' without opening marker"
                )
            elif open_tag[0] != close_kind:
                errors.append(
                    f"Marker lint failure in {doc_name}:{line_no}: mismatched closing '<!-- /{close_kind} -->' "
                    f"for '{open_tag[0]}:{open_tag[1]}' opened at line {open_tag[2]}"
                )
                open_tag = None
            else:
                open_tag = None
        else:
            errors.append(f"Marker lint failure in {doc_name}:{line_no}: malformed claim marker {raw_comment!r}")

    if open_tag is not None:
        errors.append(
            f"Marker lint failure in {doc_name}:{open_tag[2]}: unclosed '<!-- {open_tag[0]}:{open_tag[1]} -->' (missing '<!-- /{open_tag[0]} -->')"
        )

    emp_ok, emp_errs = check_empirical_regions(stripped, doc_name)
    if not emp_ok:
        errors.extend(emp_errs)

    return len(errors) == 0, errors


def validate_claims_registry(
    registry_path: Path,
    repo_root: Path = REPO_ROOT,
) -> tuple[bool, list[str]]:
    """
    Validate structural & referential integrity of docs/claims_registry.json:
    - Strict JSON (no duplicate claim IDs or non-finite constants) and zero personal paths
    - Non-empty `used_in` lists pointing to existing repo-confined docs where each marker appears
    - Required benchmark JSON artifacts exist and live Tier 2 claims are backed by `tier2_triage.enabled == true`
    - All `claim_terms` evidence files and symbols exist
    """
    errors: list[str] = []
    if not registry_path.is_file():
        return False, [f"Registry not found: {registry_path}"]
    try:
        raw_reg = registry_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return False, [f"Failed to read {registry_path}: {exc}"]
    if _has_personal_host_path_text(raw_reg):
        errors.append(f"Registry {registry_path.name} contains leaked personal host path")
    try:
        reg = _loads_strict_json(raw_reg)
    except Exception as exc:
        return False, [f"Failed to parse {registry_path.name}: {exc}"]
    if not isinstance(reg, dict):
        return False, [f"Registry {registry_path.name} root must be a JSON object"]
    if _contains_personal_host_path(reg):
        errors.append(f"Registry {registry_path.name} contains leaked personal host path in decoded strings")

    claims = reg.get("claims")
    if not isinstance(claims, dict) or not claims:
        return False, [f"Registry {registry_path.name} must define a non-empty 'claims' object"]

    resolved_root = repo_root.resolve()
    doc_cache: dict[Path, str] = {}
    json_cache: dict[Path, dict] = {}

    for cid, cfg in claims.items():
        if not isinstance(cfg, dict):
            errors.append(f"Claim '{cid}' config must be a JSON object")
            continue
        art_rel = cfg.get("source_artifact")
        if not isinstance(art_rel, str) or not art_rel.strip() or Path(art_rel).is_absolute():
            errors.append(f"Claim '{cid}' has missing or non-relative source_artifact: {art_rel!r}")
        else:
            try:
                art_path = (repo_root / art_rel).resolve()
            except (ValueError, OSError) as exc:
                errors.append(f"Claim '{cid}' has invalid source_artifact {art_rel!r}: {exc}")
                art_path = None
            if art_path is not None:
                try:
                    art_path.relative_to(resolved_root)
                except ValueError:
                    errors.append(f"Claim '{cid}' source_artifact escapes repository root: {art_rel!r}")
                else:
                    if not art_path.is_file():
                        errors.append(f"Claim '{cid}' required source_artifact does not exist: {art_rel}")
                    elif "json_path" in cfg:
                        if art_path not in json_cache:
                            try:
                                raw_art = art_path.read_text(encoding="utf-8")
                                if _has_personal_host_path_text(raw_art):
                                    errors.append(f"Claim '{cid}' source_artifact {art_rel} contains leaked personal host path")
                                parsed_art = _loads_strict_json(raw_art)
                                if _contains_personal_host_path(parsed_art):
                                    errors.append(f"Claim '{cid}' source_artifact {art_rel} contains leaked personal host path in decoded strings")
                                json_cache[art_path] = parsed_art if isinstance(parsed_art, dict) else {}
                            except Exception as exc:
                                errors.append(f"Claim '{cid}' source_artifact {art_rel} failed strict JSON parse: {exc}")
                                json_cache[art_path] = {}
                        if art_rel == "docs/benchmarks/empirical_benchmarks.json" and str(cfg.get("json_path", "")).startswith("tier2_triage."):
                            t2_sec = json_cache[art_path].get("tier2_triage", {})
                            if not isinstance(t2_sec, dict) or t2_sec.get("enabled") is not True:
                                errors.append(
                                    f"Claim '{cid}' references live Tier 2 benchmark path '{cfg.get('json_path')}', "
                                    f"but tier2_triage.enabled is not true in {art_rel}"
                                )

        used_in = cfg.get("used_in")
        if not isinstance(used_in, list) or not used_in:
            errors.append(f"Claim '{cid}' must declare a non-empty 'used_in' document list (orphaned claim)")
            continue
        seen_docs: set[str] = set()
        marker_re = re.compile(rf"<!--\s*claim:{re.escape(cid)}\s*-->.*?<!--\s*/claim\s*-->", re.DOTALL)
        for rel_doc in used_in:
            if not isinstance(rel_doc, str) or not rel_doc.strip() or Path(rel_doc).is_absolute():
                errors.append(f"Claim '{cid}' has invalid 'used_in' entry: {rel_doc!r}")
                continue
            norm_rel = rel_doc.replace("\\", "/")
            if norm_rel in seen_docs:
                errors.append(f"Claim '{cid}' has duplicate 'used_in' entry: {norm_rel}")
                continue
            seen_docs.add(norm_rel)
            try:
                doc_p = (repo_root / norm_rel).resolve()
            except (ValueError, OSError) as exc:
                errors.append(f"Claim '{cid}' has invalid 'used_in' path {norm_rel!r}: {exc}")
                continue
            try:
                doc_p.relative_to(resolved_root)
            except ValueError:
                errors.append(f"Claim '{cid}' 'used_in' path escapes repository root: {norm_rel}")
                continue
            if not doc_p.is_file():
                errors.append(f"Claim '{cid}' 'used_in' document does not exist: {norm_rel}")
                continue
            if doc_p not in doc_cache:
                doc_cache[doc_p] = doc_p.read_text(encoding="utf-8")
            if not marker_re.search(doc_cache[doc_p]):
                errors.append(f"Claim '{cid}' listed in 'used_in' for {norm_rel}, but marker is missing")

    claim_terms = reg.get("claim_terms", {})
    if isinstance(claim_terms, dict):
        for tid, tcfg in claim_terms.items():
            if isinstance(tcfg, dict):
                errors.extend(_verify_claim_term_evidence(tid, tcfg, repo_root))

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
            block_lines = block_text.splitlines()
            skip_indices: set[int] = set()
            for idx_line in range(len(block_lines) - 1):
                hdr_row = _parse_gfm_row(block_lines[idx_line], require_outer_pipes=False)
                delim_row = _parse_gfm_row(block_lines[idx_line + 1], require_outer_pipes=False)
                if (
                    hdr_row is not None
                    and delim_row is not None
                    and len(hdr_row[1]) == len(delim_row[1])
                    and _is_gfm_delimiter_row(delim_row[1])
                ):
                    skip_indices.add(idx_line)
                    skip_indices.add(idx_line + 1)

            filtered_lines = []
            for row_idx, line in enumerate(block_lines, 1):
                line_str = line.strip()
                if not line_str:
                    continue
                if (row_idx - 1) in skip_indices:
                    continue
                parsed_row = _parse_gfm_row(line, require_outer_pipes=False, min_cells=2)
                if parsed_row is not None:
                    _, parts = parsed_row
                    if _is_gfm_delimiter_row(parts):
                        continue
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
    validated_json_cache: dict[Path, dict] | None = None,
) -> tuple[bool, list[str]]:
    """Verify or update claim markers in doc_path against registry_path."""
    messages: list[str] = []
    errors: list[str] = []

    if not registry_path.is_file():
        return False, [f"Registry not found: {registry_path}"]
    if not doc_path.is_file():
        return False, [f"Target doc not found: {doc_path}"]

    raw_reg = registry_path.read_text(encoding="utf-8")
    if _has_personal_host_path_text(raw_reg):
        errors.append(f"Registry {registry_path.name} contains leaked personal host path")
    registry = _loads_strict_json(raw_reg)
    claims = registry.get("claims", {})
    resolved_values: dict[str, str] = {}

    for claim_id, claim_cfg in claims.items():
        try:
            resolved_values[claim_id] = resolve_claim_value(
                claim_id,
                claim_cfg,
                repo_root=repo_root,
                validated_json_cache=validated_json_cache,
            )
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
    marker_ok, marker_errors = lint_claim_markers_and_regions(
        latest_text, doc_path.name, registry_path=registry_path
    )
    if not marker_ok:
        errors.extend(marker_errors)

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

    ast_ok, ast_errs = lint_script_conclusions(REPO_ROOT / "scripts")
    if not ast_ok:
        overall_success = False
        for err in ast_errs:
            print(f"[FAIL] {err}", file=sys.stderr)
    else:
        print("[PASS] Benchmark script conclusion builders free of hardcoded numeric literals.")

    if args.doc is None:
        reg_ok, reg_errs = validate_claims_registry(args.registry, repo_root=REPO_ROOT)
        if not reg_ok:
            overall_success = False
            for err in reg_errs:
                print(f"[FAIL] {err}", file=sys.stderr)
        else:
            print("[PASS] Claims registry schema, non-orphan used_in mappings & Tier 2 artifact flags verified.")

    validated_json_cache: dict[Path, dict] = {}
    bench_json = REPO_ROOT / "docs" / "benchmarks" / "empirical_benchmarks.json"
    metrics_ok, metrics_errs = independent_recompute_metrics(
        bench_json,
        repo_root=REPO_ROOT,
        validated_json_cache=validated_json_cache,
    )
    if not metrics_ok:
        overall_success = False
        for err in metrics_errs:
            print(f"[FAIL] {err}", file=sys.stderr)
    else:
        print("[PASS] Independent benchmark math recomputation & Markdown parity verified.")

    emb_json = REPO_ROOT / "docs" / "benchmarks" / "embedding_comparison.json"
    emb_required = emb_json.exists()
    if args.registry.is_file():
        try:
            reg_peek = _loads_strict_json(args.registry.read_text(encoding="utf-8"))
            if any(
                isinstance(c, dict) and c.get("source_artifact") == "docs/benchmarks/embedding_comparison.json"
                for c in reg_peek.get("claims", {}).values()
            ):
                emb_required = True
        except Exception:
            pass
    if emb_required:
        emb_ok, emb_errs = independent_recompute_embedding_comparison(
            emb_json,
            repo_root=REPO_ROOT,
            validated_json_cache=validated_json_cache,
            require_governed_fields=True,
        )
        if not emb_ok:
            overall_success = False
            for err in emb_errs:
                print(f"[FAIL] {err}", file=sys.stderr)
        else:
            print("[PASS] Independent semantic embedding comparison math & narrative parity verified.")

    # Refresh contract: cmd/sentinel-bench atomically regenerates empirical_benchmarks.json and its
    # paired Markdown report (which contains no claim markers). sync_docs.py --write only propagates
    # verified artifacts into registered claim markers in README.md and docs/ after parity passes.
    if do_write and not overall_success:
        print("\nAborting --write because benchmark artifact recomputation failed.", file=sys.stderr)
        return 1

    if args.doc is not None:
        target_docs = [args.doc]
    else:
        target_docs = [DEFAULT_README_PATH]
        if args.registry.is_file():
            try:
                reg_data = _loads_strict_json(args.registry.read_text(encoding="utf-8"))
                for c_cfg in reg_data.get("claims", {}).values():
                    for rel_p in c_cfg.get("used_in", []):
                        candidate = REPO_ROOT / rel_p
                        if candidate not in target_docs:
                            target_docs.append(candidate)
            except Exception as exc:
                overall_success = False
                print(f"[FAIL] Failed to parse {args.registry}: {exc}", file=sys.stderr)

    for doc_target in target_docs:
        doc_ok, doc_msgs = sync_document(
            doc_target,
            args.registry,
            write=do_write,
            repo_root=REPO_ROOT,
            validated_json_cache=validated_json_cache,
        )
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
