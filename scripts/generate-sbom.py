#!/usr/bin/env python3
"""
generate-sbom.py
Generates a deterministic CycloneDX v1.5 JSON Software Bill of Materials (SBOM)
for Genesis Sentinel (`knowthankyew/genesis-sentinel`).

Documents application metadata, internal pure-Go stdlib packages, transparent
Pillar 1 variance disclosures, and knowthankyew privacy/security properties.
"""

import json
import os
import platform
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def detect_cli_version() -> str:
    cli_go = REPO_ROOT / "internal" / "cli" / "cli.go"
    if cli_go.is_file():
        m = re.search(r'^\s*const\s+Version\s*=\s*"([^"]+)"', cli_go.read_text(encoding="utf-8"), re.MULTILINE)
        if m:
            return m.group(1)
    return "0.2.0-phase1"


def generate_sbom(
    output_path: str = "bom.json",
    arch: str | None = None,
    version: str | None = None,
) -> None:
    if not arch:
        machine = platform.machine().lower()
        arch = "arm64" if machine in ("arm64", "aarch64") else "amd64"
    if not version:
        version = detect_cli_version()

    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        try:
            ts = datetime.fromtimestamp(int(epoch), timezone.utc)
        except (ValueError, OverflowError):
            sys.exit(f"ERROR: Invalid SOURCE_DATE_EPOCH='{epoch}'. Expected integer timestamp.")
    else:
        ts = datetime.now(timezone.utc)
    now_iso = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    seed_epoch = epoch if epoch else "local"
    serial_uuid = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'knowthankyew/genesis-sentinel/{version}/{arch}/{seed_epoch}')}"
    app_ref = f"pkg:golang/github.com/knowthankyew/genesis-sentinel@{version}?arch={arch}"

    internal_packages = [
        ("cli", "Unified CLI subcommand router (watch, scan, stats, burn, data, config, version, help) and Phase 3 stubs"),
        ("config", "Layered configuration loader (defaults -> sentinel.json -> SENTINEL_* env -> flags) with fail-closed validation and token redaction"),
        ("emit", "Loopback TCP JSONL alert sink emitting structured alerts into Project Genesis (service=sentinel) with QoS severity mapping"),
        ("ingest", "Read-only lossless Genesis .seg CRC32 segment tailer with atomic cursor persistence, HTTP /query fallback poller, multi-format parser, and Track A synthetic corpus generator"),
        ("model", "Tier wire contracts (LogEvent, TemplateWindow, RuleHit, SurprisalScore, TriageVerdict, FeedbackRecord) and fail-closed base model allowlist"),
        ("pipeline", "Tier 0 orchestrator, self-alert loop-prevention guard, HTTP status/burn server, and safe local disk state purge"),
        ("rules", "Precompiled Go RE2 deterministic rule engine (rules.json and built-in SENT-001..SENT-008 starter pack) with burst, entropy, and suppression support"),
        ("security", "Constant-time Bearer auth middleware, dial-time loopback IP enforcement, and hostile-log prompt-injection sanitizer"),
        ("template", "Bounded pure-Go Drain-style prefix-tree template collapser with linear ASCII masking and peak Shannon entropy tracking"),
    ]

    components = []
    depends_on = []
    for pkg_name, desc in internal_packages:
        ref = f"pkg:golang/github.com/knowthankyew/genesis-sentinel/internal/{pkg_name}@{version}"
        depends_on.append(ref)
        components.append(
            {
                "type": "library",
                "bom-ref": ref,
                "name": f"internal/{pkg_name}",
                "version": version,
                "scope": "required",
                "description": desc,
                "licenses": [{"license": {"id": "MIT"}}],
            }
        )

    sbom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial_uuid,
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "publisher": "knowthankyew",
                        "name": "generate-sbom",
                        "version": "1.0.0",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": app_ref,
                "name": "genesis-sentinel",
                "version": version,
                "description": "Local-first, zero-egress, pure-Go standard library security triage and anomaly detection sidecar for Project Genesis combining deterministic Tier 0 rules, Drain template collapsing, Laplace-LK surprisal scoring, and locally trained FTaaS LoRA adapters.",
                "licenses": [{"license": {"id": "MIT"}}],
                "properties": [
                    {"name": "knowthankyew:privacy:network_egress", "value": "deny"},
                    {"name": "knowthankyew:privacy:telemetry_mode", "value": "local_disk_state"},
                    {"name": "knowthankyew:privacy:pillar1_variance", "value": "intentional_lossless_seg_tailing_and_burnable_local_state"},
                    {"name": "knowthankyew:privacy:burn_enabled", "value": "true"},
                    {"name": "knowthankyew:privacy:third_party_dependencies", "value": "0"},
                    {"name": "knowthankyew:security:localhost_default_bind", "value": "true"},
                    {"name": "knowthankyew:security:alert_only", "value": "true"},
                    {"name": "knowthankyew:ml:default_base_model", "value": "HuggingFaceTB/SmolLM2-135M-Instruct"},
                    {"name": "knowthankyew:ml:excluded_families", "value": "bitnet"},
                ],
            },
        },
        "components": components,
        "dependencies": [
            {
                "ref": app_ref,
                "dependsOn": depends_on,
            }
        ],
    }

    out_abs = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2)
        f.write("\n")
    print(f"✓ CycloneDX SBOM written to {output_path}")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "bom.json"
    arch_arg = sys.argv[2] if len(sys.argv) > 2 else None
    ver_arg = sys.argv[3] if len(sys.argv) > 3 else None
    generate_sbom(out, arch_arg, ver_arg)
