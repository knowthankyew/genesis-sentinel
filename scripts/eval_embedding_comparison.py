#!/usr/bin/env python3
"""
eval_embedding_comparison.py — Phase 4 Offline Semantic Embedding Experiment
for Genesis Sentinel (`knowthankyew/genesis-sentinel`).

Compares:
  1. Pure Laplace-LK log-domain features (matching internal/surprisal/math.go exactly)
  2. Hybrid Laplace-LK + `sentence-transformers/all-MiniLM-L6-v2` semantic cosine novelty

Runs 100% offline (HF_HUB_OFFLINE=1, local_files_only=True) using cached local weights
without introducing any dependency into the pure-Go Sentinel binary.
Outputs machine-readable results to docs/benchmarks/embedding_comparison.json.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import resource
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch  # noqa: E402
from transformers import AutoModel, AutoTokenizer  # noqa: E402

MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
MIN_DEVIATION_FLOOR = 0.25
NOMINAL_MISMATCH_NATS = 2.5
DEFAULT_THRESHOLD_NATS = 5.0
K_NEIGHBORS = 3


def rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return round(usage / (1024 * 1024), 2)
    return round(usage / 1024, 2)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = float(len(text))
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def extract_log_features(svc: str, level: str, template: str, sample: str, count: int, duration_s: float) -> tuple[list[float], list[str]]:
    tokens = sample.split()
    n_bytes = max(len(sample), 1)
    sym = sum(1 for c in sample if not c.isalnum() and not c.isspace())
    dig = sum(1 for c in sample if c.isdigit())
    upp = sum(1 for c in sample if c.isupper())
    avg_inter_ms = (duration_s * 1000.0) / max(count - 1, 1) if count > 1 else 10000.0
    cont = [
        math.log1p(len(tokens)),
        math.log1p(n_bytes),
        shannon_entropy(sample),
        (sym / n_bytes) * 10.0,
        (dig / n_bytes) * 10.0,
        (upp / n_bytes) * 10.0,
        math.log1p(count),
        math.log1p(avg_inter_ms),
    ]
    status_fam = "none"
    for tok in tokens:
        if len(tok) == 3 and tok.isdigit() and tok[0] in "12345":
            status_fam = f"{tok[0]}xx"
            break
    nom = [svc.lower(), level.upper(), template.split()[0].lower() if template.split() else "empty", status_fam]
    return cont, nom


def compute_mad_devs(base_conts: list[list[float]]) -> list[float]:
    n_feat = len(base_conts[0])
    devs = []
    for j in range(n_feat):
        vals = sorted(row[j] for row in base_conts)
        mid = len(vals) // 2
        med = vals[mid] if len(vals) % 2 == 1 else 0.5 * (vals[mid - 1] + vals[mid])
        abs_dev = sorted(abs(v - med) for v in vals)
        mad = abs_dev[mid] if len(abs_dev) % 2 == 1 else 0.5 * (abs_dev[mid - 1] + abs_dev[mid])
        devs.append(max(mad, MIN_DEVIATION_FLOOR))
    return devs


def laplace_lk_score(
    cand_c: list[float],
    cand_n: list[str],
    base_conts: list[list[float]],
    base_noms: list[list[str]],
    devs: list[float],
) -> float:
    same_svc = [i for i, n in enumerate(base_noms) if n[0] == cand_n[0]]
    pool = same_svc if len(same_svc) >= K_NEIGHBORS else list(range(len(base_conts)))
    scores = []
    for idx in pool:
        bc = base_conts[idx]
        bn = base_noms[idx]
        s = 0.0
        for j in range(len(cand_c)):
            s += abs(cand_c[j] - bc[j]) / devs[j]
        for j in range(len(cand_n)):
            if cand_n[j] != bn[j]:
                s += NOMINAL_MISMATCH_NATS
        scores.append(s)
    scores.sort()
    k = min(K_NEIGHBORS, len(scores))
    return sum(scores[:k]) / k


def build_corpus() -> tuple[list[dict], list[dict]]:
    """
    Deterministic corpus separating:
      - warmup_benign (30 normal operational log windows across 5 services)
      - eval_set (50 held-out windows):
          * 25 benign operational windows (including minor harmless wording variations)
          * 10 structural/volume attack windows (bursts, high entropy, novel services/levels)
          * 15 disguised/paraphrased semantic attacks (blending into normal api/web INFO 200
            traffic with similar length, entropy, and burst rate — no Tier 0 regex triggers)
    """
    warmup_benign = [
        {"svc": "api", "lvl": "INFO", "tmpl": "GET /healthz 200", "msg": f"GET /healthz 200 1.{i%9}ms from 10.0.1.{(i%40)+1}", "count": 42 + (i % 15), "dur": 10.0}
        for i in range(6)
    ] + [
        {"svc": "web", "lvl": "INFO", "tmpl": "GET /api/v1/orders/<NUM> 200", "msg": f"GET /api/v1/orders/{1000+i} 200 {12+(i%20)}ms client=10.0.2.{(i%40)+1}", "count": 28 + (i % 12), "dur": 10.0}
        for i in range(6)
    ] + [
        {"svc": "cron", "lvl": "INFO", "tmpl": "Scheduled job metrics-rollup completed", "msg": f"Scheduled job metrics-rollup completed in {80+(i%40)}ms rows={1200+i*100}", "count": 4 + (i % 3), "dur": 10.0}
        for i in range(6)
    ] + [
        {"svc": "coredns", "lvl": "INFO", "tmpl": "A query api.internal.local", "msg": f"A query api.internal.local -> 10.0.0.{(i%15)+1} ttl=60", "count": 32 + (i % 10), "dur": 10.0}
        for i in range(6)
    ] + [
        {"svc": "dockerd", "lvl": "INFO", "tmpl": "Container worker heartbeat ok", "msg": f"Container worker-{(i%4)+1} heartbeat ok mem_mb={96+i*4}", "count": 14 + (i % 5), "dur": 10.0}
        for i in range(6)
    ]

    eval_benign = [
        {"svc": "api", "lvl": "INFO", "tmpl": "GET /healthz 200", "msg": f"GET /healthz 200 1.{i%8}ms from 10.0.1.{(i%50)+10}", "count": 45 + (i % 12), "dur": 10.0, "label": 0, "kind": "benign"}
        for i in range(5)
    ] + [
        {"svc": "web", "lvl": "INFO", "tmpl": "GET /api/v1/orders/<NUM> 200", "msg": f"GET /api/v1/orders/{4200+i} 200 {15+(i%18)}ms client=10.0.2.{(i%50)+10}", "count": 30 + (i % 10), "dur": 10.0, "label": 0, "kind": "benign"}
        for i in range(5)
    ] + [
        {"svc": "cron", "lvl": "INFO", "tmpl": "Scheduled job metrics-rollup completed", "msg": f"Scheduled job metrics-rollup completed in {95+(i%30)}ms rows={1500+i*90}", "count": 5 + (i % 2), "dur": 10.0, "label": 0, "kind": "benign"}
        for i in range(5)
    ] + [
        {"svc": "coredns", "lvl": "INFO", "tmpl": "A query api.internal.local", "msg": f"A query api.internal.local -> 10.0.0.{(i%12)+2} ttl=60", "count": 34 + (i % 8), "dur": 10.0, "label": 0, "kind": "benign"}
        for i in range(5)
    ] + [
        {"svc": "dockerd", "lvl": "INFO", "tmpl": "Container worker heartbeat ok", "msg": f"Container worker-{(i%4)+1} heartbeat ok mem_mb={102+i*5}", "count": 15 + (i % 4), "dur": 10.0, "label": 0, "kind": "benign"}
        for i in range(5)
    ]

    structural_attacks = [
        {"svc": "kernel-audit", "lvl": "ERROR", "tmpl": "AUDIT_BPF_PROG_LOAD", "msg": f"AUDIT_BPF_PROG_LOAD_UNEXPECTED_RINGBUF_DUMP::0x9F8E{i:04X}!!###@@@$$$", "count": 14, "dur": 1.0, "label": 1, "kind": "structural"}
        for i in range(4)
    ] + [
        {"svc": "egress-proxy", "lvl": "FATAL", "tmpl": "CONNECT RAW_TUNNEL", "msg": f"CONNECT RAW_TUNNEL_BURST_Q7xK9mP2vL4nR8tW1zB5yC3fH6jM0qS9uE{i:02d} 502", "count": 480, "dur": 2.0, "label": 1, "kind": "structural"}
        for i in range(3)
    ] + [
        {"svc": "pam-vault", "lvl": "ERROR", "tmpl": "SEAL_TAMPER_DETECTED", "msg": f"SEAL_TAMPER_DETECTED_TOKEN_EXPORT_0x998877{i:02X}!!$$@@##_DUMP_KEYS 403", "count": 2, "dur": 1.0, "label": 1, "kind": "structural"}
        for i in range(3)
    ]

    # Disguised semantic attacks: match normal web/api INFO 200 structural profile (similar length,
    # entropy, count, inter-arrival time, and status family 2xx), differing primarily in semantic intent!
    disguised_messages = [
        ("web", "GET /api/v1/export/customer_ssns 200 22ms client=10.0.2.44"),
        ("web", "GET /api/v1/admin/dump_credentials 200 19ms client=10.0.2.45"),
        ("web", "GET /api/v1/backup/private_keys 200 25ms client=10.0.2.46"),
        ("web", "GET /api/v1/billing/export_pan_csv 200 21ms client=10.0.2.47"),
        ("web", "GET /api/v1/iam/grant_superadmin 200 17ms client=10.0.2.48"),
        ("web", "GET /api/v1/audit/disable_logging 200 16ms client=10.0.2.49"),
        ("web", "GET /api/v1/vault/unseal_all_secrets 200 24ms client=10.0.2.50"),
        ("web", "GET /api/v1/session/hijack_root_token 200 18ms client=10.0.2.51"),
        ("api", "GET /debug/shadow_hashes 200 1.6ms from 10.0.1.33"),
        ("api", "GET /internal/exfiltrate_db 200 1.8ms from 10.0.1.34"),
        ("api", "GET /admin/delete_audit_trail 200 1.5ms from 10.0.1.35"),
        ("api", "GET /system/spawn_backdoor 200 1.7ms from 10.0.1.36"),
        ("api", "GET /secrets/rotate_bypass 200 1.4ms from 10.0.1.37"),
        ("api", "GET /auth/elevate_guest_role 200 1.9ms from 10.0.1.38"),
        ("api", "GET /config/disable_tls_verify 200 1.3ms from 10.0.1.39"),
    ]
    disguised_attacks = []
    for svc, msg in disguised_messages:
        cnt = 30 if svc == "web" else 44
        disguised_attacks.append(
            {"svc": svc, "lvl": "INFO", "tmpl": msg, "msg": msg, "count": cnt, "dur": 10.0, "label": 1, "kind": "disguised_semantic"}
        )

    return warmup_benign, eval_benign + structural_attacks + disguised_attacks


def mean_pool_normalize(model_out, attention_mask: torch.Tensor) -> torch.Tensor:
    token_embeddings = model_out.last_hidden_state
    mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    summed = torch.sum(token_embeddings * mask_expanded, dim=1)
    counts = torch.clamp(mask_expanded.sum(dim=1), min=1e-9)
    pooled = summed / counts
    return torch.nn.functional.normalize(pooled, p=2, dim=1)


def compute_metrics(preds: list[int], eval_set: list[dict]) -> dict:
    tp = sum(1 for p, row in zip(preds, eval_set) if p == 1 and row["label"] == 1)
    fp = sum(1 for p, row in zip(preds, eval_set) if p == 1 and row["label"] == 0)
    fn = sum(1 for p, row in zip(preds, eval_set) if p == 0 and row["label"] == 1)
    tn = sum(1 for p, row in zip(preds, eval_set) if p == 0 and row["label"] == 0)
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * tp) / (2 * tp + fp + fn) if (2 * tp + fp + fn) > 0 else 0.0

    struct_tot = sum(1 for r in eval_set if r["kind"] == "structural")
    struct_hit = sum(1 for p, r in zip(preds, eval_set) if r["kind"] == "structural" and p == 1)
    disg_tot = sum(1 for r in eval_set if r["kind"] == "disguised_semantic")
    disg_hit = sum(1 for p, r in zip(preds, eval_set) if r["kind"] == "disguised_semantic" and p == 1)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "structural_tp": struct_hit,
        "disguised_semantic_tp": disg_hit,
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "structural_recall": round(struct_hit / max(struct_tot, 1), 4),
        "disguised_semantic_recall": round(disg_hit / max(disg_tot, 1), 4),
    }


def pct(sorted_vals: list[float], p: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = max(0, min(len(sorted_vals) - 1, math.ceil((p / 100.0) * len(sorted_vals)) - 1))
    return sorted_vals[idx]


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Phase 4 semantic embedding vs pure Laplace-LK evaluation.")
    parser.add_argument(
        "--out-json",
        type=Path,
        default=Path("docs/benchmarks/embedding_comparison.json"),
        help="Path to write JSON results",
    )
    parser.add_argument("--semantic-weight", type=float, default=12.0, help="Nats multiplier for semantic cosine distance")
    args = parser.parse_args()
    if not math.isfinite(args.semantic_weight) or args.semantic_weight < 0.0:
        parser.error(f"--semantic-weight must be a finite number >= 0 (got {args.semantic_weight!r})")

    warmup, eval_set = build_corpus()
    base_conts, base_noms = [], []
    for row in warmup:
        c, n = extract_log_features(row["svc"], row["lvl"], row["tmpl"], row["msg"], row["count"], row["dur"])
        base_conts.append(c)
        base_noms.append(n)
    devs = compute_mad_devs(base_conts)

    # 1. Pure Laplace-LK baseline evaluation
    rss_before_model = rss_mb()
    lk_lat_ms: list[float] = []
    lk_scores: list[float] = []
    lk_preds: list[int] = []
    for row in eval_set:
        t0 = time.perf_counter()
        c, n = extract_log_features(row["svc"], row["lvl"], row["tmpl"], row["msg"], row["count"], row["dur"])
        score = laplace_lk_score(c, n, base_conts, base_noms, devs)
        lk_lat_ms.append((time.perf_counter() - t0) * 1000.0)
        lk_scores.append(score)
        lk_preds.append(1 if score >= DEFAULT_THRESHOLD_NATS else 0)

    # 2. Load cached all-MiniLM-L6-v2 strictly offline (CPU for reproducible latency)
    t_load = time.perf_counter()
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, local_files_only=True)
    encoder = AutoModel.from_pretrained(MODEL_ID, local_files_only=True)
    encoder.eval()
    load_sec = round(time.perf_counter() - t_load, 3)

    @torch.no_grad()
    def embed_texts(texts: list[str]) -> torch.Tensor:
        enc = tokenizer(texts, padding=True, truncation=True, max_length=128, return_tensors="pt")
        out = encoder(**enc)
        return mean_pool_normalize(out, enc["attention_mask"])

    base_embs = embed_texts([f"{r['svc']} {r['lvl']} {r['msg']}" for r in warmup])
    # Warm up one single-window forward pass before timing
    _ = embed_texts([f"{eval_set[0]['svc']} {eval_set[0]['lvl']} {eval_set[0]['msg']}"])

    hybrid_lat_ms: list[float] = []
    hybrid_scores: list[float] = []
    hybrid_preds: list[int] = []
    for idx, row in enumerate(eval_set):
        t0 = time.perf_counter()
        c, n = extract_log_features(row["svc"], row["lvl"], row["tmpl"], row["msg"], row["count"], row["dur"])
        lk_s = laplace_lk_score(c, n, base_conts, base_noms, devs)
        emb = embed_texts([f"{row['svc']} {row['lvl']} {row['msg']}"])
        sims = torch.matmul(emb, base_embs.T).squeeze(0)
        topk_sim = torch.topk(sims, k=min(K_NEIGHBORS, sims.numel())).values.mean().item()
        sem_dist = max(0.0, 1.0 - topk_sim)
        total_s = lk_s + (args.semantic_weight * sem_dist)
        hybrid_lat_ms.append((time.perf_counter() - t0) * 1000.0)
        hybrid_scores.append(total_s)
        hybrid_preds.append(1 if total_s >= DEFAULT_THRESHOLD_NATS else 0)

    rss_after_model = rss_mb()
    lk_lat_sorted = sorted(lk_lat_ms)
    hyb_lat_sorted = sorted(hybrid_lat_ms)

    lk_metrics = compute_metrics(lk_preds, eval_set)
    hyb_metrics = compute_metrics(hybrid_preds, eval_set)

    lk_p50 = round(pct(lk_lat_sorted, 50), 4)
    hyb_p50 = round(pct(hyb_lat_sorted, 50), 4)
    latency_ratio = round(hyb_p50 / max(lk_p50, 0.0001), 1)
    recall_delta = round(hyb_metrics["disguised_semantic_recall"] - lk_metrics["disguised_semantic_recall"], 4)
    fp_delta = hyb_metrics["fp"] - lk_metrics["fp"]
    rss_delta = round(max(rss_after_model - rss_before_model, 0.0), 2)

    if recall_delta > 0:
        recall_summary = (
            f"On this synthetic corpus at fixed threshold {DEFAULT_THRESHOLD_NATS:.1f} nats "
            f"(semantic_weight={args.semantic_weight:g}), disguised-semantic recall changed by "
            f"{recall_delta:+.4f} ({lk_metrics['disguised_semantic_recall']:.4f} -> "
            f"{hyb_metrics['disguised_semantic_recall']:.4f}) with FP delta {fp_delta:+d} "
            f"({lk_metrics['fp']} -> {hyb_metrics['fp']})."
        )
    else:
        recall_summary = (
            f"On this synthetic corpus at fixed threshold {DEFAULT_THRESHOLD_NATS:.1f} nats "
            f"(semantic_weight={args.semantic_weight:g}), disguised-semantic recall showed "
            f"{recall_delta:+.4f} change ({lk_metrics['disguised_semantic_recall']:.4f} -> "
            f"{hyb_metrics['disguised_semantic_recall']:.4f}) with FP delta {fp_delta:+d}."
        )

    recommendation = (
        f"In this Python proxy comparison, the Laplace-LK baseline scored P50 {lk_p50:.4f} ms vs hybrid "
        f"all-MiniLM-L6-v2 P50 {hyb_p50:.4f} ms (~{latency_ratio}x slower in Python, +{rss_delta:.2f} MB peak "
        f"process RSS delta after PyTorch/Transformers imports). {recall_summary} Because neural embedding "
        f"inference measured {hyb_p50:.4f} ms P50 latency and +{rss_delta:.2f} MB post-import peak process RSS "
        f"overhead in this benchmark, semantic embeddings remain optional for sidecar or offline evaluation "
        f"rather than embedded in the zero-dependency Go binary."
    )

    result = {
        "metadata": {
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "model_id": MODEL_ID,
            "offline_mode": True,
            "platform": f"{platform.system()} {platform.machine()}",
            "python_version": platform.python_version(),
            "torch_version": torch.__version__,
            "model_load_seconds": load_sec,
            "rss_measurement_method": "ru_maxrss_peak_process_post_import",
            "rss_before_model_mb": rss_before_model,
            "rss_after_model_mb": rss_after_model,
            "rss_delta_mb": rss_delta,
        },
        "dataset": {
            "warmup_benign_windows": len(warmup),
            "eval_total_windows": len(eval_set),
            "eval_benign_windows": sum(1 for r in eval_set if r["label"] == 0),
            "eval_structural_attack_windows": sum(1 for r in eval_set if r["kind"] == "structural"),
            "eval_disguised_semantic_windows": sum(1 for r in eval_set if r["kind"] == "disguised_semantic"),
            "threshold_nats": DEFAULT_THRESHOLD_NATS,
            "semantic_weight_nats": args.semantic_weight,
        },
        "pure_laplace_lk": {
            **lk_metrics,
            "latency_p50_ms": lk_p50,
            "latency_p99_ms": round(pct(lk_lat_sorted, 99), 4),
        },
        "hybrid_laplace_lk_minilm": {
            **hyb_metrics,
            "latency_p50_ms": hyb_p50,
            "latency_p99_ms": round(pct(hyb_lat_sorted, 99), 4),
        },
        "comparison": {
            "f1_delta": round(hyb_metrics["f1"] - lk_metrics["f1"], 4),
            "fp_delta": fp_delta,
            "disguised_semantic_recall_delta": recall_delta,
            "p50_latency_slowdown_x": latency_ratio,
            "recommendation": recommendation,
        },
    }

    encoded = json.dumps(result, indent=2, allow_nan=False) + "\n"
    if "/Users/" in encoded or "/home/" in encoded:
        raise RuntimeError("Refusing to write embedding comparison JSON containing personal host path")

    args.out_json.parent.mkdir(parents=True, exist_ok=True)
    args.out_json.write_text(encoded, encoding="utf-8")
    print(f"Wrote {args.out_json}")
    print(f"Pure Laplace-LK:       F1={lk_metrics['f1']:.4f} (struct={lk_metrics['structural_recall']:.4f}, disguised={lk_metrics['disguised_semantic_recall']:.4f}) P50={lk_p50:.4f}ms")
    print(f"Hybrid + MiniLM-L6-v2: F1={hyb_metrics['f1']:.4f} (struct={hyb_metrics['structural_recall']:.4f}, disguised={hyb_metrics['disguised_semantic_recall']:.4f}) P50={hyb_p50:.4f}ms")
    print(f"Recommendation: {recommendation}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
