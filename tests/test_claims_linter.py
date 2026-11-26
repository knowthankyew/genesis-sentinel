"""
Genesis Sentinel Claims & Governance Linter Test Suite.

Asserts that all Go source constants, registered documentation claim markers,
SBOM version/package parity, prohibited/guarded vocabulary rules, and personal
host path leak guards fail closed cleanly.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import sync_docs  # noqa: E402


class TestClaimsLinter(unittest.TestCase):
    def test_go_constants_and_safe_bounds(self):
        """Verify Go core constants match expected architectural bounds."""
        version = sync_docs.extract_go_constant(REPO_ROOT / "internal" / "cli" / "cli.go", "Version")
        self.assertEqual(version, "0.5.0-phase4")

        max_clusters = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "template" / "drain.go", "DefaultMaxClusters"
        )
        self.assertEqual(max_clusters, 4096)

        max_cluster_bytes = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "template" / "drain.go", "DefaultMaxClusterBytes"
        )
        self.assertEqual(max_cluster_bytes, 8 * 1024 * 1024)

        max_windows = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "template" / "drain.go", "DefaultMaxWindows"
        )
        self.assertEqual(max_windows, 4096)

        max_sample_bytes = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "template" / "drain.go", "DefaultMaxRetainedSampleBytes"
        )
        self.assertEqual(max_sample_bytes, 16 * 1024 * 1024)

        max_mem_mb = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "config" / "config.go", "DefaultMaxMemMB"
        )
        self.assertEqual(max_mem_mb, 256)

        window_sec = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "config" / "config.go", "DefaultWindowSec"
        )
        self.assertEqual(window_sec, 10)

        max_prompt = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "config" / "config.go", "DefaultMaxPromptBytes"
        )
        self.assertEqual(max_prompt, 2048)

        max_train_rec = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "config" / "config.go", "DefaultMaxTrainingRecords"
        )
        self.assertEqual(max_train_rec, 50000)

        max_train_bytes = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "config" / "config.go", "DefaultMaxTrainingFileBytes"
        )
        self.assertEqual(max_train_bytes, 25 * 1024 * 1024)

        magic_len = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "ingest" / "segreader.go", "MagicHeaderLen"
        )
        self.assertEqual(magic_len, 8)

        max_frame = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "ingest" / "segreader.go", "MaxFrameBytes"
        )
        self.assertEqual(max_frame, 1024 * 1024)

        min_dev = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "surprisal" / "math.go", "MinDeviationFloor"
        )
        self.assertEqual(min_dev, 0.25)

        nom_nats = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "surprisal" / "math.go", "NominalMismatchNats"
        )
        self.assertEqual(nom_nats, 2.5)

        warmup_min = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "surprisal" / "math.go", "DefaultWarmupMinCases"
        )
        self.assertEqual(warmup_min, 20)

        max_cand = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "surprisal" / "math.go", "DefaultMaxCandidateCases"
        )
        self.assertEqual(max_cand, 120)

        max_snap = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "surprisal" / "math.go", "MaxBaselineSnapshotBytes"
        )
        self.assertEqual(max_snap, 16 * 1024 * 1024)

        default_model = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "model" / "types.go", "ModelSmolLM2135MInstruct"
        )
        self.assertEqual(default_model, "HuggingFaceTB/SmolLM2-135M-Instruct")

        stepup_model = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "model" / "types.go", "ModelSmolLM2360MInstruct"
        )
        self.assertEqual(stepup_model, "HuggingFaceTB/SmolLM2-360M-Instruct")

        gemma_model = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "model" / "types.go", "ModelGemma22BIT"
        )
        self.assertEqual(gemma_model, "google/gemma-2-2b-it")

        triage_tokens = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "config" / "config.go", "DefaultTriageMaxTokens"
        )
        triage_client_tokens = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "triage" / "taxonomy.go", "DefaultMaxTokens"
        )
        self.assertEqual(triage_tokens, 64)
        self.assertEqual(triage_client_tokens, triage_tokens)

        max_exp = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "triage" / "taxonomy.go", "MaxExplanationBytes"
        )
        self.assertEqual(max_exp, 512)

        max_journal = sync_docs.extract_go_constant(
            REPO_ROOT / "internal" / "feedback" / "alerts_journal.go", "MaxAlertJournalRecords"
        )
        self.assertEqual(max_journal, 2000)

    def test_all_registered_claims_resolve_and_sync(self):
        """Verify every claim in docs/claims_registry.json resolves and matches its target docs."""
        reg_path = DOCS_DIR / "claims_registry.json"
        self.assertTrue(reg_path.is_file(), f"Missing {reg_path}")
        reg = json.loads(reg_path.read_text(encoding="utf-8"))

        claims = reg.get("claims", {})
        self.assertGreaterEqual(len(claims), 12)

        target_docs = set()
        for cid, cfg in claims.items():
            val = sync_docs.resolve_claim_value(cid, cfg, repo_root=REPO_ROOT)
            self.assertTrue(str(val).strip(), f"Empty resolved value for {cid}")
            for rel_doc in cfg.get("used_in", []):
                target_docs.add(REPO_ROOT / rel_doc)

        for doc_path in sorted(target_docs):
            ok, errs = sync_docs.sync_document(doc_path, reg_path, write=False, repo_root=REPO_ROOT)
            self.assertTrue(ok, f"Document sync failed for {doc_path.name}: {errs}")

    def test_bom_matches_cli_version_and_internal_packages(self):
        """Verify bom.json declares CycloneDX 1.5, current CLI version, and zero third-party deps."""
        bom_path = REPO_ROOT / "bom.json"
        self.assertTrue(bom_path.is_file(), f"Missing {bom_path}")
        bom = json.loads(bom_path.read_text(encoding="utf-8"))

        self.assertEqual(bom.get("bomFormat"), "CycloneDX")
        self.assertEqual(bom.get("specVersion"), "1.5")

        comp = bom.get("metadata", {}).get("component", {})
        expected_ver = sync_docs.extract_go_constant(REPO_ROOT / "internal" / "cli" / "cli.go", "Version")
        self.assertEqual(comp.get("version"), expected_ver)

        props = {p.get("name"): p.get("value") for p in comp.get("properties", [])}
        self.assertEqual(props.get("knowthankyew:privacy:third_party_dependencies"), "0")
        self.assertEqual(props.get("knowthankyew:privacy:network_egress"), "deny")
        self.assertEqual(props.get("knowthankyew:security:alert_only"), "true")

    def test_negative_claim_drift_detected(self):
        """Verify sync_document fails closed when a claim value drifts from ground truth."""
        reg_path = DOCS_DIR / "claims_registry.json"
        with tempfile.TemporaryDirectory() as tmp:
            drifted_doc = Path(tmp) / "README.md"
            drifted_doc.write_text(
                "<!-- claim:default_max_clusters -->999,999<!-- /claim -->\n",
                encoding="utf-8",
            )
            ok, errs = sync_docs.sync_document(drifted_doc, reg_path, write=False, repo_root=REPO_ROOT)
            self.assertFalse(ok)
            self.assertTrue(any("Claim drift" in e for e in errs), f"Expected Claim drift error, got {errs}")

    def test_negative_unmanaged_digit_in_empirical_block_detected(self):
        """Verify check_empirical_regions fails closed when an unmanaged digit or status appears."""
        bad_md = """
<!-- BEGIN_EMPIRICAL -->
| Metric | Target | Measured Result | Status |
| :--- | :--- | :--- | :--- |
| **Throughput** | 50,000 lines/sec | **<!-- claim:default_max_clusters -->4,096<!-- /claim -->** | PASSED |
<!-- END_EMPIRICAL -->
"""
        ok, errs = sync_docs.check_empirical_regions(bad_md, "bad.md")
        self.assertFalse(ok)
        self.assertTrue(any("unmanaged digits" in e for e in errs))
        self.assertTrue(any("status cell" in e for e in errs))

    def test_negative_prohibited_unguarded_words_and_host_paths_detected(self):
        """Verify lint_prose_and_words catches prohibited adjectives, unguarded claims, and /Users/ paths."""
        reg_path = DOCS_DIR / "claims_registry.json"

        ok1, errs1 = sync_docs.lint_prose_and_words(
            "Sentinel is a bulletproof and infinitely scalable log scanner.", "test1.md", registry_path=reg_path
        )
        self.assertFalse(ok1)
        self.assertGreaterEqual(len(errs1), 2)

        ok2, errs2 = sync_docs.lint_prose_and_words(
            "This is 100% verified without a marker.", "test2.md", registry_path=reg_path
        )
        self.assertFalse(ok2)
        self.assertGreaterEqual(len(errs2), 2)

        ok3, errs3 = sync_docs.lint_prose_and_words(
            "Output saved under /Users/alice/dev/logs.", "test3.md", registry_path=reg_path
        )
        self.assertFalse(ok3)
        self.assertTrue(any("Personal path leak" in e for e in errs3))

    def test_independent_recompute_metrics_passes_on_committed_artifacts(self):
        """Verify committed empirical_benchmarks.json and embedding_comparison.json pass math recomputation."""
        bench_json = DOCS_DIR / "benchmarks" / "empirical_benchmarks.json"
        ok, errs = sync_docs.independent_recompute_metrics(bench_json, repo_root=REPO_ROOT)
        self.assertTrue(ok, f"Benchmark recomputation failed: {errs}")

        emb_json = DOCS_DIR / "benchmarks" / "embedding_comparison.json"
        self.assertTrue(emb_json.is_file(), f"Missing {emb_json}")
        e_ok, e_errs = sync_docs.independent_recompute_embedding_comparison(
            emb_json, repo_root=REPO_ROOT, require_governed_fields=True
        )
        self.assertTrue(e_ok, f"Embedding comparison recomputation failed: {e_errs}")

    def test_negative_benchmark_recomputation_detects_drift_and_leaks(self):
        """Verify independent_recompute_metrics fails closed on tampered throughput, latency, F1, and /Users/ paths."""
        bench_json = DOCS_DIR / "benchmarks" / "empirical_benchmarks.json"
        base_data = json.loads(bench_json.read_text(encoding="utf-8"))
        md_rel = base_data["metadata"]["report_markdown"]
        md_text = (REPO_ROOT / md_rel).read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "docs" / "benchmarks").mkdir(parents=True)
            (tmp_root / md_rel).write_text(md_text, encoding="utf-8")

            # 1. Tampered throughput
            bad_tps = json.loads(json.dumps(base_data))
            bad_tps["tier0_replay"]["throughput_lps"] = 9999999.0
            p1 = tmp_root / "bad_tps.json"
            p1.write_text(json.dumps(bad_tps), encoding="utf-8")
            ok1, errs1 = sync_docs.independent_recompute_metrics(p1, repo_root=tmp_root)
            self.assertFalse(ok1)
            self.assertTrue(any("throughput recomputation mismatch" in e.lower() for e in errs1), errs1)

            # 2. Inverted Tier 1 latency percentiles
            bad_lat = json.loads(json.dumps(base_data))
            bad_lat["tier1_surprisal"]["p90_us"] = bad_lat["tier1_surprisal"]["p50_us"] * 0.5
            p2 = tmp_root / "bad_lat.json"
            p2.write_text(json.dumps(bad_lat), encoding="utf-8")
            ok2, errs2 = sync_docs.independent_recompute_metrics(p2, repo_root=tmp_root)
            self.assertFalse(ok2)
            self.assertTrue(any("monotonicity" in e.lower() for e in errs2), errs2)

            # 3. Tampered F1 score (strictly distinct from fixture F1 and checked at exact 4-decimal precision)
            bad_f1 = json.loads(json.dumps(base_data))
            orig_f1 = float(base_data["detection_accuracy"]["f1_score"])
            bad_f1["detection_accuracy"]["f1_score"] = 0.25 if orig_f1 > 0.5 else 0.90
            p3 = tmp_root / "bad_f1.json"
            p3.write_text(json.dumps(bad_f1), encoding="utf-8")
            ok3, errs3 = sync_docs.independent_recompute_metrics(p3, repo_root=tmp_root)
            self.assertFalse(ok3)
            self.assertTrue(any("f1_score mismatch" in e.lower() for e in errs3), errs3)

            # Sub-tolerance 4-decimal F1 drift (e.g. 0.9996 vs 1.0000) must also be rejected!
            tiny_f1 = json.loads(json.dumps(base_data))
            tiny_f1["detection_accuracy"]["f1_score"] = round(orig_f1 - 0.0004 if orig_f1 >= 0.0004 else orig_f1 + 0.0004, 4)
            p_tiny = tmp_root / "tiny_f1.json"
            p_tiny.write_text(json.dumps(tiny_f1), encoding="utf-8")
            ok_tiny, errs_tiny = sync_docs.independent_recompute_metrics(p_tiny, repo_root=tmp_root)
            self.assertFalse(ok_tiny)
            self.assertTrue(any("f1_score mismatch" in e.lower() for e in errs_tiny), errs_tiny)

            # Raw Tier 1 latency sample tamper must fail percentile recomputation!
            bad_raw_t1 = json.loads(json.dumps(base_data))
            bad_raw_t1["tier1_surprisal"]["raw_samples_us"] = [1.0] * bad_raw_t1["tier1_surprisal"]["evaluations"]
            p_raw1 = tmp_root / "bad_raw_t1.json"
            p_raw1.write_text(json.dumps(bad_raw_t1), encoding="utf-8")
            ok_raw1, errs_raw1 = sync_docs.independent_recompute_metrics(p_raw1, repo_root=tmp_root)
            self.assertFalse(ok_raw1)
            self.assertTrue(any("raw-sample recomputation mismatch" in e for e in errs_raw1), errs_raw1)

            # 4. Leaked personal host path in JSON
            bad_path = json.loads(json.dumps(base_data))
            bad_path["metadata"]["cpu"] = "/Users/alice/cpu"
            p4 = tmp_root / "bad_path.json"
            p4.write_text(json.dumps(bad_path), encoding="utf-8")
            ok4, errs4 = sync_docs.independent_recompute_metrics(p4, repo_root=tmp_root)
            self.assertFalse(ok4)
            self.assertTrue(any("personal host path" in e for e in errs4), errs4)

            # 5. Unconditional self-contained embedding comparison negative tests (independent of optional artifact)
            fixed_emb = {
                "metadata": {"date": "2026-11-25T00:00:00Z", "model_id": "test", "offline_mode": True},
                "dataset": {
                    "eval_total_windows": 4,
                    "eval_benign_windows": 2,
                    "eval_structural_attack_windows": 1,
                    "eval_disguised_semantic_windows": 1,
                },
                "pure_laplace_lk": {
                    "tp": 1, "fp": 0, "fn": 1, "tn": 2,
                    "structural_tp": 1, "disguised_semantic_tp": 0,
                    "precision": 1.0, "recall": 0.5, "f1": 0.6667,
                    "structural_recall": 1.0, "disguised_semantic_recall": 0.0,
                    "latency_p50_ms": 0.02, "latency_p99_ms": 0.04,
                    "raw_samples_ms": [0.01, 0.02, 0.03, 0.04],
                },
                "hybrid_laplace_lk_minilm": {
                    "tp": 2, "fp": 0, "fn": 0, "tn": 2,
                    "structural_tp": 1, "disguised_semantic_tp": 1,
                    "precision": 1.0, "recall": 1.0, "f1": 1.0,
                    "structural_recall": 1.0, "disguised_semantic_recall": 1.0,
                    "latency_p50_ms": 6.0, "latency_p99_ms": 8.0,
                    "raw_samples_ms": [5.0, 6.0, 7.0, 8.0],
                },
                "comparison": {
                    "f1_delta": 0.3333,
                    "fp_delta": 0,
                    "disguised_semantic_recall_delta": 1.0,
                    "p50_latency_slowdown_x": 300.0,
                },
            }
            p_emb_ok = tmp_root / "fixed_emb_ok.json"
            p_emb_ok.write_text(json.dumps(fixed_emb), encoding="utf-8")
            ok_e0, errs_e0 = sync_docs.independent_recompute_embedding_comparison(p_emb_ok)
            self.assertTrue(ok_e0, errs_e0)

            bad_emb = json.loads(json.dumps(fixed_emb))
            bad_emb["comparison"]["f1_delta"] = 0.99
            p5 = tmp_root / "bad_emb.json"
            p5.write_text(json.dumps(bad_emb), encoding="utf-8")
            ok5, errs5 = sync_docs.independent_recompute_embedding_comparison(p5)
            self.assertFalse(ok5)
            self.assertTrue(any("f1_delta mismatch" in e for e in errs5), errs5)

            # Negative disguised_semantic_recall (-0.0004 vs 0.0000) must be rejected as out of [0, 1]!
            neg_emb = json.loads(json.dumps(fixed_emb))
            neg_emb["pure_laplace_lk"]["disguised_semantic_recall"] = -0.0004
            p_neg = tmp_root / "neg_emb.json"
            p_neg.write_text(json.dumps(neg_emb), encoding="utf-8")
            ok_neg, errs_neg = sync_docs.independent_recompute_embedding_comparison(p_neg)
            self.assertFalse(ok_neg)
            self.assertTrue(any("out of [0, 1] range" in e for e in errs_neg), errs_neg)

            # Tampering subgroup recall and matching delta must STILL fail against subgroup_tp!
            bad_sub = json.loads(json.dumps(fixed_emb))
            bad_sub["pure_laplace_lk"]["disguised_semantic_recall"] = 0.5
            bad_sub["comparison"]["disguised_semantic_recall_delta"] = 0.5
            p_sub = tmp_root / "bad_sub.json"
            p_sub.write_text(json.dumps(bad_sub), encoding="utf-8")
            ok_sub, errs_sub = sync_docs.independent_recompute_embedding_comparison(p_sub)
            self.assertFalse(ok_sub)
            self.assertTrue(any("disguised_semantic_recall mismatch" in e for e in errs_sub), errs_sub)

            # Non-finite NaN constant in embedding JSON must be rejected deterministically!
            nan_emb = json.loads(json.dumps(fixed_emb))
            nan_emb["comparison"]["f1_delta"] = float("nan")
            p_emb_nan = tmp_root / "emb_nan.json"
            p_emb_nan.write_text(json.dumps(nan_emb, allow_nan=True), encoding="utf-8")
            ok_en, errs_en = sync_docs.independent_recompute_embedding_comparison(p_emb_nan)
            self.assertFalse(ok_en)
            self.assertTrue(any("Non-standard non-finite JSON constant" in e for e in errs_en), errs_en)

            # 6. Non-finite NaN, integer overflow (10**400), JSON-escaped personal path, invalid UTF-8, and bad shapes
            nan_bench = json.loads(json.dumps(base_data))
            nan_bench["tier1_surprisal"]["separation_nats"] = float("nan")
            p_nan = tmp_root / "bench_nan.json"
            p_nan.write_text(json.dumps(nan_bench, allow_nan=True), encoding="utf-8")
            ok_nan, errs_nan = sync_docs.independent_recompute_metrics(p_nan, repo_root=tmp_root)
            self.assertFalse(ok_nan)
            self.assertTrue(any("Non-standard non-finite JSON constant" in e for e in errs_nan), errs_nan)

            huge_int = json.loads(json.dumps(base_data))
            huge_int["memory_profile"]["rss_peak_kb"] = 10**400
            p_huge = tmp_root / "bench_huge.json"
            p_huge.write_text(json.dumps(huge_int), encoding="utf-8")
            ok_huge, errs_huge = sync_docs.independent_recompute_metrics(p_huge, repo_root=tmp_root)
            self.assertFalse(ok_huge)
            self.assertTrue(any("int64 bound" in e for e in errs_huge), errs_huge)

            esc_path = json.loads(json.dumps(base_data))
            esc_path["metadata"]["cpu"] = "/Users/alice/cpu"
            p_esc = tmp_root / "bench_escaped_path.json"
            p_esc.write_text(json.dumps(esc_path).replace("/Users/", r"\/Users\/"), encoding="utf-8")
            ok_esc, errs_esc = sync_docs.independent_recompute_metrics(p_esc, repo_root=tmp_root)
            self.assertFalse(ok_esc)
            self.assertTrue(any("personal host path" in e for e in errs_esc), errs_esc)

            p_bad_utf8 = tmp_root / "bad_utf8.json"
            p_bad_utf8.write_bytes(b"\xff\xfeinvalid")
            ok_utf8, errs_utf8 = sync_docs.independent_recompute_metrics(p_bad_utf8, repo_root=tmp_root)
            self.assertFalse(ok_utf8)
            self.assertTrue(any("Failed to read" in e for e in errs_utf8), errs_utf8)

            abs_md = json.loads(json.dumps(base_data))
            # Synthetic absolute path outside /Users/ and /home/ so TMPDIR location cannot mask the check.
            abs_md["metadata"]["report_markdown"] = "/opt/external/benchmark-report.md"
            p_abs = tmp_root / "abs_md.json"
            p_abs.write_text(json.dumps(abs_md), encoding="utf-8")
            ok_abs, errs_abs = sync_docs.independent_recompute_metrics(p_abs, repo_root=tmp_root)
            self.assertFalse(ok_abs)
            self.assertTrue(any("repository-relative" in e for e in errs_abs), errs_abs)

            # Invalid report_markdown containing NUL byte must return a clean validation error (no traceback).
            nul_md = json.loads(json.dumps(base_data))
            nul_md["metadata"]["report_markdown"] = "docs/benchmarks/bad\x00report.md"
            p_nul = tmp_root / "nul_md.json"
            p_nul.write_text(json.dumps(nul_md), encoding="utf-8")
            ok_nul, errs_nul = sync_docs.independent_recompute_metrics(p_nul, repo_root=tmp_root)
            self.assertFalse(ok_nul)
            self.assertTrue(any("path is invalid" in e for e in errs_nul), errs_nul)

            # Duplicate JSON object keys (e.g., hiding an escaped personal path in an overwritten first member) must fail.
            dup_json_raw = json.dumps(base_data).replace(
                '"cpu":',
                '"cpu": "\\/home\\/alice\\/cpu", "cpu":',
                1,
            )
            p_dup_key = tmp_root / "dup_key.json"
            p_dup_key.write_text(dup_json_raw, encoding="utf-8")
            ok_dk, errs_dk = sync_docs.independent_recompute_metrics(p_dup_key, repo_root=tmp_root)
            self.assertFalse(ok_dk)
            self.assertTrue(any("Duplicate JSON object member" in e for e in errs_dk), errs_dk)

            # Missing tier0_replay.clusters_active must fail instead of defaulting to 0.
            no_clusters = json.loads(json.dumps(base_data))
            del no_clusters["tier0_replay"]["clusters_active"]
            p_nc = tmp_root / "no_clusters.json"
            p_nc.write_text(json.dumps(no_clusters), encoding="utf-8")
            ok_nc, errs_nc = sync_docs.independent_recompute_metrics(p_nc, repo_root=tmp_root)
            self.assertFalse(ok_nc)
            self.assertTrue(any("clusters_active" in e for e in errs_nc), errs_nc)

            # HTML-commented, unclosed-commented, tilde-fenced, 4-backtick-fenced, and delimiter-less table rows must fail parity!
            tps_val = base_data["tier0_replay"]["throughput_lps"]
            tps_target = base_data["acceptance_gates"]["throughput_target_lps"]
            tps_status = base_data["tier0_replay"]["throughput_gate_status"]
            real_row = f"| **Tier 0+1 Throughput** | `{tps_val:.2f} lines/sec` (target >= {tps_target:.0f} lines/sec) | `{tps_status}` |"
            stale_row = f"| **Tier 0+1 Throughput** | `12345.00 lines/sec` (target >= {tps_target:.0f} lines/sec) | `MISSED TARGET` |"
            self.assertIn(real_row, md_text)

            md_variants = [
                ("comment_case", md_text.replace(real_row, f"<!-- {real_row} -->\n{stale_row}")),
                ("unclosed_comment_case", md_text.replace(real_row, f"<!-- unclosed comment\n{real_row}")),
                ("tilde_fence_case", md_text.replace(real_row, f"~~~\n| Metric | Measured Result | Gate |\n| :--- | :--- | :--- |\n{real_row}\n~~~\n{stale_row}")),
                ("four_backtick_fence_case", md_text.replace(real_row, f"````markdown\n```\n| Metric | Measured Result | Gate |\n| :--- | :--- | :--- |\n{real_row}\n```\n````\n{stale_row}")),
                ("pre_html_block_case", md_text.replace(real_row, f"<pre>\n| Metric | Measured Result | Gate |\n| :--- | :--- | :--- |\n{real_row}\n</pre>\n{stale_row}")),
                ("narrowed_header_case", md_text.replace("| Metric | Measured Result | Gate |\n| :--- | :--- | :--- |", "| Metric | Measured Result |\n| :--- | :--- |", 1)),
                ("missing_delimiter_case", md_text.replace("| :--- | :--- | :--- |\n", "")),
            ]
            for case_name, variant_md in md_variants:
                self.assertNotEqual(variant_md, md_text, f"{case_name} did not mutate md_text")
                case_root = tmp_root / case_name
                (case_root / "docs" / "benchmarks").mkdir(parents=True)
                (case_root / md_rel).write_text(variant_md, encoding="utf-8")
                p_var = case_root / "bench.json"
                p_var.write_text(json.dumps(base_data), encoding="utf-8")
                ok_var, errs_var = sync_docs.independent_recompute_metrics(p_var, repo_root=case_root)
                self.assertFalse(ok_var, f"{case_name} unexpectedly passed")
                self.assertTrue(any("published-table parity error" in e for e in errs_var), (case_name, errs_var))

            # Positive GFM edge cases: indented code containing literal '<!--' before a valid table
            # AND outer-pipe-less delimiter rows (':--- | :--- | :---') MUST still pass!
            indented_code_md = "\n    <!-- literal comment in indented code block\n\n" + md_text.replace(
                "| :--- | :--- | :--- |",
                ":--- | :--- | :---",
                1,
            )
            ind_root = tmp_root / "indented_code_ok"
            (ind_root / "docs" / "benchmarks").mkdir(parents=True)
            (ind_root / md_rel).write_text(indented_code_md, encoding="utf-8")
            p_ind = ind_root / "bench.json"
            p_ind.write_text(json.dumps(base_data), encoding="utf-8")
            ok_ind, errs_ind = sync_docs.independent_recompute_metrics(p_ind, repo_root=ind_root)
            self.assertTrue(ok_ind, errs_ind)

            # Unconditional stale Tier 2 row rejection when tier2_triage.enabled is false!
            stale_t2_root = tmp_root / "stale_t2_case"
            (stale_t2_root / "docs" / "benchmarks").mkdir(parents=True)
            stale_t2_md = md_text
            if "**Inference Latency P50 / P90 / P99 / Max**" not in stale_t2_md:
                stale_t2_md += (
                    "\n| Metric | Measured Result | Gate |\n| :--- | :--- | :--- |\n"
                    "| **Inference Latency P50 / P90 / P99 / Max** | `1.000 ms` / `1.000 ms` / `1.000 ms` / `1.000 ms` | — |\n"
                )
            (stale_t2_root / md_rel).write_text(stale_t2_md, encoding="utf-8")
            disabled_t2 = json.loads(json.dumps(base_data))
            disabled_t2["tier2_triage"]["enabled"] = False
            disabled_t2["tier2_triage"]["injection_override_gate_status"] = "SKIPPED"
            p_stale_t2 = stale_t2_root / "stale_t2.json"
            p_stale_t2.write_text(json.dumps(disabled_t2), encoding="utf-8")
            ok_st2, errs_st2 = sync_docs.independent_recompute_metrics(p_stale_t2, repo_root=stale_t2_root)
            self.assertFalse(ok_st2)
            self.assertTrue(any("stale Tier 2 row" in e for e in errs_st2), errs_st2)

            p_list = tmp_root / "bench_list.json"
            p_list.write_text("[]", encoding="utf-8")
            ok_list, errs_list = sync_docs.independent_recompute_metrics(p_list, repo_root=tmp_root)
            self.assertFalse(ok_list)
            self.assertTrue(any("must be an object" in e for e in errs_list), errs_list)

            bad_type = json.loads(json.dumps(base_data))
            bad_type["tier0_replay"]["lines_read"] = "100000"
            p_type = tmp_root / "bad_type.json"
            p_type.write_text(json.dumps(bad_type), encoding="utf-8")
            ok_type, errs_type = sync_docs.independent_recompute_metrics(p_type, repo_root=tmp_root)
            self.assertFalse(ok_type)
            self.assertTrue(any("must be an integer" in e for e in errs_type), errs_type)

            # 7. Boundary throughput status must use RECOMPUTED throughput (49999.99 < 50000 -> MISSED TARGET)
            boundary = json.loads(json.dumps(base_data))
            boundary["acceptance_gates"]["throughput_target_lps"] = 50000
            boundary["tier0_replay"]["lines_written"] = 4999999
            boundary["tier0_replay"]["lines_read"] = 4999999
            boundary["tier0_replay"]["duration_seconds"] = 100.0
            boundary["tier0_replay"]["throughput_lps"] = 50000.00
            boundary["tier0_replay"]["throughput_gate_status"] = "PASSED"
            p_bnd = tmp_root / "boundary_tps.json"
            p_bnd.write_text(json.dumps(boundary), encoding="utf-8")
            ok_bnd, errs_bnd = sync_docs.independent_recompute_metrics(p_bnd, repo_root=tmp_root)
            self.assertFalse(ok_bnd)
            self.assertTrue(any("throughput_gate_status mismatch" in e for e in errs_bnd), errs_bnd)

    def test_script_conclusion_ast_linter_passes_and_catches_hardcoded_digits(self):
        """Verify AST linter passes on scripts/ and rejects hardcoded digits/literals in conclusion builders."""
        ok, errs = sync_docs.lint_script_conclusions(REPO_ROOT / "scripts")
        self.assertTrue(ok, f"Script conclusion AST lint failed: {errs}")

        with tempfile.TemporaryDirectory() as tmp:
            sdir = Path(tmp)
            # 1. Missing conclusion builder in governed eval_embedding_comparison.py must fail.
            (sdir / "eval_embedding_comparison.py").write_text("def helper(x):\n    return str(x)\n", encoding="utf-8")
            ok_miss, errs_miss = sync_docs.lint_script_conclusions(sdir)
            self.assertFalse(ok_miss)
            self.assertTrue(any("must define a conclusion builder" in e for e in errs_miss), errs_miss)

            # 2. Hardcoded digit in f-string fragment must fail, even if format specs like :.4f are used.
            (sdir / "eval_embedding_comparison.py").write_text(
                'def build_conclusion_recommendation(v):\n'
                '    return f"P50 was {v:.4f} ms (347x slower)"\n',
                encoding="utf-8",
            )
            ok_str, errs_str = sync_docs.lint_script_conclusions(sdir)
            self.assertFalse(ok_str)
            self.assertTrue(any("hardcoded digit in string fragment" in e for e in errs_str), errs_str)

            # 3. Hardcoded numeric literal inside conclusion function body must fail.
            (sdir / "eval_embedding_comparison.py").write_text(
                'def build_conclusion_recommendation(delta):\n'
                '    return "improved" if delta > 0.5 else "unchanged"\n',
                encoding="utf-8",
            )
            ok_num, errs_num = sync_docs.lint_script_conclusions(sdir)
            self.assertFalse(ok_num)
            self.assertTrue(any("hardcoded numeric literal" in e for e in errs_num), errs_num)

            # 4. Clean parameterized conclusion with P50/P99 labels and format specs must pass.
            (sdir / "eval_embedding_comparison.py").write_text(
                'def build_conclusion_recommendation(p50_ms, ratio, improved):\n'
                '    """Docstring with 123 digits is ignored."""\n'
                '    state = "improved" if improved else "flat"\n'
                '    return f"Measured P50 {p50_ms:.4f} ms ({ratio:.1f}x, {state})"\n',
                encoding="utf-8",
            )
            ok_clean, errs_clean = sync_docs.lint_script_conclusions(sdir)
            self.assertTrue(ok_clean, errs_clean)

    def test_claims_registry_validation_and_tier2_live_gate(self):
        """Verify validate_claims_registry catches orphaned claims, missing artifacts, and disabled Tier 2."""
        reg_path = DOCS_DIR / "claims_registry.json"
        ok, errs = sync_docs.validate_claims_registry(reg_path, repo_root=REPO_ROOT)
        self.assertTrue(ok, f"Committed claims_registry.json failed validation: {errs}")

        base_reg = json.loads(reg_path.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "docs" / "benchmarks").mkdir(parents=True)
            (tmp_root / "internal" / "cli").mkdir(parents=True)
            (tmp_root / "internal" / "cli" / "cli.go").write_text('package cli\nconst Version = "0.5.0"\n', encoding="utf-8")
            (tmp_root / "README.md").write_text("v<!-- claim:ver -->0.5.0<!-- /claim -->\n", encoding="utf-8")

            # 1. Orphaned claim (empty used_in) must fail.
            orphan_reg = {
                "version": "2.0.0",
                "claim_terms": {},
                "claims": {
                    "ver": {
                        "source_artifact": "internal/cli/cli.go",
                        "go_const": "Version",
                        "format_rule": "{value}",
                        "used_in": [],
                    }
                },
            }
            p_orphan = tmp_root / "docs" / "orphan_reg.json"
            p_orphan.write_text(json.dumps(orphan_reg), encoding="utf-8")
            ok1, errs1 = sync_docs.validate_claims_registry(p_orphan, repo_root=tmp_root)
            self.assertFalse(ok1)
            self.assertTrue(any("orphaned claim" in e for e in errs1), errs1)

            # 2. Missing marker in listed used_in doc must fail.
            (tmp_root / "CHANGELOG.md").write_text("# Changelog\n", encoding="utf-8")
            missing_marker_reg = json.loads(json.dumps(orphan_reg))
            missing_marker_reg["claims"]["ver"]["used_in"] = ["CHANGELOG.md"]
            p_mm = tmp_root / "docs" / "mm_reg.json"
            p_mm.write_text(json.dumps(missing_marker_reg), encoding="utf-8")
            ok2, errs2 = sync_docs.validate_claims_registry(p_mm, repo_root=tmp_root)
            self.assertFalse(ok2)
            self.assertTrue(any("marker is missing" in e for e in errs2), errs2)

            # 3. Missing governed embedding_comparison.json must fail closed in both registry and recompute.
            missing_emb_reg = {
                "version": "2.0.0",
                "claim_terms": {},
                "claims": {
                    "embed_f1": base_reg["claims"]["embed_pure_lk_f1"],
                },
            }
            (tmp_root / "README.md").write_text("<!-- claim:embed_f1 -->0.7500<!-- /claim -->\n", encoding="utf-8")
            p_me = tmp_root / "docs" / "me_reg.json"
            p_me.write_text(json.dumps(missing_emb_reg), encoding="utf-8")
            ok3, errs3 = sync_docs.validate_claims_registry(p_me, repo_root=tmp_root)
            self.assertFalse(ok3)
            self.assertTrue(any("required source_artifact does not exist" in e for e in errs3), errs3)

            ok3b, errs3b = sync_docs.independent_recompute_embedding_comparison(
                tmp_root / "docs" / "benchmarks" / "embedding_comparison.json",
                repo_root=tmp_root,
                require_governed_fields=True,
            )
            self.assertFalse(ok3b)
            self.assertTrue(any("Missing required embedding comparison JSON" in e for e in errs3b), errs3b)

            # 4. Offline benchmark (tier2_triage.enabled = false) must fail governed Tier 2 claims.
            (tmp_root / "docs" / "benchmarks" / "empirical_benchmarks.json").write_text(
                json.dumps({"tier2_triage": {"enabled": False, "p50_ms": 0.0}}),
                encoding="utf-8",
            )
            (tmp_root / "README.md").write_text("<!-- claim:bench_tier2_p50_ms -->P50 0.00 ms<!-- /claim -->\n", encoding="utf-8")
            t2_reg = {
                "version": "2.0.0",
                "claim_terms": {},
                "claims": {"bench_tier2_p50_ms": base_reg["claims"]["bench_tier2_p50_ms"]},
            }
            p_t2 = tmp_root / "docs" / "t2_reg.json"
            p_t2.write_text(json.dumps(t2_reg), encoding="utf-8")
            ok4, errs4 = sync_docs.validate_claims_registry(p_t2, repo_root=tmp_root)
            self.assertFalse(ok4)
            self.assertTrue(any("tier2_triage.enabled is not true" in e for e in errs4), errs4)

    def test_cross_doc_marker_linter_catches_unclosed_unknown_and_mismatched_markers(self):
        """Verify lint_claim_markers_and_regions catches malformed markers in any doc while ignoring code fences."""
        reg_path = DOCS_DIR / "claims_registry.json"

        # Fenced code examples must not trigger false positives.
        fenced_ok = "```markdown\n<!-- claim:example_id -->123<!-- /claim -->\n<!-- BEGIN_EMPIRICAL -->\n```\n"
        ok0, errs0 = sync_docs.lint_claim_markers_and_regions(fenced_ok, "CONTRIBUTING.md", registry_path=reg_path)
        self.assertTrue(ok0, errs0)

        bad_cases = [
            ("<!-- claim:nonexistent_claim_xyz -->42<!-- /claim -->", "unknown claim ID"),
            ("<!-- claim:sentinel_version -->0.5.0", "unclosed"),
            ("<!-- claim:sentinel_version 0.5.0", "unclosed HTML claim marker"),
            ("orphan <!-- /claim --> here", "orphan closing"),
            ("<!-- claim:sentinel_version -->0.5.0<!-- /claim_term -->", "mismatched closing"),
            ("<!-- BEGIN_EMPIRICAL -->\n| A | B | C |\n", "unbalanced empirical delimiters"),
            ("`v<!-- claim:sentinel_version -->0.5.0<!-- /claim -->`", "inside inline backtick code span"),
        ]
        for content, expected_sub in bad_cases:
            ok, errs = sync_docs.lint_claim_markers_and_regions(content, "docs/DECISIONS.md", registry_path=reg_path)
            self.assertFalse(ok, f"Expected failure for {content!r}")
            self.assertTrue(any(expected_sub in e for e in errs), (content, errs))

        # Backticks INSIDE a claim value (outside-comment, inside-code) must pass cleanly!
        ok_inner_bt, errs_inner_bt = sync_docs.lint_claim_markers_and_regions(
            "Version <!-- claim:sentinel_version -->`v0.5.0-phase4`<!-- /claim --> is active.",
            "README.md",
            registry_path=reg_path,
        )
        self.assertTrue(ok_inner_bt, errs_inner_bt)

    def test_expanded_personal_host_paths_and_no_prohibited_word_bypass(self):
        """Verify /home/ and Windows C:\\Users\\ leaks are blocked and meta-phrases cannot bypass prohibited words."""
        reg_path = DOCS_DIR / "claims_registry.json"

        for leaked_line in (
            "Saved under /home/alice/.genesis-sentinel/cursor.json",
            r"Saved under C:\Users\alice\.genesis-sentinel\cursor.json",
            "Saved under c:/users/alice/logs",
        ):
            ok, errs = sync_docs.lint_prose_and_words(leaked_line, "doc.md", registry_path=reg_path)
            self.assertFalse(ok, f"Expected path leak rejection for {leaked_line!r}")
            self.assertTrue(any("Personal path leak" in e for e in errs), errs)

        # Normal lowercase REST paths like /api/v1/users/profile must NOT false-positive.
        ok_api, errs_api = sync_docs.lint_prose_and_words(
            "GET /api/v1/users/profile HTTP/1.1 200 OK", "doc.md", registry_path=reg_path
        )
        self.assertTrue(ok_api, errs_api)

        # Including 'prohibited word' on the same line must NOT bypass prohibited-adjective detection.
        ok_byp, errs_byp = sync_docs.lint_prose_and_words(
            "Note on prohibited word policy: this system is bulletproof.", "doc.md", registry_path=reg_path
        )
        self.assertFalse(ok_byp)
        self.assertTrue(any("bulletproof" in e for e in errs_byp), errs_byp)

    def test_provenance_gate_pinning_and_embedding_narrative_parity(self):
        """Verify git_commit cleanliness, report filename parity, Go gate pinning, and embedding recommendation parity."""
        bench_json = DOCS_DIR / "benchmarks" / "empirical_benchmarks.json"
        base_bench = json.loads(bench_json.read_text(encoding="utf-8"))
        emb_json = DOCS_DIR / "benchmarks" / "embedding_comparison.json"
        base_emb = json.loads(emb_json.read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)

            # 1. Dirty git_commit in empirical_benchmarks.json must fail closed.
            dirty_bench = json.loads(json.dumps(base_bench))
            dirty_bench["metadata"]["git_commit"] = f"{base_bench['metadata']['git_commit']}-dirty"
            p_dirty = tmp_dir / "dirty_bench.json"
            p_dirty.write_text(json.dumps(dirty_bench), encoding="utf-8")
            ok1, errs1 = sync_docs.independent_recompute_metrics(p_dirty, repo_root=REPO_ROOT)
            self.assertFalse(ok1)
            self.assertTrue(any("dirty/unknown" in e for e in errs1), errs1)

            # 2. Loosened memory_ceiling_mb vs DefaultMaxMemMB in config.go must fail closed against REPO_ROOT.
            loose_mem = json.loads(json.dumps(base_bench))
            loose_mem["acceptance_gates"]["memory_ceiling_mb"] = 1024
            p_mem = tmp_dir / "loose_mem.json"
            p_mem.write_text(json.dumps(loose_mem), encoding="utf-8")
            ok2, errs2 = sync_docs.independent_recompute_metrics(p_mem, repo_root=REPO_ROOT)
            self.assertFalse(ok2)
            self.assertTrue(any("DefaultMaxMemMB" in e for e in errs2), errs2)

            # 3. Loosened threshold_nats vs DefaultThresholdNats in math.go must fail closed against REPO_ROOT.
            loose_thr = json.loads(json.dumps(base_bench))
            loose_thr["tier1_surprisal"]["threshold_nats"] = 9.5
            p_thr = tmp_dir / "loose_thr.json"
            p_thr.write_text(json.dumps(loose_thr), encoding="utf-8")
            ok3, errs3 = sync_docs.independent_recompute_metrics(p_thr, repo_root=REPO_ROOT)
            self.assertFalse(ok3)
            self.assertTrue(any("DefaultThresholdNats" in e for e in errs3), errs3)

            # 4. Tampered rss_delta_mb, fp_delta, or recommendation prose in embedding_comparison.json must fail closed.
            bad_rss = json.loads(json.dumps(base_emb))
            bad_rss["metadata"]["rss_delta_mb"] = 12.34
            p_rss = tmp_dir / "bad_rss.json"
            p_rss.write_text(json.dumps(bad_rss), encoding="utf-8")
            ok4, errs4 = sync_docs.independent_recompute_embedding_comparison(
                p_rss, repo_root=REPO_ROOT, require_governed_fields=True
            )
            self.assertFalse(ok4)
            self.assertTrue(any("rss_delta_mb mismatch" in e for e in errs4), errs4)

            bad_fp = json.loads(json.dumps(base_emb))
            bad_fp["comparison"]["fp_delta"] = 3
            p_fp = tmp_dir / "bad_fp.json"
            p_fp.write_text(json.dumps(bad_fp), encoding="utf-8")
            ok5, errs5 = sync_docs.independent_recompute_embedding_comparison(
                p_fp, repo_root=REPO_ROOT, require_governed_fields=True
            )
            self.assertFalse(ok5)
            self.assertTrue(any("fp_delta mismatch" in e for e in errs5), errs5)

            bad_rec = json.loads(json.dumps(base_emb))
            bad_rec["comparison"]["recommendation"] = bad_rec["comparison"]["recommendation"].replace("347.6x", "999.9x")
            p_rec = tmp_dir / "bad_rec.json"
            p_rec.write_text(json.dumps(bad_rec), encoding="utf-8")
            ok6, errs6 = sync_docs.independent_recompute_embedding_comparison(
                p_rec, repo_root=REPO_ROOT, require_governed_fields=True
            )
            self.assertFalse(ok6)
            self.assertTrue(any("recommendation narrative drifted" in e for e in errs6), errs6)

    def test_static_go_network_boundary_and_landscape_gate(self):
        """Verify audit-claims.py static Go network boundary and 180-day landscape freshness gate."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("audit_claims_mod", REPO_ROOT / "scripts" / "audit-claims.py")
        audit_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit_mod)

        # 1. Committed repository passes both static Go network boundary and landscape freshness.
        errs_live: list[str] = []
        audit_mod.audit_go_network_egress_boundary(errs_live, repo_root=REPO_ROOT)
        audit_mod.audit_landscape_freshness(errs_live, repo_root=REPO_ROOT)
        self.assertEqual(errs_live, [])

        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "internal" / "security").mkdir(parents=True)
            (tmp_root / "internal" / "emit").mkdir(parents=True)
            (tmp_root / "docs").mkdir(parents=True)

            # Allowed inside internal/security, struct pointer fields (*http.Client), comments/strings, and _test.go files.
            (tmp_root / "internal" / "security" / "net.go").write_text(
                'package security\nimport "net"\nfunc d() { _, _ = net.DialTimeout("tcp", "127.0.0.1:9", 0) }\n',
                encoding="utf-8",
            )
            (tmp_root / "internal" / "emit" / "safe.go").write_text(
                'package emit\nimport "net/http"\ntype Wrapper struct { c *http.Client }\n'
                '// net.DialTimeout("tcp", "x", 0)\n/* &http.Client{} */\nconst msg = "http.Get(url)"\n',
                encoding="utf-8",
            )
            (tmp_root / "internal" / "emit" / "sink_test.go").write_text(
                'package emit\nimport "net/http"\nvar _ = &http.Client{}\n',
                encoding="utf-8",
            )
            errs_ok: list[str] = []
            audit_mod.audit_go_network_egress_boundary(errs_ok, repo_root=tmp_root)
            self.assertEqual(errs_ok, [])

            # Raw net.DialTimeout, &http.Client{}, new(http.Client), and zero-value var declarations outside internal/security must fail closed!
            (tmp_root / "internal" / "emit" / "bypass.go").write_text(
                'package emit\nimport ("net"; "net/http")\n'
                'func bad() {\n'
                '    var d net.Dialer\n'
                '    var c http.Client\n'
                '    var tr http.Transport\n'
                '    _, _ = net.DialTimeout("tcp", "localhost:9000", 0)\n'
                '    _ = &http.Client{}\n'
                '    _ = new(http.Client)\n'
                '    _, _, _ = d, c, tr\n'
                '}\n',
                encoding="utf-8",
            )
            errs_bad: list[str] = []
            audit_mod.audit_go_network_egress_boundary(errs_bad, repo_root=tmp_root)
            self.assertEqual(len(errs_bad), 6, errs_bad)
            self.assertTrue(all("bypass.go" in e for e in errs_bad), errs_bad)

            # Stale (>180 days) landscape-meta must fail closed!
            (tmp_root / "docs" / "ALTERNATIVES.md").write_text(
                "<!-- landscape-meta\n"
                "last-reviewed: 2024-01-01\n"
                "review-cadence-days: 180\n"
                "reviewed-versions: [fail2ban@v1.1, crowdsec@v1.6, falco@v0.39]\n"
                "-->\n# Alternatives\n",
                encoding="utf-8",
            )
            errs_stale: list[str] = []
            audit_mod.audit_landscape_freshness(errs_stale, repo_root=tmp_root)
            self.assertTrue(any("STALE" in e for e in errs_stale), errs_stale)

            # Inflated (>180 days) or non-integer review-cadence-days must fail closed!
            for bad_cadence, expected_sub in (("99999", "between 1 and 180"), ("abc", "not a valid integer")):
                (tmp_root / "docs" / "ALTERNATIVES.md").write_text(
                    "<!-- landscape-meta\n"
                    "last-reviewed: 2026-11-25\n"
                    f"review-cadence-days: {bad_cadence}\n"
                    "reviewed-versions: [fail2ban@v1.1, crowdsec@v1.6, falco@v0.39]\n"
                    "-->\n# Alternatives\n",
                    encoding="utf-8",
                )
                errs_cad: list[str] = []
                audit_mod.audit_landscape_freshness(errs_cad, repo_root=tmp_root)
                self.assertTrue(any(expected_sub in e for e in errs_cad), (bad_cadence, errs_cad))

    def test_hardened_json_overflow_rerun_filenames_recomputed_gates_and_gfm_edges(self):
        """Verify 1e309 float overflow, -rN rerun filenames, recomputed P99/slowdown, HTML Types 3/5, and empirical header bypasses."""
        # 1. JSON float overflow (1e309 -> inf) must fail closed in _loads_strict_json!
        with self.assertRaises(ValueError) as ctx_inf:
            sync_docs._loads_strict_json('{"val": 1e309}')
        self.assertIn("Non-finite JSON floating-point value", str(ctx_inf.exception))

        # 2. Data row containing "Measured Result" inside BEGIN_EMPIRICAL must NOT bypass unmanaged-digit / status checks!
        bypass_emp = (
            "<!-- BEGIN_EMPIRICAL -->\n"
            "| Gate | Target | Measured Result | Status |\n"
            "| :--- | :--- | :--- | :--- |\n"
            "| **Fake Row** | 123 | Measured Result 999 | PASSED |\n"
            "<!-- END_EMPIRICAL -->\n"
        )
        ok_emp, errs_emp = sync_docs.check_empirical_regions(bypass_emp, "bypass.md")
        self.assertFalse(ok_emp)
        self.assertTrue(any("status cell" in e for e in errs_emp), errs_emp)
        self.assertTrue(any("unmanaged digits" in e for e in errs_emp), errs_emp)

        # 3. CommonMark §4.6 Type 3 (<? ... ?>) and Type 5 (<![CDATA[ ... ]]>) hide tables; 1-cell body row keeps scanning!
        md_special = (
            "<?\n| A | B |\n|---|---|\n| **HiddenPI** | 1 |\n?>\n\n"
            "<![CDATA[\n| A | B |\n|---|---|\n| **HiddenCDATA** | 2 |\n]]>\n\n"
            "| Metric | Value |\n"
            "| :--- | :--- |\n"
            "| **RowOne** | 10 |\n"
            "| NotesOnly |\n"
            "| **RowTwo** | 20 |\n"
        )
        rows, labels, dups = sync_docs._extract_published_markdown_table_rows(md_special)
        self.assertEqual(dups, [])
        self.assertNotIn("**HiddenPI**", labels)
        self.assertNotIn("**HiddenCDATA**", labels)
        self.assertIn("**RowOne**", labels)
        self.assertIn("**RowTwo**", labels)
        self.assertIn("| **RowTwo** | 20 |", rows)

        # 4. Same-day rerun -r2.md accepted; invalid -r1.md rejected; recomputed P99 boundary gate uses calc_p99!
        bench_json = DOCS_DIR / "benchmarks" / "empirical_benchmarks.json"
        base_bench = json.loads(bench_json.read_text(encoding="utf-8"))
        orig_md_rel = base_bench["metadata"]["report_markdown"]
        orig_md_text = (REPO_ROOT / orig_md_rel).read_text(encoding="utf-8")

        with tempfile.TemporaryDirectory() as tmp:
            tmp_root = Path(tmp)
            (tmp_root / "docs" / "benchmarks").mkdir(parents=True)

            # 4a. Valid -r2.md suffix must pass
            r2_rel = orig_md_rel[:-3] + "-r2.md"
            (tmp_root / r2_rel).write_text(orig_md_text, encoding="utf-8")
            r2_bench = json.loads(json.dumps(base_bench))
            r2_bench["metadata"]["report_markdown"] = r2_rel
            p_r2 = tmp_root / "r2_bench.json"
            p_r2.write_text(json.dumps(r2_bench), encoding="utf-8")
            ok_r2, errs_r2 = sync_docs.independent_recompute_metrics(p_r2, repo_root=tmp_root)
            self.assertTrue(ok_r2, errs_r2)

            # 4b. Invalid -r1.md suffix must fail closed
            r1_rel = orig_md_rel[:-3] + "-r1.md"
            (tmp_root / r1_rel).write_text(orig_md_text, encoding="utf-8")
            r1_bench = json.loads(json.dumps(base_bench))
            r1_bench["metadata"]["report_markdown"] = r1_rel
            p_r1 = tmp_root / "r1_bench.json"
            p_r1.write_text(json.dumps(r1_bench), encoding="utf-8")
            ok_r1, errs_r1 = sync_docs.independent_recompute_metrics(p_r1, repo_root=tmp_root)
            self.assertFalse(ok_r1)
            self.assertTrue(any("filename" in e for e in errs_r1), errs_r1)

            # 4c. Tier 1 P99 boundary: raw samples -> calc_p99=10.000 against target 10.0; stored 9.9996 must NOT pass!
            bnd_t1 = json.loads(json.dumps(base_bench))
            bnd_t1["acceptance_gates"]["tier1_p99_target_us"] = 10.0
            bnd_t1["tier1_surprisal"]["evaluations"] = 4
            bnd_t1["tier1_surprisal"]["raw_samples_us"] = [5.0, 6.0, 9.0, 10.0]
            bnd_t1["tier1_surprisal"]["p50_us"] = 6.0
            bnd_t1["tier1_surprisal"]["p90_us"] = 10.0
            bnd_t1["tier1_surprisal"]["p99_us"] = 9.9996
            bnd_t1["tier1_surprisal"]["max_us"] = 10.0
            bnd_t1["tier1_surprisal"]["p99_gate_status"] = "PASSED"
            p_t1b = tmp_root / "bnd_t1.json"
            p_t1b.write_text(json.dumps(bnd_t1), encoding="utf-8")
            ok_t1b, errs_t1b = sync_docs.independent_recompute_metrics(p_t1b, repo_root=tmp_root)
            self.assertFalse(ok_t1b)
            self.assertTrue(any("p99_gate_status mismatch" in e for e in errs_t1b), errs_t1b)

            # 4d. Embedding comparison slowdown must derive from raw-sample recomputed P50, not unrounded stored float!
            emb_bnd = {
                "metadata": {"date": "2026-11-25T00:00:00Z", "model_id": "test", "offline_mode": True},
                "dataset": {
                    "eval_total_windows": 4,
                    "eval_benign_windows": 2,
                    "eval_structural_attack_windows": 1,
                    "eval_disguised_semantic_windows": 1,
                },
                "pure_laplace_lk": {
                    "tp": 1, "fp": 0, "fn": 1, "tn": 2,
                    "structural_tp": 1, "disguised_semantic_tp": 0,
                    "precision": 1.0, "recall": 0.5, "f1": 0.6667,
                    "structural_recall": 1.0, "disguised_semantic_recall": 0.0,
                    "latency_p50_ms": 0.020049, "latency_p99_ms": 0.04,
                    "raw_samples_ms": [0.01, 0.02, 0.03, 0.04],
                },
                "hybrid_laplace_lk_minilm": {
                    "tp": 2, "fp": 0, "fn": 0, "tn": 2,
                    "structural_tp": 1, "disguised_semantic_tp": 1,
                    "precision": 1.0, "recall": 1.0, "f1": 1.0,
                    "structural_recall": 1.0, "disguised_semantic_recall": 1.0,
                    "latency_p50_ms": 6.0, "latency_p99_ms": 8.0,
                    "raw_samples_ms": [5.0, 6.0, 7.0, 8.0],
                },
                "comparison": {
                    "f1_delta": 0.3333,
                    "fp_delta": 0,
                    "disguised_semantic_recall_delta": 1.0,
                    "p50_latency_slowdown_x": 299.3,
                },
            }
            p_eb = tmp_root / "emb_bnd.json"
            p_eb.write_text(json.dumps(emb_bnd), encoding="utf-8")
            ok_eb, errs_eb = sync_docs.independent_recompute_embedding_comparison(p_eb)
            self.assertFalse(ok_eb)
            self.assertTrue(any("p50_latency_slowdown_x mismatch" in e for e in errs_eb), errs_eb)


if __name__ == "__main__":
    unittest.main()
