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
        if emb_json.is_file():
            e_ok, e_errs = sync_docs.independent_recompute_embedding_comparison(emb_json)
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

            # 3. Tampered F1 score
            bad_f1 = json.loads(json.dumps(base_data))
            bad_f1["detection_accuracy"]["f1_score"] = 0.50
            p3 = tmp_root / "bad_f1.json"
            p3.write_text(json.dumps(bad_f1), encoding="utf-8")
            ok3, errs3 = sync_docs.independent_recompute_metrics(p3, repo_root=tmp_root)
            self.assertFalse(ok3)
            self.assertTrue(any("f1_score mismatch" in e.lower() for e in errs3), errs3)

            # 4. Leaked /Users/ path in JSON
            bad_path = json.loads(json.dumps(base_data))
            bad_path["metadata"]["cpu"] = "/Users/alice/cpu"
            p4 = tmp_root / "bad_path.json"
            p4.write_text(json.dumps(bad_path), encoding="utf-8")
            ok4, errs4 = sync_docs.independent_recompute_metrics(p4, repo_root=tmp_root)
            self.assertFalse(ok4)
            self.assertTrue(any("/Users/" in e for e in errs4), errs4)

            # 5. Tampered embedding comparison F1 delta
            emb_json = DOCS_DIR / "benchmarks" / "embedding_comparison.json"
            if emb_json.is_file():
                bad_emb = json.loads(emb_json.read_text(encoding="utf-8"))
                bad_emb["comparison"]["f1_delta"] = 0.99
                p5 = tmp_root / "bad_emb.json"
                p5.write_text(json.dumps(bad_emb), encoding="utf-8")
                ok5, errs5 = sync_docs.independent_recompute_embedding_comparison(p5)
                self.assertFalse(ok5)
                self.assertTrue(any("f1_delta mismatch" in e for e in errs5), errs5)


if __name__ == "__main__":
    unittest.main()
