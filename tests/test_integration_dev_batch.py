# Development-only integration batch. Uses test fixtures, not training seeds.

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from src.generator import GeneratorConfig, generate_from_seeds
from src.quality_report import EMAIL_FEATURE_FIELDS, build_quality_report, default_agent_path
from src.validator import validate_corpus
from tests.common import PROJECT_ROOT, fixture_seed

DEV_PLAN = [
    ("leg-norm-rich", "legitimate", "normal_authenticated", "rich"),
    ("phs-norm-rich", "phishing", "normal_authenticated", "rich"),
    ("leg-norm-most", "legitimate", "normal_authenticated", "mostly_observable"),
    ("phs-svc-part", "phishing", "third_party_service", "partial"),
    ("leg-svc-rich", "legitimate", "third_party_service", "rich"),
    ("phs-part-part", "phishing", "partially_authenticated", "partial"),
    ("leg-part-most", "legitimate", "partially_authenticated", "mostly_observable"),
    ("phs-prob-rich", "phishing", "authentication_problem", "rich"),
    ("leg-prob-part", "legitimate", "authentication_problem", "partial"),
    ("phs-plain-low", "phishing", "plain_basic", "low"),
    ("leg-plain-part", "legitimate", "plain_basic", "partial"),
    ("phs-att-low", "phishing", "attachment_bearing", "low"),
    ("leg-att-rich", "legitimate", "attachment_bearing", "rich"),
    ("phs-att-part", "phishing", "attachment_bearing", "partial"),
    ("leg-svc-most", "legitimate", "third_party_service", "mostly_observable"),
    ("phs-norm-most", "phishing", "normal_authenticated", "mostly_observable"),
    ("leg-prob-most", "legitimate", "authentication_problem", "mostly_observable"),
    ("phs-plain-part", "phishing", "plain_basic", "partial"),
]


class DevIntegrationTests(unittest.TestCase):
    def test_dev_batch_agent_extracts_eighteen_features(self) -> None:
        agent_root = default_agent_path()
        self.assertTrue((agent_root / "src" / "feature_extractor.py").is_file())
        seeds = [
            fixture_seed(seed_id, label, subject=f"Dev {seed_id}", body=f"Development fixture {seed_id}.")
            for seed_id, label, _profile, _coverage in DEV_PLAN
        ]
        profile_by_seed = {seed_id: profile for seed_id, _label, profile, _coverage in DEV_PLAN}
        coverage_by_seed = {seed_id: coverage for seed_id, _label, _profile, coverage in DEV_PLAN}
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "dev_batch"
            result = generate_from_seeds(
                seeds,
                output_dir,
                config=GeneratorConfig(random_seed=20260920),
                profile_by_seed=profile_by_seed,
                coverage_by_seed=coverage_by_seed,
            )
            self.assertEqual(result["count"], 18)
            validate_corpus(output_dir, unique_seeds=True)
            report = build_quality_report(output_dir, agent_root=agent_root, unique_seeds_expected=True)
            self.assertEqual(report["parser_failures"], [])
            self.assertEqual(report["extraction_failures"], [])
            self.assertEqual(report["parsed"], 18)
            self.assertEqual(report["email_features_schema"], list(EMAIL_FEATURE_FIELDS))
            self.assertEqual(len(EMAIL_FEATURE_FIELDS), 18)
            self.assertEqual(len(report["profile_distribution"]), 6)
            labels = {key.split("|", 1)[1] for key in report["profile_label_distribution"]}
            self.assertEqual(labels, {"legitimate", "phishing"})
            inferred = report["inferred_coverage_distribution"]
            self.assertGreater(inferred.get("rich", 0) + inferred.get("mostly_observable", 0), 0)
            self.assertGreater(inferred.get("low", 0) + inferred.get("partial", 0), 0)
            self.assertIn("legitimate", report["inferred_coverage_by_label"])
            self.assertIn("phishing", report["inferred_coverage_by_label"])
            self.assertTrue(report["disclaimer"].startswith("Distributions are controlled"))
            archive = PROJECT_ROOT / "tests" / "_dev_batch"
            archive.mkdir(exist_ok=True)
            (archive / "quality_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
