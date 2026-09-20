from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from random import Random

from src.config import MANIFEST_REQUIRED_FIELDS
from src.pilot import (
    PilotConfig,
    choose_pilot_class_counts,
    generate_pilot,
    plan_coverage,
    select_pilot_seeds,
)
from src.profile_allocation import allocate_profile_counts
from src.profiles import all_profile_names
from src.generator import assign_profiles
from src.quality_report import EMAIL_FEATURE_FIELDS
from src.validator import validate_corpus
from tests.common import fixture_seed


def _seed_csv(path: Path, n_legit: int, n_phish: int) -> Path:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["seed_id", "label", "subject", "body_plain"])
        writer.writeheader()
        for index in range(1, n_legit + 1):
            writer.writerow(
                {
                    "seed_id": f"seed_legit_{index:04d}",
                    "label": "legitimate",
                    "subject": f"Office note {index}",
                    "body_plain": f"Legitimate fixture body for seed {index} with enough words.",
                }
            )
        for index in range(1, n_phish + 1):
            writer.writerow(
                {
                    "seed_id": f"seed_phish_{index:04d}",
                    "label": "phishing",
                    "subject": f"Account notice {index}",
                    "body_plain": f"Phishing fixture body for seed {index} with enough words.",
                }
            )
    return path


class PilotSelectionTests(unittest.TestCase):
    def test_fraction_preserves_class_ratio(self) -> None:
        n_legit, n_phish = choose_pilot_class_counts(917, 1086, fraction=0.12)
        self.assertEqual((n_legit, n_phish), (110, 130))
        total = n_legit + n_phish
        self.assertGreaterEqual(total, 200)
        self.assertLessEqual(total, 300)
        self.assertNotEqual(n_legit, n_phish)
        self.assertAlmostEqual(n_legit / total, 917 / (917 + 1086), places=2)

    def test_other_fraction_changes_size(self) -> None:
        a = choose_pilot_class_counts(917, 1086, fraction=0.12)
        b = choose_pilot_class_counts(917, 1086, fraction=0.15)
        self.assertNotEqual(a, b)
        self.assertEqual(b, (138, 163))

    def test_selection_is_reproducible_and_ignores_wording(self) -> None:
        seeds = [fixture_seed(f"l{i}", "legitimate", body="Urgent password reset now.") for i in range(20)]
        seeds.extend(fixture_seed(f"p{i}", "phishing", body="Quarterly office hours reminder.") for i in range(20))
        first = [item.seed_id for item in select_pilot_seeds(seeds, Random(20260920), fraction=0.5)]
        second = [item.seed_id for item in select_pilot_seeds(seeds, Random(20260920), fraction=0.5)]
        self.assertEqual(first, second)
        other = [item.seed_id for item in select_pilot_seeds(seeds, Random(99), fraction=0.5)]
        self.assertNotEqual(first, other)
        self.assertEqual(sum(item.startswith("l") for item in first), 10)
        self.assertEqual(sum(item.startswith("p") for item in first), 10)

    def test_dynamic_allocation_on_pilot_counts(self) -> None:
        for n, label in ((110, "legitimate"), (130, "phishing"), (12, "legitimate"), (18, "phishing")):
            allocated = allocate_profile_counts(n, label)
            self.assertEqual(sum(allocated.values()), n)
            self.assertEqual(set(allocated), set(all_profile_names()))
            self.assertTrue(all(value >= 1 for value in allocated.values()))


class PilotGenerationTests(unittest.TestCase):
    def test_pilot_generation_manifest_coverage_and_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = _seed_csv(tmp_path / "content_seeds.csv", 12, 12)
            output = tmp_path / "pilot"
            result = generate_pilot(
                PilotConfig(
                    seed_csv=seeds,
                    output_dir=output,
                    random_seed=20260920,
                    fraction=0.5,
                    min_per_label=6,
                )
            )
            self.assertEqual(result["count"], 12)
            self.assertEqual(result["class_counts"]["legitimate"], 6)
            self.assertEqual(result["class_counts"]["phishing"], 6)
            self.assertTrue((output / "emails" / "legitimate").is_dir())
            self.assertTrue((output / "emails" / "phishing").is_dir())
            self.assertTrue((output / "manifest.csv").is_file())
            self.assertTrue((output / "quality_report.json").is_file())
            self.assertTrue((output / "pilot_selection.json").is_file())
            self.assertNotIn("full_corpus", str(output))
            validation = validate_corpus(output, unique_seeds=True)
            self.assertTrue(validation["ok"])
            rows = result["rows"]
            for row in rows:
                for field in MANIFEST_REQUIRED_FIELDS:
                    self.assertIn(field, row)
                self.assertEqual(row["is_simulated"], "true")
            profiles_by_label = {"legitimate": set(), "phishing": set()}
            coverage_by_label = {"legitimate": set(), "phishing": set()}
            for row in rows:
                profiles_by_label[row["label"]].add(row["profile"])
                coverage_by_label[row["label"]].add(row["coverage_level"])
            self.assertEqual(profiles_by_label["legitimate"], set(all_profile_names()))
            self.assertEqual(profiles_by_label["phishing"], set(all_profile_names()))
            for label in ("legitimate", "phishing"):
                self.assertIn("rich", coverage_by_label[label])
                self.assertTrue(coverage_by_label[label].intersection({"low", "partial"}))
            report = result["quality_report"]
            self.assertEqual(report["parser_failures"], [])
            self.assertEqual(report["extraction_failures"], [])
            self.assertEqual(report["parsed"], 12)
            self.assertEqual(report["email_features_schema"], list(EMAIL_FEATURE_FIELDS))
            self.assertEqual(report["content_preservation"]["subject_mismatches"], 0)
            self.assertEqual(report["intent_vs_observed"]["mismatch_count"], 0)

    def test_rejects_non_pilot_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = _seed_csv(tmp_path / "content_seeds.csv", 12, 12)
            with self.assertRaises(ValueError):
                generate_pilot(
                    PilotConfig(
                        seed_csv=seeds,
                        output_dir=tmp_path / "full_corpus",
                        random_seed=1,
                        fraction=0.5,
                    )
                )

    def test_plan_coverage_gives_rich_and_partial_to_both_labels(self) -> None:
        seeds = [fixture_seed(f"l{i}", "legitimate") for i in range(12)]
        seeds.extend(fixture_seed(f"p{i}", "phishing") for i in range(12))
        assigned = assign_profiles(seeds, Random(7))
        coverage = plan_coverage(assigned, Random(7))
        by_label = {"legitimate": set(), "phishing": set()}
        for seed, _profile in assigned:
            by_label[seed.label].add(coverage[seed.seed_id])
        for label in ("legitimate", "phishing"):
            self.assertIn("rich", by_label[label])
            self.assertTrue(by_label[label].intersection({"low", "partial"}))


if __name__ == "__main__":
    unittest.main()
