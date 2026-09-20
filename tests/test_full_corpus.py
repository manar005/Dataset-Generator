from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from src.config import MANIFEST_AUDIT_FIELDS, MANIFEST_REQUIRED_FIELDS
from src.full_corpus import FullCorpusConfig, generate_full_corpus
from src.profile_allocation import allocate_profile_counts
from src.profiles import all_profile_names
from src.quality_report import EMAIL_FEATURE_FIELDS
from src.validator import validate_corpus


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


class FullCorpusTests(unittest.TestCase):
    def test_full_generation_uses_all_seeds_and_stays_out_of_pilot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = _seed_csv(tmp_path / "content_seeds.csv", 12, 12)
            output = tmp_path / "full"
            stale = output / "emails" / "legitimate" / "stale.eml"
            stale.parent.mkdir(parents=True, exist_ok=True)
            stale.write_text("stale leftover", encoding="utf-8")
            sibling_pilot = tmp_path / "pilot"
            sibling_pilot.mkdir()
            (sibling_pilot / "keep.txt").write_text("do not delete", encoding="utf-8")

            result = generate_full_corpus(
                FullCorpusConfig(
                    seed_csv=seeds,
                    output_dir=output,
                    random_seed=20260920,
                    expected_total=24,
                )
            )
            self.assertEqual(result["count"], 24)
            self.assertEqual(result["class_counts"]["legitimate"], 12)
            self.assertEqual(result["class_counts"]["phishing"], 12)
            self.assertFalse(stale.exists())
            self.assertEqual((sibling_pilot / "keep.txt").read_text(encoding="utf-8"), "do not delete")
            self.assertNotIn("pilot", Path(result["output_dir"]).parts)
            self.assertTrue((output / "emails" / "legitimate").is_dir())
            self.assertTrue((output / "emails" / "phishing").is_dir())
            self.assertTrue((output / "manifest.csv").is_file())
            self.assertTrue((output / "quality_report.json").is_file())

            rows = result["rows"]
            self.assertEqual(len(rows), 24)
            self.assertEqual(len({row["sample_id"] for row in rows}), 24)
            self.assertEqual(len({row["content_seed_id"] for row in rows}), 24)
            self.assertEqual(result["file_consistency"]["orphan_files"], [])
            self.assertEqual(result["file_consistency"]["missing_files"], [])
            validation = validate_corpus(output, unique_seeds=True)
            self.assertTrue(validation["ok"])
            self.assertEqual(result["planned_profile_allocation"]["legitimate"], allocate_profile_counts(12, "legitimate"))
            self.assertEqual(result["planned_profile_allocation"]["phishing"], allocate_profile_counts(12, "phishing"))

            profiles_by_label = {"legitimate": set(), "phishing": set()}
            coverage_by_label = {"legitimate": set(), "phishing": set()}
            for row in rows:
                for field in MANIFEST_REQUIRED_FIELDS + MANIFEST_AUDIT_FIELDS:
                    self.assertIn(field, row)
                self.assertEqual(row["is_simulated"], "true")
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
            self.assertEqual(report["parsed"], 24)
            self.assertEqual(report["email_features_schema"], list(EMAIL_FEATURE_FIELDS))
            self.assertEqual(report["content_preservation"]["subject_mismatches"], 0)
            self.assertEqual(report["intent_vs_observed"]["mismatch_count"], 0)
            self.assertEqual(report["url_count_audit"]["flagged_count"], 0)
            self.assertEqual(report["generated_text_duplicates"]["extra_duplicate_messages"], 0)
            self.assertEqual(report["corpus"]["total"], 24)

    def test_rejects_non_full_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = _seed_csv(tmp_path / "content_seeds.csv", 12, 12)
            with self.assertRaises(ValueError):
                generate_full_corpus(
                    FullCorpusConfig(
                        seed_csv=seeds,
                        output_dir=tmp_path / "pilot",
                        random_seed=1,
                        expected_total=24,
                    )
                )
            with self.assertRaises(ValueError):
                generate_full_corpus(
                    FullCorpusConfig(
                        seed_csv=seeds,
                        output_dir=tmp_path / "full_corpus",
                        random_seed=1,
                        expected_total=24,
                    )
                )

    def test_rejects_wrong_seed_total(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            seeds = _seed_csv(tmp_path / "content_seeds.csv", 12, 12)
            with self.assertRaises(ValueError):
                generate_full_corpus(
                    FullCorpusConfig(
                        seed_csv=seeds,
                        output_dir=tmp_path / "full",
                        random_seed=1,
                        expected_total=2003,
                    )
                )


if __name__ == "__main__":
    unittest.main()
