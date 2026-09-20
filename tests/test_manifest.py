from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.config import MANIFEST_REQUIRED_FIELDS
from src.generator import GeneratorConfig, generate_from_seeds, load_seeds
from src.validator import validate_corpus
from tests.common import fixture_seed


class ManifestTests(unittest.TestCase):
    def test_manifest_provenance_and_unique_ids(self) -> None:
        seeds = [
            fixture_seed("s-leg-1", "legitimate"),
            fixture_seed("s-phs-1", "phishing"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            result = generate_from_seeds(
                seeds,
                Path(tmp),
                config=GeneratorConfig(random_seed=5),
                profile_by_seed={"s-leg-1": "plain_basic", "s-phs-1": "normal_authenticated"},
                coverage_by_seed={"s-leg-1": "low", "s-phs-1": "rich"},
            )
            rows = result["rows"]
            self.assertEqual(len(rows), 2)
            ids = [row["sample_id"] for row in rows]
            self.assertEqual(len(ids), len(set(ids)))
            for row in rows:
                for field in MANIFEST_REQUIRED_FIELDS:
                    self.assertIn(field, row)
                    self.assertTrue(row[field] != "" or field == "header_template_id")
                self.assertEqual(row["is_simulated"], "true")
                self.assertNotIn("header_spf_result", row)
                self.assertNotIn("has_html", row)
                self.assertNotIn("url_count", row)
            validate_corpus(Path(tmp), unique_seeds=True)

    def test_seed_schema_rejects_identity_metadata(self) -> None:
        with self.assertRaises(ValueError):
            load_seeds(
                [
                    {
                        "seed_id": "bad",
                        "label": "legitimate",
                        "subject": "Hello",
                        "body_plain": "Body",
                        "sender_address": "a@b.c",
                    }
                ]
            )


if __name__ == "__main__":
    unittest.main()
