from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from random import Random

from src.seed_prep import (
    SeedPrepConfig,
    RawRecord,
    _deduplicate,
    choose_class_counts,
    cleanup_seed_text,
    has_usable_body,
    is_english_language,
    map_source_label,
    prepare_seeds,
    recognized_placeholder_total,
    remove_source_placeholders,
    validate_seed_csv,
)
from src.safety import replace_live_urls
from src.generator import load_seeds_from_csv
from tests.common import PROJECT_ROOT

FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "meajor_mini.csv"


class SeedPrepTests(unittest.TestCase):
    def test_label_mapping(self) -> None:
        self.assertEqual(map_source_label(0), "legitimate")
        self.assertEqual(map_source_label("0.0"), "legitimate")
        self.assertEqual(map_source_label(1), "phishing")
        self.assertEqual(map_source_label("phishing"), "phishing")
        self.assertIsNone(map_source_label(""))
        self.assertIsNone(map_source_label("nan"))

    def test_english_filtering(self) -> None:
        self.assertTrue(is_english_language("en"))
        self.assertTrue(is_english_language("en;en"))
        self.assertFalse(is_english_language("fr"))
        self.assertFalse(is_english_language("de;en"))
        self.assertFalse(is_english_language("unk"))

    def test_safe_url_rewriting_is_label_agnostic(self) -> None:
        text = "See https://evil-live-example.test/steal and keep [URL] here"
        legit = replace_live_urls(text)
        phish = replace_live_urls(text)
        self.assertEqual(legit, phish)
        self.assertNotIn("evil-live-example.test", legit)
        self.assertIn("[URL]", legit)
        self.assertIn("docs.example.com", legit)

    def test_near_balanced_selection_not_forced_equal(self) -> None:
        unequal = []
        for seed in range(40):
            n_legit, n_phish, total = choose_class_counts(
                Random(seed),
                available_legitimate=5000,
                available_phishing=5000,
                target_total=2000,
                total_jitter=15,
            )
            self.assertGreaterEqual(n_legit / total, 0.45)
            self.assertLessEqual(n_legit / total, 0.55)
            self.assertGreaterEqual(n_phish / total, 0.45)
            self.assertLessEqual(n_phish / total, 0.55)
            self.assertEqual(n_legit + n_phish, total)
            if n_legit != n_phish:
                unequal.append((n_legit, n_phish))
        self.assertTrue(unequal)

    def test_class_count_reproducibility(self) -> None:
        a = choose_class_counts(Random(20260920), available_legitimate=4000, available_phishing=4000)
        b = choose_class_counts(Random(20260920), available_legitimate=4000, available_phishing=4000)
        self.assertEqual(a, b)
        other = choose_class_counts(Random(99), available_legitimate=4000, available_phishing=4000)
        self.assertNotEqual(a, other)

    def test_prepare_mini_fixture_schema_and_duplicates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "content_seeds.csv"
            report_path = Path(tmp) / "report.json"
            report = prepare_seeds(
                SeedPrepConfig(
                    source_path=FIXTURE,
                    output_csv=output,
                    report_path=report_path,
                    random_seed=7,
                    target_total=12,
                    total_jitter=1,
                )
            )
            self.assertTrue(output.is_file())
            seeds = load_seeds_from_csv(output)
            self.assertGreaterEqual(len(seeds), 11)
            self.assertLessEqual(len(seeds), 13)
            self.assertEqual({item.label for item in seeds}, {"legitimate", "phishing"})
            ids = [item.seed_id for item in seeds]
            self.assertEqual(len(ids), len(set(ids)))
            texts = {(item.subject, item.body_plain) for item in seeds}
            self.assertEqual(len(texts), len(seeds))
            self.assertTrue(all(item.seed_id.startswith("seed_legit_") or item.seed_id.startswith("seed_phish_") for item in seeds))
            joined = "\n".join(item.body_plain for item in seeds)
            self.assertNotIn("evil-live-example.test", joined)
            self.assertNotIn("phish-live-example.test", joined)
            for token in ("[URL]", "[NAME]", "[ORGANIZATION]", "[PRODUCT]", "[FINANCIAL_INFO]", "[PHONE_NUMBER]", "<|SIMBOL|>"):
                self.assertNotIn(token, joined)
            self.assertGreater(report["duplicate_removals"]["exact_duplicate_rows_removed_by_label"].get("legitimate", 0), 0)
            self.assertGreater(report["duplicate_removals"]["conflicting_label_duplicate_rows_excluded"], 0)
            self.assertFalse(report["placeholder_cleanup"]["recognized_placeholders_remaining"])
            self.assertGreater(report["placeholder_cleanup"]["rows_dropped_unusable_after_cleanup"], 0)
            validation = validate_seed_csv(output, target_total=12, total_jitter=1)
            self.assertTrue(validation["ok"])
            share = validation["legitimate"] / validation["count"]
            self.assertGreaterEqual(share, 0.45)
            self.assertLessEqual(share, 0.55)
            again = prepare_seeds(
                SeedPrepConfig(
                    source_path=FIXTURE,
                    output_csv=Path(tmp) / "content_seeds2.csv",
                    report_path=Path(tmp) / "report2.json",
                    random_seed=7,
                    target_total=12,
                    total_jitter=1,
                )
            )
            self.assertEqual(report["final_legitimate_count"], again["final_legitimate_count"])
            self.assertEqual(report["final_phishing_count"], again["final_phishing_count"])


class PlaceholderCleanupTests(unittest.TestCase):
    def test_label_blind_removal_and_example_sentence(self) -> None:
        source = "Dear [NAME], please review [URL]"
        cleaned = remove_source_placeholders(source)
        self.assertEqual(cleaned, "Dear, please review")
        self.assertEqual(remove_source_placeholders(source), cleanup_seed_text(source))

    def test_multiple_placeholder_types_and_repeats(self) -> None:
        source = (
            "Hello [NAME] from [ORGANIZATION], mail [EMAIL_ADDRESS] or open [URL] "
            "about [PRODUCT] and [FINANCIAL_INFO] then call [PHONE_NUMBER] <|SIMBOL|> extra."
        )
        cleaned = cleanup_seed_text(source)
        for token in (
            "[NAME]",
            "[ORGANIZATION]",
            "[EMAIL_ADDRESS]",
            "[URL]",
            "[PRODUCT]",
            "[FINANCIAL_INFO]",
            "[PHONE_NUMBER]",
            "<|SIMBOL|>",
        ):
            self.assertNotIn(token, cleaned)
        self.assertIn("Hello", cleaned)
        self.assertIn("extra.", cleaned)
        self.assertEqual(recognized_placeholder_total(cleaned), 0)

    def test_nested_meajor_tokens_are_removed(self) -> None:
        source = "See <|U[URL]L|> and <|[EMAIL_ADDRESS]|> then continue this office note."
        cleaned = cleanup_seed_text(source)
        self.assertNotIn("<|", cleaned)
        self.assertNotIn("[URL]", cleaned)
        self.assertIn("See", cleaned)
        self.assertIn("continue this office note.", cleaned)

    def test_text_without_placeholders_stays_the_same(self) -> None:
        source = "Quarterly office notes for the operations team this week."
        self.assertEqual(cleanup_seed_text(source), source)
        self.assertEqual(remove_source_placeholders(source), source)

    def test_cleanup_never_depends_on_label(self) -> None:
        source = "Dear [NAME], see [URL] and [EMAIL_ADDRESS] today."
        self.assertEqual(cleanup_seed_text(source), cleanup_seed_text(source))
        self.assertNotIn("label", cleanup_seed_text.__code__.co_varnames)
        self.assertNotIn("label", remove_source_placeholders.__code__.co_varnames)

    def test_unusable_body_after_cleanup(self) -> None:
        cleaned = cleanup_seed_text("[NAME] [URL] [EMAIL_ADDRESS]")
        self.assertFalse(has_usable_body(cleaned))

    def test_cleanup_can_create_exact_duplicates(self) -> None:
        shared = "Please review the attached office schedule for the staff meeting next week extra."
        records = [
            RawRecord(shared.split()[0], shared, "legitimate", "en", "trec5", True, True),
            RawRecord(
                shared.split()[0],
                "Please review the attached office schedule for the [NAME] staff meeting next week extra.",
                "legitimate",
                "en",
                "trec5",
                True,
                True,
            ),
        ]
        cleaned = [
            RawRecord(
                item.subject,
                cleanup_seed_text(item.body),
                item.label,
                item.language,
                item.source,
                True,
                True,
            )
            for item in records
        ]
        self.assertEqual(cleaned[0].body, cleaned[1].body)
        kept, stats = _deduplicate(cleaned)
        self.assertEqual(len(kept), 1)
        self.assertEqual(stats["exact_duplicate_rows_removed_by_label"]["legitimate"], 1)


if __name__ == "__main__":
    unittest.main()
