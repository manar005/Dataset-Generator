from __future__ import annotations

import unittest

from src.config import COVERAGE_LEVELS, LABELS
from src.profiles import allowed_coverage, all_profile_names
from tests.common import make_scenario


class CoverageTests(unittest.TestCase):
    def test_all_coverage_levels_exist(self) -> None:
        realized = set()
        for profile in all_profile_names():
            realized.update(allowed_coverage(profile))
        self.assertEqual(realized, set(COVERAGE_LEVELS))
        self.assertIn("low", realized)
        self.assertIn("partial", realized)
        self.assertIn("mostly_observable", realized)
        self.assertIn("rich", realized)

    def test_both_labels_can_use_every_coverage_level(self) -> None:
        mapping = {
            "low": ("plain_basic", "low"),
            "partial": ("partially_authenticated", "partial"),
            "mostly_observable": ("normal_authenticated", "mostly_observable"),
            "rich": ("normal_authenticated", "rich"),
        }
        for coverage in COVERAGE_LEVELS:
            profile, level = mapping[coverage]
            for label in LABELS:
                scenario = make_scenario(profile, level, label, sample_id=f"{coverage}-{label}")
                self.assertEqual(scenario.coverage_level, coverage)
                self.assertEqual(scenario.label, label)
                if coverage == "rich":
                    self.assertTrue(scenario.state.is_rich())
                    self.assertGreater(len(scenario.urls), 0)
                    self.assertIsNotNone(scenario.state.spf)
                    self.assertIsNotNone(scenario.state.dkim)
                    self.assertIsNotNone(scenario.state.dmarc)
                    self.assertNotEqual(scenario.state.reply_to_mode, "absent")
                    self.assertNotEqual(scenario.state.return_path_mode, "absent")
                if coverage == "low":
                    self.assertIsNone(scenario.state.spf)
                    self.assertIsNone(scenario.state.dkim)
                    self.assertIsNone(scenario.state.dmarc)

    def test_rich_does_not_require_ip_punycode_or_risky_attachment(self) -> None:
        scenario = make_scenario("normal_authenticated", "rich", "legitimate", sample_id="rich-optional")
        self.assertTrue(scenario.state.is_rich())
        self.assertNotEqual(scenario.state.url_mode, "none")
        # Optional signals may be zero/false and still be evaluable.
        self.assertIn(scenario.state.url_mode, {"one", "several", "repeated", "ip", "punycode", "mixed"})
        self.assertEqual(scenario.state.attachment_mode, "none")


if __name__ == "__main__":
    unittest.main()
