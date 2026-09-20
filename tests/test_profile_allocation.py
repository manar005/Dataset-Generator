from __future__ import annotations

import unittest
from collections import Counter
from random import Random

from src.config import PROFILE_NAMES, V1_PROFILE_LABEL_COUNTS
from src.generator import assign_profiles
from src.profile_allocation import allocate_profile_counts
from tests.common import fixture_seed


class ProfileAllocationTests(unittest.TestCase):
    def test_one_thousand_matches_original_weights(self) -> None:
        for label in ("legitimate", "phishing"):
            allocated = allocate_profile_counts(1000, label)
            expected = {name: V1_PROFILE_LABEL_COUNTS[name][label] for name in PROFILE_NAMES}
            self.assertEqual(allocated, expected)
            self.assertEqual(sum(allocated.values()), 1000)
            self.assertTrue(all(value >= 1 for value in allocated.values()))

    def test_nine_hundred_sixteen_legitimate_largest_remainder(self) -> None:
        allocated = allocate_profile_counts(916, "legitimate")
        self.assertEqual(sum(allocated.values()), 916)
        self.assertEqual(
            allocated,
            {
                "normal_authenticated": 220,
                "third_party_service": 174,
                "partially_authenticated": 165,
                "authentication_problem": 119,
                "plain_basic": 146,
                "attachment_bearing": 92,
            },
        )
        self.assertTrue(all(value >= 1 for value in allocated.values()))

    def test_one_thousand_ninety_two_phishing_largest_remainder(self) -> None:
        allocated = allocate_profile_counts(1092, "phishing")
        self.assertEqual(sum(allocated.values()), 1092)
        self.assertEqual(
            allocated,
            {
                "normal_authenticated": 197,
                "third_party_service": 175,
                "partially_authenticated": 196,
                "authentication_problem": 240,
                "plain_basic": 153,
                "attachment_bearing": 131,
            },
        )
        self.assertTrue(all(value >= 1 for value in allocated.values()))

    def test_arbitrary_valid_count(self) -> None:
        allocated = allocate_profile_counts(777, "legitimate")
        self.assertEqual(sum(allocated.values()), 777)
        self.assertEqual(
            allocated,
            {
                "normal_authenticated": 186,
                "third_party_service": 148,
                "partially_authenticated": 140,
                "authentication_problem": 101,
                "plain_basic": 124,
                "attachment_bearing": 78,
            },
        )
        self.assertTrue(all(value >= 1 for value in allocated.values()))

    def test_nine_hundred_seventeen_legitimate_stage3b(self) -> None:
        allocated = allocate_profile_counts(917, "legitimate")
        self.assertEqual(sum(allocated.values()), 917)
        self.assertEqual(
            allocated,
            {
                "normal_authenticated": 220,
                "third_party_service": 174,
                "partially_authenticated": 165,
                "authentication_problem": 119,
                "plain_basic": 147,
                "attachment_bearing": 92,
            },
        )

    def test_one_thousand_eighty_six_phishing_stage3b(self) -> None:
        allocated = allocate_profile_counts(1086, "phishing")
        self.assertEqual(sum(allocated.values()), 1086)
        self.assertEqual(
            allocated,
            {
                "normal_authenticated": 196,
                "third_party_service": 174,
                "partially_authenticated": 195,
                "authentication_problem": 239,
                "plain_basic": 152,
                "attachment_bearing": 130,
            },
        )

    def test_allocation_is_deterministic_and_text_independent(self) -> None:
        first = allocate_profile_counts(916, "legitimate")
        second = allocate_profile_counts(916, "legitimate")
        self.assertEqual(first, second)
        self.assertEqual(first, allocate_profile_counts(916, "legitimate"))

    def test_tie_break_uses_stable_profile_order(self) -> None:
        # Two 180-weight phishing profiles share the same remainder at n=1092;
        # earlier PROFILE_NAMES order receives the leftover seat.
        allocated = allocate_profile_counts(1092, "phishing")
        self.assertGreater(allocated["normal_authenticated"], allocated["partially_authenticated"])

    def test_assign_profiles_scales_to_available_seeds(self) -> None:
        seeds = [fixture_seed(f"l{i}", "legitimate") for i in range(12)]
        seeds.extend(fixture_seed(f"p{i}", "phishing") for i in range(18))
        assigned = assign_profiles(seeds, Random(20260920))
        legit = Counter(profile for seed, profile in assigned if seed.label == "legitimate")
        phish = Counter(profile for seed, profile in assigned if seed.label == "phishing")
        self.assertEqual(dict(legit), allocate_profile_counts(12, "legitimate"))
        self.assertEqual(dict(phish), allocate_profile_counts(18, "phishing"))
        self.assertEqual(sum(legit.values()), 12)
        self.assertEqual(sum(phish.values()), 18)
        again = assign_profiles(seeds, Random(20260920))
        self.assertEqual(
            [(seed.seed_id, profile) for seed, profile in assigned],
            [(seed.seed_id, profile) for seed, profile in again],
        )


if __name__ == "__main__":
    unittest.main()
