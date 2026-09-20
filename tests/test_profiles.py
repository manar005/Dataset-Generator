from __future__ import annotations

import unittest

from tests.common import make_scenario

from src.profiles import (
    all_profile_names,
    allowed_coverage,
    allowed_states,
    assert_state_coherent,
    catalog_supports_both_labels,
    profile_supports_label,
    sample_state,
)
from src.config import LABELS
from random import Random


class ProfileTests(unittest.TestCase):
    def test_all_six_profiles_exist(self) -> None:
        self.assertEqual(
            all_profile_names(),
            (
                "normal_authenticated",
                "third_party_service",
                "partially_authenticated",
                "authentication_problem",
                "plain_basic",
                "attachment_bearing",
            ),
        )

    def test_every_profile_supports_both_labels(self) -> None:
        self.assertTrue(catalog_supports_both_labels())
        for profile in all_profile_names():
            for label in LABELS:
                self.assertTrue(profile_supports_label(profile, label))
                coverage = allowed_coverage(profile)[0]
                legit = make_scenario(profile, coverage, "legitimate", sample_id=f"{profile}-leg")
                phish = make_scenario(profile, coverage, "phishing", sample_id=f"{profile}-phs")
                self.assertEqual(legit.profile, phish.profile)
                self.assertNotEqual(legit.label, phish.label)
                self.assertEqual(legit.label, legit.seed.label)
                self.assertEqual(phish.label, phish.seed.label)

    def test_profile_states_are_coherent(self) -> None:
        rng = Random(11)
        for profile in all_profile_names():
            for coverage in allowed_coverage(profile):
                for state in allowed_states(profile, coverage):
                    assert_state_coherent(profile, coverage, state)
                sample_state(profile, coverage, rng)

    def test_profile_does_not_determine_label(self) -> None:
        for profile in all_profile_names():
            coverage = allowed_coverage(profile)[0]
            a = make_scenario(profile, coverage, "legitimate", sample_id="a")
            b = make_scenario(profile, coverage, "phishing", sample_id="b")
            self.assertEqual(a.state.spf, b.state.spf)
            self.assertEqual(a.profile, b.profile)
            self.assertNotEqual(a.label, b.label)

    def test_normal_authenticated_never_fails_spf(self) -> None:
        for coverage in allowed_coverage("normal_authenticated"):
            for state in allowed_states("normal_authenticated", coverage):
                self.assertEqual(state.spf, "pass")
                self.assertEqual(state.dkim, "pass")
                self.assertEqual(state.dmarc, "pass")


if __name__ == "__main__":
    unittest.main()
