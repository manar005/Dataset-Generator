from __future__ import annotations

import unittest
from random import Random

from src.profiles import sample_state
from tests.common import make_scenario


class ReproducibilityTests(unittest.TestCase):
    def test_same_seed_same_scenario_choices(self) -> None:
        a = make_scenario("authentication_problem", "rich", "phishing", random_seed=42, sample_id="rep-a")
        b = make_scenario("authentication_problem", "rich", "phishing", random_seed=42, sample_id="rep-a")
        self.assertEqual(a.state, b.state)
        self.assertEqual(a.from_address, b.from_address)
        self.assertEqual(a.urls, b.urls)
        self.assertEqual(a.templates.header_template_id, b.templates.header_template_id)

    def test_different_seed_can_vary_allowed_choices(self) -> None:
        states = {sample_state("authentication_problem", "rich", Random(seed)) for seed in range(40)}
        self.assertGreater(len(states), 1)
        first = make_scenario("attachment_bearing", "rich", random_seed=1, sample_id="d1")
        second = make_scenario("attachment_bearing", "rich", random_seed=99, sample_id="d2")
        differed = (
            first.state != second.state
            or first.from_address != second.from_address
            or first.templates.header_template_id != second.templates.header_template_id
        )
        self.assertTrue(differed)


if __name__ == "__main__":
    unittest.main()
