from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from src.eml_builder import render_eml_bytes
from tests.common import make_scenario


def _parse(scenario):
    return BytesParser(policy=policy.compat32).parsebytes(render_eml_bytes(scenario))


class HeaderTests(unittest.TestCase):
    def test_optional_reply_to_present(self) -> None:
        scenario = make_scenario("normal_authenticated", "rich", sample_id="hdr-reply")
        message = _parse(scenario)
        self.assertTrue(message.get("Reply-To"))
        self.assertIsNotNone(scenario.reply_to_address)

    def test_missing_reply_to(self) -> None:
        scenario = make_scenario("plain_basic", "low", sample_id="hdr-noreply")
        message = _parse(scenario)
        self.assertFalse(message.get("Reply-To"))
        self.assertIsNone(scenario.reply_to_address)

    def test_return_path_match(self) -> None:
        scenario = make_scenario("normal_authenticated", "mostly_observable", sample_id="hdr-rp-match")
        self.assertEqual(scenario.state.return_path_mode, "match")
        self.assertIsNotNone(scenario.return_path_address)
        self.assertEqual(scenario.return_path_address.split("@", 1)[1], scenario.from_address.split("@", 1)[1])
        self.assertTrue(_parse(scenario).get("Return-Path"))

    def test_return_path_mismatch(self) -> None:
        scenario = make_scenario("third_party_service", "partial", sample_id="hdr-rp-mis")
        self.assertEqual(scenario.state.return_path_mode, "mismatch")
        self.assertNotEqual(scenario.return_path_address.split("@", 1)[1], scenario.from_address.split("@", 1)[1])

    def test_return_path_unavailable(self) -> None:
        scenario = make_scenario("plain_basic", "low", sample_id="hdr-rp-none")
        self.assertEqual(scenario.state.return_path_mode, "absent")
        self.assertIsNone(scenario.return_path_address)
        self.assertFalse(_parse(scenario).get("Return-Path"))

    def test_full_partial_and_no_auth(self) -> None:
        full = make_scenario("normal_authenticated", "rich", sample_id="hdr-auth-full")
        self.assertEqual((full.state.spf, full.state.dkim, full.state.dmarc), ("pass", "pass", "pass"))
        self.assertIn("spf=pass", str(_parse(full).get("Authentication-Results")))

        partial = make_scenario("partially_authenticated", "partial", sample_id="hdr-auth-part")
        present = [value for value in (partial.state.spf, partial.state.dkim, partial.state.dmarc) if value]
        self.assertGreaterEqual(len(present), 1)
        self.assertLess(len(present), 3)

        none = make_scenario("plain_basic", "low", sample_id="hdr-auth-none")
        message = _parse(none)
        self.assertIsNone(message.get("Authentication-Results"))
        self.assertIsNone(message.get("Received-SPF"))
        self.assertIsNone(none.state.spf)


if __name__ == "__main__":
    unittest.main()
