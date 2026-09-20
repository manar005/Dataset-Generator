from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser

from src.config import INERT_ATTACHMENT_PAYLOAD
from src.eml_builder import render_eml_bytes
from tests.common import make_scenario, scenario_matching


class AttachmentTests(unittest.TestCase):
    def test_no_attachment(self) -> None:
        scenario = make_scenario("plain_basic", "low", sample_id="att-none")
        self.assertEqual(scenario.state.attachment_mode, "none")
        message = BytesParser(policy=policy.compat32).parsebytes(render_eml_bytes(scenario))
        filenames = [part.get_filename() for part in message.walk() if part.get_filename()]
        self.assertEqual(filenames, [])

    def test_harmless_ordinary_attachment(self) -> None:
        scenario = scenario_matching(
            "attachment_bearing",
            "low",
            lambda item: item.state.attachment_mode == "ordinary",
        )
        message = BytesParser(policy=policy.compat32).parsebytes(render_eml_bytes(scenario))
        payloads = []
        names = []
        for part in message.walk():
            filename = part.get_filename()
            if not filename:
                continue
            names.append(filename)
            payloads.append(part.get_payload(decode=True))
        self.assertTrue(any(name.endswith(".txt") or name.endswith(".csv") for name in names))
        self.assertIn(INERT_ATTACHMENT_PAYLOAD, payloads)

    def test_risky_filename_inert_payload(self) -> None:
        scenario = scenario_matching(
            "attachment_bearing",
            "partial",
            lambda item: item.state.attachment_mode == "risky",
        )
        raw = render_eml_bytes(scenario)
        self.assertFalse(raw.lstrip().startswith(b"MZ"))
        self.assertNotIn(b"\x7fELF", raw)
        message = BytesParser(policy=policy.compat32).parsebytes(raw)
        names = []
        payloads = []
        for part in message.walk():
            filename = part.get_filename()
            if not filename:
                continue
            names.append(filename)
            payloads.append(part.get_payload(decode=True))
        self.assertTrue(any(name.endswith((".js", ".hta", ".docm")) for name in names))
        self.assertIn(INERT_ATTACHMENT_PAYLOAD, payloads)


if __name__ == "__main__":
    unittest.main()
