from __future__ import annotations

import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from random import Random
from tempfile import TemporaryDirectory

from src.eml_builder import render_eml_bytes, write_eml
from src.scenarios import assemble_scenario
from src.validator import validate_eml_file
from tests.common import fixture_seed, make_scenario


class FormatTests(unittest.TestCase):
    def _message(self, scenario):
        return BytesParser(policy=policy.compat32).parsebytes(render_eml_bytes(scenario))

    def test_plain_text(self) -> None:
        scenario = make_scenario("plain_basic", "low", sample_id="fmt-plain")
        self.assertEqual(scenario.state.body_format, "plain")
        message = self._message(scenario)
        self.assertIn("text/plain", (message.get_content_type() or "").lower())

    def test_html(self) -> None:
        from tests.common import scenario_matching

        scenario = scenario_matching("third_party_service", "partial", lambda item: item.state.body_format == "html")
        raw = render_eml_bytes(scenario).decode("utf-8", errors="replace").lower()
        self.assertIn("text/html", raw)

    def test_multipart(self) -> None:
        scenario = make_scenario("normal_authenticated", "rich", sample_id="fmt-multi")
        message = self._message(scenario)
        self.assertTrue(message.is_multipart() or scenario.state.body_format == "plain")
        alt = make_scenario("normal_authenticated", "mostly_observable", sample_id="fmt-alt")
        # Force a known multipart by using attachment-bearing rich if needed.
        attached = make_scenario("attachment_bearing", "rich", sample_id="fmt-mixed")
        mixed = self._message(attached)
        self.assertTrue(mixed.is_multipart())
        self.assertIn("multipart", (mixed.get_content_type() or "").lower())

    def test_empty_subject_is_allowed(self) -> None:
        seed = fixture_seed("empty-sub", "legitimate", subject="", body="Body text remains after an empty subject.")
        scenario = assemble_scenario(
            seed,
            "plain_basic",
            Random(1),
            coverage="low",
            sample_id="empty-sub",
            random_seed=1,
        )
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty-sub.eml"
            write_eml(scenario, path)
            validate_eml_file(path)


if __name__ == "__main__":
    unittest.main()
