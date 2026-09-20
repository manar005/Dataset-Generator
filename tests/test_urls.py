from __future__ import annotations

import re
import unittest
from email import policy
from email.parser import BytesParser

from src.eml_builder import render_eml_bytes
from src.safety import is_safe_url, normalize_seed_urls
from src.url_render import ANCHOR_LABELS, url_occurrences
from tests.common import make_scenario


def _parts(scenario):
    message = BytesParser(policy=policy.default).parsebytes(render_eml_bytes(scenario))
    plain = ""
    html = ""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype == "text/plain" and not plain:
                plain = part.get_content()
            elif ctype == "text/html":
                html = part.get_content()
    else:
        if message.get_content_type() == "text/plain":
            plain = message.get_content()
        elif message.get_content_type() == "text/html":
            html = message.get_content()
    if not isinstance(plain, str):
        plain = str(plain or "")
    if not isinstance(html, str):
        html = str(html or "")
    return plain, html


def _visible_html_text(html: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", without_tags)


class UrlTests(unittest.TestCase):
    def test_zero_urls(self) -> None:
        scenario = make_scenario("plain_basic", "low", sample_id="url-zero", url_mode_override="none")
        self.assertEqual(scenario.urls, [])
        self.assertEqual(scenario.logical_url_count, 0)
        self.assertEqual(scenario.url_rendering_mode, "none")
        self.assertNotIn("http://", scenario.body_text)
        self.assertNotIn("https://", scenario.body_text)
        plain, html = _parts(scenario)
        self.assertFalse(re.findall(r"https?://", plain))
        self.assertFalse(re.findall(r"https?://", html))

    def test_one_url_plain(self) -> None:
        scenario = make_scenario(
            "plain_basic",
            "partial",
            sample_id="url-one-plain",
            url_mode_override="one",
            body_format_override="plain",
        )
        self.assertEqual(len(scenario.urls), 1)
        self.assertEqual(scenario.url_rendering_mode, "plain")
        self.assertNotIn(scenario.urls[0], scenario.body_text)
        plain, html = _parts(scenario)
        self.assertEqual(url_occurrences(plain, scenario.urls[0]), 1)
        self.assertFalse(html)

    def test_one_url_html(self) -> None:
        scenario = make_scenario(
            "third_party_service",
            "rich",
            sample_id="url-one-html",
            url_mode_override="one",
            body_format_override="html",
        )
        self.assertEqual(scenario.url_rendering_mode, "html")
        url = scenario.urls[0]
        plain, html = _parts(scenario)
        self.assertEqual(url_occurrences(plain, url), 0)
        self.assertEqual(html.count(f'href="{url}"'), 1)
        self.assertNotIn(url, _visible_html_text(html))
        self.assertTrue(any(label in html for label in ANCHOR_LABELS))

    def test_one_url_multipart_alternative(self) -> None:
        scenario = make_scenario(
            "normal_authenticated",
            "rich",
            sample_id="url-one-alt",
            url_mode_override="one",
            body_format_override="alternative",
        )
        self.assertEqual(scenario.url_rendering_mode, "alternative")
        url = scenario.urls[0]
        plain, html = _parts(scenario)
        self.assertEqual(url_occurrences(plain, url), 1)
        self.assertEqual(html.count(f'href="{url}"'), 1)
        self.assertNotIn(url, _visible_html_text(html))

    def test_three_urls_plain(self) -> None:
        scenario = make_scenario(
            "authentication_problem",
            "rich",
            sample_id="url-three-plain",
            url_mode_override="several",
            body_format_override="plain",
        )
        self.assertEqual(len(scenario.urls), 3)
        self.assertEqual(scenario.logical_unique_url_count, 3)
        plain, _html = _parts(scenario)
        for url in scenario.urls:
            self.assertEqual(url_occurrences(plain, url), 1)

    def test_three_urls_html(self) -> None:
        scenario = make_scenario(
            "third_party_service",
            "rich",
            sample_id="url-three-html",
            url_mode_override="several",
            body_format_override="html",
        )
        plain, html = _parts(scenario)
        for url in scenario.urls:
            self.assertEqual(url_occurrences(plain, url), 0)
            self.assertEqual(html.count(f'href="{url}"'), 1)
            self.assertNotIn(url, _visible_html_text(html))

    def test_three_urls_multipart_alternative(self) -> None:
        scenario = make_scenario(
            "normal_authenticated",
            "rich",
            sample_id="url-three-alt",
            url_mode_override="several",
            body_format_override="alternative",
        )
        self.assertEqual(len(scenario.urls), 3)
        plain, html = _parts(scenario)
        for url in scenario.urls:
            self.assertEqual(url_occurrences(plain, url), 1)
            self.assertEqual(html.count(f'href="{url}"'), 1)
            self.assertNotIn(url, _visible_html_text(html))

    def test_repeated_logical_url(self) -> None:
        scenario = make_scenario(
            "normal_authenticated",
            "rich",
            sample_id="url-repeat",
            url_mode_override="repeated",
            body_format_override="plain",
        )
        self.assertEqual(len(scenario.urls), 2)
        self.assertEqual(scenario.logical_unique_url_count, 1)
        self.assertEqual(scenario.urls[0], scenario.urls[1])
        plain, _html = _parts(scenario)
        self.assertEqual(url_occurrences(plain, scenario.urls[0]), 2)

    def test_unique_url_count_preservation(self) -> None:
        several = make_scenario(
            "normal_authenticated",
            "rich",
            sample_id="url-unique-several",
            url_mode_override="several",
        )
        self.assertEqual(several.logical_unique_url_count, len(set(several.urls)))
        repeated = make_scenario(
            "normal_authenticated",
            "rich",
            sample_id="url-unique-repeat",
            url_mode_override="repeated",
        )
        self.assertEqual(repeated.logical_unique_url_count, 1)

    def test_safe_ip_host_url(self) -> None:
        scenario = make_scenario("third_party_service", "rich", sample_id="url-ip", url_mode_override="ip")
        self.assertEqual(len(scenario.urls), 1)
        self.assertRegex(scenario.urls[0], r"https?://(192\.0\.2\.|198\.51\.100\.|203\.0\.113\.)")
        raw = render_eml_bytes(scenario).decode("utf-8", errors="replace")
        self.assertIn(scenario.urls[0], raw)

    def test_safe_punycode_url(self) -> None:
        scenario = make_scenario("normal_authenticated", "rich", sample_id="url-ace", url_mode_override="punycode")
        self.assertEqual(len(scenario.urls), 1)
        self.assertIn("xn--", scenario.urls[0])
        self.assertTrue(is_safe_url(scenario.urls[0]))

    def test_no_duplicate_generic_url_block(self) -> None:
        scenario = make_scenario(
            "plain_basic",
            "partial",
            sample_id="url-no-dup-block",
            url_mode_override="one",
            body_format_override="plain",
        )
        url = scenario.urls[0]
        self.assertNotIn(url, scenario.body_text)
        plain, _html = _parts(scenario)
        self.assertEqual(url_occurrences(plain, url), 1)
        self.assertEqual(plain.count(url + "\n" + url), 0)

    def test_html_anchor_uses_descriptive_text(self) -> None:
        scenario = make_scenario(
            "third_party_service",
            "rich",
            sample_id="url-anchor",
            url_mode_override="one",
            body_format_override="html",
        )
        url = scenario.urls[0]
        _plain, html = _parts(scenario)
        self.assertIn(f'href="{url}"', html)
        self.assertNotIn(f">{url}<", html)
        self.assertTrue(any(f">{label}<" in html for label in ANCHOR_LABELS))

    def test_url_rewrite_is_label_agnostic(self) -> None:
        text = "See https://not-a-safe-live.example.invalid/x and {{URL}}"
        legit = normalize_seed_urls(text, ["https://docs.example.com/info"])
        phish = normalize_seed_urls(text, ["https://docs.example.com/info"])
        self.assertEqual(legit, phish)
        self.assertNotIn("not-a-safe-live", legit)

    def test_normal_url(self) -> None:
        scenario = make_scenario("normal_authenticated", "rich", sample_id="url-one", url_mode_override="one")
        self.assertEqual(len(scenario.urls), 1)
        self.assertTrue(is_safe_url(scenario.urls[0]))
        self.assertIn("example.", scenario.urls[0])
        self.assertNotIn(scenario.urls[0], scenario.body_text)

    def test_multiple_urls(self) -> None:
        scenario = make_scenario("normal_authenticated", "rich", sample_id="url-many", url_mode_override="several")
        self.assertGreaterEqual(len(scenario.urls), 3)
        self.assertTrue(all(is_safe_url(url) for url in scenario.urls))
        self.assertTrue(all(url not in scenario.body_text for url in scenario.urls))


if __name__ == "__main__":
    unittest.main()
