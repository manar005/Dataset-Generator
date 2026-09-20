from __future__ import annotations

import socket
import unittest
from urllib.parse import urlparse

from src.eml_builder import render_eml_bytes
from src.safety import DOCUMENTATION_IPV4_NETWORKS, is_safe_domain, is_safe_url
from src.validator import validate_eml_file
from tests.common import make_scenario, scenario_matching
import ipaddress
import tempfile
from pathlib import Path


class SafetyTests(unittest.TestCase):
    def test_reserved_domains_and_documentation_ips(self) -> None:
        scenarios = [
            make_scenario("normal_authenticated", "rich", sample_id="safe-1"),
            make_scenario("third_party_service", "rich", sample_id="safe-2", url_mode_override="ip"),
            make_scenario("plain_basic", "low", sample_id="safe-3"),
            scenario_matching("attachment_bearing", "partial", lambda item: True),
        ]
        for scenario in scenarios:
            self.assertTrue(is_safe_domain(scenario.from_address.split("@", 1)[1]))
            if scenario.reply_to_address:
                self.assertTrue(is_safe_domain(scenario.reply_to_address.split("@", 1)[1]))
            if scenario.return_path_address:
                self.assertTrue(is_safe_domain(scenario.return_path_address.split("@", 1)[1]))
            for url in scenario.urls:
                self.assertTrue(is_safe_url(url))
                host = urlparse(url).hostname
                self.assertIsNotNone(host)
                try:
                    addr = ipaddress.ip_address(host)
                    self.assertTrue(any(addr in network for network in DOCUMENTATION_IPV4_NETWORKS))
                except ValueError:
                    self.assertTrue(is_safe_domain(host))

    def test_no_network_calls_during_build(self) -> None:
        original = socket.socket

        def blocked(*_args, **_kwargs):
            raise AssertionError("Network socket opened during generation")

        socket.socket = blocked  # type: ignore[assignment]
        try:
            render_eml_bytes(make_scenario("third_party_service", "rich", sample_id="safe-net"))
        finally:
            socket.socket = original

    def test_no_executable_payload(self) -> None:
        raw = render_eml_bytes(
            scenario_matching("attachment_bearing", "rich", lambda item: item.state.attachment_mode in {"ordinary", "risky"})
        )
        self.assertFalse(raw.lstrip().startswith(b"MZ"))
        self.assertNotIn(b"\x7fELF", raw)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.eml"
            path.write_bytes(raw)
            validate_eml_file(path)


if __name__ == "__main__":
    unittest.main()
