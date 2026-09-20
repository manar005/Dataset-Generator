# Build local RFC822 / .eml files from scenarios. Never sends mail.

from __future__ import annotations

import hashlib
import html
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.policy import default
from pathlib import Path

from src.config import INERT_ATTACHMENT_PAYLOAD
from src.safety import DOCUMENTATION_IPV4_HOSTS, SAFE_HOSTS
from src.scenarios import GenerationScenario
from src.url_render import render_html_url_block, render_plain_url_block

FIXED_CLOCK = datetime(2026, 9, 20, 8, 0, tzinfo=timezone.utc)


def _format_address(template_pattern: str, address: str, display: str | None) -> str:
    return template_pattern.format(address=address, display=display or "Mail Desk")


def _auth_tokens(scenario: GenerationScenario) -> str:
    parts = []
    if scenario.state.spf is not None:
        parts.append(f"spf={scenario.state.spf} smtp.mailfrom={scenario.from_address.split('@', 1)[1]}")
    if scenario.state.dkim is not None:
        parts.append(f"dkim={scenario.state.dkim} header.d={scenario.from_address.split('@', 1)[1]}")
    if scenario.state.dmarc is not None:
        parts.append(f"dmarc={scenario.state.dmarc} action=none")
    return "; ".join(parts)


def _received_headers(scenario: GenerationScenario) -> list[str]:
    headers = []
    template = scenario.templates.received_template.pattern
    for index in range(scenario.state.received_count):
        stamp = FIXED_CLOCK + timedelta(minutes=index)
        date = stamp.strftime("%a, %d %b %Y %H:%M:%S %z")
        headers.append(
            template.format(
                helo=SAFE_HOSTS[index % len(SAFE_HOSTS)],
                ip=DOCUMENTATION_IPV4_HOSTS[index % len(DOCUMENTATION_IPV4_HOSTS)],
                mx="mx.example.net",
                rid=f"DEV{index:04d}",
                rcpt=scenario.recipient_address,
                date=date,
            )
        )
    return headers


def _url_plain_block(scenario: GenerationScenario) -> str:
    if scenario.url_rendering_mode not in {"plain", "alternative"}:
        return ""
    return render_plain_url_block(scenario.urls)


def _url_html_block(scenario: GenerationScenario) -> str:
    if scenario.url_rendering_mode not in {"html", "alternative"}:
        return ""
    return render_html_url_block(scenario.urls)


def _plain_body(scenario: GenerationScenario) -> str:
    return scenario.templates.plain_body_template.pattern.format(
        body=scenario.body_text,
        url_block=_url_plain_block(scenario),
    ).strip()


def _html_body(scenario: GenerationScenario) -> str:
    escaped = html.escape(scenario.body_text)
    escaped = escaped.replace("\n", "<br>\n")
    return scenario.templates.html_body_template.pattern.format(
        body_html=escaped,
        url_block=_url_html_block(scenario),
    )


def build_message(scenario: GenerationScenario) -> EmailMessage:
    message = EmailMessage(policy=default)
    message["Subject"] = scenario.seed.subject
    message["From"] = _format_address(
        scenario.templates.from_template.pattern,
        scenario.from_address,
        scenario.from_display,
    )
    message["To"] = scenario.recipient_address
    message["Date"] = FIXED_CLOCK.strftime("%a, %d %b %Y %H:%M:%S %z")
    token = hashlib.sha1(scenario.sample_id.encode("utf-8")).hexdigest()[:12]
    message["Message-ID"] = f"<{token}@example.com>"
    message["MIME-Version"] = "1.0"

    if scenario.reply_to_address and scenario.templates.reply_to_template:
        message["Reply-To"] = _format_address(
            scenario.templates.reply_to_template.pattern,
            scenario.reply_to_address,
            scenario.reply_to_display,
        )
    if scenario.return_path_address and scenario.templates.return_path_template:
        message["Return-Path"] = scenario.templates.return_path_template.pattern.format(
            address=scenario.return_path_address
        )

    for received in _received_headers(scenario):
        message.add_header("Received", received)

    tokens = _auth_tokens(scenario)
    if tokens and scenario.templates.auth_results_template:
        message["Authentication-Results"] = scenario.templates.auth_results_template.pattern.format(
            authserv="mx.example.net",
            tokens=tokens,
        )
    if scenario.state.include_received_spf and scenario.state.spf and scenario.templates.received_spf_template:
        domain = scenario.from_address.split("@", 1)[1]
        message["Received-SPF"] = scenario.templates.received_spf_template.pattern.format(
            result=scenario.state.spf,
            domain=domain,
            ip=DOCUMENTATION_IPV4_HOSTS[0],
            mailfrom=scenario.from_address,
            detail="documentation test token",
        )

    plain = _plain_body(scenario)
    html_body = _html_body(scenario)
    fmt = scenario.state.body_format
    if fmt == "plain":
        message.set_content(plain, subtype="plain")
    else:
        # Always keep a text/plain part so the frozen Agent body_plain field
        # receives the seed text. HTML-only parts are otherwise dropped.
        message.set_content(plain, subtype="plain")
        message.add_alternative(html_body, subtype="html")

    if scenario.state.attachment_mode != "none":
        filename = (
            scenario.templates.attachment_name_template.pattern
            if scenario.templates.attachment_name_template
            else "notes.txt"
        )
        message.add_attachment(
            INERT_ATTACHMENT_PAYLOAD,
            maintype="application",
            subtype="octet-stream",
            filename=filename,
        )
    return message


def render_eml_bytes(scenario: GenerationScenario) -> bytes:
    return build_message(scenario).as_bytes(policy=default)


def write_eml(scenario: GenerationScenario, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_eml_bytes(scenario))
    return path
