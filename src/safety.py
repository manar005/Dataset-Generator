# Reserved/test identity and URL policy. No network I/O.

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlparse

SAFE_ROOT_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "invalid",
)

SAFE_HOSTS = (
    "example.com",
    "example.org",
    "example.net",
    "mail.example.com",
    "mx.example.net",
    "docs.example.org",
    "files.example.net",
    "notices.example.com",
    "bounce.example.net",
    "list.example.org",
    "mail.invalid",
    "desk.invalid",
)

SAFE_LOCAL_PARTS = (
    "sender",
    "notices",
    "desk",
    "mailer",
    "bounce",
    "list",
    "office",
)

SAFE_DISPLAY_NAMES = (
    "Office Notices",
    "Mail Desk",
    "List Service",
    "Example Sender",
    "Notice Robot",
)

DOCUMENTATION_IPV4_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)

DOCUMENTATION_IPV4_HOSTS = (
    "192.0.2.10",
    "192.0.2.80",
    "198.51.100.20",
    "203.0.113.40",
)

# Harmless ACE labels only. Not real-brand IDN.
SAFE_PUNYCODE_HOSTS = (
    "xn--testdata.example.com",
    "docs.xn--exampl-gva.example.net",
    "xn--c1yn36f.example.org",
)

SAFE_URL_PATHS = (
    "/info",
    "/docs/item",
    "/notice",
    "/file",
    "/status",
)

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_LIVE_URL_RE = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"\{\{URL\}\}|\[URL\]|%URL%", re.IGNORECASE)


def is_safe_domain(domain: str) -> bool:
    host = domain.strip().lower().rstrip(".")
    if not host:
        return False
    if host in SAFE_HOSTS or host in SAFE_PUNYCODE_HOSTS:
        return True
    if _is_documentation_ip(host):
        return True
    return any(host == root or host.endswith("." + root) for root in SAFE_ROOT_DOMAINS)


def _is_documentation_ip(host: str) -> bool:
    candidate = host.strip("[]")
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return any(addr in network for network in DOCUMENTATION_IPV4_NETWORKS)


def is_safe_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    host = parsed.hostname
    if not host:
        return False
    return is_safe_domain(host)


def is_safe_email_address(address: str) -> bool:
    cleaned = address.strip().lower()
    if "@" not in cleaned:
        return False
    domain = cleaned.rsplit("@", 1)[1]
    return is_safe_domain(domain)


def extract_raw_urls(text: str) -> list[str]:
    if not text:
        return []
    return _URL_RE.findall(text)


def extract_live_url_candidates(text: str) -> list[str]:
    if not text:
        return []
    return _LIVE_URL_RE.findall(text)


def _candidate_as_url(raw: str) -> str:
    if raw.lower().startswith(("http://", "https://")):
        return raw
    return "http://" + raw


def is_live_operational_url(raw: str) -> bool:
    """True when a match is a non-reserved http(s)/www URL that must be rewritten."""
    return not is_safe_url(_candidate_as_url(raw))


def safe_replacement_for_url(raw: str) -> str:
    """Deterministic reserved URL. Same original string always maps to the same replacement."""
    digest = hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"https://docs.example.com/item/{digest}"


def replace_live_urls(text: str) -> str:
    """Replace live operational URLs only. Placeholders such as [URL] are left unchanged.

    The same function is used for every label.
    """
    if not text:
        return text

    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        if is_live_operational_url(raw):
            return safe_replacement_for_url(raw)
        return raw

    return _LIVE_URL_RE.sub(repl, text)


def remove_live_urls(text: str) -> str:
    """Remove live operational URLs without inserting replacements.

    Placeholders such as [URL] are left unchanged here; seed-prep placeholder
    cleanup removes those tokens separately. The same function is used for every label.
    """
    if not text:
        return text

    def repl(match: re.Match[str]) -> str:
        raw = match.group(0)
        if is_live_operational_url(raw):
            return ""
        return raw

    return _LIVE_URL_RE.sub(repl, text)


def normalize_seed_urls(text: str, replacements: list[str] | None) -> str:
    """Replace live/placeholder URLs using the same rule for every label.

    If replacements is empty or None, URLs and placeholders are removed so a
    no-URL technical state stays coherent. Replacements cycle if shorter than
    the number of matches.
    """
    if not text:
        return text
    queue = list(replacements or [])
    index = 0

    def next_url(_match: re.Match[str] | None = None) -> str:
        nonlocal index
        if not queue:
            return ""
        value = queue[index % len(queue)]
        index += 1
        return value

    updated = _PLACEHOLDER_RE.sub(lambda _m: next_url(), text)
    updated = _URL_RE.sub(lambda _m: next_url(), updated)
    updated = re.sub(r"[ \t]{2,}", " ", updated)
    return updated.strip()
