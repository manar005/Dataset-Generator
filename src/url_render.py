# Single label-blind URL rendering path. Provenance/rendering only, not model features.

from __future__ import annotations

import html
import re

from src.safety import normalize_seed_urls

ANCHOR_LABELS = (
    "View details",
    "More information",
    "Open notice",
)

_RAW_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def seed_prose_without_urls(text: str) -> str:
    """Strip leftover URL tokens from seed prose. Does not insert generator URLs."""
    return normalize_seed_urls(text, [])


def logical_url_count(urls: list[str]) -> int:
    return len(urls)


def logical_unique_url_count(urls: list[str]) -> int:
    return len(dict.fromkeys(urls))


def url_rendering_mode(body_format: str, urls: list[str]) -> str:
    """How the builder should place the logical URL list. Independent of label."""
    if not urls:
        return "none"
    if body_format == "plain":
        return "plain"
    if body_format == "html":
        return "html"
    return "alternative"


def render_plain_url_block(urls: list[str]) -> str:
    """At most one generated occurrence per logical URL entry in the plain part."""
    if not urls:
        return ""
    lines = [f"{ANCHOR_LABELS[index % len(ANCHOR_LABELS)]}: {url}" for index, url in enumerate(urls)]
    return "\n" + "\n".join(lines)


def render_html_url_block(urls: list[str]) -> str:
    """One href per logical URL with descriptive anchor text, not the raw URL."""
    if not urls:
        return ""
    parts = []
    for index, url in enumerate(urls):
        label = ANCHOR_LABELS[index % len(ANCHOR_LABELS)]
        href = html.escape(url, quote=True)
        parts.append(f"<p><a href=\"{href}\">{html.escape(label)}</a></p>")
    return "".join(parts)


def url_occurrences(text: str, url: str) -> int:
    if not text or not url:
        return 0
    return len(re.findall(re.escape(url), text))


def raw_url_strings(text: str) -> list[str]:
    if not text:
        return []
    return _RAW_URL_RE.findall(text)
