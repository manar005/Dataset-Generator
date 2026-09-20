# Generator-side structural and safety validation. Not Agent feature extraction.

from __future__ import annotations

import csv
from collections import Counter
from email import policy
from email.parser import BytesParser
from pathlib import Path

from src.config import INERT_ATTACHMENT_PAYLOAD
from src.safety import extract_raw_urls, is_safe_domain, is_safe_email_address, is_safe_url

EXECUTABLE_MAGIC = (b"MZ", b"\x7fELF")


class ValidationError(Exception):
    pass


def _load_manifest(path: Path) -> list[dict[str, str]]:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _require_headers(message) -> None:
    if not message.get("From"):
        raise ValidationError("Missing required header From")
    # Real seeds may have an empty subject. Do not invent a subject to satisfy RFC cosmetics.


def _walk_payloads(message):
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                continue
            yield part
        return
    yield message


def _check_safe_identities(message) -> None:
    for header in ("From", "To", "Reply-To", "Return-Path"):
        values = message.get_all(header, [])
        for raw in values:
            text = str(raw)
            if "@" not in text:
                continue
            start = text.find("<")
            end = text.find(">")
            address = text[start + 1 : end] if start >= 0 and end > start else text
            address = address.strip().strip("<>")
            if address and not is_safe_email_address(address):
                raise ValidationError(f"Unsafe address in {header}: {address}")
    for raw in message.get_all("Received", []):
        text = str(raw).lower()
        for token in text.replace("(", " ").replace(")", " ").replace("[", " ").replace("]", " ").split():
            if "." in token and not token.endswith(";") and "@" not in token:
                host = token.strip(".,;")
                if host.replace(".", "").isdigit() or host.endswith("example.com") or host.endswith("example.net") or host.endswith("example.org") or host.endswith(".invalid"):
                    continue
                if any(host.endswith(sfx) for sfx in (".com", ".net", ".org")) and not is_safe_domain(host):
                    raise ValidationError(f"Unsafe host in Received: {host}")


def _check_urls_in_text(text: str) -> None:
    for url in extract_raw_urls(text or ""):
        if not is_safe_url(url):
            raise ValidationError(f"Live or unsafe URL in message: {url}")


def _check_attachments(message) -> None:
    for part in _walk_payloads(message):
        filename = part.get_filename()
        payload = part.get_payload(decode=True)
        if filename is None and part.get_content_disposition() != "attachment":
            continue
        if payload is None:
            continue
        if any(payload.startswith(magic) for magic in EXECUTABLE_MAGIC):
            raise ValidationError("Unexpected executable payload")
        if b"\x00" in payload[:16] and payload not in {INERT_ATTACHMENT_PAYLOAD}:
            raise ValidationError("Unexpected binary payload")
        if payload != INERT_ATTACHMENT_PAYLOAD and part.get_content_disposition() == "attachment":
            text = payload.decode("utf-8", errors="replace")
            if "<html" in text.lower() and "javascript" in text.lower():
                raise ValidationError("Attachment payload looks active")


def validate_eml_file(path: Path) -> None:
    path = Path(path)
    if not path.is_file():
        raise ValidationError(f"Missing file {path}")
    data = path.read_bytes()
    if not data.strip():
        raise ValidationError(f"Empty file {path}")
    try:
        message = BytesParser(policy=policy.compat32).parsebytes(data)
    except Exception as exc:
        raise ValidationError(f"RFC822 load failed for {path}: {exc}") from exc
    _require_headers(message)
    if message.is_multipart() and not list(message.iter_attachments() if hasattr(message, "iter_attachments") else []):
        if not any(not part.is_multipart() for part in message.walk()):
            raise ValidationError(f"Broken MIME structure in {path}")
    _check_safe_identities(message)
    for part in _walk_payloads(message):
        payload = part.get_payload(decode=True)
        if payload:
            _check_urls_in_text(payload.decode("utf-8", errors="replace"))
    _check_attachments(message)


def validate_corpus(output_dir: Path, *, unique_seeds: bool = True) -> dict:
    output_dir = Path(output_dir)
    manifest_path = output_dir / "manifest.csv"
    if not manifest_path.is_file():
        raise ValidationError("manifest.csv is missing")
    rows = _load_manifest(manifest_path)
    if not rows:
        raise ValidationError("manifest.csv is empty")
    sample_ids = [row["sample_id"] for row in rows]
    if len(sample_ids) != len(set(sample_ids)):
        raise ValidationError("Duplicate sample_id in manifest")
    seed_ids = [row["content_seed_id"] for row in rows]
    if unique_seeds and len(seed_ids) != len(set(seed_ids)):
        raise ValidationError("Duplicate content_seed_id where v1 expects uniqueness")
    for row in rows:
        for field in ("sample_id", "label", "content_seed_id", "profile", "is_simulated", "random_seed"):
            if not row.get(field):
                raise ValidationError(f"Manifest row missing {field}")
        if row["is_simulated"] != "true":
            raise ValidationError("Generated mail must set is_simulated=true")
        rel = row.get("filename")
        if not rel:
            raise ValidationError("Manifest row missing filename")
        path = output_dir / "emails" / rel
        if not path.is_file():
            raise ValidationError(f"Manifest references missing file {rel}")
        validate_eml_file(path)
        expected_parent = row["label"]
        if expected_parent not in Path(rel).parts:
            raise ValidationError(f"File path {rel} does not match label {row['label']}")
    return {
        "ok": True,
        "count": len(rows),
        "labels": dict(Counter(row["label"] for row in rows)),
        "profiles": dict(Counter(row["profile"] for row in rows)),
    }
