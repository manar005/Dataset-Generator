# Agent-backed quality analysis. Does not copy Agent extraction logic.

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

EMAIL_FEATURE_FIELDS = (
    "subject",
    "body_plain",
    "header_spf_result",
    "header_dkim_result",
    "header_dmarc_result",
    "has_reply_to",
    "from_reply_to_address_mismatch",
    "from_reply_to_domain_mismatch",
    "from_return_path_domain_mismatch",
    "num_received_headers",
    "url_count",
    "unique_url_count",
    "url_length_max",
    "ip_url_count",
    "punycode_url_count",
    "attachment_count",
    "has_risky_attachment",
    "has_html",
)

AUTH_FIELDS = ("header_spf_result", "header_dkim_result", "header_dmarc_result")
_AGENT_HOLD: list[object] = []


def default_agent_path() -> Path:
    return Path(__file__).resolve().parents[2] / "AI-Phishing-Agent"


def load_agent_pipeline(agent_root: Path | None = None):
    """Import the frozen Agent modules without replacing Dataset-Generator's src package."""
    agent_root = Path(agent_root or default_agent_path()).resolve()
    if not (agent_root / "src" / "feature_extractor.py").is_file():
        raise FileNotFoundError(f"AI-Phishing-Agent not found at {agent_root}")

    saved = {key: sys.modules.pop(key) for key in list(sys.modules) if key == "src" or key.startswith("src.")}
    sys.path.insert(0, str(agent_root))
    try:
        from src.email_parser import parse_email
        from src.feature_extractor import extract_features
        from src.security_checks import run_security_checks

        hold = {key: sys.modules[key] for key in list(sys.modules) if key == "src" or key.startswith("src.")}
        _AGENT_HOLD.append(hold)
        return parse_email, run_security_checks, extract_features
    finally:
        if str(agent_root) in sys.path:
            sys.path.remove(str(agent_root))
        for key in list(sys.modules):
            if key == "src" or key.startswith("src."):
                sys.modules.pop(key, None)
        sys.modules.update(saved)


def _is_unknown(value) -> bool:
    return value in (None, "unknown")


def _coverage_from_features(features) -> str:
    data = features.to_dict()
    auth_present = sum(not _is_unknown(data[name]) for name in AUTH_FIELDS)
    reply = bool(data["has_reply_to"]) and not _is_unknown(data["from_reply_to_address_mismatch"])
    rp = not _is_unknown(data["from_return_path_domain_mismatch"])
    has_url = data["url_count"] > 0 and data["url_length_max"] is not None
    received = data["num_received_headers"] >= 1
    text_ok = bool(data["subject"]) and bool(data["body_plain"])
    if auth_present == 3 and reply and rp and has_url and received and text_ok:
        return "rich"
    if auth_present == 0 and not reply and not rp and not has_url:
        return "low"
    if auth_present == 3 or (auth_present >= 2 and (reply or rp) and received):
        return "mostly_observable"
    return "partial"


def _exclusive_values(by_label: dict[str, Counter]) -> list[str]:
    flags = []
    legit = set(by_label.get("legitimate", ()))
    phish = set(by_label.get("phishing", ()))
    only_legit = legit - phish
    only_phish = phish - legit
    if only_legit:
        flags.append(f"legitimate-only values: {sorted(only_legit)}")
    if only_phish:
        flags.append(f"phishing-only values: {sorted(only_phish)}")
    return flags


TEXT_ARTIFACT_PATTERNS = {
    "html_deleted_marker": r"\[\s*(?:alternative\s+)?HTML(?:\s+version)?\s+deleted\s*\]",
    "brace_anon_token": r"\{[A-Z][A-Z0-9_]{2,}\}",
    "square_bracket_span": r"\[[^\[\]\n]{1,40}\]",
}


def _auth_availability(features: dict) -> str:
    present = sum(features[name] != "unknown" for name in AUTH_FIELDS)
    if present == 3:
        return "full"
    if present == 0:
        return "none"
    return "partial"


def _intended_auth(value: str) -> str:
    return value if value else "unknown"


def _intent_mismatches(row: dict, features: dict) -> list[dict[str, str]]:
    mismatches: list[dict[str, str]] = []

    def note(field: str, intended: object, observed: object) -> None:
        mismatches.append(
            {
                "sample_id": row["sample_id"],
                "field": field,
                "intended": str(intended),
                "observed": str(observed),
            }
        )

    for name, feat in (
        ("spf", "header_spf_result"),
        ("dkim", "header_dkim_result"),
        ("dmarc", "header_dmarc_result"),
    ):
        expected = _intended_auth(row.get(name, ""))
        if features[feat] != expected:
            note(feat, expected, features[feat])

    reply_mode = row.get("reply_to_mode", "")
    if reply_mode == "absent":
        if features["has_reply_to"]:
            note("has_reply_to", False, features["has_reply_to"])
        if features["from_reply_to_address_mismatch"] != "unknown":
            note("from_reply_to_address_mismatch", "unknown", features["from_reply_to_address_mismatch"])
        if features["from_reply_to_domain_mismatch"] != "unknown":
            note("from_reply_to_domain_mismatch", "unknown", features["from_reply_to_domain_mismatch"])
    elif reply_mode == "address_match":
        if not features["has_reply_to"]:
            note("has_reply_to", True, features["has_reply_to"])
        if features["from_reply_to_address_mismatch"] != "false":
            note("from_reply_to_address_mismatch", "false", features["from_reply_to_address_mismatch"])
        if features["from_reply_to_domain_mismatch"] != "false":
            note("from_reply_to_domain_mismatch", "false", features["from_reply_to_domain_mismatch"])
    elif reply_mode == "domain_match":
        if not features["has_reply_to"]:
            note("has_reply_to", True, features["has_reply_to"])
        if features["from_reply_to_address_mismatch"] != "true":
            note("from_reply_to_address_mismatch", "true", features["from_reply_to_address_mismatch"])
        if features["from_reply_to_domain_mismatch"] != "false":
            note("from_reply_to_domain_mismatch", "false", features["from_reply_to_domain_mismatch"])
    elif reply_mode == "domain_mismatch":
        if not features["has_reply_to"]:
            note("has_reply_to", True, features["has_reply_to"])
        if features["from_reply_to_domain_mismatch"] != "true":
            note("from_reply_to_domain_mismatch", "true", features["from_reply_to_domain_mismatch"])

    rp_mode = row.get("return_path_mode", "")
    expected_rp = {"absent": "unknown", "match": "false", "mismatch": "true"}.get(rp_mode)
    if expected_rp and features["from_return_path_domain_mismatch"] != expected_rp:
        note("from_return_path_domain_mismatch", expected_rp, features["from_return_path_domain_mismatch"])

    url_mode = row.get("url_mode", "")
    url_count = features["url_count"]
    if url_mode == "none" and url_count != 0:
        note("url_count", 0, url_count)
    elif url_mode == "one" and url_count < 1:
        note("url_count", ">=1", url_count)
    elif url_mode in {"several", "mixed"} and url_count < 2:
        note("url_count", ">=2", url_count)
    elif url_mode == "repeated" and url_count < 2:
        note("url_count", ">=2", url_count)
    if url_mode == "ip" and features["ip_url_count"] < 1:
        note("ip_url_count", ">=1", features["ip_url_count"])
    if url_mode == "punycode" and features["punycode_url_count"] < 1:
        note("punycode_url_count", ">=1", features["punycode_url_count"])
    if url_mode == "mixed" and features["ip_url_count"] < 1:
        note("ip_url_count", ">=1", features["ip_url_count"])
    logical_unique = row.get("logical_unique_url_count", "")
    if logical_unique != "" and str(features["unique_url_count"]) != str(logical_unique):
        note("unique_url_count", logical_unique, features["unique_url_count"])

    att = row.get("attachment_mode", "")
    if att == "none" and features["attachment_count"] != 0:
        note("attachment_count", 0, features["attachment_count"])
    elif att == "ordinary":
        if features["attachment_count"] < 1:
            note("attachment_count", ">=1", features["attachment_count"])
        if features["has_risky_attachment"]:
            note("has_risky_attachment", False, True)
    elif att == "risky":
        if features["attachment_count"] < 1:
            note("attachment_count", ">=1", features["attachment_count"])
        if not features["has_risky_attachment"]:
            note("has_risky_attachment", True, False)

    body_format = row.get("body_format", "")
    if body_format == "plain" and features["has_html"]:
        note("has_html", False, True)
    elif body_format in {"html", "alternative"} and not features["has_html"]:
        note("has_html", True, False)

    intended_received = row.get("received_count", "")
    if intended_received != "" and str(features["num_received_headers"]) != str(intended_received):
        note("num_received_headers", intended_received, features["num_received_headers"])
    return mismatches


def _url_count_audit(feature_rows: list[dict]) -> dict:
    flagged: list[dict] = []
    observed_counts = Counter()
    by_mode = {mode: Counter() for mode in ("none", "plain", "html", "alternative")}
    unique_ok = 0
    for item in feature_rows:
        row = item["manifest"]
        feats = item["features"]
        logical = int(row.get("logical_url_count") or 0)
        logical_unique = int(row.get("logical_unique_url_count") or 0)
        mode = row.get("url_rendering_mode") or "none"
        observed = int(feats["url_count"])
        observed_unique = int(feats["unique_url_count"])
        observed_counts[observed] += 1
        by_mode.setdefault(mode, Counter())[observed] += 1
        if observed_unique == logical_unique:
            unique_ok += 1
        else:
            flagged.append(
                {
                    "sample_id": row["sample_id"],
                    "kind": "unique_mismatch",
                    "mode": mode,
                    "logical_unique": logical_unique,
                    "observed_unique": observed_unique,
                }
            )
        if mode == "none" and observed > 0:
            flagged.append(
                {
                    "sample_id": row["sample_id"],
                    "kind": "unexpected_urls",
                    "mode": mode,
                    "logical": logical,
                    "observed": observed,
                }
            )
        elif mode in {"plain", "html"} and observed > logical + 1:
            flagged.append(
                {
                    "sample_id": row["sample_id"],
                    "kind": "suspicious_multiplication",
                    "mode": mode,
                    "logical": logical,
                    "observed": observed,
                    "note": "plain/HTML extracted count should stay close to the logical URL list",
                }
            )
        elif mode == "alternative" and observed > (2 * logical) + 1:
            flagged.append(
                {
                    "sample_id": row["sample_id"],
                    "kind": "suspicious_multiplication",
                    "mode": mode,
                    "logical": logical,
                    "observed": observed,
                    "note": "multipart/alternative may count each logical URL about twice",
                }
            )
        if logical > 0 and observed >= 4 * logical:
            flagged.append(
                {
                    "sample_id": row["sample_id"],
                    "kind": "4x_or_worse",
                    "mode": mode,
                    "logical": logical,
                    "observed": observed,
                }
            )
    return {
        "observed_url_count_distribution": {str(key): value for key, value in sorted(observed_counts.items())},
        "observed_url_count_by_rendering_mode": {
            mode: {str(key): value for key, value in sorted(counter.items())} for mode, counter in by_mode.items()
        },
        "unique_url_matches": unique_ok,
        "flagged": flagged[:40],
        "flagged_count": len(flagged),
        "note": (
            "Agent url_count may be about 2× logical URLs for multipart/alternative. "
            "4×/12× peaks are generator duplication, not realistic MIME alternatives."
        ),
    }


def _text_artifact_audit(feature_rows: list[dict]) -> dict:
    import re

    compiled = {name: re.compile(pattern, re.IGNORECASE) for name, pattern in TEXT_ARTIFACT_PATTERNS.items()}
    by_label = {name: {label: {"rows": 0, "hits": 0} for label in ("legitimate", "phishing")} for name in compiled}
    n_by_label = Counter(item["manifest"]["label"] for item in feature_rows)
    examples: list[dict[str, str]] = []
    for item in feature_rows:
        label = item["manifest"]["label"]
        text = f"{item['features']['subject']}\n{item['features']['body_plain']}"
        for name, pattern in compiled.items():
            hits = pattern.findall(text)
            if not hits:
                continue
            by_label[name][label]["rows"] += 1
            by_label[name][label]["hits"] += len(hits)
            if len(examples) < 10:
                examples.append({"pattern": name, "label": label, "sample": str(hits[0])[:80]})
    class_dependent = []
    for name, table in by_label.items():
        rates = {}
        for label in ("legitimate", "phishing"):
            total = max(n_by_label[label], 1)
            rates[label] = table[label]["rows"] / total
        if abs(rates["legitimate"] - rates["phishing"]) >= 0.25 and max(rates.values()) >= 0.10:
            class_dependent.append(
                {
                    "pattern": name,
                    "row_rate_legitimate": round(rates["legitimate"], 4),
                    "row_rate_phishing": round(rates["phishing"], 4),
                    "note": "Reported only; Stage 2.5 left these source-text residues in place.",
                }
            )
    return {
        "counts": by_label,
        "examples": examples,
        "class_dependent": class_dependent,
        "note": (
            "Mailing-list/citation brackets and rare HTML-deleted notes were intentionally "
            "kept in real seed text. They are not removed here."
        ),
    }


def _shortcut_audit(feature_rows: list[dict], warnings: list[str]) -> dict:
    n_by_label = Counter(item["manifest"]["label"] for item in feature_rows)
    exclusive = []
    severe = []
    notable = []

    def collect_rates(getter) -> dict[str, dict[str, float]]:
        counts: dict[str, Counter] = {label: Counter() for label in ("legitimate", "phishing")}
        for item in feature_rows:
            counts[item["manifest"]["label"]][str(getter(item))] += 1
        rates: dict[str, dict[str, float]] = {}
        for label, counter in counts.items():
            total = max(n_by_label[label], 1)
            rates[label] = {key: value / total for key, value in counter.items()}
        return rates

    feature_getters = {
        "header_spf_result": lambda item: item["features"]["header_spf_result"],
        "header_dkim_result": lambda item: item["features"]["header_dkim_result"],
        "header_dmarc_result": lambda item: item["features"]["header_dmarc_result"],
        "has_reply_to": lambda item: item["features"]["has_reply_to"],
        "from_reply_to_address_mismatch": lambda item: item["features"]["from_reply_to_address_mismatch"],
        "from_reply_to_domain_mismatch": lambda item: item["features"]["from_reply_to_domain_mismatch"],
        "from_return_path_domain_mismatch": lambda item: item["features"]["from_return_path_domain_mismatch"],
        "has_html": lambda item: item["features"]["has_html"],
        "has_risky_attachment": lambda item: item["features"]["has_risky_attachment"],
        "attachment_present": lambda item: item["features"]["attachment_count"] > 0,
        "url_present": lambda item: item["features"]["url_count"] > 0,
        "ip_url_present": lambda item: item["features"]["ip_url_count"] > 0,
        "punycode_url_present": lambda item: item["features"]["punycode_url_count"] > 0,
        "profile": lambda item: item["manifest"]["profile"],
        "coverage_level": lambda item: item["manifest"].get("coverage_level", ""),
        "inferred_coverage": lambda item: item.get("inferred_coverage", ""),
        "header_template_id": lambda item: item["manifest"].get("header_template_id", ""),
        "body_template_id": lambda item: item["manifest"].get("body_template_id", ""),
        "url_mode": lambda item: item["manifest"].get("url_mode", ""),
        "url_rendering_mode": lambda item: item["manifest"].get("url_rendering_mode", ""),
        "reply_to_mode": lambda item: item["manifest"].get("reply_to_mode", ""),
        "return_path_mode": lambda item: item["manifest"].get("return_path_mode", ""),
        "body_format": lambda item: item["manifest"].get("body_format", ""),
    }
    for name, getter in feature_getters.items():
        rates = collect_rates(getter)
        legit_keys = set(rates["legitimate"])
        phish_keys = set(rates["phishing"])
        for key in sorted(legit_keys - phish_keys):
            if rates["legitimate"][key] >= 0.08:
                exclusive.append({"feature": name, "value": key, "only_in": "legitimate", "rate": round(rates["legitimate"][key], 4)})
        for key in sorted(phish_keys - legit_keys):
            if rates["phishing"][key] >= 0.08:
                exclusive.append({"feature": name, "value": key, "only_in": "phishing", "rate": round(rates["phishing"][key], 4)})
        for key in sorted(legit_keys & phish_keys):
            gap = abs(rates["legitimate"][key] - rates["phishing"][key])
            payload = {
                "feature": name,
                "value": key,
                "rate_legitimate": round(rates["legitimate"][key], 4),
                "rate_phishing": round(rates["phishing"][key], 4),
                "abs_gap": round(gap, 4),
            }
            if gap >= 0.50:
                severe.append(payload)
            elif gap >= 0.35:
                notable.append(payload)

    header_by_label = defaultdict(set)
    body_by_label = defaultdict(set)
    profile_by_label = defaultdict(set)
    coverage_by_label = defaultdict(set)
    for item in feature_rows:
        label = item["manifest"]["label"]
        header_by_label[label].add(item["manifest"].get("header_template_id", ""))
        body_by_label[label].add(item["manifest"].get("body_template_id", ""))
        profile_by_label[label].add(item["manifest"]["profile"])
        coverage_by_label[label].add(item["manifest"].get("coverage_level", ""))

    template_partitioned = bool(
        header_by_label["legitimate"]
        and header_by_label["phishing"]
        and header_by_label["legitimate"].isdisjoint(header_by_label["phishing"])
    )
    body_partitioned = bool(
        body_by_label["legitimate"]
        and body_by_label["phishing"]
        and body_by_label["legitimate"].isdisjoint(body_by_label["phishing"])
    )
    header_overlap = header_by_label["legitimate"] & header_by_label["phishing"]
    body_overlap = body_by_label["legitimate"] & body_by_label["phishing"]
    missing_profiles = {
        "legitimate": sorted(profile_by_label["phishing"] - profile_by_label["legitimate"]),
        "phishing": sorted(profile_by_label["legitimate"] - profile_by_label["phishing"]),
    }
    missing_coverage = {
        "legitimate": sorted(coverage_by_label["phishing"] - coverage_by_label["legitimate"]),
        "phishing": sorted(coverage_by_label["legitimate"] - coverage_by_label["phishing"]),
    }
    if exclusive:
        warnings.append("class-exclusive technical values at >=8% of a label")
    if severe:
        warnings.append("severe label rate gaps (>=0.50) on technical/template features")
    if template_partitioned or body_partitioned:
        warnings.append("templates partitioned by label")
    return {
        "class_exclusive_values": exclusive,
        "severe_rate_gaps": severe,
        "notable_rate_gaps": notable,
        "header_templates_partitioned_by_label": template_partitioned,
        "body_templates_partitioned_by_label": body_partitioned,
        "shared_header_template_count": len(header_overlap),
        "shared_body_template_count": len(body_overlap),
        "profiles_missing_from_label": missing_profiles,
        "coverage_missing_from_label": missing_coverage,
        "header_templates_only_legitimate": sorted(header_by_label["legitimate"] - header_by_label["phishing"]),
        "header_templates_only_phishing": sorted(header_by_label["phishing"] - header_by_label["legitimate"]),
        "body_templates_only_legitimate": sorted(body_by_label["legitimate"] - body_by_label["phishing"]),
        "body_templates_only_phishing": sorted(body_by_label["phishing"] - body_by_label["legitimate"]),
        "warnings": list(warnings),
        "note": (
            "Moderate profile-weight differences are expected construction choices, "
            "not automatically label shortcuts. Rare exclusive tokens at full-corpus "
            "n are listed even when they fall below the 8% exclusive-value cutoff."
        ),
    }


RARE_AUTH_TOKENS = ("fail", "softfail", "neutral", "temperror", "permerror")


def _generated_text_duplicates(feature_rows: list[dict]) -> dict:
    pairs = [(item["features"].get("subject") or "", item["features"].get("body_plain") or "") for item in feature_rows]
    counts = Counter(pairs)
    duplicate_groups = sum(1 for value in counts.values() if value > 1)
    extra = sum(value - 1 for value in counts.values() if value > 1)
    return {
        "unique_subject_body_pairs": len(counts),
        "duplicate_pair_groups": duplicate_groups,
        "extra_duplicate_messages": extra,
    }


def _rare_auth_audit(feature_rows: list[dict]) -> dict:
    labels = ("legitimate", "phishing")
    result: dict[str, dict] = {}
    exclusive: list[dict] = []
    for field in AUTH_FIELDS:
        by_label = {label: Counter() for label in labels}
        for item in feature_rows:
            by_label[item["manifest"]["label"]][item["features"][field]] += 1
        legit_keys = set(by_label["legitimate"])
        phish_keys = set(by_label["phishing"])
        field_exclusive = []
        for value in sorted((legit_keys | phish_keys) - {""}):
            only_legit = value in legit_keys and value not in phish_keys
            only_phish = value in phish_keys and value not in legit_keys
            if only_legit or only_phish:
                payload = {
                    "field": field,
                    "value": value,
                    "only_in": "legitimate" if only_legit else "phishing",
                    "count": by_label["legitimate"][value] if only_legit else by_label["phishing"][value],
                }
                field_exclusive.append(payload)
                exclusive.append(payload)
        result[field] = {
            "by_label": {label: dict(counter) for label, counter in by_label.items()},
            "exclusive_values": field_exclusive,
            "rare_tokens": {
                token: {
                    "legitimate": by_label["legitimate"].get(token, 0),
                    "phishing": by_label["phishing"].get(token, 0),
                }
                for token in RARE_AUTH_TOKENS
            },
        }
    return {"fields": result, "exclusive_values": exclusive}


def _template_profile_audit(feature_rows: list[dict]) -> dict:
    header = defaultdict(lambda: {"labels": Counter(), "profiles": Counter()})
    body = defaultdict(lambda: {"labels": Counter(), "profiles": Counter()})
    for item in feature_rows:
        label = item["manifest"]["label"]
        profile = item["manifest"]["profile"]
        header_id = item["manifest"].get("header_template_id", "")
        body_id = item["manifest"].get("body_template_id", "")
        header[header_id]["labels"][label] += 1
        header[header_id]["profiles"][profile] += 1
        body[body_id]["labels"][label] += 1
        body[body_id]["profiles"][profile] += 1

    def summarize(table: dict) -> list[dict]:
        rows = []
        for template_id, stats in sorted(table.items()):
            labels = dict(stats["labels"])
            profiles = dict(stats["profiles"])
            one_label = len(labels) == 1
            one_profile = len(profiles) == 1
            rows.append(
                {
                    "template_id": template_id,
                    "labels": labels,
                    "profiles": profiles,
                    "count": sum(labels.values()),
                    "single_label": one_label,
                    "single_profile": one_profile,
                    "tied_to_one_profile_and_label": bool(template_id)
                    and one_label
                    and one_profile
                    and sum(labels.values()) >= 8,
                }
            )
        return rows

    header_rows = summarize(header)
    body_rows = summarize(body)
    return {
        "header_templates": header_rows,
        "body_templates": body_rows,
        "header_tied_to_one_profile_and_label": [
            row["template_id"] for row in header_rows if row["tied_to_one_profile_and_label"]
        ],
        "body_tied_to_one_profile_and_label": [
            row["template_id"] for row in body_rows if row["tied_to_one_profile_and_label"]
        ],
        "note": (
            "header_template_id is a cartesian product of shared component templates. "
            "Single-occurrence composites are expected sparsity, not label encoding. "
            "A composite is flagged only if it appears at least 8 times and is confined to one profile and one label."
        ),
    }


def _observability_association(inferred: dict[str, Counter], n_by_label: Counter) -> dict:
    levels = ("low", "partial", "mostly_observable", "rich")
    percent = {}
    for label in ("legitimate", "phishing"):
        total = max(n_by_label[label], 1)
        percent[label] = {level: round(100 * inferred[label].get(level, 0) / total, 2) for level in levels}
    rich_gap = abs(percent["legitimate"]["rich"] - percent["phishing"]["rich"])
    low_gap = abs(percent["legitimate"]["low"] - percent["phishing"]["low"])
    partial_gap = abs(percent["legitimate"]["partial"] - percent["phishing"]["partial"])
    appears_predictive = rich_gap >= 25 or low_gap >= 25
    return {
        "inferred_percent_by_label": percent,
        "rich_gap_pp": round(rich_gap, 2),
        "low_gap_pp": round(low_gap, 2),
        "partial_gap_pp": round(partial_gap, 2),
        "appears_predictive_of_label": appears_predictive,
        "note": (
            "A gap of 25 percentage points on inferred rich or low coverage is treated as "
            "observability acting like a class proxy. Smaller gaps can still follow frozen profile weights."
        ),
    }


def _distributions_by_label(feature_rows: list[dict]) -> dict:
    labels = ("legitimate", "phishing")
    auth_values = {label: {name: Counter() for name in AUTH_FIELDS} for label in labels}
    auth_availability = {label: Counter() for label in labels}
    reply_presence = {label: Counter() for label in labels}
    reply_mode = {label: Counter() for label in labels}
    rp = {label: Counter() for label in labels}
    rp_mode = {label: Counter() for label in labels}
    received = {label: Counter() for label in labels}
    urls = {label: Counter() for label in labels}
    logical_urls = {label: Counter() for label in labels}
    render_mode = {label: Counter() for label in labels}
    url_mode = {label: Counter() for label in labels}
    url_length = {label: [] for label in labels}
    attachments = {label: Counter() for label in labels}
    attachment_mode = {label: Counter() for label in labels}
    fmt = {label: Counter() for label in labels}
    coverage = {label: Counter() for label in labels}
    inferred = {label: Counter() for label in labels}
    n_by_label = Counter(item["manifest"]["label"] for item in feature_rows)

    for item in feature_rows:
        label = item["manifest"]["label"]
        feats = item["features"]
        row = item["manifest"]
        for name in AUTH_FIELDS:
            auth_values[label][name][feats[name]] += 1
        auth_availability[label][_auth_availability(feats)] += 1
        reply_presence[label]["present" if feats["has_reply_to"] else "absent"] += 1
        reply_presence[label][f"address_mismatch={feats['from_reply_to_address_mismatch']}"] += 1
        reply_presence[label][f"domain_mismatch={feats['from_reply_to_domain_mismatch']}"] += 1
        reply_mode[label][row.get("reply_to_mode", "")] += 1
        rp[label][feats["from_return_path_domain_mismatch"]] += 1
        rp_mode[label][row.get("return_path_mode", "")] += 1
        received[label][str(feats["num_received_headers"])] += 1
        if feats["url_count"] == 0:
            urls[label]["none"] += 1
        else:
            urls[label]["present"] += 1
        urls[label][f"count={feats['url_count']}"] += 1
        urls[label][f"unique={feats['unique_url_count']}"] += 1
        urls[label][f"logical_count={row.get('logical_url_count', '')}"] += 1
        urls[label][f"logical_unique={row.get('logical_unique_url_count', '')}"] += 1
        if feats["ip_url_count"]:
            urls[label]["ip_host"] += 1
        if feats["punycode_url_count"]:
            urls[label]["punycode"] += 1
        logical_urls[label][str(row.get("logical_url_count", ""))] += 1
        render_mode[label][row.get("url_rendering_mode", "")] += 1
        url_mode[label][row.get("url_mode", "")] += 1
        if feats["url_length_max"] is not None:
            url_length[label].append(feats["url_length_max"])
        attachments[label]["present" if feats["attachment_count"] > 0 else "none"] += 1
        attachments[label][f"count={feats['attachment_count']}"] += 1
        attachments[label]["risky" if feats["has_risky_attachment"] else "not_risky"] += 1
        attachment_mode[label][row.get("attachment_mode", "")] += 1
        fmt[label]["html" if feats["has_html"] else "plain_only"] += 1
        fmt[label][f"body_format={row.get('body_format', '')}"] += 1
        fmt[label]["multipart_alternative" if row.get("body_format") == "alternative" else "not_alternative"] += 1
        fmt[label]["body_plain_populated" if feats["body_plain"] else "body_plain_empty"] += 1
        coverage[label][row.get("coverage_level", "")] += 1
        inferred[label][item["inferred_coverage"]] += 1

    rich_pct = {}
    partial_pct = {}
    low_pct = {}
    missing_pct = {}
    for label in labels:
        total = max(n_by_label[label], 1)
        rich_pct[label] = round(100 * inferred[label].get("rich", 0) / total, 2)
        partial_pct[label] = round(100 * inferred[label].get("partial", 0) / total, 2)
        low_pct[label] = round(100 * inferred[label].get("low", 0) / total, 2)
        missing_like = inferred[label].get("low", 0) + inferred[label].get("partial", 0)
        missing_pct[label] = round(100 * missing_like / total, 2)

    n = max(sum(n_by_label.values()), 1)
    return {
        "class_counts": dict(n_by_label),
        "class_percentages": {
            label: round(100 * n_by_label[label] / n, 2) for label in labels if n_by_label[label]
        },
        "authentication_values_by_label": {
            label: {name: dict(counter) for name, counter in auth_values[label].items()} for label in labels
        },
        "authentication_availability_by_label": {label: dict(counter) for label, counter in auth_availability.items()},
        "reply_to_by_label": {label: dict(counter) for label, counter in reply_presence.items()},
        "reply_to_mode_by_label": {label: dict(counter) for label, counter in reply_mode.items()},
        "return_path_by_label": {label: dict(counter) for label, counter in rp.items()},
        "return_path_mode_by_label": {label: dict(counter) for label, counter in rp_mode.items()},
        "received_headers_by_label": {label: dict(counter) for label, counter in received.items()},
        "url_distributions_by_label": {label: dict(counter) for label, counter in urls.items()},
        "logical_url_count_by_label": {label: dict(counter) for label, counter in logical_urls.items()},
        "url_rendering_mode_by_label": {label: dict(counter) for label, counter in render_mode.items()},
        "url_mode_by_label": {label: dict(counter) for label, counter in url_mode.items()},
        "url_length_max_by_label": {
            label: {
                "n": len(values),
                "max": max(values) if values else None,
                "median": sorted(values)[len(values) // 2] if values else None,
            }
            for label, values in url_length.items()
        },
        "attachments_by_label": {label: dict(counter) for label, counter in attachments.items()},
        "attachment_mode_by_label": {label: dict(counter) for label, counter in attachment_mode.items()},
        "format_by_label": {label: dict(counter) for label, counter in fmt.items()},
        "intended_coverage_by_label": {label: dict(counter) for label, counter in coverage.items()},
        "rich_percent_by_label": rich_pct,
        "partial_percent_by_label": partial_pct,
        "low_percent_by_label": low_pct,
        "partial_or_low_percent_by_label": missing_pct,
        "observability_label_association": _observability_association(inferred, n_by_label),
    }


def _content_preservation(feature_rows: list[dict], seeds_by_id: dict | None) -> dict:
    if not seeds_by_id:
        return {"checked": False}
    subject_mismatch = 0
    body_missing = 0
    examples = []
    for item in feature_rows:
        seed = seeds_by_id.get(item["manifest"]["content_seed_id"])
        if seed is None:
            continue
        observed_subject = item["features"]["subject"]
        observed_body = item["features"]["body_plain"]
        if (seed.subject or "") != (observed_subject or ""):
            subject_mismatch += 1
            if len(examples) < 5:
                examples.append(
                    {
                        "sample_id": item["manifest"]["sample_id"],
                        "kind": "subject",
                        "seed": (seed.subject or "")[:80],
                        "observed": (observed_subject or "")[:80],
                    }
                )
        snippet = (seed.body_plain or "").strip()[:40]
        if snippet and snippet not in (observed_body or ""):
            body_missing += 1
            if len(examples) < 5:
                examples.append(
                    {
                        "sample_id": item["manifest"]["sample_id"],
                        "kind": "body_prefix",
                        "seed": snippet,
                    }
                )
    return {
        "checked": True,
        "subject_mismatches": subject_mismatch,
        "body_prefix_missing": body_missing,
        "examples": examples,
    }


def build_quality_report(
    output_dir: Path,
    *,
    agent_root: Path | None = None,
    unique_seeds_expected: bool = True,
    seeds_by_id: dict | None = None,
) -> dict:
    parse_email, run_security_checks, extract_features = load_agent_pipeline(agent_root)
    output_dir = Path(output_dir)
    with (output_dir / "manifest.csv").open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    parse_failures = []
    extract_failures = []
    feature_rows = []
    warnings: list[str] = []

    sample_ids = [row["sample_id"] for row in rows]
    if len(sample_ids) != len(set(sample_ids)):
        warnings.append("duplicated sample IDs")
    seed_ids = [row["content_seed_id"] for row in rows]
    if unique_seeds_expected and len(seed_ids) != len(set(seed_ids)):
        warnings.append("duplicated content seeds where v1 expects uniqueness")

    for row in rows:
        path = output_dir / "emails" / row["filename"]
        try:
            parsed = parse_email(path)
        except Exception as exc:
            parse_failures.append({"sample_id": row["sample_id"], "error": str(exc)})
            continue
        try:
            features = extract_features(parsed, run_security_checks(parsed))
        except Exception as exc:
            extract_failures.append({"sample_id": row["sample_id"], "error": str(exc)})
            continue
        exported = features.to_dict()
        if list(exported.keys()) != list(EMAIL_FEATURE_FIELDS):
            extract_failures.append({"sample_id": row["sample_id"], "error": "unexpected EmailFeatures schema"})
            continue
        feature_rows.append({"manifest": row, "features": exported, "inferred_coverage": _coverage_from_features(features)})

    def dist(getter) -> dict[str, int]:
        return dict(Counter(getter(item) for item in feature_rows))

    profile_label = Counter((item["manifest"]["profile"], item["manifest"]["label"]) for item in feature_rows)
    coverage_label = Counter((item["manifest"].get("coverage_level", item["inferred_coverage"]), item["manifest"]["label"]) for item in feature_rows)

    auth_by_label = {label: Counter() for label in ("legitimate", "phishing")}
    mismatch_by_label = {label: Counter() for label in ("legitimate", "phishing")}
    missing_by_label = {label: Counter() for label in ("legitimate", "phishing")}
    presence_by_label = {label: Counter() for label in ("legitimate", "phishing")}

    joints = Counter()
    label_joints = {label: Counter() for label in ("legitimate", "phishing")}
    intent_mismatches: list[dict[str, str]] = []
    for item in feature_rows:
        feats = item["features"]
        label = item["manifest"]["label"]
        for name in AUTH_FIELDS:
            auth_by_label[label][f"{name}={feats[name]}"] += 1
            if feats[name] == "unknown":
                missing_by_label[label][name] += 1
            else:
                presence_by_label[label][name] += 1
        for name in (
            "from_reply_to_address_mismatch",
            "from_reply_to_domain_mismatch",
            "from_return_path_domain_mismatch",
        ):
            mismatch_by_label[label][f"{name}={feats[name]}"] += 1
            if feats[name] == "unknown":
                missing_by_label[label][name] += 1
            else:
                presence_by_label[label][name] += 1
        if feats["has_reply_to"]:
            presence_by_label[label]["has_reply_to"] += 1
        else:
            missing_by_label[label]["has_reply_to"] += 1
        if feats["url_count"] == 0:
            missing_by_label[label]["urls"] += 1
        else:
            presence_by_label[label]["urls"] += 1
        if feats["has_html"]:
            presence_by_label[label]["has_html"] += 1
        else:
            missing_by_label[label]["has_html"] += 1
        if feats["attachment_count"] > 0:
            presence_by_label[label]["attachments"] += 1
        else:
            missing_by_label[label]["attachments"] += 1
        if feats["has_risky_attachment"]:
            presence_by_label[label]["has_risky_attachment"] += 1
        intent_mismatches.extend(_intent_mismatches(item["manifest"], feats))

        spf_ok = feats["header_spf_result"] != "unknown"
        dkim_ok = feats["header_dkim_result"] != "unknown"
        dmarc_ok = feats["header_dmarc_result"] != "unknown"
        any_auth = spf_ok or dkim_ok or dmarc_ok
        reply = feats["has_reply_to"]
        rp = feats["from_return_path_domain_mismatch"] != "unknown"
        url = feats["url_count"] > 0
        html = feats["has_html"]
        att = feats["attachment_count"] > 0
        if spf_ok and dkim_ok and dmarc_ok:
            joints["spf_dkim_dmarc_observable"] += 1
        if any_auth:
            joints["at_least_one_auth"] += 1
        if any_auth and reply:
            joints["auth_and_reply_to"] += 1
        if any_auth and rp:
            joints["auth_and_return_path"] += 1
        if any_auth and url:
            joints["auth_and_url"] += 1
        if any_auth and reply and url:
            joints["auth_reply_to_url"] += 1
        if any_auth and reply and rp and url:
            joints["auth_reply_to_return_path_url"] += 1
        if html and url:
            joints["html_and_url"] += 1
        if url and att:
            joints["url_and_attachment"] += 1
        if item["inferred_coverage"] == "rich":
            joints["rich_technical_coverage"] += 1
        label_joints[label]["spf_dkim_dmarc_observable"] += int(spf_ok and dkim_ok and dmarc_ok)
        label_joints[label]["at_least_one_auth"] += int(any_auth)
        label_joints[label]["auth_and_reply_to"] += int(any_auth and reply)
        label_joints[label]["auth_and_return_path"] += int(any_auth and rp)
        label_joints[label]["auth_and_url"] += int(any_auth and url)
        label_joints[label]["auth_reply_to_url"] += int(any_auth and reply and url)
        label_joints[label]["auth_reply_to_return_path_url"] += int(any_auth and reply and rp and url)
        label_joints[label]["html_and_url"] += int(html and url)
        label_joints[label]["url_and_attachment"] += int(url and att)
        label_joints[label]["rich_technical_coverage"] += int(item["inferred_coverage"] == "rich")

    joints_by_label = {label: dict(counter) for label, counter in label_joints.items()}

    intended_coverage = Counter(item["manifest"].get("coverage_level", "") for item in feature_rows)
    inferred_coverage = Counter(item["inferred_coverage"] for item in feature_rows)
    inferred_by_label = defaultdict(Counter)
    for item in feature_rows:
        inferred_by_label[item["manifest"]["label"]][item["inferred_coverage"]] += 1

    n = max(len(feature_rows), 1)
    rich_n = inferred_coverage.get("rich", 0)
    partial_n = inferred_coverage.get("partial", 0)
    low_n = inferred_coverage.get("low", 0)

    for name in AUTH_FIELDS:
        values = {label: Counter(item["features"][name] for item in feature_rows if item["manifest"]["label"] == label) for label in ("legitimate", "phishing")}
        for flag in _exclusive_values(values):
            warnings.append(f"class-exclusive {name}: {flag}")

    for name in ("from_reply_to_address_mismatch", "from_reply_to_domain_mismatch", "from_return_path_domain_mismatch"):
        values = {label: Counter(item["features"][name] for item in feature_rows if item["manifest"]["label"] == label) for label in ("legitimate", "phishing")}
        for flag in _exclusive_values(values):
            warnings.append(f"class-exclusive {name}: {flag}")

    profiles_by_label = defaultdict(set)
    for item in feature_rows:
        profiles_by_label[item["manifest"]["label"]].add(item["manifest"]["profile"])
    if profiles_by_label["legitimate"] and profiles_by_label["phishing"]:
        if profiles_by_label["legitimate"].isdisjoint(profiles_by_label["phishing"]):
            warnings.append("deterministic profile/label association")

    rich_legit = inferred_by_label["legitimate"]["rich"]
    rich_phish = inferred_by_label["phishing"]["rich"]
    if (rich_legit == 0) != (rich_phish == 0) and (rich_legit + rich_phish) > 0:
        warnings.append("rich-coverage/label association")

    header_templates = Counter(item["manifest"].get("header_template_id", "") for item in feature_rows)
    if header_templates and len(header_templates) == 1 and len(feature_rows) > 4:
        warnings.append("obvious template fingerprints: a single header_template_id used for the whole batch")

    templates_by_label = defaultdict(set)
    for item in feature_rows:
        templates_by_label[item["manifest"]["label"]].add(item["manifest"].get("header_template_id", ""))
    if templates_by_label["legitimate"] and templates_by_label["phishing"]:
        if templates_by_label["legitimate"].isdisjoint(templates_by_label["phishing"]):
            warnings.append("obvious template fingerprints: header templates partitioned by label")

    for field_name in ("has_html", "has_reply_to"):
        rates = {}
        for label in ("legitimate", "phishing"):
            subset = [item for item in feature_rows if item["manifest"]["label"] == label]
            if not subset:
                continue
            rates[label] = sum(1 for item in subset if item["features"][field_name]) / len(subset)
        if len(rates) == 2 and abs(rates["legitimate"] - rates["phishing"]) >= 0.8:
            warnings.append(f"severe feature-presence imbalance for {field_name}")

    unknown_rates = {}
    for label in ("legitimate", "phishing"):
        subset = [item for item in feature_rows if item["manifest"]["label"] == label]
        if not subset:
            continue
        unknown_rates[label] = sum(item["features"]["header_spf_result"] == "unknown" for item in subset) / len(subset)
    if len(unknown_rates) == 2 and abs(unknown_rates["legitimate"] - unknown_rates["phishing"]) >= 0.8:
        warnings.append("severe missingness imbalance for SPF")

    report = {
        "disclaimer": "Distributions are controlled generator coverage, not real-world email prevalence.",
        "agent_root": str(Path(agent_root or default_agent_path()).resolve()),
        "count": len(rows),
        "parsed": len(feature_rows),
        "parser_failures": parse_failures,
        "extraction_failures": extract_failures,
        "profile_distribution": dist(lambda item: item["manifest"]["profile"]),
        "profile_label_distribution": {f"{profile}|{label}": count for (profile, label), count in profile_label.items()},
        "coverage_level_distribution": dict(intended_coverage),
        "coverage_level_label_distribution": {f"{cov}|{label}": count for (cov, label), count in coverage_label.items()},
        "inferred_coverage_distribution": dict(inferred_coverage),
        "inferred_coverage_by_label": {label: dict(counter) for label, counter in inferred_by_label.items()},
        "rich_coverage": {"count": rich_n, "percent": round(100 * rich_n / n, 2)},
        "partial_coverage": {"count": partial_n, "percent": round(100 * partial_n / n, 2)},
        "low_coverage": {"count": low_n, "percent": round(100 * low_n / n, 2)},
        "authentication_distributions": {label: dict(counter) for label, counter in auth_by_label.items()},
        "reply_to_and_return_path": {label: dict(counter) for label, counter in mismatch_by_label.items()},
        "missingness_by_label": {label: dict(counter) for label, counter in missing_by_label.items()},
        "presence_by_label": {label: dict(counter) for label, counter in presence_by_label.items()},
        "individual_feature_coverage": {
            field: {
                "non_default": sum(
                    1
                    for item in feature_rows
                    if item["features"][field]
                    not in (None, "", 0, False, "unknown")
                )
            }
            for field in EMAIL_FEATURE_FIELDS
        },
        "joint_feature_coverage": dict(joints),
        "joint_feature_coverage_by_label": joints_by_label,
        "warnings": warnings,
        "email_features_schema": list(EMAIL_FEATURE_FIELDS),
    }
    extra = _distributions_by_label(feature_rows)
    report.update(extra)
    header_template_label = Counter(
        (item["manifest"].get("header_template_id", ""), item["manifest"]["label"]) for item in feature_rows
    )
    body_template_label = Counter(
        (item["manifest"].get("body_template_id", ""), item["manifest"]["label"]) for item in feature_rows
    )
    report["header_template_label_distribution"] = {
        f"{template}|{label}": count for (template, label), count in header_template_label.items()
    }
    report["body_template_label_distribution"] = {
        f"{template}|{label}": count for (template, label), count in body_template_label.items()
    }
    report["shortcut_audit"] = _shortcut_audit(feature_rows, warnings)
    report["warnings"] = warnings
    report["text_artifact_audit"] = _text_artifact_audit(feature_rows)
    report["intent_vs_observed"] = {
        "mismatch_count": len(intent_mismatches),
        "mismatches": intent_mismatches[:40],
    }
    report["content_preservation"] = _content_preservation(feature_rows, seeds_by_id)
    url_audit = _url_count_audit(feature_rows)
    report["url_count_audit"] = url_audit
    report["generated_text_duplicates"] = _generated_text_duplicates(feature_rows)
    report["rare_auth_audit"] = _rare_auth_audit(feature_rows)
    report["template_profile_audit"] = _template_profile_audit(feature_rows)
    if report["rare_auth_audit"]["exclusive_values"]:
        warnings.append(
            f"{len(report['rare_auth_audit']['exclusive_values'])} authentication tokens exclusive to one class"
        )
    if report["template_profile_audit"]["header_tied_to_one_profile_and_label"]:
        warnings.append("header templates tied to a single profile and label")
    if report["template_profile_audit"]["body_tied_to_one_profile_and_label"]:
        warnings.append("body templates tied to a single profile and label")
    if report["generated_text_duplicates"]["extra_duplicate_messages"]:
        warnings.append("exact duplicated subject+body pairs in generated messages")
    if extra.get("observability_label_association", {}).get("appears_predictive_of_label"):
        warnings.append("inferred observability appears predictive of label")
    if url_audit["flagged_count"]:
        warnings.append(f"{url_audit['flagged_count']} URL-count audit flags")
    if intent_mismatches:
        warnings.append(f"{len(intent_mismatches)} intended-vs-Agent evidence mismatches")
    report["warnings"] = warnings
    report["shortcut_audit"]["warnings"] = list(warnings)
    return report


def write_quality_report(output_dir: Path, report: dict | None = None, **kwargs) -> Path:
    output_dir = Path(output_dir)
    payload = report or build_quality_report(output_dir, **kwargs)
    path = output_dir / "quality_report.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path
