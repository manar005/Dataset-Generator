# Prepare audited real content seeds from MeAJOR. Does not generate .eml files.

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from random import Random

from src.config import (
    DEFAULT_MEAJOR_SOURCE,
    DEFAULT_RANDOM_SEED,
    SEED_CLASS_MAX_SHARE,
    SEED_CLASS_MIN_SHARE,
    SEED_CSV_COLUMNS,
    SEED_MAX_PER_NEAR_DUP_CLUSTER,
    SEED_MIN_BODY_LETTERS,
    SEED_NEAR_DUP_PREFIX_CHARS,
    SEED_TARGET_TOTAL,
    SEED_TOTAL_JITTER,
    Label,
)
from src.generator import load_seeds_from_csv
from src.profile_allocation import allocate_profile_counts
from src.safety import (
    extract_live_url_candidates,
    is_live_operational_url,
    remove_live_urls,
)

RECOGNIZED_BRACKET_TOKENS = (
    "URL",
    "EMAIL_ADDRESS",
    "NAME",
    "ORGANIZATION",
    "PRODUCT",
    "FINANCIAL_INFO",
    "PHONE_NUMBER",
)
RECOGNIZED_ANGLE_TOKENS = ("SIMBOL", "EMOJI")

PLACEHOLDER_PATTERNS = {
    f"[{name}]": re.compile(rf"\[{name}\]", re.IGNORECASE) for name in RECOGNIZED_BRACKET_TOKENS
}
PLACEHOLDER_PATTERNS.update(
    {f"<|{name}|>": re.compile(rf"<\|{name}\|>") for name in RECOGNIZED_ANGLE_TOKENS}
)

_KNOWN_BRACKET_RE = re.compile(
    r"\[(?:" + "|".join(RECOGNIZED_BRACKET_TOKENS) + r")\]",
    re.IGNORECASE,
)
_SCHEME_BRACKET_RE = re.compile(r"\[[A-Z][A-Z0-9_]{1,}\]")
_SCHEME_ANGLE_RE = re.compile(r"<\|[^|]*\|>")
_EMPTY_BRACKETS_RE = re.compile(r"\[\s*\]")
_SPACE_RE = re.compile(r"[ \t]+")
_SPACE_BEFORE_PUNCT_RE = re.compile(r" +([,.;:!?])")
_EMPTY_PARENS_RE = re.compile(r"\(\s*\)")
_CLEAN_MULTI_NEWLINE_RE = re.compile(r"\n{3,}")
_NEWLINE_SPACES_RE = re.compile(r"[ \t]*\n[ \t]*")

_OTHER_ARTIFACT_PATTERNS = {
    "square_bracket_span": re.compile(r"\[[^\[\]\n]{1,40}\]"),
    "brace_anon_token": re.compile(r"\{[A-Z][A-Z0-9_]{2,}\}"),
    "dunder_anon_token": re.compile(r"__[A-Z][A-Z0-9_]{2,}__"),
    "angle_pipe_token": re.compile(r"<\|[^|]+\|>"),
    "html_deleted_marker": re.compile(
        r"\[\s*(?:alternative\s+)?HTML(?:\s+version)?\s+deleted\s*\]",
        re.IGNORECASE,
    ),
}

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")
_MULTI_SPACE_RE = re.compile(r"[ \t]{4,}")
_MULTI_NEWLINE_RE = re.compile(r"\n{4,}")


@dataclass
class RawRecord:
    subject: str
    body: str
    label: Label
    language: str
    source: str
    english: bool
    usable_body: bool


@dataclass
class SeedPrepConfig:
    source_path: Path = DEFAULT_MEAJOR_SOURCE
    output_csv: Path = Path("data/seeds/content_seeds.csv")
    report_path: Path = Path("output/seed_preparation_report.json")
    random_seed: int = DEFAULT_RANDOM_SEED
    target_total: int = SEED_TARGET_TOTAL
    total_jitter: int = SEED_TOTAL_JITTER
    class_min_share: float = SEED_CLASS_MIN_SHARE
    class_max_share: float = SEED_CLASS_MAX_SHARE
    min_body_letters: int = SEED_MIN_BODY_LETTERS
    near_dup_prefix_chars: int = SEED_NEAR_DUP_PREFIX_CHARS
    max_per_near_dup_cluster: int = SEED_MAX_PER_NEAR_DUP_CLUSTER


def map_source_label(value: object) -> Label | None:
    """Map MeAJOR ground-truth labels. 0 = legitimate, 1 = phishing."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"", "nan", "none"}:
        return None
    if text in {"legitimate", "legit", "ham"}:
        return "legitimate"
    if text in {"phishing", "phish", "spam"}:
        return "phishing"
    try:
        number = float(text)
    except ValueError:
        return None
    if number == 0:
        return "legitimate"
    if number == 1:
        return "phishing"
    return None


def is_english_language(value: object) -> bool:
    if value is None:
        return False
    parts = [item.strip().lower() for item in str(value).split(";") if item.strip()]
    return bool(parts) and all(part == "en" for part in parts)


def normalize_text(value: object) -> str:
    text = "" if value is None else str(value)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.replace("\t", " ")
    text = _MULTI_NEWLINE_RE.sub("\n\n", text)
    text = _MULTI_SPACE_RE.sub("  ", text)
    return text.strip()


def letter_count(text: str) -> int:
    return sum(1 for char in text if char.isalpha())


def has_usable_body(text: str, min_letters: int = SEED_MIN_BODY_LETTERS) -> bool:
    return letter_count(text) >= min_letters


def exact_text_key(subject: str, body: str) -> tuple[str, str]:
    return (subject, body)


def near_duplicate_key(subject: str, body: str, prefix_chars: int = SEED_NEAR_DUP_PREFIX_CHARS) -> str:
    """Lightweight template signature: lowercase alnum prefix of subject+body.

    Placeholders and markup tokens are stripped so anonymization tokens do not
    create false clusters. This is prefix matching, not aggressive merging.
    """
    combined = f"{subject}\n{body}".lower()
    combined = re.sub(r"\[.*?\]", " ", combined)
    combined = re.sub(r"<\|[^|]+\|>", " ", combined)
    combined = _NON_ALNUM_RE.sub(" ", combined)
    combined = re.sub(r"\s+", " ", combined).strip()
    if len(combined) < 40:
        digest = hashlib.sha1(combined.encode("utf-8")).hexdigest()[:16]
        return f"unique:{digest}"
    return combined[:prefix_chars]


def placeholder_counts(text: str) -> dict[str, int]:
    return {name: len(pattern.findall(text)) for name, pattern in PLACEHOLDER_PATTERNS.items()}


def recognized_placeholder_total(text: str) -> int:
    return sum(placeholder_counts(text).values())


def _normalize_after_token_removal(text: str) -> str:
    updated = _EMPTY_PARENS_RE.sub("", text)
    updated = _NEWLINE_SPACES_RE.sub("\n", updated)
    updated = _SPACE_RE.sub(" ", updated)
    updated = _SPACE_BEFORE_PUNCT_RE.sub(r"\1", updated)
    updated = _CLEAN_MULTI_NEWLINE_RE.sub("\n\n", updated)
    return updated.strip()


def remove_source_placeholders(text: str) -> str:
    """Remove recognized MeAJOR anonymization tokens. Label is not an input."""
    if not text:
        return text
    updated = text
    for _ in range(12):
        previous = updated
        updated = _KNOWN_BRACKET_RE.sub("", updated)
        updated = _SCHEME_BRACKET_RE.sub("", updated)
        updated = _SCHEME_ANGLE_RE.sub("", updated)
        updated = _EMPTY_BRACKETS_RE.sub("", updated)
        if updated == previous:
            break
    return _normalize_after_token_removal(updated)


def cleanup_seed_text(text: str) -> str:
    """Label-agnostic seed cleanup: drop source tokens and live URLs, then normalize.

    Does not insert URLs or semantically informative replacement tokens.
    """
    updated = remove_source_placeholders(text)
    updated = remove_live_urls(updated)
    return _normalize_after_token_removal(updated)


def live_url_count(text: str) -> int:
    return sum(1 for item in extract_live_url_candidates(text) if is_live_operational_url(item))


def choose_class_counts(
    rng: Random,
    *,
    available_legitimate: int,
    available_phishing: int,
    target_total: int = SEED_TARGET_TOTAL,
    total_jitter: int = SEED_TOTAL_JITTER,
    class_min_share: float = SEED_CLASS_MIN_SHARE,
    class_max_share: float = SEED_CLASS_MAX_SHARE,
) -> tuple[int, int, int]:
    """Return (n_legitimate, n_phishing, chosen_total). Not forced equal."""
    available_total = available_legitimate + available_phishing
    if available_total <= 0:
        raise ValueError("No usable records available for sampling")
    low = max(1, target_total - total_jitter)
    high = target_total + total_jitter
    chosen_total = rng.randint(low, high)
    chosen_total = min(chosen_total, available_total)
    phish_share = rng.uniform(class_min_share, class_max_share)
    n_phishing = int(round(chosen_total * phish_share))
    min_count = math.ceil(class_min_share * chosen_total)
    max_count = math.floor(class_max_share * chosen_total)
    n_phishing = min(max(n_phishing, min_count), max_count)
    n_legitimate = chosen_total - n_phishing
    if n_legitimate < min_count:
        n_legitimate = min_count
        n_phishing = chosen_total - n_legitimate
    n_legitimate = min(n_legitimate, available_legitimate)
    n_phishing = min(n_phishing, available_phishing)
    chosen_total = n_legitimate + n_phishing
    if chosen_total <= 0:
        raise ValueError("Unable to choose a near-balanced split")
    legit_share = n_legitimate / chosen_total
    phish_share_final = n_phishing / chosen_total
    if not (class_min_share - 1e-9 <= legit_share <= class_max_share + 1e-9):
        raise ValueError(f"Legitimate share {legit_share:.3f} outside allowed range")
    if not (class_min_share - 1e-9 <= phish_share_final <= class_max_share + 1e-9):
        raise ValueError(f"Phishing share {phish_share_final:.3f} outside allowed range")
    if n_legitimate == n_phishing and chosen_total % 2 == 0:
        # Equality is allowed if the draw lands there, but is not required.
        pass
    return n_legitimate, n_phishing, chosen_total


def _median(values: list[int]) -> float:
    if not values:
        return 0.0
    return float(statistics.median(values))


def _length_bins(lengths: list[int]) -> dict[str, int]:
    bins = {"0-99": 0, "100-399": 0, "400-999": 0, "1000-2999": 0, "3000+": 0}
    for length in lengths:
        if length < 100:
            bins["0-99"] += 1
        elif length < 400:
            bins["100-399"] += 1
        elif length < 1000:
            bins["400-999"] += 1
        elif length < 3000:
            bins["1000-2999"] += 1
        else:
            bins["3000+"] += 1
    return bins


def load_meajor_records(path: Path, min_body_letters: int) -> list[RawRecord]:
    records: list[RawRecord] = []
    with Path(path).open(encoding="utf-8", newline="", errors="replace") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"No header row in {path}")
        required = {"subject", "body", "label"}
        missing = required.difference(reader.fieldnames)
        if missing:
            raise ValueError(f"MeAJOR file missing columns {sorted(missing)}")
        for row in reader:
            mapped = map_source_label(row.get("label"))
            if mapped is None:
                continue
            subject = normalize_text(row.get("subject"))
            body = normalize_text(row.get("body"))
            language = "" if row.get("language") is None else str(row.get("language")).strip()
            source = "" if row.get("source") is None else str(row.get("source")).strip()
            if source.lower() in {"", "nan", "none"}:
                source = "unknown"
            records.append(
                RawRecord(
                    subject=subject,
                    body=body,
                    label=mapped,
                    language=language,
                    source=source,
                    english=is_english_language(language),
                    usable_body=has_usable_body(body, min_body_letters),
                )
            )
    return records


def _placeholder_audit(records: list[RawRecord]) -> dict:
    by_label = {label: Counter() for label in ("legitimate", "phishing")}
    rows_with = {label: Counter() for label in ("legitimate", "phishing")}
    live = {label: {"urls": 0, "rows": 0} for label in ("legitimate", "phishing")}
    for record in records:
        text = f"{record.subject}\n{record.body}"
        counts = placeholder_counts(text)
        for name, count in counts.items():
            by_label[record.label][name] += count
            if count:
                rows_with[record.label][name] += 1
        n_live = live_url_count(text)
        live[record.label]["urls"] += n_live
        if n_live:
            live[record.label]["rows"] += 1
    suspicious = []
    n_by_label = Counter(record.label for record in records)
    for name in PLACEHOLDER_PATTERNS:
        rates = {}
        for label in ("legitimate", "phishing"):
            total = max(n_by_label[label], 1)
            rates[label] = rows_with[label][name] / total
        if abs(rates["legitimate"] - rates["phishing"]) >= 0.25 and max(rates.values()) >= 0.10:
            suspicious.append(
                {
                    "placeholder": name,
                    "row_rate_legitimate": round(rates["legitimate"], 4),
                    "row_rate_phishing": round(rates["phishing"], 4),
                    "note": "Class-dependent placeholder rate in source text before cleanup.",
                }
            )
    return {
        "token_counts_by_label": {label: dict(counter) for label, counter in by_label.items()},
        "row_counts_by_label": {label: dict(counter) for label, counter in rows_with.items()},
        "live_urls_before_rewrite": live,
        "suspicious_class_dependent_placeholders": suspicious,
    }


def _deduplicate(records: list[RawRecord]) -> tuple[list[RawRecord], dict]:
    grouped: dict[tuple[str, str], list[RawRecord]] = defaultdict(list)
    for record in records:
        grouped[exact_text_key(record.subject, record.body)].append(record)
    kept: list[RawRecord] = []
    exact_removed = Counter()
    conflicting = 0
    for _key, items in grouped.items():
        labels = {item.label for item in items}
        if len(labels) > 1:
            conflicting += len(items)
            continue
        kept.append(items[0])
        exact_removed[items[0].label] += len(items) - 1
    return kept, {
        "exact_duplicate_rows_removed_by_label": dict(exact_removed),
        "conflicting_label_duplicate_rows_excluded": conflicting,
        "conflicting_label_duplicate_groups": sum(
            1 for items in grouped.values() if len({item.label for item in items}) > 1
        ),
    }


def _cap_near_duplicates(
    records: list[RawRecord],
    rng: Random,
    prefix_chars: int,
    max_per_cluster: int,
) -> tuple[list[RawRecord], dict]:
    clusters: dict[str, list[RawRecord]] = defaultdict(list)
    for record in records:
        clusters[near_duplicate_key(record.subject, record.body, prefix_chars)].append(record)
    kept: list[RawRecord] = []
    cluster_sizes = []
    dropped = 0
    for members in clusters.values():
        cluster_sizes.append(len(members))
        if len(members) <= max_per_cluster:
            kept.extend(members)
            continue
        rng.shuffle(members)
        kept.extend(members[:max_per_cluster])
        dropped += len(members) - max_per_cluster
    multi = [size for size in cluster_sizes if size > 1]
    return kept, {
        "method": (
            "lowercase alphanumeric prefix of subject+body "
            f"({prefix_chars} chars) after stripping [placeholders] and <|tokens|>"
        ),
        "clusters_total": len(clusters),
        "clusters_with_more_than_one": len(multi),
        "largest_cluster": max(cluster_sizes) if cluster_sizes else 0,
        "rows_dropped_by_cluster_cap": dropped,
        "max_kept_per_cluster": max_per_cluster,
    }


def _sample_source_aware(
    records: list[RawRecord],
    n: int,
    rng: Random,
) -> list[RawRecord]:
    by_source: dict[str, list[RawRecord]] = defaultdict(list)
    for record in records:
        by_source[record.source].append(record)
    for bag in by_source.values():
        rng.shuffle(bag)
    sources = list(by_source)
    rng.shuffle(sources)
    selected: list[RawRecord] = []
    while len(selected) < n and any(by_source[source] for source in sources):
        for source in sources:
            if len(selected) >= n:
                break
            if by_source[source]:
                selected.append(by_source[source].pop())
    return selected


def _stats_for(records: list[RawRecord]) -> dict:
    if not records:
        return {"count": 0}
    subjects = [item.subject for item in records]
    bodies = [item.body for item in records]
    sub_len = [len(item) for item in subjects]
    body_len = [len(item) for item in bodies]
    return {
        "count": len(records),
        "subject_present_pct": round(100 * sum(1 for item in subjects if item) / len(records), 2),
        "body_present_pct": round(100 * sum(1 for item in bodies if item) / len(records), 2),
        "median_subject_length": _median(sub_len),
        "median_body_length": _median(body_len),
        "body_length_distribution": _length_bins(body_len),
    }


def _source_label_counts(records: list[RawRecord]) -> dict[str, dict[str, int]]:
    table: dict[str, Counter] = defaultdict(Counter)
    for record in records:
        table[record.source][record.label] += 1
    return {source: dict(counter) for source, counter in sorted(table.items())}


def _record_with_text(record: RawRecord, subject: str, body: str) -> RawRecord:
    return RawRecord(
        subject=subject,
        body=body,
        label=record.label,
        language=record.language,
        source=record.source,
        english=record.english,
        usable_body=has_usable_body(body),
    )


def _remaining_artifact_scan(records: list[RawRecord]) -> dict:
    recognized = _placeholder_audit(records)
    n_by_label = Counter(record.label for record in records)
    other: dict[str, dict[str, dict[str, int]]] = {
        name: {label: {"rows": 0, "hits": 0} for label in ("legitimate", "phishing")}
        for name in _OTHER_ARTIFACT_PATTERNS
    }
    examples: list[dict[str, str]] = []
    for record in records:
        text = f"{record.subject}\n{record.body}"
        for name, pattern in _OTHER_ARTIFACT_PATTERNS.items():
            hits = pattern.findall(text)
            if not hits:
                continue
            other[name][record.label]["rows"] += 1
            other[name][record.label]["hits"] += len(hits)
            if len(examples) < 8:
                examples.append({"pattern": name, "label": record.label, "sample": str(hits[0])[:80]})
    class_dependent = []
    for name, by_label in other.items():
        rates = {}
        for label in ("legitimate", "phishing"):
            total = max(n_by_label[label], 1)
            rates[label] = by_label[label]["rows"] / total
        if abs(rates["legitimate"] - rates["phishing"]) >= 0.25 and max(rates.values()) >= 0.10:
            class_dependent.append(
                {
                    "pattern": name,
                    "row_rate_legitimate": round(rates["legitimate"], 4),
                    "row_rate_phishing": round(rates["phishing"], 4),
                    "note": "Reported only; not silently removed.",
                }
            )
    recognized_hits = 0
    for label in ("legitimate", "phishing"):
        recognized_hits += sum(recognized["token_counts_by_label"][label].values())
    return {
        "recognized_placeholders_remaining": recognized_hits > 0,
        "recognized_placeholder_audit": recognized,
        "other_source_format_patterns": other,
        "other_pattern_examples": examples,
        "class_dependent_other_patterns": class_dependent,
    }


def write_seed_csv(records: list[dict[str, str]], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SEED_CSV_COLUMNS), extrasaction="raise")
        writer.writeheader()
        for row in records:
            writer.writerow({column: row[column] for column in SEED_CSV_COLUMNS})
    return path


def validate_seed_csv(
    path: Path,
    *,
    class_min_share: float = SEED_CLASS_MIN_SHARE,
    class_max_share: float = SEED_CLASS_MAX_SHARE,
    target_total: int = SEED_TARGET_TOTAL,
    total_jitter: int = SEED_TOTAL_JITTER,
) -> dict:
    with Path(path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    if fieldnames != list(SEED_CSV_COLUMNS):
        raise ValueError(f"Unexpected seed columns: {fieldnames}")
    n = len(rows)
    low = target_total - total_jitter - 5
    high = target_total + total_jitter + 5
    if not (low <= n <= high):
        raise ValueError(f"Seed count {n} is not approximately {target_total}")
    labels = [row["label"] for row in rows]
    counts = Counter(labels)
    if set(counts) != {"legitimate", "phishing"}:
        raise ValueError(f"Expected both labels, got {dict(counts)}")
    for label, count in counts.items():
        share = count / n
        if share < class_min_share or share > class_max_share:
            raise ValueError(f"{label} share {share:.3f} outside {class_min_share}-{class_max_share}")
    if len({row["seed_id"] for row in rows}) != n:
        raise ValueError("seed_id values are not unique")
    keys = [(row["subject"], row["body_plain"]) for row in rows]
    if len(set(keys)) != n:
        raise ValueError("Exact duplicate subject+body rows present")
    by_text: dict[tuple[str, str], set[str]] = defaultdict(set)
    for row in rows:
        by_text[(row["subject"], row["body_plain"])].add(row["label"])
    if any(len(labels) > 1 for labels in by_text.values()):
        raise ValueError("Conflicting labels for the same subject+body")
    for row in rows:
        if not has_usable_body(row["body_plain"]):
            raise ValueError(f"Unusable body for {row['seed_id']}")
        text = f"{row['subject']}\n{row['body_plain']}"
        live = [item for item in extract_live_url_candidates(text) if is_live_operational_url(item)]
        if live:
            raise ValueError(f"Live URL survived in {row['seed_id']}: {live[0]}")
        if recognized_placeholder_total(text):
            raise ValueError(f"Recognized source placeholder survived in {row['seed_id']}")
    loaded = load_seeds_from_csv(path)
    if len(loaded) != n:
        raise ValueError("Stage 1 generator could not load every seed row")
    return {
        "ok": True,
        "count": n,
        "legitimate": counts["legitimate"],
        "phishing": counts["phishing"],
        "legitimate_pct": round(100 * counts["legitimate"] / n, 2),
        "phishing_pct": round(100 * counts["phishing"] / n, 2),
        "loaded_by_generator": len(loaded),
    }


def prepare_seeds(config: SeedPrepConfig | None = None) -> dict:
    cfg = config or SeedPrepConfig()
    rng = Random(cfg.random_seed)
    source_path = Path(cfg.source_path)
    if not source_path.is_file():
        raise FileNotFoundError(f"MeAJOR source not found: {source_path}")

    raw_records = load_meajor_records(source_path, cfg.min_body_letters)
    original_usable = [item for item in raw_records if item.usable_body and item.label in {"legitimate", "phishing"}]
    english_usable = [item for item in original_usable if item.english]
    english_by_label = Counter(item.label for item in english_usable)

    placeholder_before = _placeholder_audit(english_usable)

    cleaned: list[RawRecord] = []
    rows_affected = 0
    for item in english_usable:
        subject = cleanup_seed_text(item.subject)
        body = cleanup_seed_text(item.body)
        if subject != item.subject or body != item.body:
            rows_affected += 1
        cleaned.append(_record_with_text(item, subject, body))

    dropped_unusable = [item for item in cleaned if not item.usable_body]
    usable_after_cleanup = [item for item in cleaned if item.usable_body]
    placeholder_after = _placeholder_audit(usable_after_cleanup)

    exact_pool, dup_stats = _deduplicate(usable_after_cleanup)
    capped_pool, near_stats = _cap_near_duplicates(
        exact_pool, rng, cfg.near_dup_prefix_chars, cfg.max_per_near_dup_cluster
    )
    available = Counter(item.label for item in capped_pool)
    n_legit, n_phish, chosen_total = choose_class_counts(
        rng,
        available_legitimate=available["legitimate"],
        available_phishing=available["phishing"],
        target_total=cfg.target_total,
        total_jitter=cfg.total_jitter,
        class_min_share=cfg.class_min_share,
        class_max_share=cfg.class_max_share,
    )

    by_label: dict[str, list[RawRecord]] = defaultdict(list)
    for item in capped_pool:
        by_label[item.label].append(item)
    selected_legit = _sample_source_aware(by_label["legitimate"], n_legit, rng)
    selected_phish = _sample_source_aware(by_label["phishing"], n_phish, rng)
    selected = selected_legit + selected_phish
    rng.shuffle(selected)

    export_rows: list[dict[str, str]] = []
    legit_i = 0
    phish_i = 0
    for item in selected:
        if item.label == "legitimate":
            legit_i += 1
            seed_id = f"seed_legit_{legit_i:04d}"
        else:
            phish_i += 1
            seed_id = f"seed_phish_{phish_i:04d}"
        export_rows.append(
            {
                "seed_id": seed_id,
                "label": item.label,
                "subject": item.subject,
                "body_plain": item.body,
            }
        )

    selected_for_stats = []
    for item, row in zip(selected, export_rows, strict=True):
        selected_for_stats.append(
            RawRecord(
                subject=row["subject"],
                body=row["body_plain"],
                label=row["label"],
                language=item.language,
                source=item.source,
                english=True,
                usable_body=True,
            )
        )

    write_seed_csv(export_rows, cfg.output_csv)
    validation = validate_seed_csv(
        cfg.output_csv,
        class_min_share=cfg.class_min_share,
        class_max_share=cfg.class_max_share,
        target_total=cfg.target_total,
        total_jitter=cfg.total_jitter,
    )

    selected_stats = {
        "legitimate": _stats_for([item for item in selected_for_stats if item.label == "legitimate"]),
        "phishing": _stats_for([item for item in selected_for_stats if item.label == "phishing"]),
    }
    text_length_flag = None
    med_legit = selected_stats["legitimate"].get("median_body_length", 0)
    med_phish = selected_stats["phishing"].get("median_body_length", 0)
    if med_legit and med_phish:
        ratio = max(med_legit, med_phish) / max(min(med_legit, med_phish), 1)
        if ratio >= 8:
            text_length_flag = {
                "note": "Extreme median body-length gap; inspect for corpus construction artifact.",
                "median_body_legitimate": med_legit,
                "median_body_phishing": med_phish,
            }

    remaining_artifacts = _remaining_artifact_scan(selected_for_stats)
    planned_profiles = {
        "legitimate": allocate_profile_counts(n_legit, "legitimate"),
        "phishing": allocate_profile_counts(n_phish, "phishing"),
    }

    report = {
        "disclaimer": (
            "Seed counts and source mix are dataset-construction choices, "
            "not real-world phishing prevalence."
        ),
        "source_path": str(source_path.resolve()),
        "random_seed": cfg.random_seed,
        "original_rows_read": len(raw_records),
        "original_usable_counts": dict(Counter(item.label for item in original_usable)),
        "english_usable_counts": dict(english_by_label),
        "english_filter": "language field tokens are all 'en' (e.g. en, en;en)",
        "placeholder_cleanup": {
            "method": (
                "Label-agnostic removal of recognized MeAJOR anonymization tokens "
                "and live operational URLs, then whitespace/punctuation normalization. "
                "No semantically informative replacement tokens and no URL insertion."
            ),
            "rows_affected": rows_affected,
            "rows_dropped_unusable_after_cleanup": len(dropped_unusable),
            "rows_dropped_unusable_after_cleanup_by_label": dict(
                Counter(item.label for item in dropped_unusable)
            ),
            "placeholder_counts_before": placeholder_before,
            "placeholder_counts_after": placeholder_after,
            "recognized_placeholders_remaining": remaining_artifacts["recognized_placeholders_remaining"],
        },
        "chosen_target_total": chosen_total,
        "final_legitimate_count": n_legit,
        "final_phishing_count": n_phish,
        "final_class_percentages": {
            "legitimate": round(100 * n_legit / chosen_total, 2),
            "phishing": round(100 * n_phish / chosen_total, 2),
        },
        "planned_profile_allocation": planned_profiles,
        "duplicate_removals": dup_stats,
        "near_duplicate_statistics": near_stats,
        "source_label_availability_english_usable": _source_label_counts(english_usable),
        "source_label_selected_counts": _source_label_counts(selected_for_stats),
        "placeholder_frequency_by_label": {
            "before_cleanup": placeholder_before,
            "after_cleanup": placeholder_after,
        },
        "text_length_statistics": selected_stats,
        "remaining_source_artifacts": remaining_artifacts,
        "suspicious_text_artifacts": {
            "placeholders_before_cleanup": placeholder_before.get(
                "suspicious_class_dependent_placeholders", []
            ),
            "body_length": text_length_flag,
            "other_class_dependent_after_cleanup": remaining_artifacts["class_dependent_other_patterns"],
            "simbol_note": (
                "<|SIMBOL|> and similar MeAJOR markup tokens are removed by the "
                "same label-agnostic cleanup as other recognized source placeholders."
            ),
        },
        "validation": validation,
        "output_csv": str(Path(cfg.output_csv).resolve()),
        "profile_note": (
            "Seed labels do not choose technical profiles. Stage 3 must allocate "
            "profiles independently from DESIGN.md 1,000-base weights scaled to "
            "these class counts via largest remainder."
        ),
    }
    report_path = Path(cfg.report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    report["report_path"] = str(report_path.resolve())
    return report
