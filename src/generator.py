# Orchestrate seed → profile → scenario → .eml → manifest. Does not train a model.

from __future__ import annotations

import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from random import Random

from src.config import (
    DEFAULT_RANDOM_SEED,
    MANIFEST_AUDIT_FIELDS,
    MANIFEST_REQUIRED_FIELDS,
    CoverageLevel,
    Label,
    ProfileName,
)
from src.eml_builder import write_eml
from src.profile_allocation import allocate_profile_counts
from src.profiles import all_profile_names
from src.scenarios import ContentSeed, GenerationScenario, assemble_scenario, validate_seed


@dataclass(frozen=True)
class GeneratorConfig:
    random_seed: int = DEFAULT_RANDOM_SEED
    profile_label_counts: dict[ProfileName, dict[Label, int]] | None = None
    output_dir: Path | None = None
    unique_seeds_required: bool = True

    def counts(self) -> dict[ProfileName, dict[Label, int]] | None:
        return self.profile_label_counts


def load_seeds(records: list[dict]) -> list[ContentSeed]:
    seeds = [validate_seed(record) for record in records]
    seen: set[str] = set()
    for seed in seeds:
        if seed.seed_id in seen:
            raise ValueError(f"Duplicate content_seed_id in input: {seed.seed_id}")
        seen.add(seed.seed_id)
    return seeds


def load_seeds_from_csv(path: Path) -> list[ContentSeed]:
    records = []
    with Path(path).open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        for row in reader:
            records.append(
                {
                    "seed_id": row.get("seed_id", ""),
                    "label": row.get("label", ""),
                    "subject": row.get("subject", ""),
                    "body_plain": row.get("body_plain", ""),
                }
            )
    extra = set(fieldnames) - {"seed_id", "label", "subject", "body_plain"}
    if extra:
        raise ValueError(f"Seed CSV contains unexpected columns: {sorted(extra)}")
    return load_seeds(records)


def load_seeds_from_jsonl(path: Path) -> list[ContentSeed]:
    records = []
    with Path(path).open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return load_seeds(records)


def assign_profiles(
    seeds: list[ContentSeed],
    rng: Random,
    counts: dict[ProfileName, dict[Label, int]] | None = None,
) -> list[tuple[ContentSeed, ProfileName]]:
    by_label: dict[Label, list[ContentSeed]] = defaultdict(list)
    for seed in seeds:
        by_label[seed.label].append(seed)

    if counts is None:
        counts = {}
        for label, group in by_label.items():
            allocated = allocate_profile_counts(len(group), label)
            for profile, n in allocated.items():
                counts.setdefault(profile, {})[label] = n

    remaining: dict[Label, dict[ProfileName, int]] = {
        "legitimate": {name: counts.get(name, {}).get("legitimate", 0) for name in all_profile_names()},
        "phishing": {name: counts.get(name, {}).get("phishing", 0) for name in all_profile_names()},
    }
    assigned: list[tuple[ContentSeed, ProfileName]] = []
    for label, group in by_label.items():
        shuffled = list(group)
        rng.shuffle(shuffled)
        quota = remaining[label]
        needed = sum(quota.values())
        if needed != len(shuffled):
            raise ValueError(
                f"Profile allocation for {label} is {needed}, but {len(shuffled)} seeds are available"
            )
        cursor = 0
        for profile, n in quota.items():
            for _ in range(n):
                assigned.append((shuffled[cursor], profile))
                cursor += 1
    rng.shuffle(assigned)
    return assigned


def scenario_to_manifest_row(scenario: GenerationScenario, filename: str) -> dict[str, str]:
    row = {
        "sample_id": scenario.sample_id,
        "label": scenario.label,
        "content_seed_id": scenario.seed.seed_id,
        "profile": scenario.profile,
        "coverage_level": scenario.coverage_level,
        "is_simulated": "true",
        "header_template_id": scenario.templates.header_template_id,
        "body_template_id": scenario.templates.body_template_id,
        "random_seed": str(scenario.random_seed),
        "filename": filename,
        "spf": scenario.state.spf or "",
        "dkim": scenario.state.dkim or "",
        "dmarc": scenario.state.dmarc or "",
        "reply_to_mode": scenario.state.reply_to_mode,
        "return_path_mode": scenario.state.return_path_mode,
        "url_mode": scenario.state.url_mode,
        "attachment_mode": scenario.state.attachment_mode,
        "body_format": scenario.state.body_format,
        "received_count": str(scenario.state.received_count),
        "logical_url_count": str(scenario.logical_url_count),
        "logical_unique_url_count": str(scenario.logical_unique_url_count),
        "url_rendering_mode": scenario.url_rendering_mode,
        "from_template_id": scenario.templates.from_template.template_id,
        "reply_to_template_id": (
            scenario.templates.reply_to_template.template_id if scenario.templates.reply_to_template else ""
        ),
        "return_path_template_id": (
            scenario.templates.return_path_template.template_id if scenario.templates.return_path_template else ""
        ),
        "received_template_id": scenario.templates.received_template.template_id,
        "auth_results_template_id": (
            scenario.templates.auth_results_template.template_id if scenario.templates.auth_results_template else ""
        ),
        "received_spf_template_id": (
            scenario.templates.received_spf_template.template_id if scenario.templates.received_spf_template else ""
        ),
        "attachment_name_template_id": (
            scenario.templates.attachment_name_template.template_id
            if scenario.templates.attachment_name_template
            else ""
        ),
    }
    for key in MANIFEST_REQUIRED_FIELDS:
        if key not in row or row[key] == "":
            if key == "header_template_id":
                continue
            if not row.get(key):
                raise ValueError(f"Manifest missing required provenance field {key}")
    return row


def write_manifest(rows: list[dict[str, str]], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(MANIFEST_REQUIRED_FIELDS) + [item for item in MANIFEST_AUDIT_FIELDS if item not in MANIFEST_REQUIRED_FIELDS]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})
    return path


def _sample_id(index: int, label: Label, seed_id: str) -> str:
    prefix = "leg" if label == "legitimate" else "phs"
    return f"syn-{prefix}-{index:04d}-{seed_id}"


def generate_from_seeds(
    seeds: list[ContentSeed],
    output_dir: Path,
    *,
    config: GeneratorConfig | None = None,
    coverage_by_seed: dict[str, CoverageLevel] | None = None,
    profile_by_seed: dict[str, ProfileName] | None = None,
) -> dict:
    """Generate .eml files and a provenance manifest. Stage 1 helper; not the v1 2,000 run."""
    cfg = config or GeneratorConfig()
    rng = Random(cfg.random_seed)
    output_dir = Path(output_dir)
    email_root = output_dir / "emails"
    if profile_by_seed:
        assigned = [(seed, profile_by_seed[seed.seed_id]) for seed in seeds]
    else:
        assigned = assign_profiles(seeds, rng, cfg.counts())

    rows: list[dict[str, str]] = []
    scenarios: list[GenerationScenario] = []
    for index, (seed, profile) in enumerate(assigned, start=1):
        requested_coverage = None if coverage_by_seed is None else coverage_by_seed.get(seed.seed_id)
        sample_id = _sample_id(index, seed.label, seed.seed_id)
        scenario = assemble_scenario(
            seed,
            profile,
            rng,
            coverage=requested_coverage,
            sample_id=sample_id,
            random_seed=cfg.random_seed,
        )
        rel = Path(seed.label) / f"{sample_id}.eml"
        write_eml(scenario, email_root / rel)
        rows.append(scenario_to_manifest_row(scenario, str(rel).replace("\\", "/")))
        scenarios.append(scenario)

    manifest_path = write_manifest(rows, output_dir / "manifest.csv")
    return {
        "output_dir": str(output_dir),
        "manifest_path": str(manifest_path),
        "count": len(scenarios),
        "scenarios": scenarios,
        "rows": rows,
    }
