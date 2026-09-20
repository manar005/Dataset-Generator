# Stage 3B full-corpus generation. One .eml per Stage 2 content seed.

from __future__ import annotations

import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from random import Random

from src.config import DEFAULT_FULL_OUTPUT, DEFAULT_RANDOM_SEED, DEFAULT_SEED_CSV, EXPECTED_FULL_TOTAL
from src.generator import GeneratorConfig, assign_profiles, generate_from_seeds, load_seeds_from_csv
from src.pilot import plan_coverage
from src.profile_allocation import allocate_profile_counts
from src.quality_report import build_quality_report, write_quality_report
from src.validator import ValidationError, validate_corpus


@dataclass(frozen=True)
class FullCorpusConfig:
    seed_csv: Path = DEFAULT_SEED_CSV
    output_dir: Path = DEFAULT_FULL_OUTPUT
    random_seed: int = DEFAULT_RANDOM_SEED
    unique_seeds_required: bool = True
    expected_total: int | None = EXPECTED_FULL_TOTAL


def _clear_generated_emails(output_dir: Path) -> None:
    email_root = output_dir / "emails"
    if email_root.is_dir():
        shutil.rmtree(email_root)
    manifest = output_dir / "manifest.csv"
    if manifest.is_file():
        manifest.unlink()
    report_path = output_dir / "quality_report.json"
    if report_path.is_file():
        report_path.unlink()


def _file_consistency(output_dir: Path, rows: list[dict[str, str]]) -> dict:
    email_root = output_dir / "emails"
    on_disk = {path.relative_to(email_root).as_posix() for path in email_root.rglob("*.eml")}
    listed = {row["filename"] for row in rows}
    return {
        "eml_files": len(on_disk),
        "manifest_rows": len(rows),
        "orphan_files": sorted(on_disk - listed),
        "missing_files": sorted(listed - on_disk),
    }


def generate_full_corpus(config: FullCorpusConfig | None = None) -> dict:
    cfg = config or FullCorpusConfig()
    seed_csv = Path(cfg.seed_csv)
    if not seed_csv.is_file():
        raise FileNotFoundError(f"Content seed CSV not found: {seed_csv}")
    output_dir = Path(cfg.output_dir)
    parts = [part.lower() for part in output_dir.parts]
    if output_dir.name.lower() != "full":
        raise ValueError(f"Full corpus output must be a dedicated full directory, got {output_dir}")
    if "pilot" in parts:
        raise ValueError("Full corpus must not be written into the pilot directory")

    _clear_generated_emails(output_dir)

    seeds = load_seeds_from_csv(seed_csv)
    if cfg.expected_total is not None and len(seeds) != cfg.expected_total:
        raise ValueError(f"Expected {cfg.expected_total} seeds, found {len(seeds)} in {seed_csv}")
    labels = Counter(item.label for item in seeds)
    if labels["legitimate"] == 0 or labels["phishing"] == 0:
        raise ValueError(f"Both labels required, got {dict(labels)}")

    rng = Random(cfg.random_seed)
    ordered = sorted(seeds, key=lambda item: item.seed_id)
    assigned = assign_profiles(ordered, rng)
    coverage_by_seed = plan_coverage(assigned, rng)
    profile_by_seed = {seed.seed_id: profile for seed, profile in assigned}
    allocation = {
        "legitimate": allocate_profile_counts(labels["legitimate"], "legitimate"),
        "phishing": allocate_profile_counts(labels["phishing"], "phishing"),
    }

    result = generate_from_seeds(
        ordered,
        output_dir,
        config=GeneratorConfig(random_seed=cfg.random_seed, unique_seeds_required=cfg.unique_seeds_required),
        profile_by_seed=profile_by_seed,
        coverage_by_seed=coverage_by_seed,
    )
    if result["count"] != len(seeds):
        raise ValidationError(f"Generated {result['count']} messages, expected {len(seeds)}")

    validation = validate_corpus(output_dir, unique_seeds=cfg.unique_seeds_required)
    files = _file_consistency(output_dir, result["rows"])
    if files["orphan_files"] or files["missing_files"]:
        raise ValidationError(f"Manifest/file mismatch: {files}")

    seeds_by_id = {item.seed_id: item for item in seeds}
    report = build_quality_report(
        output_dir,
        unique_seeds_expected=cfg.unique_seeds_required,
        seeds_by_id=seeds_by_id,
    )
    n = result["count"]
    sample_ids = [row["sample_id"] for row in result["rows"]]
    seed_ids = [row["content_seed_id"] for row in result["rows"]]
    report["corpus"] = {
        "total": n,
        "class_counts": dict(labels),
        "class_percentages": {
            "legitimate": round(100 * labels["legitimate"] / n, 2),
            "phishing": round(100 * labels["phishing"] / n, 2),
        },
        "planned_profile_allocation": allocation,
        "random_seed": cfg.random_seed,
        "seed_csv": str(seed_csv.resolve()),
        "file_consistency": files,
        "duplication": {
            "unique_sample_ids": len(set(sample_ids)) == n,
            "unique_content_seed_ids": len(set(seed_ids)) == n,
            "one_message_per_seed": n == len(seeds) == len(set(seed_ids)),
        },
        "validation": validation,
    }
    write_quality_report(output_dir, report)
    result["validation"] = validation
    result["quality_report_path"] = str((output_dir / "quality_report.json").resolve())
    result["class_counts"] = dict(labels)
    result["quality_report"] = report
    result["planned_profile_allocation"] = allocation
    result["file_consistency"] = files
    return result
