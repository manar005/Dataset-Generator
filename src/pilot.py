# Stage 3A real-seed generation pilot. Does not generate the full corpus.

from __future__ import annotations

import json
import shutil
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from random import Random

from src.config import (
    DEFAULT_PILOT_OUTPUT,
    DEFAULT_RANDOM_SEED,
    DEFAULT_SEED_CSV,
    PILOT_FRACTION,
    PILOT_MIN_PER_LABEL,
    PROFILE_ALLOWED_COVERAGE,
    CoverageLevel,
    Label,
    ProfileName,
)
from src.generator import GeneratorConfig, assign_profiles, generate_from_seeds, load_seeds_from_csv
from src.profile_allocation import allocate_profile_counts
from src.quality_report import build_quality_report, write_quality_report
from src.scenarios import ContentSeed, choose_coverage
from src.validator import validate_corpus


@dataclass(frozen=True)
class PilotConfig:
    seed_csv: Path = DEFAULT_SEED_CSV
    output_dir: Path = DEFAULT_PILOT_OUTPUT
    random_seed: int = DEFAULT_RANDOM_SEED
    fraction: float = PILOT_FRACTION
    min_per_label: int = PILOT_MIN_PER_LABEL
    unique_seeds_required: bool = True


def choose_pilot_class_counts(
    available_legitimate: int,
    available_phishing: int,
    *,
    fraction: float = PILOT_FRACTION,
    min_per_label: int = PILOT_MIN_PER_LABEL,
) -> tuple[int, int]:
    """Scale each class by fraction. Preserves the source ratio; not forced 50/50."""
    if not 0 < fraction <= 1:
        raise ValueError(f"pilot_fraction must be in (0, 1], got {fraction}")
    if available_legitimate < min_per_label or available_phishing < min_per_label:
        raise ValueError(
            f"Need at least {min_per_label} seeds per label for profile coverage, "
            f"got legitimate={available_legitimate} phishing={available_phishing}"
        )
    n_legit = int(round(available_legitimate * fraction))
    n_phish = int(round(available_phishing * fraction))
    n_legit = min(max(n_legit, min_per_label), available_legitimate)
    n_phish = min(max(n_phish, min_per_label), available_phishing)
    return n_legit, n_phish


def select_pilot_seeds(
    seeds: list[ContentSeed],
    rng: Random,
    *,
    fraction: float = PILOT_FRACTION,
    min_per_label: int = PILOT_MIN_PER_LABEL,
) -> list[ContentSeed]:
    """Label-aware count only. Does not inspect subject/body text."""
    by_label: dict[Label, list[ContentSeed]] = defaultdict(list)
    for seed in seeds:
        by_label[seed.label].append(seed)
    n_legit, n_phish = choose_pilot_class_counts(
        len(by_label["legitimate"]),
        len(by_label["phishing"]),
        fraction=fraction,
        min_per_label=min_per_label,
    )
    legit = list(by_label["legitimate"])
    phish = list(by_label["phishing"])
    rng.shuffle(legit)
    rng.shuffle(phish)
    selected = legit[:n_legit] + phish[:n_phish]
    rng.shuffle(selected)
    return selected


def min_rich_for_label(n: int) -> int:
    if n < 6:
        return 0
    return max(2, int(round(0.08 * n)))


def plan_coverage(
    assigned: list[tuple[ContentSeed, ProfileName]],
    rng: Random,
) -> dict[str, CoverageLevel]:
    """Sample allowed coverage, then guarantee both labels have rich and missingness."""
    coverage: dict[str, CoverageLevel] = {}
    for seed, profile in assigned:
        coverage[seed.seed_id] = choose_coverage(profile, rng)

    by_label: dict[Label, list[tuple[ContentSeed, ProfileName]]] = defaultdict(list)
    for seed, profile in assigned:
        by_label[seed.label].append((seed, profile))

    for _label, items in by_label.items():
        need_rich = min_rich_for_label(len(items))
        rich_now = [seed for seed, _profile in items if coverage[seed.seed_id] == "rich"]
        if len(rich_now) < need_rich:
            candidates = [
                (seed, profile)
                for seed, profile in items
                if "rich" in PROFILE_ALLOWED_COVERAGE[profile] and coverage[seed.seed_id] != "rich"
            ]
            candidates.sort(key=lambda item: item[0].seed_id)
            for seed, _profile in candidates[: need_rich - len(rich_now)]:
                coverage[seed.seed_id] = "rich"

        missing_like = [
            seed for seed, _profile in items if coverage[seed.seed_id] in {"low", "partial"}
        ]
        if not missing_like:
            candidates = [
                (seed, profile)
                for seed, profile in items
                if any(level in PROFILE_ALLOWED_COVERAGE[profile] for level in ("low", "partial"))
            ]
            candidates.sort(key=lambda item: item[0].seed_id)
            if candidates:
                seed, profile = candidates[0]
                allowed = PROFILE_ALLOWED_COVERAGE[profile]
                coverage[seed.seed_id] = "low" if "low" in allowed else "partial"
    return coverage


def generate_pilot(config: PilotConfig | None = None) -> dict:
    cfg = config or PilotConfig()
    seed_csv = Path(cfg.seed_csv)
    if not seed_csv.is_file():
        raise FileNotFoundError(f"Content seed CSV not found: {seed_csv}")
    output_dir = Path(cfg.output_dir)
    if "pilot" not in output_dir.as_posix().lower():
        raise ValueError(f"Pilot output must be a dedicated pilot directory, got {output_dir}")
    email_root = output_dir / "emails"
    if email_root.is_dir():
        shutil.rmtree(email_root)

    all_seeds = load_seeds_from_csv(seed_csv)
    rng = Random(cfg.random_seed)
    selected = select_pilot_seeds(
        all_seeds,
        rng,
        fraction=cfg.fraction,
        min_per_label=cfg.min_per_label,
    )
    selected = sorted(selected, key=lambda item: item.seed_id)
    assigned = assign_profiles(selected, rng)
    coverage_by_seed = plan_coverage(assigned, rng)
    profile_by_seed = {seed.seed_id: profile for seed, profile in assigned}
    allocation = {
        "legitimate": allocate_profile_counts(
            sum(1 for item in selected if item.label == "legitimate"), "legitimate"
        ),
        "phishing": allocate_profile_counts(
            sum(1 for item in selected if item.label == "phishing"), "phishing"
        ),
    }

    result = generate_from_seeds(
        selected,
        output_dir,
        config=GeneratorConfig(random_seed=cfg.random_seed, unique_seeds_required=cfg.unique_seeds_required),
        profile_by_seed=profile_by_seed,
        coverage_by_seed=coverage_by_seed,
    )
    validation = validate_corpus(output_dir, unique_seeds=cfg.unique_seeds_required)
    seeds_by_id = {item.seed_id: item for item in selected}
    report = build_quality_report(
        output_dir,
        unique_seeds_expected=cfg.unique_seeds_required,
        seeds_by_id=seeds_by_id,
    )
    report["pilot"] = {
        "fraction": cfg.fraction,
        "random_seed": cfg.random_seed,
        "seed_csv": str(seed_csv.resolve()),
        "selected_seed_ids": [item.seed_id for item in selected],
        "class_counts": dict(Counter(item.label for item in selected)),
        "planned_profile_allocation": allocation,
        "validation": validation,
    }
    write_quality_report(output_dir, report)

    selection_path = output_dir / "pilot_selection.json"
    selection_path.write_text(
        json.dumps(
            {
                "disclaimer": "Pilot subset of Stage 2 seeds. Not a prevalence sample and not a trained model.",
                "fraction": cfg.fraction,
                "random_seed": cfg.random_seed,
                "seed_csv": str(seed_csv.resolve()),
                "selected_seed_ids": [item.seed_id for item in selected],
                "class_counts": dict(Counter(item.label for item in selected)),
                "planned_profile_allocation": allocation,
                "coverage_by_seed": coverage_by_seed,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    result["validation"] = validation
    result["quality_report_path"] = str((output_dir / "quality_report.json").resolve())
    result["selection_path"] = str(selection_path.resolve())
    result["selected_seed_ids"] = [item.seed_id for item in selected]
    result["class_counts"] = dict(Counter(item.label for item in selected))
    result["quality_report"] = report
    return result
