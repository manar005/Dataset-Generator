# CLI for Stage 2 seed preparation. Does not generate .eml messages.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.config import DEFAULT_MEAJOR_SOURCE, DEFAULT_RANDOM_SEED
from src.seed_prep import SeedPrepConfig, prepare_seeds


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare audited MeAJOR content seeds.")
    parser.add_argument("--source", type=Path, default=DEFAULT_MEAJOR_SOURCE)
    parser.add_argument("--output", type=Path, default=Path("data/seeds/content_seeds.csv"))
    parser.add_argument("--report", type=Path, default=Path("output/seed_preparation_report.json"))
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED)
    args = parser.parse_args()
    report = prepare_seeds(
        SeedPrepConfig(
            source_path=args.source,
            output_csv=args.output,
            report_path=args.report,
            random_seed=args.random_seed,
        )
    )
    print(json.dumps({key: report[key] for key in (
        "source_path",
        "english_usable_counts",
        "placeholder_cleanup",
        "chosen_target_total",
        "final_legitimate_count",
        "final_phishing_count",
        "final_class_percentages",
        "planned_profile_allocation",
        "remaining_source_artifacts",
        "validation",
        "output_csv",
        "report_path",
    )}, indent=2))


if __name__ == "__main__":
    main()
