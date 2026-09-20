# CLI for Stage 3A real-seed pilot generation. Does not generate the full corpus.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.config import DEFAULT_PILOT_OUTPUT, DEFAULT_RANDOM_SEED, DEFAULT_SEED_CSV, PILOT_FRACTION
from src.pilot import PilotConfig, generate_pilot


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a Dataset-Generator Stage 3A pilot corpus.")
    parser.add_argument("--seeds", type=Path, default=DEFAULT_SEED_CSV)
    parser.add_argument("--output", type=Path, default=DEFAULT_PILOT_OUTPUT)
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED)
    parser.add_argument("--fraction", type=float, default=PILOT_FRACTION)
    args = parser.parse_args()
    result = generate_pilot(
        PilotConfig(
            seed_csv=args.seeds,
            output_dir=args.output,
            random_seed=args.random_seed,
            fraction=args.fraction,
        )
    )
    report = result["quality_report"]
    print(
        json.dumps(
            {
                "output_dir": result["output_dir"],
                "count": result["count"],
                "class_counts": result["class_counts"],
                "validation": result["validation"],
                "parsed": report.get("parsed"),
                "parser_failures": len(report.get("parser_failures") or []),
                "extraction_failures": len(report.get("extraction_failures") or []),
                "url_count_audit": report.get("url_count_audit"),
                "shortcut_warnings": report.get("shortcut_audit", {}).get("warnings", report.get("warnings", [])),
                "quality_report_path": result["quality_report_path"],
                "selection_path": result["selection_path"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
