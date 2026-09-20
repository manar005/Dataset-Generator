# CLI for Stage 3B full-corpus generation. Does not train a model.

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.config import DEFAULT_FULL_OUTPUT, DEFAULT_RANDOM_SEED, DEFAULT_SEED_CSV, EXPECTED_FULL_TOTAL
from src.full_corpus import FullCorpusConfig, generate_full_corpus


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the Dataset-Generator Stage 3B full corpus.")
    parser.add_argument("--seeds", type=Path, default=DEFAULT_SEED_CSV)
    parser.add_argument("--output", type=Path, default=DEFAULT_FULL_OUTPUT)
    parser.add_argument("--random-seed", type=int, default=DEFAULT_RANDOM_SEED)
    parser.add_argument("--expected-total", type=int, default=EXPECTED_FULL_TOTAL)
    args = parser.parse_args()
    result = generate_full_corpus(
        FullCorpusConfig(
            seed_csv=args.seeds,
            output_dir=args.output,
            random_seed=args.random_seed,
            expected_total=args.expected_total,
        )
    )
    report = result["quality_report"]
    print(
        json.dumps(
            {
                "output_dir": result["output_dir"],
                "count": result["count"],
                "class_counts": result["class_counts"],
                "planned_profile_allocation": result["planned_profile_allocation"],
                "file_consistency": result["file_consistency"],
                "validation": result["validation"],
                "parsed": report.get("parsed"),
                "parser_failures": len(report.get("parser_failures") or []),
                "extraction_failures": len(report.get("extraction_failures") or []),
                "intent_mismatches": report.get("intent_vs_observed", {}).get("mismatch_count"),
                "url_flagged_count": (report.get("url_count_audit") or {}).get("flagged_count"),
                "shortcut_warnings": report.get("warnings", []),
                "quality_report_path": result["quality_report_path"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
