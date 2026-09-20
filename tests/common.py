# Test-only fixtures. Not training data. Never written under data/seeds/.

from __future__ import annotations

import sys
from pathlib import Path
from random import Random

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.scenarios import ContentSeed, assemble_scenario


def fixture_seed(seed_id: str, label: str, subject: str | None = None, body: str | None = None) -> ContentSeed:
    return ContentSeed(
        seed_id=seed_id,
        label=label,
        subject=subject or f"Fixture subject {seed_id}",
        body_plain=body or f"Fixture body for {seed_id}. This is not training data.",
    )


def make_scenario(
    profile,
    coverage,
    label="legitimate",
    *,
    random_seed=7,
    sample_id="t-sample",
    url_mode_override=None,
    body_format_override=None,
):
    rng = Random(random_seed)
    seed = fixture_seed(f"{sample_id}-{label}", label)
    return assemble_scenario(
        seed,
        profile,
        rng,
        coverage=coverage,
        sample_id=sample_id,
        random_seed=random_seed,
        url_mode_override=url_mode_override,
        body_format_override=body_format_override,
    )


def scenario_matching(profile, coverage, predicate, label="legitimate", max_tries=80):
    for value in range(1, max_tries + 1):
        scenario = make_scenario(profile, coverage, label, random_seed=value, sample_id=f"m{value}")
        if predicate(scenario):
            return scenario
    raise AssertionError(f"No matching scenario for {profile}/{coverage}")

