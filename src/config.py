# Explicit Dataset-Generator v1 configuration.
# These are controlled coverage weights, not real-world prevalence.

from __future__ import annotations

from pathlib import Path
from typing import Literal

Label = Literal["legitimate", "phishing"]
ProfileName = Literal[
    "normal_authenticated",
    "third_party_service",
    "partially_authenticated",
    "authentication_problem",
    "plain_basic",
    "attachment_bearing",
]
CoverageLevel = Literal["low", "partial", "mostly_observable", "rich"]

PROFILE_NAMES: tuple[ProfileName, ...] = (
    "normal_authenticated",
    "third_party_service",
    "partially_authenticated",
    "authentication_problem",
    "plain_basic",
    "attachment_bearing",
)

COVERAGE_LEVELS: tuple[CoverageLevel, ...] = (
    "low",
    "partial",
    "mostly_observable",
    "rich",
)

LABELS: tuple[Label, ...] = ("legitimate", "phishing")

# Frozen v1 profile × label WEIGHTS (1,000-base). Scale to actual seed counts.
# Not prevalence estimates and not a required 1,000/1,000 corpus size.
V1_PROFILE_LABEL_COUNTS: dict[ProfileName, dict[Label, int]] = {
    "normal_authenticated": {"legitimate": 240, "phishing": 180},
    "third_party_service": {"legitimate": 190, "phishing": 160},
    "partially_authenticated": {"legitimate": 180, "phishing": 180},
    "authentication_problem": {"legitimate": 130, "phishing": 220},
    "plain_basic": {"legitimate": 160, "phishing": 140},
    "attachment_bearing": {"legitimate": 100, "phishing": 120},
}

# Used when a profile can realize more than one coverage level.
DEFAULT_COVERAGE_WEIGHTS: dict[CoverageLevel, float] = {
    "low": 0.20,
    "partial": 0.30,
    "mostly_observable": 0.25,
    "rich": 0.25,
}

# Coverage levels each profile can realize coherently.
PROFILE_ALLOWED_COVERAGE: dict[ProfileName, tuple[CoverageLevel, ...]] = {
    "normal_authenticated": ("mostly_observable", "rich"),
    "third_party_service": ("partial", "mostly_observable", "rich"),
    "partially_authenticated": ("partial", "mostly_observable"),
    "authentication_problem": ("partial", "mostly_observable", "rich"),
    "plain_basic": ("low", "partial"),
    "attachment_bearing": ("low", "partial", "mostly_observable", "rich"),
}

MANIFEST_REQUIRED_FIELDS: tuple[str, ...] = (
    "sample_id",
    "label",
    "content_seed_id",
    "profile",
    "coverage_level",
    "is_simulated",
    "header_template_id",
    "body_template_id",
    "random_seed",
)

# Provenance-only extra columns. Never model features.
MANIFEST_AUDIT_FIELDS: tuple[str, ...] = (
    "filename",
    "spf",
    "dkim",
    "dmarc",
    "reply_to_mode",
    "return_path_mode",
    "url_mode",
    "attachment_mode",
    "body_format",
    "received_count",
    "logical_url_count",
    "logical_unique_url_count",
    "url_rendering_mode",
    "from_template_id",
    "reply_to_template_id",
    "return_path_template_id",
    "received_template_id",
    "auth_results_template_id",
    "received_spf_template_id",
    "attachment_name_template_id",
)

DEFAULT_RANDOM_SEED = 20260920

INERT_ATTACHMENT_PAYLOAD = b"INERT_TEST_PAYLOAD\nnot_an_executable\n"

# Seed preparation (Stage 2). Counts are construction choices, not prevalence.
SEED_CSV_COLUMNS = ("seed_id", "label", "subject", "body_plain")
SEED_TARGET_TOTAL = 2000
SEED_TOTAL_JITTER = 15
SEED_CLASS_MIN_SHARE = 0.45
SEED_CLASS_MAX_SHARE = 0.55
SEED_MIN_BODY_LETTERS = 20
SEED_NEAR_DUP_PREFIX_CHARS = 280
SEED_MAX_PER_NEAR_DUP_CLUSTER = 1

DEFAULT_MEAJOR_SOURCE = (
    Path(__file__).resolve().parents[2] / "Archive" / "meajor_dataset.csv"
)

DEFAULT_SEED_CSV = Path(__file__).resolve().parents[1] / "data" / "seeds" / "content_seeds.csv"
DEFAULT_PILOT_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "pilot"
DEFAULT_FULL_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "full"
PILOT_FRACTION = 0.12
PILOT_MIN_PER_LABEL = 6
EXPECTED_FULL_TOTAL = 2003
