# Coherent technical profile families. Profiles are sending situations, not labels.

from __future__ import annotations

from dataclasses import dataclass
from random import Random

from src.config import (
    PROFILE_ALLOWED_COVERAGE,
    PROFILE_NAMES,
    CoverageLevel,
    Label,
    ProfileName,
)


@dataclass(frozen=True)
class TechnicalState:
    """One coherent allowed state inside a profile × coverage cell."""

    spf: str | None
    dkim: str | None
    dmarc: str | None
    reply_to_mode: str
    return_path_mode: str
    received_count: int
    body_format: str
    url_mode: str
    attachment_mode: str
    include_received_spf: bool = False

    def is_rich(self) -> bool:
        return (
            self.spf is not None
            and self.dkim is not None
            and self.dmarc is not None
            and self.reply_to_mode != "absent"
            and self.return_path_mode != "absent"
            and self.received_count >= 1
            and self.url_mode != "none"
        )


def _state(**kwargs) -> TechnicalState:
    return TechnicalState(**kwargs)


# Catalogs are explicit allowed bundles. Randomness only picks among these.
_CATALOG: dict[tuple[ProfileName, CoverageLevel], tuple[TechnicalState, ...]] = {
    ("normal_authenticated", "mostly_observable"): (
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="absent", return_path_mode="match", received_count=2, body_format="plain", url_mode="none", attachment_mode="none"),
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="address_match", return_path_mode="match", received_count=3, body_format="html", url_mode="one", attachment_mode="none"),
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="domain_match", return_path_mode="match", received_count=2, body_format="alternative", url_mode="several", attachment_mode="none"),
    ),
    ("normal_authenticated", "rich"): (
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="address_match", return_path_mode="match", received_count=3, body_format="alternative", url_mode="one", attachment_mode="none"),
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="domain_match", return_path_mode="match", received_count=4, body_format="alternative", url_mode="punycode", attachment_mode="none"),
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="address_match", return_path_mode="match", received_count=2, body_format="plain", url_mode="repeated", attachment_mode="none"),
    ),
    ("third_party_service", "partial"): (
        _state(spf="pass", dkim=None, dmarc=None, reply_to_mode="domain_mismatch", return_path_mode="mismatch", received_count=2, body_format="html", url_mode="one", attachment_mode="none", include_received_spf=True),
        _state(spf="pass", dkim="pass", dmarc=None, reply_to_mode="absent", return_path_mode="mismatch", received_count=3, body_format="plain", url_mode="none", attachment_mode="none"),
    ),
    ("third_party_service", "mostly_observable"): (
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="domain_mismatch", return_path_mode="mismatch", received_count=3, body_format="html", url_mode="several", attachment_mode="none"),
        _state(spf="pass", dkim="pass", dmarc="none", reply_to_mode="address_match", return_path_mode="mismatch", received_count=2, body_format="alternative", url_mode="one", attachment_mode="none"),
    ),
    ("third_party_service", "rich"): (
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="domain_mismatch", return_path_mode="mismatch", received_count=4, body_format="alternative", url_mode="one", attachment_mode="none"),
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="domain_match", return_path_mode="mismatch", received_count=3, body_format="alternative", url_mode="ip", attachment_mode="none"),
    ),
    ("partially_authenticated", "partial"): (
        _state(spf="pass", dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="match", received_count=1, body_format="plain", url_mode="none", attachment_mode="none", include_received_spf=True),
        _state(spf=None, dkim="pass", dmarc=None, reply_to_mode="domain_match", return_path_mode="absent", received_count=2, body_format="html", url_mode="one", attachment_mode="none"),
        _state(spf="neutral", dkim=None, dmarc="none", reply_to_mode="absent", return_path_mode="absent", received_count=1, body_format="plain", url_mode="none", attachment_mode="none"),
    ),
    ("partially_authenticated", "mostly_observable"): (
        _state(spf="pass", dkim="pass", dmarc=None, reply_to_mode="address_match", return_path_mode="match", received_count=2, body_format="alternative", url_mode="one", attachment_mode="none"),
        _state(spf="pass", dkim=None, dmarc="pass", reply_to_mode="domain_match", return_path_mode="match", received_count=3, body_format="html", url_mode="several", attachment_mode="none"),
    ),
    ("authentication_problem", "partial"): (
        _state(spf="fail", dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="absent", received_count=1, body_format="plain", url_mode="none", attachment_mode="none", include_received_spf=True),
        _state(spf="softfail", dkim="fail", dmarc=None, reply_to_mode="domain_mismatch", return_path_mode="mismatch", received_count=2, body_format="html", url_mode="one", attachment_mode="none"),
        _state(spf=None, dkim=None, dmarc="fail", reply_to_mode="absent", return_path_mode="match", received_count=2, body_format="plain", url_mode="none", attachment_mode="none"),
    ),
    ("authentication_problem", "mostly_observable"): (
        _state(spf="fail", dkim="fail", dmarc="fail", reply_to_mode="domain_mismatch", return_path_mode="mismatch", received_count=3, body_format="html", url_mode="several", attachment_mode="none"),
        _state(spf="pass", dkim="fail", dmarc="softfail", reply_to_mode="address_match", return_path_mode="match", received_count=2, body_format="alternative", url_mode="one", attachment_mode="none"),
        _state(spf="neutral", dkim="temperror", dmarc="permerror", reply_to_mode="absent", return_path_mode="mismatch", received_count=2, body_format="plain", url_mode="none", attachment_mode="none"),
    ),
    ("authentication_problem", "rich"): (
        _state(spf="fail", dkim="fail", dmarc="fail", reply_to_mode="domain_mismatch", return_path_mode="mismatch", received_count=3, body_format="alternative", url_mode="one", attachment_mode="none"),
        _state(spf="softfail", dkim="neutral", dmarc="fail", reply_to_mode="address_match", return_path_mode="match", received_count=4, body_format="alternative", url_mode="several", attachment_mode="none"),
        _state(spf="pass", dkim="permerror", dmarc="fail", reply_to_mode="domain_match", return_path_mode="match", received_count=2, body_format="plain", url_mode="repeated", attachment_mode="none"),
    ),
    ("plain_basic", "low"): (
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="absent", received_count=0, body_format="plain", url_mode="none", attachment_mode="none"),
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="absent", received_count=1, body_format="plain", url_mode="none", attachment_mode="none"),
    ),
    ("plain_basic", "partial"): (
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="address_match", return_path_mode="absent", received_count=1, body_format="plain", url_mode="one", attachment_mode="none"),
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="match", received_count=1, body_format="html", url_mode="none", attachment_mode="none"),
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="absent", received_count=1, body_format="plain", url_mode="one", attachment_mode="none"),
    ),
    ("attachment_bearing", "low"): (
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="absent", received_count=1, body_format="plain", url_mode="none", attachment_mode="ordinary"),
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="absent", received_count=0, body_format="plain", url_mode="none", attachment_mode="risky"),
    ),
    ("attachment_bearing", "partial"): (
        _state(spf="pass", dkim=None, dmarc=None, reply_to_mode="absent", return_path_mode="match", received_count=2, body_format="plain", url_mode="one", attachment_mode="ordinary"),
        _state(spf=None, dkim=None, dmarc=None, reply_to_mode="domain_match", return_path_mode="absent", received_count=1, body_format="html", url_mode="none", attachment_mode="risky"),
    ),
    ("attachment_bearing", "mostly_observable"): (
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="address_match", return_path_mode="match", received_count=3, body_format="alternative", url_mode="one", attachment_mode="ordinary"),
        _state(spf="pass", dkim="pass", dmarc=None, reply_to_mode="absent", return_path_mode="match", received_count=2, body_format="html", url_mode="several", attachment_mode="risky"),
    ),
    ("attachment_bearing", "rich"): (
        _state(spf="pass", dkim="pass", dmarc="pass", reply_to_mode="address_match", return_path_mode="match", received_count=3, body_format="alternative", url_mode="one", attachment_mode="ordinary"),
        _state(spf="pass", dkim="pass", dmarc="none", reply_to_mode="domain_match", return_path_mode="match", received_count=4, body_format="alternative", url_mode="mixed", attachment_mode="risky"),
        _state(spf="fail", dkim="pass", dmarc="pass", reply_to_mode="address_match", return_path_mode="mismatch", received_count=2, body_format="plain", url_mode="repeated", attachment_mode="ordinary"),
    ),
}


def all_profile_names() -> tuple[ProfileName, ...]:
    return PROFILE_NAMES


def allowed_coverage(profile: ProfileName) -> tuple[CoverageLevel, ...]:
    return PROFILE_ALLOWED_COVERAGE[profile]


def allowed_states(profile: ProfileName, coverage: CoverageLevel) -> tuple[TechnicalState, ...]:
    key = (profile, coverage)
    if key not in _CATALOG:
        raise ValueError(f"No coherent states for profile={profile!r} coverage={coverage!r}")
    return _CATALOG[key]


def profile_supports_label(_profile: ProfileName, _label: Label) -> bool:
    """Every family is usable with both labels. Label never selects the state."""
    return True


def assert_state_coherent(profile: ProfileName, coverage: CoverageLevel, state: TechnicalState) -> None:
    if coverage not in allowed_coverage(profile):
        raise ValueError(f"{profile} cannot realize coverage {coverage}")
    if state not in allowed_states(profile, coverage):
        raise ValueError(f"State is not in the allowed catalog for {profile}/{coverage}")
    _check_profile_invariants(profile, state)
    if coverage == "rich" and not state.is_rich():
        raise ValueError("rich coverage requires evaluable auth, Reply-To, Return-Path, Received, and URLs")
    if coverage == "low" and any((state.spf, state.dkim, state.dmarc)):
        if profile != "attachment_bearing":
            raise ValueError("low coverage must omit authentication results")


def _check_profile_invariants(profile: ProfileName, state: TechnicalState) -> None:
    auth = (state.spf, state.dkim, state.dmarc)
    if profile == "normal_authenticated":
        if auth != ("pass", "pass", "pass"):
            raise ValueError("normal_authenticated requires SPF/DKIM/DMARC pass")
        if state.return_path_mode == "mismatch":
            raise ValueError("normal_authenticated does not use Return-Path mismatch")
        if state.attachment_mode != "none":
            raise ValueError("normal_authenticated is not the attachment family")
    elif profile == "third_party_service":
        if state.return_path_mode != "mismatch":
            raise ValueError("third_party_service requires Return-Path domain mismatch")
        if state.spf not in {"pass", None}:
            raise ValueError("third_party_service auth stays aligned with the sending service")
        if state.attachment_mode != "none":
            raise ValueError("third_party_service is not the attachment family")
    elif profile == "partially_authenticated":
        present = sum(value is not None for value in auth)
        if present == 0 or present == 3:
            raise ValueError("partially_authenticated must have some but not all auth methods")
        if state.attachment_mode != "none":
            raise ValueError("partially_authenticated is not the attachment family")
    elif profile == "authentication_problem":
        problem = {"fail", "softfail", "neutral", "temperror", "permerror"}
        if not any(value in problem for value in auth):
            raise ValueError("authentication_problem needs at least one problem/neutral auth token")
        if state.attachment_mode != "none":
            raise ValueError("authentication_problem is not the attachment family")
    elif profile == "plain_basic":
        if any(auth):
            raise ValueError("plain_basic omits authentication headers")
        if state.body_format not in {"plain", "html"}:
            raise ValueError("plain_basic stays simple")
        if state.received_count > 1:
            raise ValueError("plain_basic has little routing complexity")
        if state.attachment_mode != "none":
            raise ValueError("plain_basic is not the attachment family")
    elif profile == "attachment_bearing":
        if state.attachment_mode == "none":
            raise ValueError("attachment_bearing requires an attachment")
    else:
        raise ValueError(f"Unknown profile {profile}")


def sample_state(profile: ProfileName, coverage: CoverageLevel, rng: Random) -> TechnicalState:
    choices = allowed_states(profile, coverage)
    state = rng.choice(choices)
    assert_state_coherent(profile, coverage, state)
    return state


def catalog_supports_both_labels() -> bool:
    for profile in PROFILE_NAMES:
        for coverage in allowed_coverage(profile):
            if not allowed_states(profile, coverage):
                return False
            if not profile_supports_label(profile, "legitimate"):
                return False
            if not profile_supports_label(profile, "phishing"):
                return False
    return True
