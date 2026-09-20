# Assemble generation scenarios from seeds, profiles, and shared templates.

from __future__ import annotations

from dataclasses import dataclass, field
from random import Random

from src.config import (
    DEFAULT_COVERAGE_WEIGHTS,
    PROFILE_ALLOWED_COVERAGE,
    CoverageLevel,
    Label,
    ProfileName,
)
from src.profiles import TechnicalState, allowed_coverage, sample_state
from src.safety import (
    SAFE_DISPLAY_NAMES,
    SAFE_HOSTS,
    SAFE_LOCAL_PARTS,
    SAFE_PUNYCODE_HOSTS,
    SAFE_ROOT_DOMAINS,
    SAFE_URL_PATHS,
    DOCUMENTATION_IPV4_HOSTS,
)
from src.url_render import (
    logical_unique_url_count as count_unique_logical_urls,
    logical_url_count as count_logical_urls,
    seed_prose_without_urls,
    url_rendering_mode as choose_url_rendering_mode,
)
from src.templates import (
    ATTACHMENT_NAME_TEMPLATES,
    AUTH_RESULTS_TEMPLATES,
    FROM_TEMPLATES,
    HTML_BODY_TEMPLATES,
    PLAIN_BODY_TEMPLATES,
    RECEIVED_SPF_TEMPLATES,
    RECEIVED_TEMPLATES,
    REPLY_TO_TEMPLATES,
    RETURN_PATH_TEMPLATES,
    URL_STRUCTURE_TEMPLATES,
    NamedTemplate,
    header_template_bundle_id,
)


@dataclass(frozen=True)
class ContentSeed:
    seed_id: str
    label: Label
    subject: str
    body_plain: str


@dataclass(frozen=True)
class TemplateChoices:
    from_template: NamedTemplate
    reply_to_template: NamedTemplate | None
    return_path_template: NamedTemplate | None
    received_template: NamedTemplate
    auth_results_template: NamedTemplate | None
    received_spf_template: NamedTemplate | None
    plain_body_template: NamedTemplate
    html_body_template: NamedTemplate
    attachment_name_template: NamedTemplate | None
    url_structure_template: NamedTemplate

    @property
    def header_template_id(self) -> str:
        return header_template_bundle_id(
            self.from_template.template_id,
            self.reply_to_template.template_id if self.reply_to_template else None,
            self.return_path_template.template_id if self.return_path_template else None,
            self.received_template.template_id,
            self.auth_results_template.template_id if self.auth_results_template else None,
            self.received_spf_template.template_id if self.received_spf_template else None,
        )

    @property
    def body_template_id(self) -> str:
        return f"{self.plain_body_template.template_id}+{self.html_body_template.template_id}"


@dataclass
class GenerationScenario:
    """Intended generation state before RFC822 construction. Provenance, not model input."""

    sample_id: str
    seed: ContentSeed
    profile: ProfileName
    coverage_level: CoverageLevel
    state: TechnicalState
    templates: TemplateChoices
    from_address: str
    from_display: str
    reply_to_address: str | None
    reply_to_display: str | None
    return_path_address: str | None
    recipient_address: str
    urls: list[str]
    body_text: str
    random_seed: int
    is_simulated: bool = True
    extra_audit: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> Label:
        return self.seed.label

    @property
    def logical_url_count(self) -> int:
        return count_logical_urls(self.urls)

    @property
    def logical_unique_url_count(self) -> int:
        return count_unique_logical_urls(self.urls)

    @property
    def url_rendering_mode(self) -> str:
        return choose_url_rendering_mode(self.state.body_format, self.urls)


def validate_seed(raw: dict) -> ContentSeed:
    required = ("seed_id", "label", "subject", "body_plain")
    missing = [key for key in required if key not in raw]
    if missing:
        raise ValueError(f"Seed missing required fields: {missing}")
    if raw["seed_id"] in (None, "") or raw["label"] in (None, "") or raw["body_plain"] in (None, ""):
        raise ValueError("seed_id, label, and body_plain must be non-empty")
    if raw["subject"] is None:
        raise ValueError("subject must be present (empty string is allowed)")
    label = raw["label"]
    if label not in {"legitimate", "phishing"}:
        raise ValueError(f"Unsupported seed label: {label!r}")
    forbidden = {
        "sender",
        "sender_address",
        "sender_domain",
        "receiver",
        "ip",
        "timestamp",
        "message_id",
        "source",
        "from_address",
        "to_address",
    }
    extra = forbidden.intersection(raw)
    if extra:
        raise ValueError(f"Seed contains identity metadata that must not be imported: {sorted(extra)}")
    return ContentSeed(
        seed_id=str(raw["seed_id"]),
        label=label,
        subject=str(raw["subject"]),
        body_plain=str(raw["body_plain"]),
    )


def choose_coverage(profile: ProfileName, rng: Random, requested: CoverageLevel | None = None) -> CoverageLevel:
    allowed = allowed_coverage(profile)
    if requested is not None:
        if requested not in allowed:
            raise ValueError(f"Profile {profile} cannot realize coverage {requested}")
        return requested
    weights = [DEFAULT_COVERAGE_WEIGHTS[level] for level in allowed]
    total = sum(weights)
    pick = rng.random() * total
    running = 0.0
    for level, weight in zip(allowed, weights, strict=True):
        running += weight
        if pick <= running:
            return level
    return allowed[-1]


def _pick(rng: Random, items):
    return rng.choice(list(items))


def _address(local: str, domain: str) -> str:
    return f"{local}@{domain}"


def _build_identities(state: TechnicalState, rng: Random) -> dict[str, str | None]:
    from_domain = _pick(rng, SAFE_ROOT_DOMAINS[:3])
    other_roots = [item for item in SAFE_ROOT_DOMAINS[:3] if item != from_domain]
    service_domain = _pick(rng, other_roots)
    from_local = _pick(rng, SAFE_LOCAL_PARTS)
    from_address = _address(from_local, from_domain)
    display = _pick(rng, SAFE_DISPLAY_NAMES)
    recipient = _address(_pick(rng, ("desk", "office", "list")), _pick(rng, SAFE_ROOT_DOMAINS[:3]))

    reply_to_address = None
    reply_to_display = None
    if state.reply_to_mode == "address_match":
        reply_to_address = from_address
        reply_to_display = display
    elif state.reply_to_mode == "domain_match":
        alt_local = _pick(rng, [item for item in SAFE_LOCAL_PARTS if item != from_local] or SAFE_LOCAL_PARTS)
        reply_to_address = _address(alt_local, from_domain)
        reply_to_display = _pick(rng, SAFE_DISPLAY_NAMES)
    elif state.reply_to_mode == "domain_mismatch":
        reply_to_address = _address(_pick(rng, SAFE_LOCAL_PARTS), service_domain)
        reply_to_display = _pick(rng, SAFE_DISPLAY_NAMES)

    return_path_address = None
    if state.return_path_mode == "match":
        return_path_address = _address("bounce", from_domain)
    elif state.return_path_mode == "mismatch":
        return_path_address = _address("bounce", service_domain)

    return {
        "from_address": from_address,
        "from_display": display,
        "reply_to_address": reply_to_address,
        "reply_to_display": reply_to_display,
        "return_path_address": return_path_address,
        "recipient_address": recipient,
    }


def build_safe_urls(url_mode: str, rng: Random) -> list[str]:
    if url_mode == "none":
        return []
    host_t = _pick(rng, URL_STRUCTURE_TEMPLATES[:2])
    ip_t = URL_STRUCTURE_TEMPLATES[2]
    path = _pick(rng, SAFE_URL_PATHS)
    normal = host_t.pattern.format(host=_pick(rng, SAFE_HOSTS), path=path)
    second = host_t.pattern.format(host=_pick(rng, SAFE_HOSTS), path=_pick(rng, SAFE_URL_PATHS))
    ip_url = ip_t.pattern.format(host=_pick(rng, DOCUMENTATION_IPV4_HOSTS), path=path)
    puny = host_t.pattern.format(host=_pick(rng, SAFE_PUNYCODE_HOSTS), path=path)
    if url_mode == "one":
        return [normal]
    if url_mode == "several":
        third = host_t.pattern.format(host=_pick(rng, SAFE_HOSTS), path="/notice")
        return [normal, second, third]
    if url_mode == "repeated":
        return [normal, normal]
    if url_mode == "ip":
        return [ip_url]
    if url_mode == "punycode":
        return [puny]
    if url_mode == "mixed":
        return [normal, ip_url]
    raise ValueError(f"Unknown url_mode {url_mode}")


def select_templates(state: TechnicalState, rng: Random) -> TemplateChoices:
    reply = _pick(rng, REPLY_TO_TEMPLATES) if state.reply_to_mode != "absent" else None
    rp = _pick(rng, RETURN_PATH_TEMPLATES) if state.return_path_mode != "absent" else None
    auth = None
    if any(value is not None for value in (state.spf, state.dkim, state.dmarc)):
        auth = _pick(rng, AUTH_RESULTS_TEMPLATES)
    spf_t = _pick(rng, RECEIVED_SPF_TEMPLATES) if state.include_received_spf and state.spf else None
    att = None
    if state.attachment_mode == "ordinary":
        att = _pick(rng, [item for item in ATTACHMENT_NAME_TEMPLATES if item.pattern.endswith((".txt", ".csv"))])
    elif state.attachment_mode == "risky":
        att = _pick(rng, [item for item in ATTACHMENT_NAME_TEMPLATES if item.pattern.endswith((".js", ".hta", ".docm"))])
    return TemplateChoices(
        from_template=_pick(rng, FROM_TEMPLATES),
        reply_to_template=reply,
        return_path_template=rp,
        received_template=_pick(rng, RECEIVED_TEMPLATES),
        auth_results_template=auth,
        received_spf_template=spf_t,
        plain_body_template=_pick(rng, PLAIN_BODY_TEMPLATES),
        html_body_template=_pick(rng, HTML_BODY_TEMPLATES),
        attachment_name_template=att,
        url_structure_template=_pick(rng, URL_STRUCTURE_TEMPLATES),
    )


def assemble_scenario(
    seed: ContentSeed,
    profile: ProfileName,
    rng: Random,
    *,
    coverage: CoverageLevel | None = None,
    sample_id: str,
    random_seed: int,
    url_mode_override: str | None = None,
    body_format_override: str | None = None,
) -> GenerationScenario:
    if seed.label not in {"legitimate", "phishing"}:
        raise ValueError("Scenario label comes from the seed, never from the profile")
    coverage_level = choose_coverage(profile, rng, coverage)
    state = sample_state(profile, coverage_level, rng)
    if url_mode_override or body_format_override:
        state = TechnicalState(
            spf=state.spf,
            dkim=state.dkim,
            dmarc=state.dmarc,
            reply_to_mode=state.reply_to_mode,
            return_path_mode=state.return_path_mode,
            received_count=state.received_count,
            body_format=body_format_override or state.body_format,
            url_mode=url_mode_override or state.url_mode,
            attachment_mode=state.attachment_mode,
            include_received_spf=state.include_received_spf,
        )
        if coverage_level == "rich" and state.url_mode == "none":
            raise ValueError("rich coverage cannot drop URLs")
    identities = _build_identities(state, rng)
    templates = select_templates(state, rng)
    urls = build_safe_urls(state.url_mode, rng)
    # Seed prose only. Logical URLs are rendered later by the EML builder.
    body_text = seed_prose_without_urls(seed.body_plain)
    return GenerationScenario(
        sample_id=sample_id,
        seed=seed,
        profile=profile,
        coverage_level=coverage_level,
        state=state,
        templates=templates,
        from_address=str(identities["from_address"]),
        from_display=str(identities["from_display"]),
        reply_to_address=identities["reply_to_address"],
        reply_to_display=identities["reply_to_display"],
        return_path_address=identities["return_path_address"],
        recipient_address=str(identities["recipient_address"]),
        urls=urls,
        body_text=body_text,
        random_seed=random_seed,
        extra_audit={
            "provenance_note": "generator metadata only; never a model feature",
            "allowed_coverage": ",".join(PROFILE_ALLOWED_COVERAGE[profile]),
            "logical_url_count": str(count_logical_urls(urls)),
            "logical_unique_url_count": str(count_unique_logical_urls(urls)),
            "url_rendering_mode": choose_url_rendering_mode(state.body_format, urls),
        },
    )
