# Dataset-Generator Design Freeze

This document is the source of truth for Dataset-Generator v1 until a later revision explicitly replaces it.

**Implementation status:** design freeze only. Do not generate emails. Do not create fake content seeds. Do not modify `AI-Phishing-Agent`. Do not begin model training.

The generator wraps **real labeled email content** in **coherent, realistic technical envelopes**. It does not invent phishing language, and it does not manufacture the Agent’s 18-feature table.

---

## 1. Core principle

The dataset must prioritize realistic, coherent email behavior over random synthetic generation.

The goal is **not** to make every phishing email look obviously suspicious and every legitimate email look obviously safe.

The goal is overlapping, realistic conditions where the model must learn **combinations of evidence** rather than simple shortcuts.

Technical profiles represent **plausible sending situations**, not labels.

Public header-stripped corpora keep text well and technical behavior poorly. Fully synthetic corpora often encode deterministic class shortcuts (for example: phishing always fails SPF; legitimate mail never has Reply-To). v1 therefore:

1. Keeps real labeled text.
2. Simulates missing technical structure with **profiles**, not independent coin-flips.
3. Forces **overlap** of security states and of missingness across both labels.
4. Emits raw `.eml` so the frozen Agent extractor, not the generator, produces model features.

### Non-goals (v1)

- Random or LLM-generated phishing/legitimate prose as the primary content source.
- Directly writing the frozen `EmailFeatures` CSV.
- Training a detector.
- Live DNS, reputation, WHOIS, URL visiting, or mailbox delivery.
- IWSPA-specific redaction workarounds in generated mail. Public-corpus artifacts are seed-preprocessing concerns, not live-Agent special cases.
- Real company domains in generated identities, real credentials, malware, live phishing links, or operational phishing infrastructure.

---

## 2. Dataset size

Dataset-Generator v1 target:

| Class | Count |
| --- | ---: |
| Legitimate | 1,000 |
| Phishing | 1,000 |
| **Total** | **2,000** |

This is a **validation-scale** dataset first. It may be scaled later after quality checks show that the methodology is sound.

These counts are controlled coverage for training/evaluation methodology. They are **not** claims about real-world email prevalence.

---

## 3. Profile × label distribution

Use these initial controlled sampling counts. Every profile appears in **both** classes.

| Profile | Legitimate | Phishing |
| --- | ---: | ---: |
| `normal_authenticated` | 240 | 180 |
| `third_party_service` | 190 | 160 |
| `partially_authenticated` | 180 | 180 |
| `authentication_problem` | 130 | 220 |
| `plain_basic` | 160 | 140 |
| `attachment_bearing` | 100 | 120 |
| **Total** | **1,000** | **1,000** |

These numbers are **1,000-base weights**, not a required 1,000/1,000 corpus. When a label has a different seed count (for example 916 legitimate or 1,092 phishing), scale the weights for that label with a deterministic largest-remainder allocation so the integers sum to the available seeds. Every profile must still appear in both classes. Allocation does not depend on email text.

Important:

- These are controlled training weights, not real-world prevalence.
- Rate differences are allowed (phishing may use `authentication_problem` somewhat more often). Hard partitions are not.
- No profile identifier may become model input.
- Do not map `phishing → authentication_problem` and `legitimate → normal_authenticated`.

Worked implications:

- Compromised-mailbox phishing can look like `normal_authenticated`.
- A legitimate mailing list or ticket system can look like `third_party_service` with Return-Path and/or Reply-To differences.
- A misconfigured legitimate domain can look like `authentication_problem`.
- A simple legitimate notification can look like `plain_basic` with unknown SPF/DKIM/DMARC.

---

## 4. Real content seeds

Real labeled email content is the foundation. Planned source: MeAJOR and similar labeled corpora.

v1 rule: **one unique real content seed per generated email**.

Target (construction goal, not a forced exact split):

- approximately 2,000 unique seeds
- each class roughly 45%–55% (near-balanced, not forced equal)

Minimal seed schema (only these fields):

| Field | Role |
| --- | --- |
| `seed_id` | Stable id of the source content (`content_seed_id` in the manifest) |
| `label` | `phishing` or `legitimate`; inherited, never relabeled by wrapping |
| `subject` | Real subject text |
| `body_plain` | Real body text |

Do **not** import unnecessary dataset metadata such as:

- sender address or sender domain
- receiver address
- IP address
- timestamp
- message ID
- dataset source as a per-row field
- original exact domain identity
- other dataset-specific identity fields

Do not rely on random or LLM-generated prose as the main text source.

If a later version creates several generated emails from one content seed, **all derivatives of the same `content_seed_id` must remain in the same train/test split**. Split logic uses `content_seed_id`, not `sample_id`.

---

## 5. Body content and mutation

Preserve real subject/body content as much as possible.

Do **not**:

- rewrite the main text using an LLM
- generate random phishing prose
- create label-specific message templates
- systematically make phishing wording more extreme
- systematically make legitimate wording cleaner or more formal

Allowed modifications:

- plain-text vs HTML rendering
- replacing existing URLs or URL placeholders with harmless reserved/test URLs
- adding minimal shared structural wrappers where necessary
- MIME formatting required to construct valid `.eml` messages

Any HTML/body templates must be **shared between both labels**.

Seed body text may already mention real organizations. That historical text is not rewritten into new live infrastructure. Generated From / Return-Path / URL hosts must still be reserved/test identities and must not add real brand domains on top of the seed.

---

## 6. URL handling

Apply the **same** URL handling rules to phishing and legitimate content.

Generated URLs must use harmless reserved/test values only (see §20).

If seed content contains URLs or URL placeholders:

- MeAJOR `[URL]` anonymization tokens are removed during seed preparation (label-agnostic; no URL is inserted at that stage)
- remaining live operational URLs are stripped during seed preparation rather than rewritten to documentation hosts
- at `.eml` generation time, the selected technical profile decides whether a harmless reserved/test URL is present

If a selected profile requires a URL but the seed has none:

- a harmless URL may be inserted
- use shared URL structures/templates available to **both** classes

Do **not** create:

- one URL style specifically for phishing
- one URL style specifically for legitimate
- live credential-harvesting links
- operational malicious infrastructure

URL behavior should support the frozen Agent features:

- `url_count`
- `unique_url_count`
- `url_length_max`
- `ip_url_count`
- `punycode_url_count`

Use only harmless/test examples. IP-literal and ACE/`xn--` hosts may appear in **either** class when a profile variant calls for them; they must not be class-exclusive.

Rewriting only phishing URLs would itself be a shortcut.

---

## 7. Attachments

Generated attachments must always be harmless and inert.

Attachment behavior can occur in both classes.

Potentially risky file extensions may appear in both classes where needed for feature coverage, but the actual payload must remain safe and non-executable.

Do **not** generate malware or malicious attachment content.

Attachment presence and risky attachment type must **not** determine the label.

`attachment_bearing` is the family that requires one or more attachments. Other families may still include zero attachments. Risky-extension metadata is a within-family option, not a phishing flag.

---

## 8. Header diversity

Use multiple interchangeable **shared** header templates for:

- `Received`
- `Authentication-Results`
- `Received-SPF` where applicable
- `From`
- `Reply-To`
- `Return-Path`
- `MIME-Version`
- `Content-Type`
- multipart boundaries

Header representation templates must be shared across both labels.

The selected **profile** determines the intended security/behavior state.

The **header template** only determines how that state is represented.

Do **not** use:

- one fixed header block for phishing
- another fixed header block for legitimate
- one deterministic template per profile

Use several shared representations to reduce template fingerprinting.

Header claims stay claims. This generator does not sign mail or check DNS.

---

## 9. Profile logic

Technical fields must **not** be selected independently at random.

Each profile defines coherent constraints and allowed states. Randomness may only be used within realistic choices allowed by the selected profile.

Prefer:

```
profile constraints
    → realistic allowed ranges
        → controlled variation inside those ranges
```

Do not generate combinations that make no email/security sense merely to increase feature variety.

### Profile families

These are sending/security situations, **not** labels. The same family may occur in either class.

#### `normal_authenticated`

May include:

- SPF pass, DKIM pass, DMARC pass
- realistic Received chain
- HTML or plain text
- zero or several URLs
- optional Reply-To

Both phishing and legitimate messages can use this profile.

#### `third_party_service`

May naturally allow:

- different Return-Path domain
- Reply-To differences
- authenticated sending service
- HTML content
- links

This profile can occur in either label (service mail, mailing lists, ticket systems, or phishing that imitates those situations).

#### `partially_authenticated`

May have realistic partial combinations, for example:

- SPF available, DKIM unknown, DMARC unknown
- or other incomplete signing / forwarding-like mixes

Missing methods stay `unknown` after Agent extraction, not `fail`.

#### `authentication_problem`

May include:

- fail
- softfail
- neutral
- unknown
- inconsistent auth evidence

It must **not** automatically mean phishing. Misconfigured legitimate mail is in scope.

#### `plain_basic`

May contain:

- plain text only
- no URL
- little routing complexity
- missing authentication evidence

Either label may use it. Missing auth is not evidence of malice.

#### `attachment_bearing`

May include:

- normal attachments
- potentially risky extension metadata (inert payload)
- HTML or plain text
- either label

---

## 10. Natural feature missingness / partial and full coverage

Generated emails must **not** all contain every one of the 18 model features in an observable/non-missing form.

Real emails naturally vary in how much security and structural evidence is available.

The generated corpus must intentionally include a realistic mix of:

- emails with several unavailable/missing fields
- emails with partial security evidence
- emails with most fields available
- emails where all relevant 18 features can be meaningfully evaluated

The purpose is to represent both:

1. incomplete / partially observable real-world emails
2. information-rich emails where many technical signals are available together

There **must** be a meaningful number of fully observable / rich-coverage samples in **both** phishing and legitimate classes.

### Rich-coverage (fully observable)

A rich-coverage email means that fields whose observability depends on source evidence can all be meaningfully evaluated. It should generally provide:

- subject
- non-empty body
- SPF result
- DKIM result
- DMARC result
- Reply-To evidence
- From/Reply-To comparison evidence
- Return-Path evidence
- From/Return-Path comparison evidence
- one or more Received headers
- one or more URLs so URL length can be measured
- URL-related evidence
- attachment state that can be evaluated
- HTML/plain-text format information

This does **not** mean every rich sample must contain:

- an IP-based URL
- a punycode URL
- a risky attachment

Those features can validly be observed as `0` / `False`. The important point is that they are **evaluable** rather than unavailable.

### Realistic partial coverage

Many other emails should naturally lack some evidence. Examples:

- no Reply-To
- no usable Return-Path
- SPF available but DKIM and DMARC unknown
- DKIM available but SPF unknown
- no authentication results at all
- no URLs
- one URL
- multiple URLs
- no attachments
- attachments present
- plain-text only
- HTML content
- short Received chain
- longer Received chain

### Missing-evidence semantics

Missing evidence must keep correct Agent semantics. Do **not** treat missing evidence as suspicious or phishing.

| Situation | Agent-facing result |
| --- | --- |
| Authentication unavailable | `"unknown"` (not `"fail"`) |
| Mismatch cannot be evaluated | `"unknown"` (not treated as mismatch) |
| No URLs | `url_count = 0`, `unique_url_count = 0`, `url_length_max = None`, `ip_url_count = 0`, `punycode_url_count = 0` |
| No attachments | `attachment_count = 0`, `has_risky_attachment = False` |
| No HTML | `has_html = False` |

Header value `"none"` for SPF/DKIM/DMARC, when present, remains `"none"` and is distinct from missing/`"unknown"`.

### Missingness must overlap labels

Feature availability must overlap between labels. Both legitimate and phishing emails must contain examples with:

- full authentication coverage
- partial authentication coverage
- no authentication coverage
- Reply-To present and absent
- Return-Path match, mismatch, and unknown
- URLs present and absent
- HTML present and absent
- attachments present and absent
- rich/full technical coverage
- partial technical coverage

Do **not** make:

- “all fields available” = legitimate
- “all fields available” = phishing
- “many unknown fields” = phishing
- “many unknown fields” = legitimate

Missingness itself must not become a label shortcut.

The goal is realistic evidence diversity: some emails incomplete, some partially complete, some mostly complete, and some richly populated with relevant security evidence available together.

---

## 11. Frozen Agent feature schema

The live `AI-Phishing-Agent` currently uses exactly these 18 model-facing features:

1. `subject`
2. `body_plain`
3. `header_spf_result`
4. `header_dkim_result`
5. `header_dmarc_result`
6. `has_reply_to`
7. `from_reply_to_address_mismatch`
8. `from_reply_to_domain_mismatch`
9. `from_return_path_domain_mismatch`
10. `num_received_headers`
11. `url_count`
12. `unique_url_count`
13. `url_length_max`
14. `ip_url_count`
15. `punycode_url_count`
16. `attachment_count`
17. `has_risky_attachment`
18. `has_html`

Dataset-Generator must support these **indirectly** by creating realistic raw `.eml` messages.

Do **not** directly manufacture these 18 columns.

Generated emails must first exist as RFC822 / `.eml` messages.

Feature extraction later happens through the frozen Agent pipeline:

```
parse_email()
  → run_security_checks()
    → extract_features()
```

Notes aligned with the frozen Agent (do not change the Agent here):

- Missing authentication remains `"unknown"`, not `"fail"`.
- Missing Return-Path evidence remains unknown, not a mismatch.
- `url_length_max` is `float | None`; no URLs ⇒ `None`, not `0`.
- Mismatch fields are `"true"` / `"false"` / `"unknown"` strings.
- `has_reply_to`, `has_html`, `has_risky_attachment` are booleans.
- Punycode counts ACE hostname labels containing `xn--` only; no Unicode-IDN conversion in the Agent.

---

## 12. Seed privacy and storage

Local seed data belongs under `data/seeds/` and remains Git-ignored.

Retain only:

- `seed_id`
- `label`
- `subject`
- `body_plain`

Do not retain unnecessary PII or identity metadata.

Document original dataset source and licensing **separately** in project documentation (not as a per-row model field, and not inside generated `.eml` headers).

---

## 13. Generator output

The generator will eventually write:

```
output/
├── emails/
│   ├── legitimate/
│   └── phishing/
├── manifest.csv
└── quality_report.json
```

Every generated sample must have provenance in `manifest.csv`.

Required provenance fields:

| Field | Role |
| --- | --- |
| `sample_id` | Stable unique id of the generated `.eml` |
| `label` | Inherited from the seed |
| `content_seed_id` | Source `seed_id` |
| `profile` | Technical profile family |
| `is_simulated` | `true` for all generator output |
| `header_template_id` | Which shared header representation was used |
| `body_template_id` | Which shared body/HTML wrapper was used |

These fields are **audit metadata only**. They must **never** become model features.

Provenance lives in the sidecar manifest, not as `X-Label` / `X-Phishing` / profile headers the Agent would ingest as content.

`is_simulated` is always `true` for generator output.

---

## 14. Quality validation

The Dataset-Generator may validate basic RFC822 / `.eml` structure itself.

Do **not** duplicate the Agent’s 18-feature extraction logic inside Dataset-Generator.

Feature-level quality validation must use the frozen sibling `AI-Phishing-Agent` pipeline:

```
parse_email()
  → run_security_checks()
    → extract_features()
```

`quality_report.py` should later accept a **configurable path** to `AI-Phishing-Agent` rather than copying its source code.

### What to measure

- parsing failures
- feature extraction failures
- exact duplicate content
- repeated `content_seed_id`
- profile distribution
- profile × label distribution
- authentication-state distribution
- Reply-To presence
- Reply-To mismatch distribution
- Return-Path mismatch distribution
- URL coverage
- HTML coverage
- attachment coverage
- risky attachment coverage
- individual feature coverage
- missingness by class
- joint feature coverage

Also specifically measure:

- number and percentage of fully observable / rich-coverage emails
- number and percentage of partially observable emails
- number and percentage of low-coverage emails
- fully observable percentage by label
- partially observable percentage by label
- whether **both** classes contain enough rich-coverage examples
- whether full-vs-partial coverage itself is strongly correlated with the label

Joint coverage should include examples such as:

- SPF + DKIM + DMARC all observable
- at least one authentication result
- authentication + Reply-To evidence
- authentication + Return-Path evidence
- authentication + URL evidence
- authentication + Reply-To + URL
- authentication + Reply-To + Return-Path + URL
- URL + attachment
- HTML + URL
- full/rich technical evidence available together

### What to flag

- class-exclusive technical values
- strong feature-presence imbalance
- strong feature-missingness imbalance
- suspiciously large class distribution gaps
- deterministic mappings between profile and label
- full coverage becoming a label proxy
- missingness becoming a label proxy
- template fingerprinting
- duplicate / prose leakage
- any feature that nearly reveals the label by itself

A usable corpus must overlap security states **and** missingness across phishing and legitimate mail.

---

## 15. Synthetic shortcut prevention

No single technical feature should be sufficient to infer the label.

### Bad generation logic (forbidden)

Phishing always:

- SPF fail, DMARC fail, Reply-To mismatch, URL present

Legitimate always:

- SPF pass, DMARC pass, no mismatch, no URLs

Also forbidden:

- phishing = many unknown fields; legitimate = every field available
- or the reverse

Invalid “safe” designs that still leak the label:

- all phishing URLs are IP literals; all legitimate URLs are hostnames
- only phishing uses `xn--` labels
- only phishing has risky attachments
- legitimate Return-Path always matches From; phishing never does

### Required overlap examples

Phishing sample:

- SPF pass, DKIM pass, DMARC pass, HTML, one harmless URL, Return-Path available

Legitimate sample:

- SPF unknown, DKIM unknown, DMARC unknown, Reply-To mismatch, HTML, multiple harmless URLs

Another phishing sample may have:

- partial authentication, no Reply-To, no attachment, plain text

Another legitimate sample may have:

- full authentication, Reply-To, several URLs, attachment

The model should need to combine:

content + authentication evidence + header behavior + URL behavior + attachment behavior + format/context

rather than learning one artificial rule.

---

## 16. Template leakage prevention

Header templates, HTML wrappers, URL structures, attachment naming patterns, and MIME layouts must not encode the label.

Shared template pools must be used across both labels.

Where multiple generated versions later come from one seed, keep them in the same train/test split.

Split logic must use `content_seed_id` rather than `sample_id`.

v1 uses one unique seed per generated email, which already prevents same-prose leakage across splits if splits are by `content_seed_id`.

---

## 17. Realism vs randomness

Do not use pure independent randomization.

Do not generate combinations that make no email/security sense merely to increase feature variety.

Prefer:

1. profile constraints
2. realistic allowed ranges
3. controlled variation inside those ranges

Randomness is allowed only where several realistic options exist.

---

## 18. Model-evaluation principle

Do **not** tune the generator to maximize classifier accuracy.

Unexpected near-perfect model accuracy must be treated as a **warning**.

If model results are extremely high, investigate for:

- source leakage
- template leakage
- class-exclusive features
- deterministic profiles
- missingness leakage
- full-coverage leakage
- duplicate content
- artificial feature correlations

before accepting the result.

Synthetic performance alone must not be used as evidence of real-world performance.

---

## 19. Real-world prevalence

Do not claim that the generated distributions represent real-world email prevalence unless supported by external evidence.

The v1 dataset uses **controlled feature coverage** for training and evaluation methodology.

Profile weights and technical-state distributions are designed for balanced behavioral coverage, not population prevalence estimation.

---

## 20. Safety

The generator must remain defensive and local.

Do **not** create:

- malicious payloads
- credential collection
- executable malware
- operational phishing pages
- live harmful infrastructure
- real credential theft workflows

Use harmless reserved/test identities and URLs, for example:

- documentation domains: `example.com`, `example.net`, `example.org`, plus `test` / `invalid` / `localhost` names
- documentation IPv4: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- documentation IPv6: `2001:db8::/32`
- ACE/punycode labels only as test labels, never real IDN brands

No network lookups to make headers “more real.”

---

## 21. Implementation status

Do **not** implement generation logic yet.

At this stage:

- `DESIGN.md` is the freeze document
- no generated emails
- no fake content seeds
- no `AI-Phishing-Agent` changes
- no model training

### Intended later pipeline

```
labeled content seeds (seed_id, label, subject, body_plain)
        │
        ▼
  scenario sampler  →  profile family + allowed-state variant
        │              (exact v1 counts in §3; overlap required)
        ▼
  eml_builder  →  RFC822 .eml in output/emails/{label}/
               →  provenance row in manifest.csv
        │
        ▼
  validator (parseable, safe URLs/domains, required provenance)
        │
        ▼
  quality_report via frozen Agent extractor
        → output/quality_report.json
```

### Module responsibilities (still unimplemented)

| Module | Responsibility |
| --- | --- |
| `src/profiles.py` | Profile family constraints and coherent allowed-state bundles |
| `src/scenarios.py` | Seed-to-profile assignment using the §3 counts |
| `src/eml_builder.py` | RFC822 serialization from seed + bundle + shared templates |
| `src/generator.py` | Orchestration, ids, `output/` layout, manifest |
| `src/validator.py` | Parseability, safety, required provenance |
| `src/quality_report.py` | Shortcut / leakage / overlap audit via Agent path |

---

## Previous open concerns

The concerns listed in the prior freeze are resolved as follows:

| Prior concern | Resolution |
| --- | --- |
| Class-conditional profile mix | Exact counts in §3; every family in both classes |
| Seed URL hygiene | Same rules for both classes; replace live URLs with reserved/test values; shared URL templates (§6) |
| Brand names in seed bodies vs generated headers | Preserve seed text; generated From/URL/Return-Path hosts are reserved/test only (§5, §20) |
| Body mutation | Preserve seed prose; no LLM rewrite; shared wrappers only (§5) |
| Attachment policy | Inert payloads; risky extensions allowed in both classes; must not determine label (§7) |
| Template diversity | Multiple shared interchangeable templates; not one block per label or per profile (§8, §16) |
| Split units | `content_seed_id`; v1 is one unique seed per email (§4, §16) |
| Seed license and PII | Keep only `seed_id`, `label`, `subject`, `body_plain`; license documented separately (§12) |
| Quality report vs Agent | Configurable path to frozen Agent; do not copy extraction code (§14) |

### Remaining items that are not design blockers

These do not block the first generator implementation stage. They are operational details to choose while coding, then verify with `quality_report`:

- Exact numeric cutoffs for “enough” rich-coverage per class (semantics are defined in §10; quality_report must flag label correlation).
- Exact within-family rates (for example, how often `attachment_bearing` uses a risky extension, or how many shared Received templates exist). Encode as constraint pools, then audit overlap.
- Physical seed-file format and the license text of the chosen corpus, documented beside `data/seeds/` when seeds are introduced.

Until generation is implemented, do not produce mail.
