# Dataset-Generator

Controlled semi-synthetic email corpus generator for the AI phishing detection system.

This repository does **not** train a model and does **not** replace `AI-Phishing-Agent`. It produces raw RFC822 / `.eml` messages from labeled **content seeds** plus coherent technical profiles.

**Status:** Implementation Stage 3B (full corpus generation and quality audit). The training-ready decision is based on `output/full/quality_report.json`, not on a trained classifier.

## Content seeds (Stage 2)

Real labeled subject/body text is selected from the local Archive MeAJOR CSV. The full MeAJOR file is not copied into this repo.

```
python -m src.prepare_seeds --source ../Archive/meajor_dataset.csv
```

This writes Git-ignored `data/seeds/content_seeds.csv` (`seed_id,label,subject,body_plain` only) and `output/seed_preparation_report.json`.

Class counts are near-balanced (about 45%–55% each), not forced to 1,000/1,000, and are not prevalence claims. Seed labels do not choose technical profiles.

## Stage 3A pilot

After seeds exist, generate a ~12% real-seed pilot (not the full corpus):

```
python -m src.generate_pilot --seeds data/seeds/content_seeds.csv --output output/pilot
```

This writes `output/pilot/emails/{legitimate,phishing}/*.eml`, `manifest.csv`, `quality_report.json`, and `pilot_selection.json`. Pilot files stay separate from the full corpus.

## Stage 3B full corpus

After seeds exist, generate one `.eml` per content seed (do not resample or rebalance labels):

```
python -m src.generate_full --seeds data/seeds/content_seeds.csv --output output/full --random-seed 20260920
```

This writes `output/full/emails/{legitimate,phishing}/*.eml`, `manifest.csv`, and `quality_report.json`. Previous `output/full` email artifacts are cleared first. Pilot output, seeds, tests, and source files are not deleted. This command does not train a model.

## Purpose

Public datasets keep subject/body text better than they keep headers and authentication behavior. Fully synthetic datasets often leak artifacts (for example, phishing always fails SPF).

This project wraps real labeled text in realistic technical envelopes so a classifier has to learn phishing behavior instead of generator shortcuts.

Generated mail is **semi-synthetic**:

- Content: real labeled subject/body seeds (later). Stage 1 tests use tiny fixtures only.
- Technical/header behavior: controlled by profile families, not by the class label.
- Files stay local. The generator never sends mail and never contacts the network.

## Relation to AI-Phishing-Agent

`DESIGN.md` is the methodology freeze. Do not weaken it.

`AI-Phishing-Agent` is a sibling project. It remains responsible for:

```
parse_email() → run_security_checks() → extract_features()
```

Dataset-Generator does **not** reimplement those 18 model-facing features. It writes `.eml` files and provenance. Quality analysis imports the frozen Agent pipeline by filesystem path.

## Reproducibility

Pass `GeneratorConfig(random_seed=...)`. The same seeds, profile assignments, and random seed replay the same scenario choices (profiles pick among explicit allowed-state catalogs; templates are shared across labels).

v1 profile × label weights in `src/config.py` are 1,000-base construction weights, not prevalence claims. They are scaled to the actual seed count per label and never change a seed’s label.

## Running tests

From this repository, with the sibling Agent available at `../AI-Phishing-Agent`:

```
python -m unittest discover -s tests -v
```

Test fixtures live under `tests/` only. They are not training data and must not be copied to `data/seeds/`.

## Agent-backed quality report

After a local generation run:

```
from pathlib import Path
from src.quality_report import build_quality_report, write_quality_report

report = build_quality_report(Path("output/dev_batch"), agent_root=Path("../AI-Phishing-Agent"))
write_quality_report(Path("output/dev_batch"), report)
```

The report measures coverage, missingness, joint feature presence, and shortcut warnings. It does **not** claim real-world prevalence and must not be used to tune a classifier.

## Layout

```
data/seeds/     Git-ignored content_seeds.csv (Stage 2)
output/         reports and later generated .eml (mostly gitignored)
src/            generator engine and seed preparation
tests/          unit tests (fixtures only; not training data)
DESIGN.md       frozen methodology
```
