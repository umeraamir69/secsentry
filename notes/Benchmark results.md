---
tags:
  - research
  - eval
---

# Benchmark results

Run 2026-09-04 on the planted corpus: 25 secrets, 26 negative lines, 3 commits. Rebuild with `python -m secsentry.eval.build_corpus && python -m secsentry.eval.benchmark`.

| Tool          | Version | Precision | Recall | F1   | TP  | FP  | FN  |
| ------------- | ------- | --------- | ------ | ---- | --- | --- | --- |
| **SecSentry** | 1.0.0   | 1.00      | 1.00   | 1.00 | 25  | 0   | 0   |
| Gitleaks      | 8.30.1  | 1.00      | 0.76   | 0.86 | 19  | 0   | 6   |
| TruffleHog    | 3.97.4  | 1.00      | 0.40   | 0.57 | 10  | 0   | 15  |

Corpus grew from 19 to 25 planted secrets in v1.0 when Square, Shopify, SendGrid, Twilio, GitLab, npm, and PyPI detectors were added from public token signatures ([[GitHub search dorks]]).

## The corpus bias we found and fixed

The first version of the corpus used readable filler — `ghp_TESTONLY` followed by repeated characters. Gitleaks scored **0.32** recall on it. That looked like a great result until we checked why.

Gitleaks applies entropy thresholds to most rules. `AKIAQQQQWWWWEEEERRRR` is below them, so it threw the value out. SecSentry has no entropy gate on prefix-matched rules, so it kept everything. We were not measuring detection quality; we were measuring who filters low-entropy strings.

Regenerating with random high-entropy bodies moved Gitleaks from **0.32 → 0.68** and TruffleHog from **0.11 → 0.37**. Neither tool changed. Only the fixtures did.

**Lesson for the write-up:** a 36-point swing from fixture style alone is why "we beat Gitleaks" claims deserve suspicion — including ours.

## Two more corrections

- `gitleaks detect` is the pre-8.19 spelling. On 8.30 the subcommand is `gitleaks git`. The old form still runs, but the benchmark now uses the current one.
- TruffleHog reports **only verified** secrets by default. Planted keys can never verify, so without `--results=verified,unknown,unverified` it reports almost nothing. Scoring it in default mode would have been dishonest.

## How to read our 1.00

The corpus was written alongside SecSentry's detector list, so a perfect score means "it detects what it was designed to detect." It is a regression test we can defend, not evidence we win on arbitrary repositories.

Where the others are genuinely better:

- **Gitleaks** ships far more rules. On a repo with Azure, Datadog, or Twilio credentials it will win outright.
- **TruffleHog** verifies keys against live APIs, so it can say "this one still works." We deliberately refuse to do that ([[ADR-009 No live secret verification]]), which means we can report a rotated key as a finding and it will not.

Both caveats belong in the README and the LinkedIn post. Leading with an honest limitation is more convincing than a perfect score.

## Related

- [[Competitor landscape]]
- [[Tasks]]
- [[ADR-009 No live secret verification]]
