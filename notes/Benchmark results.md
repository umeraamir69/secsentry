---
tags:
  - research
  - eval
---

# Benchmark results

Two measurements. The planted corpus is a **regression test**. The demo repo is the **incident story**. Do not collapse them into one "we beat Gitleaks" headline.

## Demo repo: testKeys (the real pitch)

Repo: [umeraamir69/testKeys](https://github.com/umeraamir69/testKeys). Two commits: plant fake keys, then delete them. Working tree is clean. Run 2026-09-04, local machine.

| Tool | Version / source | Findings | Unique secrets | Masked report | `still_in_head` | AWS | PEM | OpenAI |
|---|---|---|---|---|---|---|---|---|
| **SecSentry** | 1.2.0 Go | 11 occ | **8** | yes | **false on all 8** | yes | yes | yes |
| zerosecret | `secret-scanner-2` | 9 occ | not aggregated | **no — dumps `matched_string`** | not reported | yes | no | no |
| Gitleaks | 8.30 | 7 | — | Secret field present | commit metadata only | **no** | yes | yes |
| TruffleHog | `--results=verified,unknown,unverified` | 2 | — | — | no | no | no | no |

zerosecret's 9 findings included one free-floating `aws_secret_access_key` (any 40-char base64-shaped string). SecSentry only flags that shape next to a labeled `AWS_SECRET_ACCESS_KEY=` assignment. zerosecret also **wrote the planted AWS access key in cleartext** into `findings.json`. SecSentry JSON/SARIF/HTML on the same repo did not contain it.

TruffleHog only reported Postgres URLs. Planted tokens cannot verify against vendor APIs, which is the mode it is designed for — scoring it on fakes is mostly measuring the wrong thing.

### What this number is allowed to mean

On *this* incident (deleted keys still in git), SecSentry is the only tool that produced a case file: who introduced it, that it is gone from HEAD, and how to rotate, without reprinting the value.

It is **not** allowed to mean we have more rules than Gitleaks.

## Planted corpus (regression)

25 secrets, 26 negative lines, 3 commits. Rebuild with the Python eval helpers if you still have that tree, or treat `go test ./internal/scan/` as the Go stand-in.

| Tool          | Version | Precision | Recall | F1   | TP  | FP  | FN  |
| ------------- | ------- | --------- | ------ | ---- | --- | --- | --- |
| **SecSentry** | 1.2.0   | 1.00      | 1.00   | 1.00 | 25  | 0   | 0   |
| Gitleaks      | 8.30.1  | 1.00      | 0.76   | 0.86 | 19  | 0   | 6   |
| TruffleHog    | 3.97.4  | 1.00      | 0.40   | 0.57 | 10  | 0   | 15  |

The corpus was written alongside SecSentry's detector list. A perfect score means "it detects what it was designed to detect."

## The corpus bias we found and fixed

The first version used readable filler — `ghp_TESTONLY` plus repeated characters. Gitleaks scored **0.32** recall. Gitleaks applies entropy thresholds; `AKIAQQQQWWWWEEEERRRR` is below them. Regenerating with random high-entropy bodies moved Gitleaks **0.32 → 0.68** and TruffleHog **0.11 → 0.37**. Neither tool changed. Only the fixtures did.

**Lesson:** a 36-point swing from fixture style is why "we beat Gitleaks" claims deserve suspicion — including ours.

## Two more corrections

- `gitleaks detect` is the pre-8.19 spelling. On 8.30 the subcommand is `gitleaks git`.
- TruffleHog reports **only verified** secrets by default. Planted keys can never verify. The table above used `--results=verified,unknown,unverified`.

## ProwlBench (external, 24,603 cases)

Ran 2026-09-04 with the published [Lercas/prowlbench](https://github.com/Lercas/prowlbench) protocol on `Podric/prowl-secrets-corpus` (`prowlbench.parquet`). Snippet-level flag ≥ 1. Artifact: `eval/results/prowlbench_leaderboard.json`. Charts: the ProwlBench results canvas.

**Gitleaks and TruffleHog match the published leaderboard exactly** (F1 0.573 and 0.458). The harness is fair. Prowl cascade is quoted from their README, not re-run.

| Tool | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Prowl cascade (published) | 0.951 | 0.823 | **0.883** | 0.853 |
| Gitleaks | 0.931 | 0.413 | 0.573 | 0.585 |
| **SecSentry 1.2.0** | **0.951** | 0.347 | 0.509 | 0.549 |
| TruffleHog | 0.940 | 0.303 | 0.458 | 0.518 |

1.3.0 added Slack webhooks, Discord, Telegram, Azure storage, Datadog, DigitalOcean, Basic auth, and looser PEM/GCP/AWS-secret pairing. **This table is still the 1.2.0 run.** Re-score before replacing the row.

Counts for this run: SecSentry TP 5748 / FP 298 / FN 10804 / TN 7753.

### Per-tier (T1–T3 = recall, T4 = FP rate)

| Tool | T1 structured (n=7033) | T2 generic-context (n=3519) | T3 free-form multilingual (n=6000) | T4 hard-negative FP (n=8051) |
|---|---|---|---|---|
| **SecSentry** | 0.64 | **0.01** | 0.20 | **0.037** |
| Gitleaks | 0.65 | 0.35 | 0.17 | 0.063 |
| TruffleHog | 0.60 | 0.00 | 0.13 | 0.040 |

T1 is a dead heat with Gitleaks. T2 is the hole: we almost never fire on unlabeled generic keys/passwords; Gitleaks does. T4 we are the quietest of the three we ran.

### How to read this

Highest **precision** of the three tools we executed. We lose **recall** because the set is full of `generic_password` / prose keys we do not target (top misses: generic_password 3284, generic_api_key 3143, generic_high_entropy 1101). That is the same disclosure Prowl makes about 57% of the positives.

This number is allowed to mean: on an independent structured+prose corpus, we are a high-precision prefix scanner, not a multilingual password finder.

It is **not** allowed to mean we beat Prowl. Their cascade F1 is 0.883 on this set; we did not re-run their binary.

## Where the others are genuinely better

- **Prowl** — 159 rules, optional ML, Jira/images/org scan, live `--verify`, and the recall this corpus is built to reward. PolyForm Noncommercial. [[Prowl]]
- **Gitleaks** ships far more rules and wins T2 generic-context (0.35 vs our 0.01). On Prowl's clean-OSS check, Gitleaks is the quietest.
- **TruffleHog** can say "this key still logs in." We refuse ([[ADR-009 No live secret verification]]).
- **zerosecret** has SecretBench loaders. ProwlBench we have now run.

## Related

- [[Competitor landscape]]
- [[What makes this real and unique]]
- [[Prowl]]
