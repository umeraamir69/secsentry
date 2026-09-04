---
tags:
  - research
  - competitors
---

# Prowl (Lercas/prowl)

Read 2026-09-04 from the public README. [github.com/Lercas/prowl](https://github.com/Lercas/prowl). **27 stars**, Go, PolyForm Noncommercial 1.0.0.

Prowl is the scanner that already occupies the “high-recall Go CLI, mask by default, SARIF, git history, archives” slot. It is not a Gitleaks clone and it is not zerosecret. Treat it as the **closest shipped product**, not as something to out-F1 on ProwlBench.

## What it is

A cascade:

1. **L1** — regex + keyword (Aho-Corasick) + checksum (Luhn, GitHub CRC, JWT) + Shannon entropy. Ships in every binary.
2. **L2** — optional `--ml` HistGradientBoosting over 49 features, or `--ml-url` sidecar. Static Homebrew/Docker builds **refuse** in-process `--ml`.
3. **`--verify`** — call the vendor’s read-only identity API and report live/dead, plus “blast radius” probes (what the key unlocks).

Surfaces we do not have and are not racing: org-wide GitHub/GitLab, Jira/Confluence, container images, S3/GCS, APK/IPA, live `--authorized` domains, CI logs, MCP server, OCR, Office docs, 159 YAML rules, drop-in `.gitleaks.toml`.

It **masks by default**. `--show-secrets` unmasks for “authorized triage.” That is the opposite of [[ADR-004 Mask secrets never print them]] — we never offer an unmask flag.

Git: `--staged`, `--since <rev>` (diffs), `--history` (every blob). Grouped by **file**, not by fingerprint. README does not mention still-in-HEAD or introduced-by as first-class state.

## Their own benchmark, quoted honestly

ProwlBench: 24,603 cases (16,552 pos / 8,051 neg). Published leaderboard:

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| **Prowl** cascade | 0.951 | 0.823 | **0.883** |
| detect-secrets | 0.848 | 0.423 | 0.564 |
| gitleaks | 0.931 | 0.413 | 0.573 |
| deepsecrets | 0.921 | 0.309 | 0.462 |
| trufflehog | 0.940 | 0.303 | 0.458 |

**They say the quiet part:** 57% of positives are generic passwords in multilingual prose. Gitleaks and TruffleHog are not designed for that tier, so the recall gap **narrows on structured tokens**. On a second check against clean `psf/requests`, **gitleaks is quietest (4 findings)**; Prowl cascade 18, Prowl `--ml` 9. They do not claim to beat Gitleaks on real clean code.

### Our row (same protocol, 2026-09-04)

We ran the published harness. Gitleaks/TruffleHog matched their published F1 exactly, so SecSentry’s row is comparable.

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| Prowl cascade (published, not re-run) | 0.951 | 0.823 | 0.883 |
| Gitleaks | 0.931 | 0.413 | 0.573 |
| **SecSentry 1.2.0** | **0.951** | 0.347 | 0.509 |
| TruffleHog | 0.940 | 0.303 | 0.458 |

1.3.0 added pack 1 structured prefixes. The row above is still 1.2.0 until the harness is re-run.

T1 structured recall 0.64 (Gitleaks 0.65). T2 generic-context 0.01 (Gitleaks 0.35). T4 FP rate 0.037 (lowest of the three we ran). Full write-up: [[Benchmark results]]. Artifact: `eval/results/prowlbench_leaderboard.json`.

## License

**PolyForm Noncommercial 1.0.0** — free for noncommercial use, not for commercial products. SecSentry is MIT. That is a real adoption difference, not a quality one.

## What to steal locally (no network)

- **PEM header alone is not a key.** They require a body. We now do too.
- Mask by default (we already do; they add an unmask flag we will not copy).
- Archives + decode (we already do).
- Keyword prefilter (we already do; they use Aho-Corasick because they have 159 rules).

## What not to steal

- `--verify` and capability probes. [[ADR-009 No live secret verification]]
- `--show-secrets`
- The 159-rule YAML library and gitleaks.toml compatibility as a v1 pitch
- Org / Jira / image / domain scanners
- Claiming we beat Prowl on ProwlBench F1. We ran the harness; they still win recall.

## How we still have a slice

Prowl answers “is there a credential in this blob / ticket / image?” SecSentry answers **“is this the same secret, who first committed it, and is it still in HEAD?”** Unique-secret aggregation, rotation text, and a localhost case-file dashboard are not in their README. Zero-exfil is a *guarantee* for us and an *optional off switch* for them.

If an examiner asks “why not just use Prowl?”: they should, if they want live verify, 159 rules, and Jira. Use SecSentry if they want an **incident file** that never leaves the box and can be shipped commercially under MIT.

## Related

- [[Competitor landscape]]
- [[How the incumbents work]]
- [[Benchmark results]]
- [[ADR-009 No live secret verification]]
- [[ADR-004 Mask secrets never print them]]
