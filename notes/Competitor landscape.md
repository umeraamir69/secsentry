---
tags:
  - research
---

# Competitor landscape

Do not claim to beat Gitleaks on rule count. Unique slice: [[What makes this real and unique]]. Deep dive: [[How the incumbents work]]. Numbers: [[Benchmark results]].

| Tool | They do | We do instead |
|---|---|---|
| **Gitleaks** (frozen; author moved on) | Huge regex catalog, patches via `git log -p`, optional redact | Fewer P0 rules, **case file**: who, still-in-HEAD, explain score, mask always |
| **Betterleaks** (Gitleaks successor) | Expr filters, BPE “rare not random,” **HTTP validation in-rule** | Local BPE rarity. Never HTTP-validate. |
| **TruffleHog** | 800+ detectors, live API verify | **Never** send the secret out [[ADR-009 No live secret verification]] |
| **Prowl** ([Lercas/prowl](https://github.com/Lercas/prowl)) | Go cascade + optional ML + **`--verify` live vendor APIs**; 159 YAML rules; Jira/images/org scan; masks by default then `--show-secrets`; **PolyForm Noncommercial** | Stay an **incident case file** that never unmasks and never calls a vendor. MIT. Do not race ProwlBench. Deep dive: [[Prowl]] |
| **zerosecret** (`secret-scanner-2`) | Structural validators + planned SecretBench classifier; writes `matched_string` | Same zero-exfil idea, but **mask**, unique-secret aggregation, still-in-HEAD. |
| **detect-secrets** | Python pre-commit | History + fingerprint + npm wrapper around the Go binary |
| gitsentry (PyPI) | LLM git audit CLI | Name collision only; we are `secsentry` |

## zerosecret specifically

This is the closest academic cousin: blob-deduped git history, local structural checks, no vendor HTTP. Head-to-head on testKeys (2026-09-04): they reported 9 occurrences and **dumped the planted AWS key in JSON**. We reported 8 unique secrets, all `still_in_head=false`, none of the raw values in the report.

Ideas we took from their validator set (synthetic fixtures only):

- Slack segment-shaped tokens (`xoxb-123-456-…`)
- Redis / AMQP URLs with a real password
- Skip placeholder DB passwords (`changeme`, `password`, …)
- Never treat Twilio `AC…` Account SIDs as secrets
- Stripe publishable `pk_*` is public by design

Ideas we did **not** take:

- Flagging AWS role/group IDs (`AROA`, `AIDA`, …) as credentials
- Free-floating 40-character “AWS secret keys” (that is a hash/base64 FP factory)
- Storing `matched_string` / `line_text` in the finding

README gets a short “when to use Gitleaks vs SecSentry vs Prowl” — honesty is part of the portfolio.

If an examiner asks why not Prowl: use Prowl for live verify, 159 rules, and tickets/images. Use SecSentry when the question is “who introduced this, is it still in HEAD, and can I ship the scanner commercially without sending the key to AWS.”

## Related

- [[Name availability]]
- [[Product vision]]
- [[ADR-005 Defer SAST and SCA]]
- [[ADR-009 No live secret verification]]
- [[Benchmark results]]
