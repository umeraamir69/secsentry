---
tags:
  - research
---

# Competitor landscape

Do not claim to beat Gitleaks on rule count. Unique slice: [[What makes this real and unique]]. Deep dive: [[How the incumbents work]].

| Tool | They do | We do instead |
|---|---|---|
| **Gitleaks** (frozen; author moved on) | Huge regex catalog, patches via `git log -p`, optional redact | Fewer P0 rules, **case file**: who, still-in-HEAD, explain score, mask always |
| **Betterleaks** (Gitleaks successor) | Expr filters, BPE “rare not random,” **HTTP validation in-rule**, GH/GL/HF/S3 sources | Local BPE rarity. Never HTTP-validate. Stay a local incident scanner. |
| **TruffleHog** | 800+ detectors, live API verify + permission analysis | **Never** send the secret out [[ADR-009 No live secret verification]] |
| **detect-secrets** | Python pre-commit | History + fingerprint + dual pip/npm |
| gitsentry (PyPI) | LLM git audit CLI | Name collision only; we are `secsentry` |

README gets a short “when to use Gitleaks vs SecSentry” — honesty is part of the portfolio.

## Related

- [[Name availability]]
- [[Product vision]]
- [[ADR-005 Defer SAST and SCA]]
- [[ADR-009 No live secret verification]]
