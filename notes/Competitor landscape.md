---
tags:
  - research
---

# Competitor landscape

Do not claim to beat Gitleaks on rule count. Unique slice: [[What makes this real and unique]].

| Tool | They do | We do instead |
|---|---|---|
| **Gitleaks** | Huge regex catalog, fast CI | Fewer P0 rules, **case file**: who, still-in-HEAD, explain score |
| **TruffleHog** | Verifies secrets against vendor APIs | **Never** send the secret out [[ADR-009 No live secret verification]] |
| **detect-secrets** | Python pre-commit | History + fingerprint + dual pip/npm |
| gitsentry (PyPI) | LLM git audit CLI | Name collision only; we are `secsentry` |
| git-secret-guard | Pre-commit regex | History + entropy + investigation UI |
| secretsentry | Similar name, secrets in git | Different package; we stay `secsentry` |

README gets a short “when to use Gitleaks vs SecSentry” — honesty is part of the portfolio.

## Related

- [[Name availability]]
- [[Product vision]]
- [[ADR-005 Defer SAST and SCA]]
- [[ADR-009 No live secret verification]]
