---
tags:
  - research
  - naming
  - packaging
---

# Name availability

Checked **2026-09-04** (registries live), re-verified the same day after accounts were created: PyPI, TestPyPI, and npm all still return 404 for `secsentry`. Accounts and usernames: [[Accounts and keys]].

## Dual publish — `secsentry`

| Channel | Status | Evidence |
|---|---|---|
| **PyPI** `secsentry` | **Free** | `pypi.org/pypi/secsentry/json` → 404 |
| **npm** `secsentry` | **Free** | `registry.npmjs.org/secsentry` → 404 |
| GitHub org/user `secsentry` | No dedicated org found | Other people own `SecretSentry` repos; you can still use `yourname/secsentry` |
| GitHub `JiJunmo/SecSentry` | Exists | Different user; does not block your repo |

**Claim PyPI + npm on the first TestPyPI / npm dry-run** so the name is not taken while you build. Same version, one engine. [[Dual packaging]] [[ADR-008 One engine two packages]]

Do **not** use: `gitsentry` (PyPI taken), `git-secret-scanner`, `git-secret-guard`, `secretsentry`, `git-sentry` (npm taken).

## Own website domain

| Domain | Status | Use |
|---|---|---|
| **secsentry.com** | **Taken** | Squarespace / Google Domains, created 2023-09-03. **Do not count on this.** |
| **secsentry.io** | **Available** | `whois.nic.io` → Domain not found. **Best product URL.** |
| **secsentry.net** | **Available** | Verisign: no match |
| **secsentry.tech** | **Available** | nic.tech: available for registration |
| **secsentry.ai** | **Available** | nic.ai: Domain not found |
| **getsecsentry.com** | **Available** | Verisign: no match |
| **usesecsentry.com** | **Available** | Verisign: no match |
| **secsentry.dev** | **Likely free** | DNS NXDOMAIN; confirm at Google Domains / registrar (WHOIS for .dev is awkward) |
| **secsentry.app** | **Likely free** | Same as .dev |

Custom domain is **out of the critical path**. Use Vercel (`*.vercel.app`) or GitHub Pages. Buy a domain later if you want; `secsentry.com` is already taken.

## Identity to print on LinkedIn and README

```
pip install secsentry
npx secsentry scan .
```

Website URL: whatever host you get. Not a blocker.

## Related

- [[Dual packaging]]
- [[Complete plan]]
- [[ADR-001 Package name]]
