---
tags:
  - product
  - features
---

# Feature evaluation — platform and SAST

You asked whether we can add the old GitSentry.com feature list. Short answer: **some yes, later; some no, different product.**

Those bullets are a SaaS pricing page (Open Source / Team / Enterprise), not a secrets-scanner spec. SQL injection, XSS, and vulnerable gems are static analysis and dependency scanning. Putting them in v1 would stall the history-scan demo.

## Verdict table

| Feature | Fits secrets scanner? | When | Notes |
|---|---|---|---|
| Open source | Yes | v1 | MIT license, public GitHub |
| Free | Yes | v1 | Local CLI is free |
| Unlimited public repos | Yes | v1 | Local scan has no repo cap |
| On-demand scans | Yes | v1 | `secsentry scan .` |
| Automatic scans | Yes | v1.0 CI | GitHub Actions on push/PR |
| Private repos | Yes | v1 local; later remote | Local already works; remote needs a token |
| GitHub support | Yes | after MVP | Clone + scan, then PR comments |
| Bitbucket support | Yes | after GitHub | Same clone/scan path, different API |
| Pull requests | Yes | after GitHub API | Comment findings on the PR diff |
| Email alerts | Yes | after JSON reports | CI emails, or a later `--notify` |
| Internally hosted repos | Yes | later | `git clone` any URL, then scan |
| Security threat detection | Partial | v1 | For **secrets**, not generic AppSec |
| Email support / premium support | No (product) | never in code | Docs + GitHub issues instead |
| SQL injection detection | No | separate tool | Needs language parsers |
| XSS exploit detection | No | separate tool | Needs HTML/JS analysis |
| Vulnerable gem detection | No | separate tool | That's SCA (Bundler/npm/pip CVEs) |

## What we will add to SecSentry

Keep the product one sentence: **find leaked secrets in Git.**

### Already implied by v1

- Open source, free, unlimited local repos (public or private)
- On-demand scans
- Automatic scans via GitHub Actions
- Private repos on disk

### Phase after v1.0 (platform)

1. **GitHub** — `secsentry scan --remote https://github.com/org/repo` (clone to temp, history scan). Token from `GITHUB_TOKEN`, never logged.
2. **Bitbucket** — same remote path, Bitbucket clone URL + app password.
3. **Pull requests** — GitHub Action posts a review comment on added lines only.
4. **Email alerts** — optional: CI mails the JSON summary. Do not build a mail server.
5. **Internally hosted Git** — scan a clone of GitLab/Gitea/Bitbucket Server. No vendor lock-in if we scan git, not "GitHub only."

### Team / Enterprise as packaging, not code

| SaaS label | What it actually means for us |
|---|---|
| Team | GitHub Action + PR comments + email from CI |
| Enterprise | Scan clones of internal git; no cloud required |
| Premium support | README + issues. Not a feature. |

We do **not** need a hosted multi-tenant app for a portfolio v1.

## What we will not add to this repo

### SQL injection detection

Requires SQL/ORM parsers, taint tracking, or at least query-string analysis per language. False-positive rate is high. Overlaps Semgrep, CodeQL, Bandit. **Out.**

### XSS exploit detection

Requires HTML/template/JS analysis. Different detectors, different tests, different demo. Overlaps Semgrep/CodeQL. **Out.**

### Vulnerable gem detection

"Gems" is Ruby Bundler. Real SCA is `bundler-audit`, `npm audit`, `pip-audit`, Dependabot, osv-scanner. Needs a CVE/OSV feed and lockfile parsers. **Out** of SecSentry.

If you want that later, it is a **second project** (for example `secsentry-deps`), not a flag on the secrets CLI.

## Recommended story for the README

> SecSentry finds leaked secrets in Git working trees, staged files, and history. It runs locally, is free and open source, and can run on every push. GitHub and Bitbucket remote scans and PR comments are on the roadmap. It does not replace SAST (SQLi/XSS) or SCA (vulnerable libraries).

## Related

- [[Product scope]]
- [[ADR-005 Defer SAST and SCA]]
- [[Feature backlog]]
- [[Roadmap]]
