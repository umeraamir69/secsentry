---
tags:
  - product
  - scope
---

# Product scope

SecSentry is a **secrets leak scanner for Git**. It is not a full SAST platform and not a Ruby gem CVE scanner.

Those extra features (SQL injection, XSS, vulnerable gems, team SaaS) came from the old [gitsentry.com](https://gitsentry.com/) product — a 2014 Ruby static-analysis SaaS that is no longer active. They are a different product. Full evaluation: [[Feature evaluation — platform and SAST]].

## In scope for v1

- Scan current files
- Scan staged files
- Scan Git history
- Regex detectors including OpenAI, Claude/Anthropic, and generic API keys — [[API key detectors]]
- Shannon entropy for unknown secrets
- Severity + confidence
- False-positive reduction
- Dedup by fingerprint
- Masked output
- First-seen commit
- Pre-commit hook
- JSON + local dashboard (`secsentry serve`)
- Clean CLI (`pip` and `npx`)
- Tests + docs
- Runs entirely locally
- Open source, free, unlimited public (and private) local repos

## Later (same product)

Platform features that still serve secret scanning:

- GitHub remote clone/scan
- Bitbucket remote clone/scan
- Pull request / merge request comments
- On-demand vs automatic (CI) scans
- Email alerts
- Private remote repos (auth token in env, never in git)
- Baseline + ignore + fingerprint allowlist
- Internally hosted Git (GitLab self-managed, Gitea, generic git URL)

See [[Feature backlog]].

## Out of scope (different product)

Do not mix these into SecSentry v1. They need parsers, CVE feeds, and a different threat model:

- SQL injection detection
- XSS exploit detection
- Vulnerable gem / npm / pip CVE detection (SCA)
- "Security threat detection" as a generic SAST bucket
- Email support / premium support as a company offering (you can still write docs)

Decision: [[ADR-005 Defer SAST and SCA]]

## Related

- [[Product vision]]
- [[Feature evaluation — platform and SAST]]
- [[Roadmap]]
