---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-005 Defer SAST and SCA

## Context

Requested extras from the old GitSentry.com pricing page: SQL injection detection, XSS exploit detection, vulnerable gem detection, plus Team/Enterprise SaaS (PRs, email, private repos, automatic scans).

## Decision

- **Defer** SQLi, XSS, and vulnerable-library scanning. They are SAST/SCA, not secret scanning. Would be a second product.
- **Accept later** (after secrets v1): GitHub, Bitbucket, pull request comments, email-from-CI, internally hosted git, automatic CI scans.
- **Reject as code**: premium support SKU, hosted multi-tenant dashboard for v1.

Full write-up: [[Feature evaluation — platform and SAST]]

## Consequences

v1 stays a coherent portfolio demo. Platform integrations extend the same scanner. AppSec/SCA would split focus and tests.

## Related

- [[Product scope]]
- [[Feature backlog]]
- [[Decisions]]
