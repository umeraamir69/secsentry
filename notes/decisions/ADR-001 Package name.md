---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-001 Package name

## Context

The working title was GitSentry. PyPI and npm names must be globally unique. We checked live registries on 2026-09-03.

## Decision

**Package, import, CLI, PyPI, and npm are `secsentry`.** Display name: SecSentry.

Do not publish `gitsentry`, `git-secret-scanner`, `git-secret-guard`, or `secretsentry`.

## Consequences

- `pip install secsentry` and `npm install -g secsentry` / `npx secsentry`
- Same version on both registries ([[ADR-008 One engine two packages]])
- Matches this workspace folder
- Avoids collision with existing PyPI `gitsentry` (beret21)
- GitHub repo can be `yourname/secsentry` even though `JiJunmo/SecSentry` exists

Evidence: [[Name availability]]

## Related

- [[Dual packaging]]
- [[ADR-008 One engine two packages]]
- [[CLI]]
- [[Decisions]]
