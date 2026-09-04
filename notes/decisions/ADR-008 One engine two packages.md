---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-008 One engine two packages

## Context

We need install via **pip and npm** at the same time (`pip install secsentry` and `npx secsentry`). Duplicating detectors in TypeScript would drift and double the false-positive work.

## Decision

- Python package on PyPI is the engine and the CLI
- npm package `secsentry` is a **bin wrapper** that invokes that CLI
- Same version number on both registries, published in one GitHub Release
- Next.js / GitHub Action also call the Python CLI or worker, not a JS port

## Consequences

- Node users still need Python 3.12+ (document clearly in the npm README)
- One test suite (pytest) covers detection
- Claim both names early so they stay available

## Related

- [[Dual packaging]]
- [[ADR-001 Package name]]
- [[PyPI publishing]]
- [[Decisions]]
