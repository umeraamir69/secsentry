---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-002 Git via subprocess not GitPython

## Context

The original plan listed GitPython. GitPython adds a dependency and historically has edge cases around diffs, encoding, and packed repos.

## Decision

Call the `git` CLI via subprocess for history, staged diffs, and metadata.

## Consequences

- Requires `git` on PATH (true for this tool anyway)
- Fewer Python deps
- Easy to reproduce bugs with the same git commands
- Revisit GitPython only if subprocess becomes a bottleneck

## Related

- [[Git history scanner]]
- [[Architecture]]
- [[Decisions]]
