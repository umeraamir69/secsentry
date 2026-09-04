---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-004 Mask secrets never print them

## Context

A secrets scanner that prints full tokens in logs and HTML reports becomes a leak channel.

## Decision

- Display a masked form (`ghp_••••91Kd`)
- Identify duplicates with `SHA-256(secret)` fingerprints
- Allowlist fingerprints, never raw secrets
- Tests use obviously fake values

## Consequences

- JSON/HTML/CI logs are safer to share
- Dedup still works
- Debugging a miss is slightly harder (keep an optional `--show-unmasked` behind an explicit flag later, default off)

## Related

- [[Finding model]]
- [[Threat model]]
- [[Decisions]]
