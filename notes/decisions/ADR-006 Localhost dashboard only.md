---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-006 Localhost dashboard only

## Context

We want a website with dashboards and “who introduced which secret.” A hosted SaaS would mean accounts, auth, and shipping scan data off-machine — bad for a secrets tool and too big for four weeks.

## Decision

This ADR is the **offline CLI UI** (if we build it).

- Serve a local web UI: `secsentry serve` on **127.0.0.1** only
- Default port 8765
- Persist the last scan as `.secsentry/last-scan.json` (gitignored)
- Masked secrets only, same [[Finding model]]
- No authentication (loopback is the control)

**4-week plan:** do **not** build this and the hosted Next.js app in the same month. Hosted product is [[ADR-007 Hosted Next.js scans Python engine]] / [[Next.js web app]]. FastAPI `serve` is a later offline mode.

## Consequences

- Strong LinkedIn/Master’s visual without becoming a cloud product
- “Who leaked what” uses git author of first-seen commit
- Cannot share the dashboard with teammates over the network in v1 (export JSON/HTML instead)
- Must gitignore `.secsentry/` so findings are not committed

## Related

- [[Local dashboard]]
- [[ADR-004 Mask secrets never print them]]
- [[Threat model]]
- [[Decisions]]
