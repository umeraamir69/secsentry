---
tags:
  - adr
  - index
---

# Decisions

Index of architecture decision records.

Template: [[templates/decision]]

## Active

- [[ADR-001 Package name]] — publish as `secsentry`, not `gitsentry`
- [[ADR-002 Git via subprocess not GitPython]]
- [[ADR-003 History scans diffs not snapshots]]
- [[ADR-004 Mask secrets never print them]]
- [[ADR-005 Defer SAST and SCA]] — no SQLi/XSS/gems in this repo
- [[ADR-006 Localhost dashboard only]] — FastAPI `serve` deferred if Next.js ships first
- [[ADR-007 Hosted Next.js scans Python engine]]
- [[ADR-008 One engine two packages]] — pip + npm same version
- [[ADR-009 No live secret verification]] — never check keys against vendor APIs
