---
tags:
  - index
---

# SecSentry

Local Git secrets leak scanner. Python engine, **pip + npm** in the same release, optional Next.js site. Obsidian is the project brain — Cursor reads and writes these same files.

**Do not name the PyPI package `gitsentry`.** That name is taken. Use `secsentry`. See [[ADR-001 Package name]].

## Start here

- [[Tasks]] — **the checklist. Every task, phase 0 → v1.0.0**
- [[What makes this real and unique]] — why this is not a Gitleaks clone
- [[Complete plan]] — four weeks, what to cut
- [[Product vision]]
- [[Roadmap]]
- [[Name availability]] — pip/npm free; **domain later**

## Map

### Product
- [[Tasks]]
- [[Complete plan]]
- [[What makes this real and unique]]
- [[Product vision]]
- [[Product scope]]
- [[CLI]]
- [[Finding model]]
- [[Reports]]
- [[LinkedIn showcase plan]]
- [[Demo vulnerable repo]]
- [[Dual packaging]]
- [[Next.js web app]]

### Architecture
- [[Architecture]]
- [[Detection engine]]
- [[Detector catalog]]
- [[API key detectors]]
- [[Git history scanner]]
- [[False positives]]
- [[Threat model]]

### Decisions
- [[Decisions]]
- [[ADR-001 Package name]]
- [[ADR-002 Git via subprocess not GitPython]]
- [[ADR-003 History scans diffs not snapshots]]
- [[ADR-004 Mask secrets never print them]]
- [[ADR-005 Defer SAST and SCA]]
- [[ADR-008 One engine two packages]]
- [[ADR-009 No live secret verification]]

### Research
- [[Research]]
- [[Name availability]]
- [[Competitor landscape]]

### Ops
- [[Accounts and keys]]
- [[Runbooks]]
- [[Inbox]]

## Current status

Week 1 CLI works and the **history demo is proven**: [[Demo vulnerable repo]] (`umeraamir69/testKeys`) — clean tree scans to 0 findings, `--history` recovers all 11. Next: push that repo, record the GIF, then first-seen/last-seen. **Do not start with PyPI/npm publish** — accounts now, publish Week 4. [[Tasks]] [[Accounts and keys]]

## How we use this vault

1. Capture in [[Inbox]] or a Daily Note.
2. Promote into architecture, decisions, research, or runbooks.
3. Link with `[[wikilinks]]`.
4. Never store real secrets here.
