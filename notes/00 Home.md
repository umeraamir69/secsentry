---
tags:
  - index
---

# SecSentry

Local Git secrets leak scanner. Python engine, **pip + npm** in the same release, optional Next.js site. Obsidian is the project brain — Cursor reads and writes these same files.

**Do not name the PyPI package `gitsentry`.** That name is taken. Use `secsentry`. See [[ADR-001 Package name]].

## Start here

- [[What makes this real and unique]] — why this is not a Gitleaks clone
- [[Complete plan]] — four weeks, what to cut
- [[Product vision]]
- [[Roadmap]]
- [[Name availability]] — pip/npm free; **domain later**

## Map

### Product
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
- [[Runbooks]]
- [[Inbox]]

## Current status

Plan: unique investigation scanner, not a rule-count race. Domain deferred. Next: scaffold `src/secsentry`.

## How we use this vault

1. Capture in [[Inbox]] or a Daily Note.
2. Promote into architecture, decisions, research, or runbooks.
3. Link with `[[wikilinks]]`.
4. Never store real secrets here.
