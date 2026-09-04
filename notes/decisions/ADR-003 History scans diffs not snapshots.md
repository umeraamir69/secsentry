---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-003 History scans diffs not snapshots

## Context

Two history approaches: walk every file in every commit (snapshots) or scan added lines in diffs.

## Decision

MVP scans **added lines** from commit diffs. That finds secrets later deleted from HEAD and stays fast.

## Consequences

- Demo (`commit secret` → `delete secret` → history scan) works
- Renames / copy detection may need a follow-up
- Do not start with full-tree snapshots

## Related

- [[Git history scanner]]
- [[Demo vulnerable repo]]
- [[Decisions]]
