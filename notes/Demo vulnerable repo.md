---
tags:
  - product
  - demo
---

# Demo vulnerable repo

The portfolio proof. Only **obviously fake** values. Never real keys.

Path: `examples/vulnerable-repo/` (or a separate public repo later).

## Script

1. Commit 1: add fake `AWS_ACCESS_KEY`, `DATABASE_URL`, `GITHUB_TOKEN` (`ghp_TESTONLY_…`, `AKIA` + TEST, `postgres://user:password@localhost/db`)
2. Commit 2: delete them from the working tree
3. Run `secsentry scan --history`
4. Findings still point at commit 1

Current filesystem looks clean. Git history does not. That is the demo. GIF that for the README.

## Related

- [[Git history scanner]]
- [[Product vision]]
- [[PyPI publishing]]
