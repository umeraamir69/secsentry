---
tags:
  - architecture
  - git
---

# Git history scanner

This is the core feature. A later commit that deletes a secret does **not** make history safe.

```
Git repository
      │
      ↓
Enumerate commits
      │
      ↓
Get diffs (added lines)
      │
      ↓
Run detectors
      │
      ↓
Create findings + commit metadata
      │
      ↓
Deduplicate by fingerprint
      │
      ↓
Report
```

## Approach

**MVP: diffs, not full snapshots.** Scan `+` lines. Fast and enough to find deleted secrets. [[ADR-003 History scans diffs not snapshots]]

Full tree snapshots only if diffs miss renames later.

## Metadata on historical findings

- Commit SHA
- Author
- Date
- File
- Line
- First seen / last seen (later: secret age, exposure timeline)

## Staged mode

Pre-commit uses `git diff --cached` only. Target: under 1 second on a normal repo. [[Pre-commit hook]]

## Related

- [[Demo vulnerable repo]]
- [[Architecture]]
- [[Detection engine]]
