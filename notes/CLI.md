---
tags:
  - product
  - cli
---

# CLI

Package and command: `secsentry` (not `gitsentry`). [[ADR-001 Package name]]

## Commands

| Command | Purpose |
|---|---|
| `secsentry scan .` | Working tree |
| `npx secsentry scan .` | Same CLI via npm wrapper |
| `secsentry scan . --history` | Full git history |
| `secsentry scan --staged` | Index only |
| `secsentry scan . --severity high` | Filter |
| `secsentry scan . --type aws` | One detector family |
| `secsentry scan . --format json` | CI / dashboard cache |
| `secsentry serve` | Local dashboard at http://127.0.0.1:8765 |
| `secsentry serve . --history` | Scan then open dashboard |
| `secsentry install-hook` | Write `.git/hooks/pre-commit` |
| `secsentry uninstall-hook` | Remove hook |
| `secsentry baseline create` | Later: ignore known old findings |

## Terminal UI

Rich. Show repo, files scanned, commits scanned, counts by severity, then findings with type, file, line, commit, confidence, masked secret.

Exit code non-zero when HIGH/CRITICAL found (configurable).

## Related

- [[Architecture]]
- [[Reports]]
- [[Local dashboard]]
- [[Pre-commit hook]]
