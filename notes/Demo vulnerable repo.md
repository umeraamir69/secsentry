---
tags:
  - product
  - demo
---

# Demo vulnerable repo

The portfolio proof. Only **obviously fake** values. Never real keys.

**Built 2026-09-04.** Lives in its own repo: `umeraamir69/testKeys` (local path `~/Documents/testKeys`).

## Why a separate repo, not `examples/`

Planting fake keys inside the SecSentry repo itself would mean:

- `secsentry scan . --history` on our own repo reports them forever
- GitHub secret scanning flags the main portfolio repo
- The demo is muddled with the tool's own source

A separate repo also lets us run the SecSentry **GitHub Action on it as an outside consumer**, which is the more convincing demo. [[GitHub integration]]

## Script (done)

| Commit | Message | Effect |
|---|---|---|
| `3836986` | Add service configuration and deploy key | Plants 8 fake credentials in `app/config.py`, `app/db.py`, `.env`, `deploy/id_rsa` |
| `ce0b792` | Remove hardcoded credentials, read config from environment | Deletes them, adds `.gitignore` + `.env.example` |

## Result

```
secsentry scan ~/Documents/testKeys
  → files=6  findings=0        clean tree, and no false positives

secsentry scan ~/Documents/testKeys --history
  → findings=11                every planted key, still_in_head=False,
                               commit=3836986b, author=Umer Aamir
```

11 occurrences from 8 unique secrets (the AWS key, GitHub PAT, and DB URL each appear in two files, which is what the fingerprint dedup is for).

## Planted

Positives: AWS access key, GitHub PAT, OpenAI key, Slack bot token, Postgres URL with password, RSA private key, generic `api_key`, JWT.

Negatives in `tests/fixtures.py` that must **not** fire: UUID, git SHA, `sha512-` lockfile hash, `password = "password"`, `AKIAIOSFODNN7EXAMPLE`. All five stayed quiet. [[False positives]]

## Bugs this demo caught

Running it end to end found two release blockers that unit tests missed:

1. `ScanReport.should_fail` compared uppercase severities (`"CRITICAL"`) against a lowercase rank table, so **the CI gate never failed**. Fixed; `tests/test_engine.py` covers it.
2. `__main__.py` called `main()` without `sys.exit()`, so `python -m secsentry` **always exited 0** — breaking the pre-commit hook, the GitHub Action, and the npm wrapper, all of which shell out that way. Fixed.

## Still to do

- [ ] Push `testKeys` to GitHub (may need to allow GitHub push protection — nothing is live)
- [ ] Record the GIF: clean scan → history scan
- [ ] Run the SecSentry Action against this repo from a PR

## Related

- [[Tasks]]
- [[Git history scanner]]
- [[Product vision]]
