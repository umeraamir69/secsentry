---
tags:
  - backup
  - product
---

# SecSentry — context for a new Cursor session

Read this before digging through the JSONL transcripts.

## What it is

**SecSentry** is a Git **incident** scanner for leaked secrets (not a Gitleaks clone). Engine is **Go**. npm and PyPI are PATH wrappers that spawn the Go binary (ADR-008). Never print/store raw secrets. Never vendor-verify keys. Always mask; location (`path:line:column`) always shown.

Repo: https://github.com/umeraamir69/secsentry (public)  
Demo: https://github.com/umeraamir69/testKeys (public, fake keys planted then deleted)

## Shipped

**v1.4.0** is live: GitHub Release binaries, `go install …@v1.4.0`, PyPI 1.4.0, npm 1.4.0.

Install that is the product:

```
go install github.com/umeraamir69/secsentry/cmd/secsentry@v1.4.0
```

`pip install secsentry` / `npx secsentry` still need that binary on PATH.

## Standing rules

- Fakes only in tests
- One detector engine: Go
- Do not chase generic_password in multilingual prose, unlabeled high-entropy, live `--verify`, or an unmask flag
- Do not copy Prowl’s 159 YAML rules or Gitleaks’ catalog as the pitch
- Do not `git push` unless asked
- Never claim ProwlBench numbers for a version that was not the binary that was actually run

## ProwlBench (honest, frozen)

Cite as **SecSentry 1.2.0 only**, commit `8c96549`. No `v1.2.0` tag. 1.3.x / 1.4.0 changed detectors.

Artifact: `eval/results/prowlbench_leaderboard.json`

- P 0.951, R 0.347, F1 0.509
- T1 0.64 vs Gitleaks 0.65; T2 0.01 vs Gitleaks 0.35
- T2 gap is **missing coverage**, not the classifier as the main drop

Do **not** commit `eval/results/prowlbench_cases.jsonl`.

## Known bug (not tagged yet)

Published **npm 1.4.0** `npx secsentry` recurses: the wrapper `spawnSync("secsentry")` without stripping its own bin dir. Local fix is in `packages/npm/bin/secsentry.js` (same idea as the pip wrapper). Needs a **1.4.1** publish. Pip wrapper works.

## Do not commit

- `src/secsentry/scan/archives.py`, `decode.py`, leftover Python engine tests
- Obsidian `graph.json` / `Untitled.canvas`
- `prowlbench_cases.jsonl`

## Accounts (public usernames only)

GitHub/npm `umeraamir69`; PyPI `umeraamir45`. No runtime vendor keys. Trusted Publishing for PyPI; npm Trusted Publisher + empty `NODE_AUTH_TOKEN` must be unset for OIDC.

## Transcripts

Raw chats: `notes/chats/agent-transcripts/`. Main thread is `c98fc775-…` (plan → Go port → 1.4.0 → LinkedIn). Shorter thread `8115824c-…`.
