# Project directory and structure

Every path below exists in this repo. The Go engine is the only place detectors live. npm and the GitHub Action **call** that binary.

```
secsentry/
│
├── README.md                      Complete plan + how to run
├── STRUCTURE.md                   This file
├── LICENSE                        MIT
├── VERSION                        Single version for Go and npm
├── go.mod
├── cmd/secsentry/                 Go CLI
├── internal/                      Detector engine (Go)
├── pyproject.toml                 Legacy Python tree; not the product engine
├── action.yml                     Marketplace-ready GitHub Action
├── SECURITY.md                    How to report issues; no live secrets
├── .gitignore
├── .env.example                   Empty placeholders only
│
├── .github/
│   └── workflows/
│       └── secsentry.yml          PR check: "SecSentry / secrets"
│
├── src/secsentry/                 Installable package (src layout)
│   ├── __init__.py
│   ├── __main__.py                python -m secsentry
│   ├── cli.py                     argparse: scan, install-hook, …
│   ├── models.py                  Finding, mask_secret, fingerprint
│   │
│   ├── git/
│   │   ├── __init__.py
│   │   ├── run.py                 git -C subprocess helper
│   │   └── blobs.py               rev-list + ls-tree; scan each blob OID once
│   │
│   ├── scan/
│   │   ├── __init__.py
│   │   ├── engine.py              Orchestrates detectors → verify → classify
│   │   ├── working_tree.py        Walk files; hash-object for blob reuse
│   │   ├── staged.py              git diff --cached
│   │   └── history.py             All commits; attach cached blob findings
│   │
│   ├── detectors/
│   │   ├── __init__.py
│   │   ├── registry.py            Rule list + dispatch
│   │   ├── patterns.py            P0 prefixes (AWS, GitHub, OpenAI, Claude, …)
│   │   └── entropy.py             Shannon entropy candidates
│   │
│   ├── verify/
│   │   ├── __init__.py
│   │   └── structural.py          JWT/PEM/prefix/length — no network
│   │
│   ├── classify/
│   │   ├── __init__.py
│   │   ├── features.py            Path, keywords, entropy, structural_ok
│   │   ├── heuristic.py           Rules before/without sklearn
│   │   └── ml.py                  Optional joblib model
│   │
│   ├── reports/
│   │   ├── __init__.py
│   │   ├── terminal.py
│   │   └── json_report.py
│   │
│   ├── hooks/
│   │   ├── __init__.py
│   │   └── pre_commit.py
│   │
│   └── eval/
│       ├── __init__.py
│       ├── build_corpus.py        Plant labeled fakes in mini git repos
│       ├── train.py
│       └── benchmark.py           Precision/recall vs Gitleaks, TruffleHog
│
├── packages/
│   └── npm/
│       ├── package.json           name: secsentry, same VERSION
│       ├── bin/secsentry.js       Spawns python -m secsentry
│       └── README.md
│
├── web/                           Next.js hosted UI (not required for v0.1)
│   └── README.md
│
├── tests/
│   ├── test_models.py
│   ├── test_patterns.py
│   ├── test_structural.py
│   └── test_cli.py
│
├── eval/
│   ├── README.md                  How to rebuild the labeled corpus
│   └── .data/                     Generated (gitignored)
│
├── examples/
│   └── vulnerable-repo/
│       └── README.md              Commit fakes, delete, scan --history
│
└── notes/                         Obsidian vault (Cursor reads these too)
    └── 00 Home.md
```

## Ownership

| Need | Path |
|---|---|
| Detection logic | `src/secsentry/detectors/` |
| History + blob dedup | `src/secsentry/git/blobs.py`, `scan/history.py` |
| No vendor API | `src/secsentry/verify/structural.py` |
| ML / benchmark | `src/secsentry/eval/` |
| `npx secsentry` | `packages/npm/` |
| PR sidebar check | `action.yml` + `.github/workflows/` |
| Website | `web/` later |
| Product decisions | `notes/` |

## Version sync

`VERSION` is `0.1.0`. Keep `pyproject.toml` `[project].version` and `packages/npm/package.json` `"version"` identical.
