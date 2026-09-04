---
tags:
  - architecture
---

# Architecture

One scan engine, three inputs, one finding model. Detectors never print raw secrets.

```
                    SecSentry
                        │
         ┌──────────────┴──────────────┐
         │                             │
     CLI Interface              Pre-commit hook
         │                             │
         └──────────────┬──────────────┘
                        │
                   Scan engine
                        │
        ┌───────────────┼───────────────┐
        │               │               │
   File scanner   Git history     Staged scanner
        │               │               │
        └───────────────┼──────────────┘
                        │
                Detection engine
                        │
         ┌──────────────┼──────────────┐
         │              │              │
       Regex         Entropy        Context
         │              │              │
         └──────────────┼──────────────┘
                        │
                  Risk scoring
                        │
                  Deduplication
                        │
               ┌────────┴────────┐
               │                 │
           Terminal          Reporting
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
                   JSON         HTML     Local dashboard
                                         (127.0.0.1)
```

Details: [[Detection engine]], [[Git history scanner]], [[Finding model]], [[Reports]], [[Local dashboard]], [[CLI]], [[Pre-commit hook]].

## Stack

Keep v1 small.

| Choice | Why |
|---|---|
| Python 3.12+ | Matches the plan; typing and `tomllib` |
| Typer | Clean CLI, `--help`, exit codes |
| Rich | Professional terminal UI |
| Git **subprocess** | Diffs, staged, log without GitPython bugs. [[ADR-002 Git via subprocess not GitPython]] |
| stdlib `re`, `math`, `hashlib` | Regex, entropy, fingerprints |
| FastAPI + uvicorn | Local dashboard only (`127.0.0.1`) |
| Jinja2 | Dashboard pages + optional HTML export |
| pytest | Tests |

No ML in v1. Regex + entropy + context is enough.

## Repo layout (src layout for PyPI)

```
secsentry/
├── src/secsentry/
│   ├── __init__.py
│   ├── cli.py
│   ├── scanner/
│   │   ├── file_scanner.py
│   │   ├── staged_scanner.py
│   │   ├── git_history.py
│   │   ├── entropy_scanner.py
│   │   └── deduplicator.py
│   ├── detectors/
│   │   ├── openai.py
│   │   ├── anthropic.py
│   │   ├── aws.py
│   │   ├── github.py
│   │   ├── google.py
│   │   ├── stripe.py
│   │   ├── jwt.py
│   │   ├── private_keys.py
│   │   └── generic.py
│   ├── models/finding.py
│   ├── reports/
│   │   ├── terminal.py
│   │   ├── json_report.py
│   │   └── html_report.py
│   ├── dashboard/
│   │   ├── app.py
│   │   └── templates/
│   └── hooks/pre_commit.py
├── packages/npm/          # npx / npm i -g secsentry
├── web/                   # Next.js hosted app
├── tests/
├── examples/vulnerable-repo/
├── notes/          ← this Obsidian vault
├── pyproject.toml
├── VERSION
├── README.md
└── LICENSE
```

`[project.scripts]` → `secsentry = secsentry.cli:app`

npm `"bin": { "secsentry": "bin/secsentry.js" }` — wrapper only. [[Dual packaging]]

## File scanner exclusions

Do not scan blindly. Skip `.git/`, `node_modules/`, `venv/`, `.venv/`, `__pycache__/`, `dist/`, `build/`, binaries.

Later: `.secsentryignore`.

## Related

- [[Threat model]]
- [[Decisions]]
- [[Roadmap]]
