---
tags:
  - product
  - packaging
---

# Dual packaging (pip + npm)

The engine is the **Go binary**. npm is a PATH wrapper, not a second scanner. [[ADR-008 One engine two packages]]

```
go install github.com/umeraamir69/secsentry/cmd/secsentry@latest
npx secsentry scan .
```

`secsentry` is free on npm (checked 2026-09-03). [[Name availability]]

## Monorepo layout

```
secsentry/
├── cmd/secsentry/          # Go CLI
├── internal/               # engine
├── packages/npm/           # npm wrapper
│   ├── package.json
│   ├── bin/secsentry.js    # spawns the Go binary
│   └── README.md
├── .github/workflows/release.yml
└── VERSION
```

`package.json` `"version"` and `internal/version/version.go` must match `VERSION`.

## What the npm package does

`bin/secsentry.js`:

1. Prefer `python3 -m secsentry` if the pip package is installed
2. Else try `secsentry` already on PATH (pipx / venv)
3. Else print: install Python 3.12+ and `pip install secsentry`, exit 1

Do **not** reimplement regexes in JavaScript. Next.js calls the same CLI/worker. [[Next.js web app]]

Optional later: Docker-based `npx` that does not need a local Python. Not required for v0.1.

## Simultaneous release

On tag `vX.Y.Z`:

1. Build wheel + sdist → TestPyPI (first release) or PyPI Trusted Publishing
2. `npm publish` from `packages/npm` (npm Trusted Publisher / token)
3. GitHub Release notes list both install lines

Local check **before** either registry:

```
pip install dist/secsentry-*.whl
secsentry --help
node packages/npm/bin/secsentry.js --help
```

## Accounts you need

| Registry | Account | Notes |
|---|---|---|
| PyPI | pypi.org + test.pypi.org | 2FA, Trusted Publishing from GitHub |
| npm | npmjs.com | 2FA, enable 2FA-required publish |

Claim `secsentry` on **both** as soon as the first test publish works, so the name is not taken while you build.

## Related

- [[PyPI publishing]]
- [[ADR-001 Package name]]
- [[ADR-008 One engine two packages]]
- [[Roadmap]]
