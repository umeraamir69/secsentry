---
tags:
  - product
  - packaging
---

# Dual packaging (pip + npm)

Ship **both** registries on every version. Same name, same version, same CLI.

```
pip install secsentry
npm install -g secsentry
npx secsentry scan .
```

`secsentry` is free on **PyPI and npm** (checked 2026-09-03). [[Name availability]]

There is **one detector engine** (Python). npm is a wrapper, not a second scanner. [[ADR-008 One engine two packages]]

## Monorepo layout

```
secsentry/
├── src/secsentry/          # Python package (PyPI)
├── pyproject.toml
├── packages/npm/           # npm package
│   ├── package.json        # name: secsentry, bin: secsentry
│   ├── bin/secsentry.js    # finds python, runs the CLI
│   └── README.md
├── web/                    # Next.js app (later)
├── .github/workflows/release.yml   # publishes BOTH
└── VERSION                 # single source, e.g. 0.1.0
```

`package.json` `"version"` and `[project].version` must match. Release CI reads `VERSION` (or git tag `v0.1.0`) and writes both.

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
