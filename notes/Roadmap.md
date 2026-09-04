---
tags:
  - product
  - roadmap
---

# Roadmap

Four weeks, not eight. Ship something demoable at the end of every week so LinkedIn has a real version to announce. Full announcement calendar: [[LinkedIn showcase plan]].

Rule: **history scan by the end of week 2.** That is the portfolio moment. The **website** is weeks 3–4 (Next.js), not a second detector.

Hosted GitHub UI: [[Next.js web app]]. FastAPI localhost UI is deferred. [[ADR-007 Hosted Next.js scans Python engine]]

## Versions (aligned with posts)

| When          | Version | You can show                                                          |
| ------------- | ------- | --------------------------------------------------------------------- |
| End of week 1 | v0.1.0  | `secsentry scan .` finds AWS / GitHub / PEM in files                  |
| End of week 2 | v0.2.0  | `secsentry scan . --history` finds a **deleted** secret               |
| End of week 3 | v0.3.0  | Next.js site: paste **public** GitHub URL, dashboard, download report |
| End of week 4 | v1.0.0  | Connect GitHub (private), email report, deploy, tests, LinkedIn recap |

If week 4 slips, ship public-only web + CLI. Private OAuth is the stretch, not history scan.

Platform (GitHub/Bitbucket remotes, PR comments, email): after these 4 weeks. See [[Feature backlog]] and [[Ideas beyond v1]].

## Week 1 — working CLI

**Goal:** a real command, not a script.

- `src/secsentry` + `pyproject.toml` + Typer
- File walker (skip `.git`, `node_modules`, venv, binaries)
- [[Finding model]] + masking + fingerprint
- Detectors: OpenAI, Anthropic/Claude, AWS, GitHub, Google, Stripe, PEM, generic `*_API_KEY` + entropy. See [[API key detectors]]
- Scaffold `packages/npm` wrapper in the same week (even if unpublished)
- Rich terminal output
- Rich terminal output
- pytest on fixtures with **fake** secrets only

**Done when:** `secsentry scan examples/` prints HIGH findings with masked values.

**LinkedIn:** kickoff post on day 1; v0.1 post on Sunday. Copy: [[LinkedIn showcase plan]].

## Week 2 — the demo

**Goal:** deleted secrets still show up.

- Shannon entropy + context scoring + severity
- [[False positives]] fixtures (UUID, lockfile, `password="password"`)
- [[Git history scanner]] (diffs, commit SHA / author / date)
- Dedup by fingerprint
- [[Demo vulnerable repo]]: commit fakes → delete → history still finds them
- JSON output (`--format json`)

**Done when:** one terminal recording of history scan on the demo repo.

**LinkedIn:** this is the main post of the month. GIF + explanation. v0.2.0.

## Week 3 — usable by other developers

**Goal:** it can block a commit, and you have a local website for reports.

- `--staged` + [[Pre-commit hook]] (`install-hook` / `uninstall-hook`)
- Persist last scan to `.secsentry/last-scan.json` (gitignored)
- [[Local dashboard]]: `secsentry serve` on `127.0.0.1:8765`
  - Overview, Secrets, **People (who introduced what)**, Timeline, Files
- JSON export from the UI; optional static HTML download
- `.secsentryignore` + fingerprint allowlist (keep baseline simple)
- `--severity high`
- Rotation one-liners per detector type

**Done when:** a dirty commit is blocked; browser opens the dashboard on the demo repo and the People page shows the fake commit author.

**LinkedIn:** v0.3.0 screenshot of Overview + People. Secrets masked.

## Week 4 — portfolio + publish

**Goal:** someone else can install it and you can talk about it in interviews.

- Broader tests + a small benchmark table (tiny / medium repo)
- GitHub Actions: scan this repo on push (fail on HIGH)
- README: install, demo GIF, architecture, limitations, related work
- SECURITY.md + CHANGELOG
- TestPyPI **and** npm pack locally; week 4 publishes **both** ([[Dual packaging]])
- Short “what I built / what I learned” write-up for LinkedIn + CV

**Done when:** `pip install` and `npx secsentry --help` both work (TestPyPI + npm), GitHub README has the GIF, LinkedIn recap is posted.

## Daily rhythm (keep it sustainable)

| Day | Default |
|---|---|
| Mon–Thu | Build the week’s “done when” |
| Friday | Tests + version bump + changelog line |
| Weekend | One LinkedIn post for that version — not daily updates |

If a week slips, **do not skip week 2.** Cut extra LLM prefixes (keep OpenAI+Anthropic+generic), private GitHub OAuth, or PyPI **before** you skip npm wrapper **or** history scan. Still publish both installers even if one is “beta.”

## Related

- [[LinkedIn showcase plan]]
- [[Dual packaging]]
- [[API key detectors]]
- [[Next.js web app]]
- [[Product vision]]
