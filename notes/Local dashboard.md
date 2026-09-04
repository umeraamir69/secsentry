---
tags:
  - product
  - dashboard
---

# Local dashboard

Yes. A **localhost website** for dashboards and reports — including **who introduced which leak**. It is not a cloud SaaS. It never binds to `0.0.0.0` in v1.

Command:

```
secsentry scan . --history
secsentry serve
```

Or one shot:

```
secsentry serve . --history
```

Opens `http://127.0.0.1:8765`. Browser-only on your machine. [[ADR-006 Localhost dashboard only]]

This **replaces** a static `report.html` as the main visual. You can still export HTML/JSON from the UI.

## Why this is worth a week

LinkedIn and a Master’s viva both need a picture. A terminal is necessary; a dashboard shows:

- How many unique secrets
- What types
- **Who** (git author of first-seen commit)
- **When** (timeline)
- **Where** (file + still in HEAD vs only in history)
- What to do next (rotate)

## Pages

| Route | Name | What you see |
|---|---|---|
| `/` | Overview | KPIs: unique secrets, occurrences, CRITICAL/HIGH/MEDIUM/LOW, files scanned, commits scanned. Severity bars. “Still in working tree” vs “history only.” |
| `/secrets` | Secrets | One row per **fingerprint**. Type, severity, confidence, masked value, occurrence count, first seen, last seen. Click → detail. |
| `/secrets/{fingerprint}` | Secret detail | Occurrences (file, line, commit). First-seen author. Rotation guidance. Still present? |
| `/people` | Who leaked what | Table: author name, email, unique secrets introduced, highest severity, last incident date. Click a person. |
| `/people/{author_id}` | Person | Every secret whose **first-seen commit** is theirs. Files and dates. This is the “who leak what” view. |
| `/commits` | Timeline | Commits that added a finding, newest first. |
| `/files` | Hot files | Paths with the most findings. |
| `/report` | Export | Download JSON / standalone HTML. Last scan timestamp. |

No login. Local process + loopback is the access control.

## “Who leaked what”

Git already has the data. We do **not** guess from file ownership. We use:

- `commit.author_name`
- `commit.author_email`
- `commit.timestamp`
- first-seen commit per fingerprint

**Introduced by** = author of the commit where that fingerprint **first appears**. Later copies of the same secret (other files) are occurrences, not new blame.

Tone in the UI: **Introduced by**, not “leaked by” / “guilty.” This is incident investigation. The README should say authors can be wrong (pair programming, bot commits, `--author` override).

Working-tree-only scans (no `--history`) have empty author fields. The People page then shows “No commit metadata — run `secsentry scan --history`.”

## Data flow

```
Scan engine
    → findings (masked + fingerprint + author)
    → .secsentry/last-scan.json   (local cache, gitignored)
    → FastAPI reads JSON
    → Jinja pages + a little Chart.js (or CSS bars only)
```

Do not put a database in v1. One JSON file per repo is enough. Re-scan overwrites it.

`.gitignore` must include `.secsentry/` so reports never get committed.

## Stack (keep it Python)

| Piece | Choice |
|---|---|
| HTTP | FastAPI (uvicorn) |
| Pages | Jinja2 templates, one CSS file — no React |
| Charts | CSS bars first; Chart.js from a CDN only if needed |
| Bind | `127.0.0.1` only |
| Port | `8765` (configurable `--port`) |

Same finding model as the CLI. The dashboard is a viewer, not a second scanner.

## UI look (professional, not a toy)

- Dark, dense, security-tool feel (matches Rich terminal)
- Top bar: repo name, last scan time, **Scan again** button (runs scan, refreshes JSON, reloads)
- Filters: severity, type, “history only”, author
- Secrets always **masked**
- Empty state: “No findings” with a link to the demo repo

## Week 3 fit

The 4-week plan already had HTML reports in week 3. The live dashboard **is** that report, plus People / Timeline. Pre-commit hook still ships the same week; the dashboard is the visual. See [[Roadmap]].

If week 3 is too tight: ship `/` + `/secrets` + `/people` first. `/commits` and `/files` can be week 4.

## What this is not

- Not GitHub.com hosting
- Not email alerts
- Not multi-user team accounts
- Not SQLi/XSS dashboards
- Not bound to LAN/public IP in v1

Those stay in [[Feature evaluation - platform and SAST]] / after v1.

## LinkedIn

Screenshot of Overview + People (fake authors from the demo repo) is the week 3 post. Masked secrets visible. [[LinkedIn showcase plan]]

## Related

- [[Reports]]
- [[CLI]]
- [[Finding model]]
- [[ADR-006 Localhost dashboard only]]
- [[Threat model]]
- [[Demo vulnerable repo]]
