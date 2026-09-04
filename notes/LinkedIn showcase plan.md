---
tags:
  - product
  - portfolio
  - linkedin
---

# LinkedIn showcase plan

You are a Master’s student. LinkedIn should look like a **public build log**, not a product launch. Post when a version exists. Do not post every commit.

Package name in public: **SecSentry** (`secsentry`). Never tell people to `pip install gitsentry`. [[ADR-001 Package name]]

## Rules

1. **Show work, not hype.** GIF or screenshot of the CLI. No “disrupting DevSecOps.”
2. **Never paste a real secret.** Demo values only (`ghp_TESTONLY_`, `AKIA` + TEST). Same rule as the repo.
3. **Be honest.** Gitleaks and TruffleHog already exist. You are building one to learn detection, Git history, and packaging — and to show you can ship.
4. **Name the program.** One line: Master’s student in [your field] building a local Git secrets scanner.
5. **Four posts in four weeks** plus a kickoff. Optional fifth: a short article. That is enough.

Put the GitHub repo in Featured on your profile after week 2 (when the history demo works).

## Calendar

| When | Version | Post type | What you announce |
|---|---|---|---|
| Day 1 | — | Kickoff | What you are building and why history scan matters |
| End of week 1 | v0.1.0 | Progress | CLI + regex detectors, masked output |
| End of week 2 | v0.2.0 | **Main demo** | History scan still finds deleted fake secrets |
| End of week 3 | v0.3.0 | Product | Pre-commit hook + localhost dashboard |
| End of week 4 | v1.0.0 | Recap | Install, tests, CI, what you learned |
| Optional later | — | Article | How secret scanning actually works (entropy + diffs) |

Hashtags (3–5, not 20): `#CyberSecurity` `#DevSecOps` `#AppSec` `#Python` `#OpenSource` — plus your university if they allow student project posts.

## Profile setup (once)

- Headline: something like `Master’s student | Building SecSentry, a local Git secrets scanner`
- Featured: GitHub repo (after v0.2), then PyPI when it exists
- About: 4–5 lines — problem (secrets in git history), approach (regex + entropy + diffs), status (week N / version)
- Experience or Projects: SecSentry with version and date, updated each week

## Post drafts (edit the brackets)

### 1 — Kickoff (day 1)

> I’m a Master’s student working on **SecSentry**, a local Python tool that finds leaked secrets in Git repos.
>
> Most scanners look at the files you have now. That’s not enough: a key can be committed, deleted in the next commit, and still live in `git log`.
>
> Over the next four weeks I’m building:
> - regex + entropy detection (masked output, no raw secrets in logs)
> - full history scan
> - a pre-commit hook
> - a **localhost dashboard** (who introduced which secret, reports — nothing leaves the machine)
>
> Week 1 target: `secsentry scan .` on a dummy repo.
>
> I’ll post each version here. Repo: [link once it exists]
>
> #CyberSecurity #Python #AppSec

### 2 — v0.1.0 (end of week 1)

> **SecSentry v0.1.0**
>
> This week the CLI actually runs.
>
> `secsentry scan .` walks a repo, skips junk directories, and flags known shapes (GitHub tokens, AWS keys, JWTs, private keys) plus generic `api_key=` / `password=` assignments.
>
> Output is masked (`ghp_••••91Kd`) with a SHA-256 fingerprint so I can dedupe without storing the secret.
>
> Next week: Git history — the case where the secret was deleted but still in old commits.
>
> [screenshot of terminal, secrets masked]
>
> GitHub: [link]

### 3 — v0.2.0 (end of week 2) — use this one in applications

> **SecSentry v0.2.0 — history scan**
>
> Demo I wanted for the portfolio:
>
> 1. Commit fake AWS / GitHub / DB credentials
> 2. Delete them in a later commit
> 3. Working tree looks clean
> 4. `secsentry scan . --history` still reports the first commit
>
> That’s the incident-response version of secret scanning: current files are not the whole story.
>
> Also this week: Shannon entropy + keyword context so unknown random strings can score, and obvious false positives (UUIDs, lockfile hashes) score down.
>
> [GIF of the four steps]
>
> GitHub: [link]

### 4 — v0.3.0 (end of week 3)

> **SecSentry v0.3.0**
>
> History scan finds old leaks. A hook tries to stop new ones. This week I also added a local website.
>
> `secsentry serve` → `http://127.0.0.1:8765`
>
> - Overview: severity counts, still-in-tree vs history-only
> - Secrets: unique fingerprints, masked values
> - People: **who introduced what** (git author of the first-seen commit)
>
> `secsentry install-hook` still blocks a dirty `git commit` on staged files.
>
> Loopback only — scan data does not go to a cloud dashboard. Demo authors are fake.
>
> [screenshot: Overview + People, secrets masked]
>
> GitHub: [link]

### 5 — v1.0.0 recap (end of week 4)

> **SecSentry v1.0.0** — four-week Master’s project recap
>
> I shipped a Python Git secrets scanner:
> - working tree, staged, and history
> - regex + entropy + context scoring
> - masked findings + fingerprints
> - pre-commit hook
> - localhost dashboard (who introduced what — git authors, masked secrets)
> - JSON export + GitHub Action
> - installable package (`pip install secsentry` / TestPyPI)
>
> What I learned: detection is easy to over-fire; the hard part is confidence, history, and not leaking the secret again in the report.
>
> What I’m not claiming: this does not replace Gitleaks/TruffleHog in production. It is a complete tool I can explain line by line.
>
> Next (if I continue): GitHub/Bitbucket remote scan and PR comments — not SQLi/XSS. Those are a different product.
>
> Repo + demo GIF: [link]
>
> Happy to talk about secret scanning, Git internals, or the evaluation set I used.

### Optional LinkedIn article (after v1)

Title idea: **Why scanning the working tree is not enough**

Sections: problem (deleted secrets), method (diff-based history), scoring (regex vs entropy vs context), evaluation (true/false positives on fixtures), limitations, related work. This doubles as a mini paper for your Master’s portfolio.

## What to put in the GitHub README for LinkedIn traffic

People click through. README must have, in order:

1. One-sentence pitch
2. GIF of history scan
3. Install + three commands
4. Screenshot of the localhost dashboard (People page)
5. Architecture (short)
6. **Limitations** (you will be asked this in interviews)
7. Related work (Gitleaks, TruffleHog, detect-secrets)
8. License

## CV / applications one-liner

> SecSentry — Python CLI + local dashboard that detects leaked secrets in Git working trees, staged diffs, and full history (regex + Shannon entropy, masked reports, pre-commit hook). v1.0 in four weeks; [GitHub].

Update the version number when you post.

## Related

- [[Roadmap]]
- [[Demo vulnerable repo]]
- [[Ideas beyond v1]]
- [[Local dashboard]]
