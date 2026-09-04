---
tags:
  - product
  - web
---

# Next.js web app (hosted scans)

Yes, you can build a **website** where someone pastes a public GitHub URL, or signs in for **private** repos, we scan, show a report, allow **download**, and **email** the report.

Do this in **Next.js**. Do **not** rewrite detectors in TypeScript. The Python engine stays the scanner. Next.js is login, jobs, dashboard, download, email.

This is a second product surface on top of the CLI. Spec: [[ADR-007 Hosted Next.js scans Python engine]]. Timeline: [[Roadmap]].

## User flow

```
Landing
  ├── Public repo: paste https://github.com/org/repo  → Scan
  └── Private repo: Connect GitHub → pick a repo you can access → Scan
           │
           ↓
     Job queued (clone on a worker, not on Vercel)
           │
           ↓
     Dashboard (masked findings, who introduced what)
           │
           ├── Download JSON / HTML
           └── Email report to the address on the GitHub account (opt-in)
```

No “paste a personal access token into a text box.” That is how tokens get stolen. Private access = **GitHub App** (or OAuth with `repo` only if App is too slow for the MVP).

## What the Next.js app owns

| Piece | Stack |
|---|---|
| UI | Next.js App Router, TypeScript, one clean dashboard |
| Auth | NextAuth (GitHub) **or** GitHub App installation |
| Public scan | Server action: validate `github.com/owner/repo`, enqueue job |
| Private scan | Installation token, never stored as a user PAT in our DB |
| Jobs | Queue (Postgres + worker loop is enough for a student MVP) |
| Worker | Python `secsentry scan --history --format json` after `git clone` |
| DB | Postgres: users, repos, jobs, **masked** findings only |
| Email | Resend or similar, HTML report, opt-in |
| Download | JSON + standalone HTML (same [[Finding model]]) |

## What Next.js must not do

- Clone a 2 GB history inside a Vercel serverless function (timeouts, no git)
- Store raw secrets, clone tarballs, or GitHub tokens in plaintext logs
- Ask the user to paste `ghp_…` into the form
- Scan every repo in an org unless they picked it
- Bind this as “replace Gitleaks Cloud” in four weeks

History scan needs a **long-running worker** with `git` + Python. Vercel hosts the **website**. Fly.io, Railway, or a single Docker Compose box hosts the **worker**. Student-simple: one VPS/Docker Compose runs Next.js + worker + Postgres.

```
Browser  →  Next.js (UI + API)
                 │
                 │ job: { repo, installation_id or public url }
                 ↓
           Worker
             git clone --no-checkout / fetch history
             secsentry scan . --history --format json
             shred clone directory
             write masked JSON to Postgres
                 │
                 ↓
           Next.js dashboard reads findings
```

## Public vs private

| Mode | Auth | How we get the code |
|---|---|---|
| Public | None (rate-limit by IP) | `git clone https://github.com/org/repo.git` |
| Private | GitHub App installed on that repo, or OAuth | Clone with short-lived installation token |

Public paste is the LinkedIn demo (use `examples` or a public **fake-secret** demo repo). Private is the “Connect GitHub” path.

## Email and download

- **Download:** always. JSON + HTML. Masked. Same as local reports.
- **Email:** button “Send to my GitHub email.” Not a newsletter. Not other people’s addresses. Include a one-line warning: this mail still describes findings; use a mailbox you control.
- Do not attach the git clone. Attach the **report**.

## Security (non-negotiable)

This is why hosted scanning is harder than `secsentry serve` on localhost.

1. Mask in the worker **before** anything hits the database. [[ADR-004 Mask secrets never print them]]
2. Delete the clone when the job ends (success or fail).
3. Gitignore and never log `git clone` URLs that contain tokens.
4. Privacy policy: what you store (repo name, masked findings, author names from git), retention (e.g. 30 days), how to delete.
5. Rate limits: public anonymous scans.
6. Only the GitHub user who started the job sees that private report.
7. `fetch-depth: 0` / full clone for history — warn that large repos take minutes.

Treat this like a small security product, not a student CRUD app. Interviewers will ask “where do the secrets go?” Answer: **never stored; fingerprints and masks only; clone is ephemeral.**

## Two UIs — pick one for the four weeks

Do not build FastAPI **and** Next.js in four weeks.

| UI | Role |
|---|---|
| Rich terminal | Always. CLI + hook. |
| Next.js site | Hosted dashboard + GitHub connect + email/download. **This is your website.** |
| `secsentry serve` (FastAPI) | Skip in the 4-week plan if Next.js is the website. Add later as offline mode if you want. |

Local users still run `secsentry scan` with no account. The website is for people who will not install Python.

## Four-week fit

Python engine is weeks 1–2 (unchanged). Weeks 3–4 become the Next.js MVP instead of FastAPI.

- Week 3: landing, paste public URL, job, dashboard, download
- Week 4: GitHub connect (private), email, deploy, LinkedIn GIF of the **site**

If week 4 slips: ship public-only. Private OAuth is the stretch. Details: [[Roadmap]]

## LinkedIn angle

“I built a GitHub-connected scanner in Next.js” is a strong post **if** you also say the engine is Python and secrets are not stored. Screenshot the web dashboard (fake demo repo). [[LinkedIn showcase plan]]

## Related

- [[ADR-007 Hosted Next.js scans Python engine]]
- [[Local dashboard]] — local-only alternative we deprioritize if this ships
- [[Architecture]]
- [[Threat model]]
