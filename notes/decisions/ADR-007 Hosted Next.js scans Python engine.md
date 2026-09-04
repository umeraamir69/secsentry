---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-007 Hosted Next.js scans Python engine

## Context

We want a public website: paste a GitHub URL (public) or Connect GitHub (private), scan, dashboard, download, email. The user asked for Next.js.

A secrets scanner that clones private repos onto our servers is a **higher** trust bar than a local CLI. Rewriting detection in JavaScript would fork the engine and miss history/`git`.

## Decision

1. **Next.js** is the hosted UI (App Router, GitHub login, jobs, reports, email, download).
2. **Python `secsentry`** remains the only detection engine. The worker shells out to it.
3. Persist **masked findings and fingerprints only**. Ephemeral clone, then delete.
4. Private repos: GitHub App (preferred) or GitHub OAuth. Never a PAT form field.
5. In the **4-week** plan, Next.js **replaces** the FastAPI localhost dashboard so we do not build two websites. The CLI/terminal remains.
6. Host the worker next to git+Python (Docker Compose / Fly / Railway). Do not run history clones inside Vercel serverless.

## Consequences

- Portfolio shows full-stack (Next.js + OAuth + Python worker) and still one detector codebase
- Must write a short privacy/retention note before inviting others to connect private repos
- Public-repo paste is the safe demo; private connect is week 4 stretch
- `secsentry serve` is deferred, not cancelled

## Related

- [[Next.js web app]]
- [[ADR-004 Mask secrets never print them]]
- [[ADR-006 Localhost dashboard only]]
- [[Roadmap]]
- [[Decisions]]
