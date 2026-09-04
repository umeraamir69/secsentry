---
tags:
  - product
  - plan
---

# Complete plan

Single source of truth. Positioning: [[What makes this real and unique]]. Domain: **deferred** — use Vercel/GitHub Pages. [[Name availability]]

## Identity (lock)

| Piece | Value |
|---|---|
| Display | SecSentry |
| pip / npm / CLI | `secsentry` (both registries **free** as of 2026-09-04) |
| Engine | Python 3.12+ |
| npm | Wrapper only [[ADR-008 One engine two packages]] |
| Website | Later; `*.vercel.app` is enough |
| Not | `gitsentry` |

## Problem we actually solve

A developer deletes a key from `config.py` and thinks they are safe. Git history still has it. Existing tools either dump noisy regex hits or **verify** the key by sending it to the vendor.

We produce a **case file**: unique secret (fingerprint), masked value, who introduced it, first/last seen, still in HEAD or not, why we think it is a secret, how to rotate. Never print or re-transmit the raw secret.

## Four weeks

### Week 1 — real CLI

- `src/secsentry`, Typer, Rich, Finding model (mask + fingerprint + **explain** fields)
- File walker + ignores
- P0 detectors: PEM, AWS, GitHub, OpenAI, Anthropic/Claude, Google, Stripe, Slack, JWT, DB URLs, generic `*_API_KEY`+entropy
- Tests: fake fixtures only; include false positives (UUID, lockfile)
- npm folder stub that shells to Python

**Done:** `secsentry scan examples/` shows HIGH, masked, and a one-line “why.”

### Week 2 — the unique demo

- History via diffs [[ADR-003 History scans diffs not snapshots]]
- `still_in_head`, first-seen author, secret age
- Dedup by fingerprint
- [[Demo vulnerable repo]]: add fakes → delete → history still finds them
- JSON out

**Done:** GIF of that four-step demo. This is the LinkedIn/thesis clip.

### Week 3 — people can use it

- `--staged` + pre-commit hook (block HIGH/CRITICAL + rotation line)
- Next.js **or** simple dashboard: Overview, Secrets, People, Timeline (skip FastAPI if Next.js)
- Public-repo paste can wait until the UI works on a **local JSON** from a scan (no custom domain)

**Done:** screenshot of People + still-in-HEAD vs history-only. Secrets masked.

### Week 4 — installable

- pytest + small benchmark
- GitHub Action (fail on HIGH; `fetch-depth: 0`)
- README: demo GIF, limitations, **vs Gitleaks/TruffleHog honest table**
- TestPyPI **and** `npm pack` / publish same version
- LinkedIn recap

**Done:** `pip install` + `npx secsentry --help`.

Cut order if slipping: extra YAML rules → private GitHub OAuth → email → custom domain. **Never cut** history demo, masking, or explainable score.

## Detectors

P0 in week 1. P1 LLM/cloud if tests are cheap. P2 YAML catalog is **optional** and must not become the pitch. [[Detector catalog]] [[API key detectors]]

## Website (when you get to it)

Next.js + Python worker, GitHub public URL then OAuth. No vendor verification. No PAT in a form. Domain whenever. [[Next.js web app]] [[ADR-007 Hosted Next.js scans Python engine]] [[ADR-009 No live secret verification]]

## LinkedIn

[[LinkedIn showcase plan]] — one post per version. Lead with the history incident, not “221 services.”

## Related

- [[Roadmap]]
- [[Product vision]]
- [[Architecture]]
- [[Dual packaging]]
