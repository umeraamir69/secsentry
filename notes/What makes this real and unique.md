---
tags:
  - product
  - positioning
---

# What makes this real and unique

Gitleaks already has 200+ regexes. TruffleHog already verifies keys against vendor APIs. A Master’s project that ships “another rule list” is not helpful and not unique.

SecSentry is an **incident-investigation scanner for Git**, built so a student can **explain every finding** and a developer can **act on it** without leaking the secret again in the report.

Leave custom domains. Site can be `secsentry.vercel.app` or GitHub Pages until you care. [[Name availability]]

## Do not compete on

| Already exists | Why we skip as the pitch |
|---|---|
| 221 Gitleaks clones in YAML | We will not advertise “we copied their catalog.” P0 quality > P2 count. [[Detector catalog]] |
| Live API verification | TruffleHog sends candidates to AWS/OpenAI/etc. We **never** use a found secret to call a vendor. Safer, offline, thesis-clean. |
| SQLi / XSS / gem CVEs | Different product. [[ADR-005 Defer SAST and SCA]] |
| Fancy domain | Does not make the tool real. |

## Compete on (this is the product)

### 1. History is the feature, not a flag

Working tree can look clean. `secsentry scan --history` still names the **first-seen commit**, **author**, and **whether the secret is still in HEAD**.

Demo: commit fake key → delete → scan history. That is a real incident story. [[Demo vulnerable repo]]

### 2. “Who / what / still live?” not “500 matches”

One fingerprint = one secret. Occurrences hang off it. People page = **introduced by** (git author of first-seen commit). Split:

- **Still in working tree** → remove + rotate now
- **History only** → rotate anyway; deleting the file was not enough

Gitleaks dumps lines. We dump a case file.

### 3. Explainable confidence (Master’s + interviews)

Every finding shows **why it fired**:

- rule id (e.g. `anthropic-api-key`)
- entropy
- nearby keyword (`OPENAI_API_KEY`)
- why it is not a UUID / lockfile hash

That is unique in a student tool and honest. [[Finding model]] [[Detection engine]]

### 4. Secrets never get worse in our output

Mask + SHA-256 fingerprint. Hosted Next.js stores **masks only**, clone deleted after the job. CLI never phones home. [[ADR-004 Mask secrets never print them]] [[ADR-009 No live secret verification]]

### 5. LLM keys as day-one, plus generic catch-all

OpenAI, Claude, Groq, Gemini, Hugging Face are what students actually paste in 2026. Generic `*_API_KEY` + entropy covers vendors we did not list. We do **not** claim “every API key on earth.” [[API key detectors]]

### 6. Helpful next step on the finding

Not “SECRET FOUND.” One rotation line per type (revoke GitHub PAT, rotate Anthropic key, IAM for AKIA). Pre-commit prints the same line when it blocks.

### 7. One engine, two installs (practical, not a gimmick)

JS and Python teams both run:

`pip install secsentry` / `npx secsentry scan .`

Wrapper, not a second detector. [[Dual packaging]]

## What we ship in four weeks (unique slice)

| Week | Unique thing you can show |
|---|---|
| 1 | Masked CLI + LLM/cloud prefixes + explainable score |
| 2 | History + still-in-HEAD vs history-only + who introduced |
| 3 | Next.js (or local UI): People + timeline; pre-commit with rotate hint |
| 4 | pip **and** npm same version; GitHub Action; honest README vs Gitleaks |

P2 “100 extra YAML rules” is optional polish, not the thesis.

## LinkedIn one-liner (use this)

> I built SecSentry: a Git secrets scanner that treats leaks as incidents — history, who introduced it, still-in-HEAD vs deleted, masked reports — instead of dumping another regex list. Offline: we never validate keys against vendor APIs.

## Related

- [[Product vision]]
- [[Complete plan]]
- [[Competitor landscape]]
- [[ADR-009 No live secret verification]]
