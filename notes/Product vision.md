---
tags:
  - product
---

# Product vision

SecSentry is a **Git incident scanner** for leaked secrets. It is not a Gitleaks clone and not a live-key verifier.

Helpful: tell you **what** leaked, **who** first committed it, **whether it is still in HEAD**, and **how to rotate** — with the secret **masked**.

Unique (student-real): explainable scores, history-as-the-demo, no vendor API checks, pip+npm one engine. Full argument: [[What makes this real and unique]].

## What it does

1. Scan working tree, staged files, and **Git history**
2. Detect known keys (OpenAI, Claude, AWS, GitHub, …) plus generic high-entropy `*_API_KEY`
3. Score with regex + entropy + context, and **show why**
4. Dedup by SHA-256 fingerprint; never print the raw secret
5. CLI: `secsentry scan . --history` — also `npx secsentry`
6. UI later: who introduced what, still-in-HEAD vs history-only

## Success

The demo repo: secrets committed, then deleted, history scan still produces a case file with author + commit + masked value.

## Related

- [[Complete plan]]
- [[Product scope]]
- [[Roadmap]]
- [[ADR-009 No live secret verification]]
