---
tags:
  - security
---

# Threat model

SecSentry is a **speed bump** against accidental secret commits. It is not a vault and not an AppSec suite.

## Assets we protect

- Cloud keys, PATs, JWTs, private keys, DB URLs that a developer might paste into source

## In scope

Hard-coded credentials in text files that enter git (working tree, index, or history).

## Out of scope

- Attacker with `--no-verify` / force-push
- Secrets in binaries
- Deliberate obfuscation (unless we add it later)
- SQL injection, XSS, vulnerable libraries — [[ADR-005 Defer SAST and SCA]]
- Sending a found secret to OpenAI/AWS/GitHub to “see if it still works” — [[ADR-009 No live secret verification]]

## Rules for this project

- Mask secret **values** in all output; still show file, line, and column so the leak can be fixed
- Fingerprint instead of storing raw values
- Allowlist by fingerprint, never by pasting the secret into config
- Demo repo uses fake values only
- No real API keys in this vault or the GitHub repo
- Dashboard binds to 127.0.0.1 only ([[ADR-006 Localhost dashboard only]])
- Gitignore `.secsentry/` so scan caches are not committed

## Related

- [[Product scope]]
- [[ADR-004 Mask secrets never print them]]
- [[Detection engine]]
