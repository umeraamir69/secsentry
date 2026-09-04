---
tags:
  - adr
status: accepted
date: 2026-09-03
---

# ADR-004 Mask secrets never print them

## Context

A secrets scanner that prints full tokens in logs, JSON, HTML, or PR comments becomes a leak channel. Hiding the **location** would make the tool useless: you cannot rotate what you cannot find.

## Decision

Mask the **value**. Always show **where it leaked**.

Every report (terminal, JSON, GitHub Action comment, dashboard) is a case file: enough to open the file and jump to the line, never enough to copy-paste the credential.

### Always show (leak location)

| Field | Why |
|---|---|
| `path` | Which file |
| `line` | Which line |
| `column` | Where on the line (when known) |
| `secret_type`, `severity`, `why` | What it is and why we flagged it |
| `commit`, `author`, `timestamp` | Who introduced it (history scans) |
| `still_in_head` | Still in the latest tree, or history-only |
| `masked` | Short preview (`ghp_••••91Kd`) so humans can recognize the kind of token |
| `fingerprint` | SHA-256 of the secret — dedup and allowlist, never the raw value |

### Never show

- The full secret string
- A pasteable token in any log, JSON, HTML, CI summary, or PR comment

Allowlist by **fingerprint**, never by pasting a raw secret into config. Tests use obviously fake values.

`--show-unmasked` is not required. Path + line is enough to open the file and rotate. If that flag is added later, it stays off by default and is local-only.

## Consequences

- JSON / HTML / CI logs are safer to share
- Developers still get `config.py:42:18` and can fix the leak
- Dedup still works
- Hosted UI stores masks + fingerprints + locations, never raw secrets

## Related

- [[Finding model]]
- [[Reports]]
- [[Threat model]]
- [[Decisions]]
