---
tags:
  - architecture
  - model
---

# Finding model

Every detector, report, and hook uses this shape. Do not invent a second one.

## Fields

| Field | Example | Notes |
|---|---|---|
| detector / secret_type | `github_token` | Stable ID for allowlists |
| severity | HIGH | CRITICAL, HIGH, MEDIUM, LOW |
| confidence | 0.97 | Combined score |
| file / line / column | config.py:42:18 | **Always shown** — where it leaked. Masking does not hide location. |
| commit / author / timestamp | a81f92c, Ada, ada@uni.edu | Empty for working-tree scans |
| author_email | ada@uni.edu | For People page; do not treat as proven guilt |
| masked_secret | ghp_••••91Kd | Never the full value. Location stays public in the report. |
| fingerprint | sha256:91c7…a82d | Dedup + allowlist key |
| first_seen / last_seen | 2026-03-12 | History scans |
| still_in_head | true / false | Working tree vs history-only |

## Severity

| Severity | Examples |
|---|---|
| CRITICAL | Private key, cloud long-lived credential |
| HIGH | API token, database password |
| MEDIUM | Generic secret assignment |
| LOW | Suspicious high-entropy string |

## Dedup

A **secret** (fingerprint) can have many **occurrences** (file, line, commit).

Reports show unique secrets, then list occurrences — not 500 identical HIGH lines.

## JSON sketch

```json
{
  "severity": "HIGH",
  "type": "github_token",
  "file": "config.py",
  "commit": "a81f92c",
  "line": 42,
  "confidence": 0.97,
  "author": "Ada",
  "author_email": "ada@uni.edu",
  "still_in_head": false,
  "masked": "ghp_••••91Kd",
  "fingerprint": "91c7…a82d"
}
```

## Related

- [[Detection engine]]
- [[Reports]]
- [[Local dashboard]]
- [[ADR-004 Mask secrets never print them]]
