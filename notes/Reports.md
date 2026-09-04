---
tags:
  - product
  - reports
---

# Reports

Three surfaces, one [[Finding model]]. Never print raw secrets.

## Terminal

Default. See [[CLI]]. Professional Rich output: severity counts, masked secrets, file, line, commit, confidence.

## JSON

For CI/CD and as the dashboard cache (`.secsentry/last-scan.json`).

## Local dashboard (primary visual)

`secsentry serve` — localhost website. Overview, secrets, **who introduced what**, timeline, files, export. This is the report you screenshot for LinkedIn.

Full spec: [[Local dashboard]]

Static HTML is an **export** from that UI, not a separate product.

## CI

```
Push → GitHub Actions → pip install / run secsentry
  → secrets found? fail : continue
```

Checkout with `fetch-depth: 0` so history scan works. CI uses JSON, not the dashboard.

## Related

- [[Finding model]]
- [[CLI]]
- [[PyPI publishing]]
- [[Roadmap]]
