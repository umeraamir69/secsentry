---
tags:
  - product
  - backlog
---

# Feature backlog

Ordered. Do not start later items before MVP detection + history work.

## Now (Weeks 1–4)

- File walker with ignores
- Detector framework
- AWS, GitHub, Google, JWT, PEM, generic
- Entropy + context scoring
- Finding model, masking, fingerprint
- Git history via diffs
- Terminal + JSON

## Next (Weeks 5–8)

- Pre-commit hook + staged scan
- Local dashboard (`secsentry serve`)
- JSON export
- `.secsentryignore`
- Fingerprint allowlist
- Baseline for old findings
- GitHub Actions
- Tests, benchmarks, README
- TestPyPI then PyPI

## After v1.0 (platform — yes, these were requested)

- GitHub remote scan
- Bitbucket remote scan
- Pull request review comments
- Automatic CI scans (already partly GitHub Actions)
- Email alert from CI (workflow, not a custom mailer)
- Generic git URL / internally hosted repos
- Rotation guidance in finding output
- Secret age + exposure timeline

## Explicitly not this product

- SQL injection detection → [[ADR-005 Defer SAST and SCA]]
- XSS exploit detection → same
- Vulnerable gem / library CVE detection → same
- Hosted team dashboard / premium support SKU

## Related

- [[Feature evaluation - platform and SAST]]
- [[Roadmap]]
- [[Product scope]]
