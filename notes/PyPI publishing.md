---
tags:
  - product
  - packaging
---

# PyPI publishing

Python half of dual publish. npm is released in the **same** GitHub Action. Full picture: [[Dual packaging]].

`secsentry` is free on PyPI. Do not use `gitsentry`. [[Name availability]]

## Requirements

| Item | Requirement |
|---|---|
| Name | `secsentry` |
| Accounts | pypi.org + test.pypi.org, 2FA |
| Metadata | version, description, README, MIT, `requires-python >=3.12` |
| Entry point | `[project.scripts] secsentry = secsentry.cli:app` |
| Layout | `src/secsentry` |
| Build | `python -m build` → wheel + sdist |
| Local prove | `pip install dist/*.whl && secsentry --help` |
| TestPyPI first | `twine upload --repository testpypi` |
| Production | GitHub Trusted Publishing (OIDC) |

Version must equal `packages/npm/package.json`. [[ADR-008 One engine two packages]]

## Must not ship

Real secrets, `.env` files, demo credentials that look live.

## Related

- [[Dual packaging]]
- [[ADR-001 Package name]]
- [[CLI]]
- [[Roadmap]]
