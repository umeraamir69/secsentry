---
tags:
  - product
  - hooks
---

# Pre-commit hook

`secsentry install-hook` writes `.git/hooks/pre-commit`.

On `git commit`, scan **staged** files only (`git diff --cached`). If HIGH/CRITICAL, print a blocked-commit banner and exit non-zero.

Do not scan the whole repo on every commit. Target under ~1 second.

Also support `uninstall-hook`. Later: `.pre-commit-config.yaml` entry as well as the raw git hook.

## Tests

- Hook blocks a staged fake GitHub token
- Hook allows a clean commit
- Hook does not print the full secret

## Related

- [[CLI]]
- [[Git history scanner]]
- [[Finding model]]
