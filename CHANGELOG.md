# Changelog

All notable changes to SecSentry. Versions are shared by the pip and npm packages.

## [1.0.0] — 2026-09-04

First public release. `pip install secsentry` and `npx secsentry`.

### Added

- `secsentry serve` — localhost dashboard with Overview, Secrets, People, Timeline, and Files. Binds `127.0.0.1` only.
- Unique-secret aggregation: one fingerprint, many occurrences, instead of repeating identical lines.
- First seen, last seen, secret age, and "introduced by" from the earliest commit containing each secret.
- Rotation guidance per detector — every finding says how to revoke it.
- `.gitignore` support via `git ls-files`, plus `.secsentryignore` for scanner-only patterns.
- `.secsentryallow` — accept known findings by SHA-256 fingerprint prefix, never by storing the secret.
- `--severity`, `--type`, `--version`, and `--format html`.
- Scan cache at `.secsentry/last-scan.json`.
- Benchmark harness scoring precision and recall against Gitleaks and TruffleHog.
- CI across Python 3.12 and 3.13, a version-sync gate, and a check that no `.env` or key material reaches the sdist.

### Fixed

- `should_fail` compared uppercase severities against a lowercase table, so the CI gate never failed even on CRITICAL findings.
- `python -m secsentry` discarded the exit code, silently breaking the pre-commit hook, the GitHub Action, and the npm wrapper.
- The pre-commit hook no longer overwrites an existing hook without backing it up, and `uninstall-hook` leaves hooks it did not write alone.

### Changed

- Benchmark corpus now uses high-entropy generated values. The previous readable filler was below Gitleaks' entropy thresholds, which flattered SecSentry by roughly 36 points of competitor recall.
- Terminal output leads with `path:line:column` for every finding. Masking hides the value, never the location.

## [0.3.0] — 2026-09-04

- Pre-commit hook (`install-hook` / `uninstall-hook`).
- GitHub Action and PR workflow with a masked comment.

## [0.2.0] — 2026-09-04

- Git history scanning with blob-level deduplication across branches.
- `still_in_head` to separate live leaks from history-only ones.
- Demo repository proving a deleted secret is still recoverable.

## [0.1.0] — 2026-09-03

- CLI, P0 detectors, Shannon entropy, structural verification, masking and SHA-256 fingerprints.
