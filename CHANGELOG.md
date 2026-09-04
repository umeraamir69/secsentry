# Changelog

All notable changes to SecSentry. The engine is the Go binary; the npm package is a wrapper around it.

## [1.3.1] — 2026-09-04

Rename a notes file so `go install` can build the module zip. Go rejects an em dash in a file path.

pip `secsentry` is a PATH wrapper around the Go binary (same idea as npm). The old Python detector tree is not published.

## [1.3.0] — 2026-09-04

Pack 1 structured detectors. Precision-first: no generic passwords, no unlabeled high-entropy, no live verify.

### Added

- Slack incoming webhooks (`hooks.slack.com/services/…`), Discord bot tokens, Telegram bot tokens, Azure storage account keys, Datadog API keys, DigitalOcean `dop_v1_` tokens.
- `Authorization: Basic …` when the payload is base64 `user:password`.
- `nats://` / `sqlserver://` / SQLAlchemy / JDBC URLs that actually carry a password.

### Changed

- PEM: `ENCRYPTED PRIVATE KEY`, body on the same line as the header (JSON one-liners). A header with no body is still not a finding. Public certificates are ignored.
- GCP service-account JSON: truncated snippets that still contain `service_account` and a private key or SA email.
- AWS secret keys: `aws_secret_access_key is …` (not only `=`), and a 40-char secret on the line after `AKIA`/`ASIA`. Free-floating 40-char blobs are not reported.
- Twilio: 32-hex auth token when `TWILIO_API_KEY` / `TWILIO_AUTH_TOKEN` is on the same line.

ProwlBench numbers in the README are still **1.2.0**. Re-run before claiming a new row.

## [1.2.0] — 2026-09-04

The detector engine is Go. One implementation, one binary.

### Added

- Go CLI (`go install github.com/umeraamir69/secsentry/cmd/secsentry@latest`) with the same scan / serve / hook commands.
- Keyword prefilter so regex does not run on chunks with no secret-shaped tokens.
- Local BPE rarity score in the classifier (no network, no vendor model).
- `--format sarif` for GitHub code scanning.
- Extra formats from a structural-validator reference set: AWS STS (`ASIA`), labeled AWS secret keys, Stripe test/restricted/webhook, GCP service-account JSON. Publishable `pk_*` Stripe keys and Twilio Account SIDs are ignored on purpose.
- Slack segment-shaped tokens, Redis/AMQP URLs, skip of placeholder DB passwords, and PEM headers that have no key body (Prowl's FP fix, done locally).

### Changed

- GitHub Action builds the Go binary with `setup-go` instead of installing a Python package.
- npm wrapper spawns the Go `secsentry` on PATH.
- ADR-008: one Go engine, not a Python engine plus wrappers.

## [1.1.0] — 2026-09-04

Close the gap Gitleaks already had: look *inside* wrappers, still never print the value.

### Added

- **Decode pass** — base64, hex, and percent-encoding, recursive up to 3 layers. A key sitting in `echo KEY | base64` is now a finding, tagged `decoded:base64`, with the file and line of the wrapper.
- **Archive walk** — zip, tar, gzip, and nested archives (depth 2). Location is `deploy.zip!secrets/.env`.
- History reads blobs as raw bytes so a committed zip is not corrupted by UTF-8 replace.
- Eval corpus plants one base64-hidden AWS key and one zip-hidden GitHub token.

### Why this version exists

v1.0 only scanned UTF-8 as stored. That is how a developer “hides” a leak from a naive scanner without actually rotating. Gitleaks and TruffleHog already unwrap these. We do it locally, same as them — no vendor HTTP — and we still mask.

## [1.0.0] — 2026-09-04

First public release. `pip install secsentry` and `npx secsentry`.

### Added

- Detectors for Square, Shopify, SendGrid, Twilio, GitLab, npm, and PyPI tokens, derived from public token signatures. Slack widened to `xox[baprs]-`.
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
