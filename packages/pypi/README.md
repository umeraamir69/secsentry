# SecSentry

A Git **incident** scanner for leaked secrets. It searches the working tree and the full commit history, deduplicates by blob so the same object is never scanned twice, and reports every finding as a case file: what leaked, where, who introduced it, whether it is still in HEAD, and how to revoke it.

Values are always masked. SecSentry never sends a credential to a vendor API to check whether it still works.

> **This PyPI package is a PATH wrapper.** The detectors live in the Go binary. `pip install secsentry` gives you the `secsentry` console script; that script still needs the Go CLI on `PATH`.

## Install

```bash
# 1. Engine (required)
go install github.com/umeraamir69/secsentry/cmd/secsentry@latest
# or download a binary from GitHub Releases: linux / macOS / Windows

# 2. This wrapper (optional — only if you want `pip` / `uv` on PATH)
pip install secsentry

secsentry --version
secsentry scan .
```

If the Go binary is missing, the wrapper prints the `go install` line and exits `1`. It does not reimplement any detectors.

## Usage

```bash
secsentry scan .                          # working tree
secsentry scan . --history                # every commit
secsentry scan --staged                   # index only
secsentry scan . --severity high
secsentry scan . --type aws --type github
secsentry scan . --format json -o out.json
secsentry scan . --format html -o report.html
secsentry scan . --format sarif -o secsentry.sarif
secsentry serve . --history               # dashboard, 127.0.0.1 only

secsentry install-hook                    # block commits that stage secrets
```

Exit code is `1` when a finding reaches `--fail-on` (default `high`), otherwise `0`.

## What you get

| Layer | Behaviour |
|---|---|
| Scanner | Working tree, staged diff, or full history. Each unique blob OID is read once. Decodes base64 / hex / percent and walks zip / tar / gz. |
| Detectors | AWS, GitHub, OpenAI, Anthropic, Google, Stripe, Slack, Discord, Telegram, Azure storage, Datadog, DigitalOcean, xAI, Perplexity, private keys, JWTs, Basic auth, database URLs, labeled `API_KEY=` / `PASSWORD=` with Shannon entropy. |
| Verification | Prefix, length, and format checks **locally**. No network calls. |
| Reporting | Terminal, JSON, SARIF, HTML, localhost dashboard. Masked everywhere. Location (`path:line:column`) is always shown. |
| Enforcement | Pre-commit hook and a GitHub Action. |

You cannot rotate what you cannot find, so every report shows path, commit, and author. What it never shows is a pasteable credential. Duplicates are tracked by SHA-256 fingerprint; the allowlist (`.secsentryallow`) accepts fingerprints, never raw secrets.

## GitHub Action

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0
- uses: umeraamir69/secsentry@v1.0.0
  with:
    history: true
    fail-on: high
```

## Links

- Source and full README: [github.com/umeraamir69/secsentry](https://github.com/umeraamir69/secsentry)
- Releases / binaries: [GitHub Releases](https://github.com/umeraamir69/secsentry/releases)
- npm wrapper: [npmjs.com/package/secsentry](https://www.npmjs.com/package/secsentry)
- Demo leak repo: [umeraamir69/testKeys](https://github.com/umeraamir69/testKeys)

## License

MIT. Every credential in the tests, the demo repo, and the eval corpus is fake.
