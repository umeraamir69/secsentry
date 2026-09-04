# SecSentry

A Git **incident** scanner for leaked secrets. It searches the working tree and the full commit history, deduplicates by blob so the same object is never scanned twice across branches, and reports every finding as a case file: what leaked, where, who introduced it, whether it is still in HEAD, and how to revoke it.

Values are always masked. SecSentry never sends a credential to a vendor API to check whether it still works.

```bash
pip install secsentry
npx secsentry scan .

secsentry scan .              # working tree
secsentry scan . --history    # every commit
secsentry serve .  --history  # dashboard on 127.0.0.1
```

## The problem

You delete an API key from `config.py`, commit, and move on. The key is still in `git log`, still in every clone, and still valid. A scanner that only reads the working tree tells you everything is fine.

```
$ secsentry scan ~/code/app
0 unique secret(s)                       # the tree is clean

$ secsentry scan ~/code/app --history
8 unique secret(s), 11 occurrence(s)  —  2 critical  4 high  2 medium

[CRITICAL] aws_access_key  AKIA••••••••••••ZZZZ  confidence=0.90
    .env:2:19  3836986b
    app/config.py:4:22  3836986b
    introduced by Umer Aamir on 2026-09-04
    deleted from HEAD, still in history
    why: rule=aws_access_key; structural_ok; entropy=2.92
    fix: IAM → Users → Security credentials → deactivate, then delete this key.
```

Live demo repository: [umeraamir69/testKeys](https://github.com/umeraamir69/testKeys) — secrets committed, then deleted, and still fully recoverable.

## What it does

| Layer | Behaviour |
|---|---|
| Scanner | Working tree, staged diff, or full history. Each unique blob OID is read once and its findings attached to every commit and path that contains it. |
| Detectors | AWS, GitHub, OpenAI, Anthropic, Google, Stripe, Slack, Groq, HuggingFace, Square, Shopify, SendGrid, Twilio, GitLab, npm, PyPI, private keys, JWTs, database URLs, generic `*_API_KEY` plus Shannon entropy. |
| Verification | Prefix, length, and format checks performed **locally**. No network calls, ever. |
| Classifier | Path and context heuristics, with an optional scikit-learn model trained on a labeled corpus. |
| Reporting | Terminal, JSON, self-contained HTML, and a localhost dashboard. Masked everywhere. |
| Enforcement | Pre-commit hook and a GitHub Action that fails the build and comments on the PR. |

## Masking hides the value, not the location

You cannot rotate what you cannot find, so every report shows `path:line:column`, the commit, and the author. What it never shows is a pasteable credential. Duplicates are tracked by SHA-256 fingerprint, and the allowlist accepts fingerprints — never raw secrets.

## Benchmark

Measured on a generated corpus of 25 planted credentials and 26 negative lines across three commits. Rebuild it with `python -m secsentry.eval.build_corpus && python -m secsentry.eval.benchmark`.

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| SecSentry 1.0.0 | 1.00 | 1.00 | 1.00 |
| Gitleaks 8.30.1 | 1.00 | 0.76 | 0.86 |
| TruffleHog 3.97.4 | 1.00 | 0.40 | 0.57 |

**Read that table skeptically.** The corpus was written alongside SecSentry's own detector list, so a perfect score means "it finds what it was built to find," not that it wins on real repositories. Gitleaks ships far more rules than we do and will beat us on vendors we have never heard of. TruffleHog is built around live verification, which a corpus of necessarily-fake keys cannot exercise — its score here measures the wrong thing for its design.

An earlier version of this corpus used readable filler like `TESTONLY` padded with repeated characters. Those strings fall below Gitleaks' entropy thresholds, so it discarded them and scored 0.32 recall. Switching to high-entropy generated values raised it to 0.68. That 36-point swing came entirely from how the fixtures were written, which is worth remembering whenever you read someone else's benchmark.

## What it will not do

- Verify keys against vendor APIs. Sending a leaked credential to a third party to test it is the behaviour we are avoiding.
- Match Gitleaks rule for rule. We cover the common cases well and fall back to entropy for the rest.
- Scan for SQL injection, XSS, or vulnerable dependencies.
- Detect secrets in binaries, or anything deliberately obfuscated.
- Save you from `git commit --no-verify`.

## Usage

```bash
secsentry scan .                          # working tree
secsentry scan . --history                # every commit
secsentry scan --staged                   # index only
secsentry scan . --severity high          # filter by severity
secsentry scan . --type aws --type github # filter by detector
secsentry scan . --format json -o out.json
secsentry scan . --format html -o report.html
secsentry serve . --history               # dashboard, loopback only

secsentry install-hook                    # block commits that stage secrets
secsentry uninstall-hook
```

Exit code is `1` when a finding reaches `--fail-on` (default `high`), otherwise `0`.

### Configuration

| File | Purpose |
|---|---|
| `.gitignore` | Honoured automatically inside a git repo |
| `.secsentryignore` | Scanner-only path patterns |
| `.secsentryallow` | Accepted findings, one SHA-256 fingerprint per line |
| `.secsentry/last-scan.json` | Cached scan, written after each run |

### GitHub Action

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0        # required, or there is no history to scan
- uses: umeraamir69/secsentry@v1.0.0
  with:
    history: true
    fail-on: high
```

The check appears in the pull request sidebar as `SecSentry / secrets` and comments a masked summary.

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest tests -q
python scripts/check_version_sync.py
python -m secsentry.eval.build_corpus
python -m secsentry.eval.benchmark
```

`VERSION`, `pyproject.toml`, `packages/npm/package.json`, and `__init__.py` must always agree; CI enforces it.

## Layout

```
src/secsentry/
├── cli.py            argparse entry point
├── models.py         Finding, mask_secret, fingerprint
├── rotation.py       how to revoke each credential type
├── git/              subprocess helpers, unique blob walk
├── scan/             engine, working tree, staged, history, aggregate, ignore
├── detectors/        regex rules and Shannon entropy
├── verify/           local structural checks, no network
├── classify/         heuristics, features, optional ML
├── reports/          terminal, JSON, HTML, dashboard server
├── hooks/            pre-commit
└── eval/             corpus builder, training, benchmark

packages/npm/         wrapper that spawns the Python CLI
notes/                Obsidian vault: plan, ADRs, runbooks
```

There is one detector implementation. The npm package, the GitHub Action, and any future web UI all shell out to the Python engine rather than reimplementing it.

## Architecture decisions

The reasoning behind the non-obvious choices lives in [`notes/decisions/`](notes/decisions/): git via subprocess rather than a library, history via blob dedup, masking rules, localhost-only dashboard, one engine across two registries, and no live verification.

## License

MIT. Every credential in the tests, the demo repo, and the eval corpus is fake.
