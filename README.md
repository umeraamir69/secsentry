# SecSentry

A Git **incident** scanner for leaked secrets. It searches the working tree and the full commit history, deduplicates by blob so the same object is never scanned twice across branches, and reports every finding as a case file: what leaked, where, who introduced it, whether it is still in HEAD, and how to revoke it.

Values are always masked. SecSentry never sends a credential to a vendor API to check whether it still works.

```bash
go install github.com/umeraamir69/secsentry/cmd/secsentry@latest
# or download a binary from GitHub Releases (linux / macOS / windows)

secsentry scan .              # working tree
secsentry scan . --history    # every commit
secsentry serve .  --history  # dashboard on 127.0.0.1
```

`pip install secsentry` and `npx secsentry` are wrappers. They still need that Go binary on `PATH`.

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
| Scanner | Working tree, staged diff, or full history. Each unique blob OID is read once. **Decode** (base64 / hex / percent) and **archives** (zip / tar / gz) so a key in `echo KEY \| base64` or `deploy.zip!.env` is still a case file. |
| Detectors | AWS, GitHub, OpenAI, Anthropic, Google, Stripe, Slack (bot + webhook), Discord, Telegram, Azure storage, Datadog, DigitalOcean, xAI, Perplexity, Groq, HuggingFace, Square, Shopify, SendGrid, Twilio, GitLab, npm, PyPI, private keys, JWTs, Basic auth, database URLs, labeled `API_KEY=` / `PASSWORD=` plus Shannon entropy. |
| Verification | Prefix, length, and format checks performed **locally**. No network calls, ever. |
| Classifier | Path heuristics, Shannon entropy, and a local BPE rarity score. No network, no vendor model. |
| Reporting | Terminal, JSON, SARIF, self-contained HTML, and a localhost dashboard. Masked everywhere. |
| Enforcement | Pre-commit hook and a GitHub Action that fails the build and comments on the PR. |

## Masking hides the value, not the location

You cannot rotate what you cannot find, so every report shows `path:line:column`, the commit, and the author. What it never shows is a pasteable credential. Duplicates are tracked by SHA-256 fingerprint, and the allowlist accepts fingerprints — never raw secrets.

## Benchmark

Two measurements. The first is the **incident we actually sell**. The second is a regression corpus — read it skeptically.

### Demo: deleted keys still in git ([testKeys](https://github.com/umeraamir69/testKeys))

Working tree is clean. History is not.

| Tool | Findings | Case file | Raw secret in output |
|---|---|---|---|
| **SecSentry 1.2.0** | **8 unique / 11 occ**, all `still_in_head=false` | who / when / rotate | no |
| zerosecret | 9 occurrences, not aggregated | no | **yes** (`matched_string`) |
| Gitleaks 8.30 | 7 (missed the AWS key) | commit metadata | Secret field |
| TruffleHog (unverified on) | 2 Postgres URLs | no | — |

### ProwlBench (24,603 cases, independent)

Same protocol as [Lercas/prowlbench](https://github.com/Lercas/prowlbench). Gitleaks and TruffleHog match the published leaderboard, so the row is comparable. Prowl cascade is quoted, not re-run.

**Cite this table as SecSentry 1.2.0 only** (source commit `8c96549`; artifact `eval/results/prowlbench_leaderboard.json`, 2026-09-04). There is no `v1.2.0` git tag. Later versions (1.3.0, 1.3.1, 1.4.0) changed detectors; they are a different binary and must not be reported against these figures until the harness is re-run.

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| Prowl cascade (published) | 0.951 | 0.823 | 0.883 |
| Gitleaks | 0.931 | 0.413 | 0.573 |
| **SecSentry 1.2.0** | **0.951** | 0.347 | 0.509 |
| TruffleHog | 0.940 | 0.303 | 0.458 |

Highest precision of the three we ran. T1 structured-token recall is 0.64 vs Gitleaks 0.65. Overall recall is 0.347 vs 0.413 because T2 generic-context is 0.01 vs 0.35. That T2 gap is **missing coverage, not the classifier quietly discarding hits**: 1.2.0 had no `generic_password` rule, no unlabeled high-entropy rule, and `generic_api_key` only matched *quoted* `api_key="…"` assignments, so those snippets never reached classify. Where a quoted generic *did* match, classify can still drop it (`docs_or_tests` on `.md` paths the harness uses for Jira/Confluence, or `english_like` rarity) — a second, smaller filter, not the reason T2 is essentially empty.

### Planted corpus (25 designed-to-match secrets)

Rebuild with `python -m secsentry.eval.build_corpus && python -m secsentry.eval.benchmark`.

| Tool | Precision | Recall | F1 |
|---|---|---|---|
| SecSentry 1.2.0 | 1.00 | 1.00 | 1.00 |
| Gitleaks 8.30.1 | 1.00 | 0.76 | 0.86 |
| TruffleHog 3.97.4 | 1.00 | 0.40 | 0.57 |

**Read that table skeptically.** The corpus was written alongside SecSentry's own detector list, so a perfect score means "it finds what it was built to find," not that it wins on real repositories. Gitleaks ships far more rules than we do and will beat us on vendors we have never heard of. TruffleHog is built around live verification, which a corpus of necessarily-fake keys cannot exercise.

An earlier version of this corpus used readable filler like `TESTONLY` padded with repeated characters. Those strings fall below Gitleaks' entropy thresholds, so it discarded them and scored 0.32 recall. Switching to high-entropy generated values raised it to 0.68. That 36-point swing came entirely from how the fixtures were written.

## What it will not do

- Verify keys against vendor APIs. Sending a leaked credential to a third party to test it is the behaviour we are avoiding.
- Match Gitleaks rule for rule, or Prowl's 159 YAML templates and live `--verify`. We cover the common cases and stay offline.
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
secsentry scan . --format sarif -o secsentry.sarif
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
go test ./...
go build -o secsentry ./cmd/secsentry
./secsentry --version
python3 scripts/check_version_sync.py
```

`VERSION`, `internal/version/version.go`, and `packages/npm/package.json` must always agree; CI enforces it.

## Layout

```
cmd/secsentry/        CLI entry point
internal/
├── detect/           regex rules, keyword prefilter, Shannon entropy
├── verify/           local structural checks, no network
├── classify/         heuristics + local BPE rarity
├── scan/             engine, decode, archives, history, aggregate, ignore
├── gitutil/          subprocess git, unique blob walk
├── report/           terminal, JSON, HTML, SARIF, dashboard
├── hooks/            pre-commit
├── rotate/           how to revoke each credential type
├── model/            Finding, Mask, Fingerprint
└── version/

packages/npm/         wrapper that spawns the Go CLI
notes/                Obsidian vault: plan, ADRs, runbooks
```

There is one detector implementation. The npm package, the GitHub Action, and any future web UI all shell out to the Go binary rather than reimplementing it.

## Architecture decisions

The reasoning behind the non-obvious choices lives in [`notes/decisions/`](notes/decisions/): git via subprocess rather than a library, history via blob dedup, masking rules, localhost-only dashboard, one engine across two registries, and no live verification.

## License

MIT. Every credential in the tests, the demo repo, and the eval corpus is fake.
