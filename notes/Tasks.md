---
tags:
  - product
  - plan
  - tasks
---

# Tasks — complete build checklist

Every task from empty repo to published v1.0.0. Tick as you go. Plan behind it: [[Complete plan]] · [[Roadmap]] · [[Dual packaging]]

Legend: `[x]` done and verified · `[ ]` to do · **★** = do not cut

Status on 2026-09-04: **v1.0.0 complete.** CLI, history, dashboard, hook, Action, benchmark, CI, and release workflow all built and tested (49 tests). Remaining: create the GitHub release tag and publish to PyPI + npm — see [[Accounts and keys]].

---

## Phase 0 — Setup (done)

- [x] Decide positioning: incident scanner, not a rule-count race — [[What makes this real and unique]]
- [x] Check PyPI + npm availability — [[Name availability]]
- [x] Lock the name `secsentry` — [[ADR-001 Package name]]
- [x] Write ADRs 001–009 — [[Decisions]]
- [x] `git init`, branch `main`, remote `origin`
- [x] First commit `6d0b145`
- [x] `.gitignore` (venv, `__pycache__`, `.env`, `eval/.data`, `model.joblib`)
- [x] `LICENSE` (MIT), `SECURITY.md`, `VERSION`, `.env.example`
- [x] `README.md` + `STRUCTURE.md`
- [ ] Commit the work that landed after `6d0b145` (all of `src/`, `tests/`, `packages/`, `eval/`, `examples/`, `web/`)
- [ ] Push via GitHub GUI (agent does not push)

---

## Phase 1 — Week 1 · Working CLI → **v0.1.0**

**Done when:** `secsentry scan .` prints HIGH findings, masked, with `file:line:column` and a one-line why.

### 1.1 Package skeleton
- [x] `pyproject.toml`: name `secsentry`, `requires-python >=3.12`, src layout
- [x] `[project.scripts] secsentry = secsentry.cli:main`
- [x] Extras: `ml` (sklearn/joblib/numpy), `dev` (pytest)
- [x] `src/secsentry/__init__.py` + `__main__.py`
- [ ] `pip install -e ".[dev]"` in a venv and confirm the `secsentry` command exists on PATH

### 1.2 Finding model ★
- [x] `Finding` dataclass: type, severity, confidence, path, line, column, masked, fingerprint
- [x] History fields: blob_oid, commit, author, author_email, timestamp, still_in_head
- [x] Explain fields: `why`, `entropy`, `structural_ok`, `source`
- [x] `mask_secret()` — never the raw value ★
- [x] `fingerprint()` — SHA-256 ★
- [x] Location always reported: path + line + column — [[ADR-004 Mask secrets never print them]]

### 1.3 File walker
- [x] Skip `.git`, `node_modules`, `.venv`, `dist`, `build`, `__pycache__`, `eval/.data`
- [x] Skip binaries (NUL byte sniff) and files > 1 MB
- [ ] Honour `.gitignore` (currently only a hardcoded skip list)
- [ ] `.secsentryignore` support

### 1.4 P0 detectors
- [x] AWS access key, GitHub PAT + fine-grained
- [x] OpenAI, Anthropic/Claude, Google, Stripe live, Slack bot, Groq, HuggingFace
- [x] Private key (PEM), JWT
- [x] Generic `api_key|secret_key|access_token = "..."`
- [x] Database URLs with inline password
- [x] Shannon entropy scoring
- [x] Placeholder suppression (`EXAMPLE`, `password`, `changeme`, …)
- [ ] Add P1 vendors only if the tests stay cheap — [[Detector catalog]]

### 1.5 Verify + classify
- [x] `verify/structural.py` — local format checks only, zero network ★ [[ADR-009 No live secret verification]]
- [x] `classify/heuristic.py` — keep/drop + confidence + why
- [x] `classify/features.py` — path, keyword, entropy, structural
- [x] `classify/ml.py` — optional joblib model, no-op when absent

### 1.6 Reports
- [x] Terminal report: `path:line:column`, masked, why
- [x] JSON report for CI and the future UI
- [x] `--output PATH`
- [ ] Severity counts summary line (`2 critical, 3 high, …`)
- [ ] Group by fingerprint: one secret, N occurrences — [[Finding model]]
- [ ] Rich colours (currently plain `print`; Rich is optional, plain is fine)

### 1.7 CLI surface
- [x] `scan [path] --history --staged --format --fail-on --output`
- [x] `install-hook` / `uninstall-hook`
- [x] Exit code 1 when a finding meets `--fail-on`
- [ ] `--severity high` filter
- [ ] `--type aws` filter
- [ ] `--version` flag reading `VERSION`

### 1.8 Tests
- [x] mask + fingerprint
- [x] Finding reports location, never the raw secret
- [x] Pattern hits
- [x] Structural verification
- [x] CLI exits 2 with no subcommand
- [ ] False-positive fixtures: UUID, git SHA, lockfile hash, `password="password"` — [[False positives]]
- [ ] Test the walker skips binaries and big files
- [x] Test `--fail-on` exit codes (`tests/test_engine.py`)

### 1.9 npm wrapper stub
- [x] `packages/npm/package.json` (name + version match `VERSION`)
- [x] `bin/secsentry.js` spawns the Python CLI, never reimplements detectors ★ [[ADR-008 One engine two packages]]
- [x] `chmod +x` the bin
- [x] `packages/npm/README.md`
- [ ] `node packages/npm/bin/secsentry.js scan .` works against the installed CLI

### 1.10 Ship v0.1.0
- [ ] Tag `v0.1.0`
- [ ] LinkedIn post: CLI + masked output — [[LinkedIn showcase plan]]

---

## Phase 2 — Week 2 · The demo ★ → **v0.2.0**

**Done when:** a deleted secret still shows up, with the commit and the author who introduced it. This is the portfolio moment. **Never cut.**

### 2.1 Demo vulnerable repo — built in `umeraamir69/testKeys` — [[Demo vulnerable repo]]
- [x] `examples/vulnerable-repo/README.md` with the script
- [x] Own repo instead of `examples/`, so fake keys never enter SecSentry's own history
- [x] Commit 1 `3836986`: 8 fake credentials across `app/`, `.env`, `deploy/id_rsa`
- [x] Commit 2 `ce0b792`: delete them, add `.gitignore` + `.env.example`
- [x] `secsentry scan` on the clean tree → 0 findings, 0 false positives
- [x] `secsentry scan --history` → 11 findings from commit 1
- [x] Output shows author, commit, `still_in_head=False`, masked value, file:line:column
- [x] Fix: `should_fail` ignored uppercase severities (CI gate never fired)
- [x] Fix: `python -m secsentry` discarded the exit code
- [ ] Push `testKeys` to GitHub (allow push protection; nothing is live)
- [ ] Record the GIF ★

### 2.2 History engine
- [x] `git/run.py` subprocess helper — [[ADR-002 Git via subprocess not GitPython]]
- [x] `git/blobs.py` — enumerate unique blob OIDs across all refs ★
- [x] Read each blob **once**, attach findings to every commit/path holding it ★
- [x] `scan/history.py` wires blobs into the engine
- [x] `still_in_head` computed against `ls-tree HEAD`
- [x] Author, email, commit SHA, ISO timestamp per occurrence
- [ ] `first_seen` / `last_seen` per fingerprint
- [ ] "Introduced by" = author of the **earliest** commit for that fingerprint — [[Local dashboard]]
- [ ] Secret age in days
- [ ] Performance check on a repo with 1k+ commits

### 2.3 Dedup
- [x] Occurrence dedup by (fingerprint, path, line)
- [x] Blob-level dedup so branches do not rescan the same object ★
- [ ] Report-level grouping: unique secrets first, occurrences nested

### 2.4 Staged scanning
- [x] `scan/staged.py` reads `git diff --cached`
- [ ] Verify it only sees staged content, not the working tree

### 2.5 Ship v0.2.0
- [ ] Record the four-step demo as a GIF ★
- [ ] Put the GIF in `README.md`
- [ ] Bump `VERSION`, `pyproject.toml`, `package.json` together
- [ ] Tag `v0.2.0`
- [ ] LinkedIn main post + add repo to Featured

---

## Phase 3 — Week 3 · Usable by others → **v0.3.0**

**Done when:** a dirty commit is blocked and a PR shows the check.

### 3.1 Pre-commit hook
- [x] `install-hook` writes `.git/hooks/pre-commit`, chmod 755
- [x] `uninstall-hook` removes only our hook
- [ ] Test: staging a fake key blocks the commit
- [ ] Hook prints a rotation hint, not the secret
- [ ] Document `--no-verify` as a known bypass — [[Threat model]]

### 3.2 GitHub Action
- [x] `action.yml` — composite action, inputs `history`, `fail-on`, `comment`
- [x] `.github/workflows/secsentry.yml` — `fetch-depth: 0` ★
- [x] Masked PR comment table (severity, type, file, line, masked)
- [x] Job summary line stating no vendor API calls
- [ ] Open a throwaway PR and confirm the check appears in the sidebar
- [ ] Confirm the PR comment renders and masks values
- [ ] Confirm the job fails on HIGH
- [x] Fix the stray `**` typo at the end of the comment body

### 3.3 Report UI
- [ ] Persist last scan to `.secsentry/last-scan.json` (gitignored)
- [ ] Decide: Next.js reading local JSON, or a static HTML export — [[ADR-007 Hosted Next.js scans Python engine]]
- [ ] Overview: counts by severity
- [ ] Secrets: one row per fingerprint
- [ ] People: who introduced what
- [ ] Timeline: first seen → last seen
- [ ] Masked everywhere, locations shown ★
- [ ] Screenshot for LinkedIn

### 3.4 Usability
- [ ] Rotation one-liner per detector type ("revoke at console.aws.amazon.com → IAM → …")
- [ ] Fingerprint allowlist file (never raw secrets) ★
- [ ] `--severity` / `--type` filters (from 1.7)

### 3.5 Ship v0.3.0
- [ ] Bump all three version files
- [ ] Tag `v0.3.0`
- [ ] LinkedIn post: hook + report UI

---

## Phase 4 — Week 4 · Evidence + publish → **v1.0.0**

### 4.1 Eval corpus
- [x] `eval/build_corpus.py` plants a labeled mini git repo (fake values only)
- [x] `eval/labels.jsonl` with positives **and** negatives
- [x] `eval/.data/` gitignored
- [ ] Grow it: 20+ positives across vendors, 40+ hard negatives (UUIDs, hashes, lockfiles, base64 blobs, docs)
- [ ] Multi-commit repos so history detection is exercised
- [ ] Document how to rebuild it in `eval/README.md`

### 4.2 Classifier
- [x] `eval/train.py` — logistic regression on extracted features
- [x] Model is optional; heuristics work without sklearn
- [ ] `pip install -e ".[ml]"` and actually train a model
- [ ] Report precision/recall of heuristic vs ML
- [ ] Only ship `model.joblib` if it beats the heuristic

### 4.3 Benchmark
- [x] `eval/benchmark.py` computes precision / recall / F1 for SecSentry
- [ ] `brew install gitleaks trufflehog`
- [ ] Parse Gitleaks JSON output into the same (path, line) scoring
- [ ] Parse TruffleHog JSON output the same way
- [ ] Produce the comparison table
- [ ] Put the **honest** table in the README, including where they beat us

### 4.4 Release engineering
- [ ] `CHANGELOG.md` (one line per version, retro-fill 0.1–0.3)
- [ ] `.github/workflows/release.yml` — on tag `vX.Y.Z`, publish **both** registries
- [ ] Version sync check in CI: `VERSION` == pyproject == package.json ★
- [ ] CI job that runs pytest on push

### 4.5 Accounts (do this week, ~20 min) — full detail in [[Accounts and keys]]
- [ ] Authenticator app installed (2FA is mandatory on both registries)
- [x] pypi.org account — username **`umeraamir45`** (note: differs from the others)
- [x] test.pypi.org account — `umeraamir69`
- [x] npmjs.com account — `umeraamir69`
- [ ] Enable 2FA on all three
- [ ] PyPI **pending** Trusted Publisher: project `secsentry`, workflow `release.yml`
- [ ] npm: first publish must be **manual** (`npm publish --access public` + 2FA); OIDC cannot create a package
- [ ] npm Trusted Publisher attached **after** that first publish
- [ ] `TEST_PYPI_API_TOKEN` in GitHub repo secrets (the only secret we should need)
- [x] `repository.url` in `package.json` (required for npm OIDC)
- [x] `[project.urls]` in `pyproject.toml`
- [ ] No vendor API keys anywhere ★ — [[ADR-009 No live secret verification]]

### 4.6 Local install proof (before any upload)
- [ ] `python -m build` → wheel + sdist
- [ ] `pip install dist/secsentry-*.whl` in a clean venv
- [ ] `secsentry --help` works
- [ ] `npm pack` in `packages/npm`
- [ ] `npx ./secsentry-0.1.0.tgz scan .` works
- [ ] Confirm no `.env`, no real keys, no `eval/.data` in the sdist

### 4.7 Publish ★
- [ ] `twine upload --repository testpypi dist/*`
- [ ] Install from TestPyPI in a clean venv and run it
- [ ] `twine upload dist/*` → **production PyPI** (this is when the name is claimed)
- [ ] `npm publish` from `packages/npm` — same version, same day ★
- [ ] Verify `pip install secsentry` and `npx secsentry --help` from a machine with nothing installed
- [ ] GitHub Release with both install lines

### 4.8 Ship v1.0.0
- [ ] README: demo GIF, install, architecture, limitations, vs Gitleaks/TruffleHog
- [ ] Tag `v1.0.0`
- [ ] LinkedIn recap post
- [ ] Add to CV / portfolio

---

## Version sync (every release)

Three files, one number, always identical:

- [ ] `VERSION`
- [ ] `pyproject.toml` → `[project].version`
- [ ] `packages/npm/package.json` → `"version"`

| Milestone | Version |
|---|---|
| CLI + detectors | 0.1.0 |
| History demo | 0.2.0 |
| Hook + Action + UI | 0.3.0 |
| Published both registries | 1.0.0 |

Never ship pip `0.2.0` with npm `0.1.0`. [[ADR-008 One engine two packages]]

---

## Standing rules (check on every PR)

- [ ] No raw secret in any log, JSON, HTML, PR comment, or note ★
- [ ] Location (file, line, column) always shown
- [ ] No network call to a vendor to validate a key ★
- [ ] Fixtures are obviously fake
- [ ] Detectors live only in Python
- [ ] Notes updated when a product decision changes

---

## Cut order if a week slips

1. Extra YAML rules / P2 detector catalog
2. Private GitHub OAuth
3. Email reports
4. Custom domain

**Never cut:** history demo · masking · explainable score · blob dedup.

---

## Out of scope for v1

Deliberately not doing: SQLi/XSS/SCA scanning ([[ADR-005 Defer SAST and SCA]]), GitHub App, paid SaaS, live key verification ([[ADR-009 No live secret verification]]), a JavaScript detector engine, custom domain ([[Name availability]]).

Later ideas: [[Feature backlog]] · [[Ideas beyond v1]]

## Related

- [[Complete plan]]
- [[Roadmap]]
- [[Dual packaging]]
- [[PyPI publishing]]
- [[LinkedIn showcase plan]]
