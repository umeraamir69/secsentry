---
tags:
  - product
  - ideas
---

# Ideas beyond v1

Things that can be added **after** the 4-week core. Split: still a secrets scanner vs Master’s-portfolio extras vs do not add.

Core 4 weeks stay in [[Roadmap]]. Platform requests (GitHub/Bitbucket/PRs/email) stay in [[Feature evaluation - platform and SAST]].

## High value for a Master’s showcase

These read well in a thesis appendix, LinkedIn article, or viva.

| Idea | Why it looks like research, not a tutorial |
|---|---|
| Labeled evaluation set | Precision / recall / F1 on fixtures + a small public corpus of *fake* leaks |
| Confusion matrix | True positives vs UUID/lockfile/docs false positives |
| Related-work write-up | Honest comparison vs Gitleaks, TruffleHog, Yelp detect-secrets |
| Ablation | Regex-only vs regex+entropy vs +context — table of extra hits and extra noise |
| Threat model in the README | What you catch vs `--no-verify` vs binaries |
| Limitations section | You will be asked this |

Do this in week 4 if time, or immediately after v1. It is the difference between “I cloned a scanner” and “I evaluated one.”

## Strong product add-ons (same tool)

| Idea | Notes |
|---|---|
| More detectors | Stripe, Slack, OpenAI/Anthropic, Azure, Twilio, SendGrid — easy wins |
| Custom rules file | `secsentry.toml` / YAML so orgs add patterns without forking |
| Inline allow | `# secsentry: allow github_token` on one line |
| SARIF output | Drops findings into GitHub Code Scanning |
| Official GitHub Action | Marketplace badge on the README |
| pre-commit.com hook | `.pre-commit-config.yaml` in addition to `install-hook` |
| Docker image | `docker run … secsentry scan /repo` for CI that is not Python-native |
| Secret age / first seen | “In history for 114 days” — good screenshot |
| Exposure timeline | Added → copied → deleted from HEAD → still in history |
| Per-type rotation guidance | AWS vs GitHub vs PEM — incident-response flavor |
| Baseline | Old findings silenced in CI so only **new** leaks fail the build |
| Parallel walk | Faster on big trees; mention in benchmarks |
| `--fail-on` | CI policy: fail on CRITICAL only vs HIGH |
| Scan a patch | `git diff \| secsentry scan --stdin` |
| Config discovery | Respect `.gitignore` plus `.secsentryignore` |

## Platform (you already asked)

After v1, in this order:

1. GitHub Action on this repo (week 4)
2. Clone-and-scan a **public** GitHub URL
3. PR comment on added lines
4. Bitbucket + generic git URL (internal GitLab/Gitea)
5. Email via existing CI (not your own mail server)

## Nice but later (don’t start in the 4 weeks)

- VS Code / Cursor extension (needs a second codebase)
- Slack/Discord webhooks
- Language-aware string extraction (AST) — fewer false positives, more work
- Scan Docker layers / Jupyter notebooks as first-class
- Plugin API for third-party detectors
- Signed releases (sigstore) — excellent for a security tool, week 5+
- Translations / i18n

## Do not add to SecSentry

Same as [[ADR-005 Defer SAST and SCA]]:

- SQL injection, XSS, “vulnerable gems”
- Full SAST (Semgrep/CodeQL clone)
- SCA / CVE lockfile scanning (`npm audit`, osv-scanner)
- Hosted multi-tenant SaaS dashboard for the student project

If you want a second Master’s artifact later: **SecSentry-eval** (dataset + metrics paper) or a **deps** tool. Not flags on this CLI.

## Suggested order after the 4 weeks

1. Evaluation table + LinkedIn article  
2. Stripe/Slack/OpenAI detectors  
3. SARIF + GitHub Action marketplace  
4. Remote GitHub scan + PR comments  
5. Baseline + secret age  

## Related

- [[Feature backlog]]
- [[LinkedIn showcase plan]]
- [[Roadmap]]
- [[Product scope]]
