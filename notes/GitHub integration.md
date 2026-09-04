---
tags:
  - product
  - github
---

# GitHub integration (like Vercel on a PR)

Vercel is not a badge in the README. It is a **GitHub App** plus **Checks** on the pull request. After you install it, every PR grows a row on the left: `Vercel — Preview ready`. SecSentry can show up in the **same place**.

Custom domain is unrelated. You do not need `secsentry.io` for this.

## What actually appears on GitHub

| Surface | What the user sees | How we get it |
|---|---|---|
| **PR Checks** (left sidebar, like Vercel) | Green/red `SecSentry / secrets` | GitHub **Action** or Checks API from an App |
| **PR comment** | Summary: N secrets, masked, who introduced | `pull-requests: write` in the Action, or App webhook |
| **Repo → Settings → Integrations** | “SecSentry” installed | **GitHub App** (same model as Vercel) |
| **Marketplace** | Install button for other repos | Publish the Action, then later the App |

Do **both**, in this order:

1. **Action first** (this repo already has the files). Push to GitHub → every PR shows a check. No server to host.
2. **GitHub App** when the Next.js worker exists. That is the “Install on my org” Vercel flow.

## GitHub Action (ships now)

Other repos add:

```yaml
# .github/workflows/secsentry.yml
name: SecSentry
on:
  pull_request:
  push:
    branches: [main, master]

jobs:
  secrets:
    name: SecSentry / secrets
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      checks: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: YOUR_GITHUB_USER/secsentry@v0.1.0
        with:
          history: true
          fail-on: high
```

`fetch-depth: 0` is required for history. Without it the check only sees the latest commit.

This repo’s own workflow lives at `.github/workflows/secsentry.yml` and uses `./` so it works before we publish a tag.

The Action:

- Installs Python + this package
- Runs `secsentry scan . --history`
- Writes a **job summary** (visible on the check)
- Optionally comments on the PR (masked findings only)
- Fails the check on HIGH/CRITICAL so merge can be blocked (branch protection)

That is the Vercel sidebar effect: **Checks → SecSentry / secrets**.

## GitHub App (Vercel-shaped, after the website)

An Action runs only when a workflow file exists in **that** repo. Vercel does not require every repo to copy a YAML file: you **Install the app** once on the org.

App responsibilities:

1. User clicks **Install SecSentry** on GitHub (or on our site)
2. GitHub sends `pull_request` / `push` webhooks to our worker
3. Worker clones with the installation token, runs Python `secsentry` (no vendor API calls)
4. Posts a **Check Run** named `SecSentry` and a PR comment

Needs a hosted HTTPS endpoint (the Next.js/worker box). Not Vercel serverless for the git clone. [[Next.js web app]] [[ADR-007 Hosted Next.js scans Python engine]]

Permissions to request (least): `contents: read`, `pull-requests: write`, `checks: write`. Never `secrets` or org admin.

## Marketplace

After the Action is stable on a public repo + tagged release (`v0.1.0`):

1. Publish GitHub Action to Marketplace (category: Security)
2. Later publish the GitHub App listing

Install button then looks like Vercel’s.

## What we will not do

- Put a PAT in workflow YAML
- Post **unmasked** secrets on a PR (the PR is often public)
- Call OpenAI/AWS to “verify” the key [[ADR-009 No live secret verification]]

## Related

- [[Complete plan]]
- [[Dual packaging]]
- [[Next.js web app]]
