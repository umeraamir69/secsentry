---
tags:
  - runbook
  - packaging
---

# Accounts and keys

What you actually have to sign up for, and what secrets go where. Checked 2026-09-04.

> [!important] Right now you need **nothing**.
> SecSentry has zero runtime credentials. You can build and demo everything through v0.3.0 with only the GitHub account you already have. Accounts below are for **publishing** in Week 4. [[Tasks]]

## Accounts — created 2026-09-04

> [!warning] The PyPI username is **not** the same as the other two.
> Three sites, two different usernames. Check the list before you try to log in.

| Site | Username | Profile |
|---|---|---|
| GitHub | `umeraamir69` | [github.com/umeraamir69](https://github.com/umeraamir69) |
| **PyPI** | **`umeraamir45`** | [pypi.org/user/umeraamir45](https://pypi.org/user/umeraamir45/) |
| TestPyPI | `umeraamir69` | [test.pypi.org/user/umeraamir69](https://test.pypi.org/user/umeraamir69/) |
| npm | `umeraamir69` | [npmjs.com/~umeraamir69](https://www.npmjs.com/~umeraamir69) |

TestPyPI is a genuinely separate instance from PyPI, so a different username there is normal and harmless. Usernames never need to match the package name.

You also need an **authenticator app** (Google Authenticator, 1Password, Authy). PyPI and npm both require 2FA to publish.

## Name availability — re-checked 2026-09-04

| Registry | `secsentry` | Check |
|---|---|---|
| PyPI | **Free** | `pypi.org/pypi/secsentry/json` → 404 |
| TestPyPI | **Free** | `test.pypi.org/pypi/secsentry/json` → 404 |
| npm | **Free** | `registry.npmjs.org/secsentry` → 404 |

Still unclaimed. Nothing reserves it until the first real upload.

## What each account needs from you

| Account | Needed when | Cost | Key you must store |
|---|---|---|---|
| **GitHub** | Already have it | Free | **None** — `GITHUB_TOKEN` is injected automatically |
| **PyPI** | Week 4, publish | Free | **None** — pending Trusted Publisher works from the first upload |
| **TestPyPI** | Week 4, rehearsal | Free | API token (simplest for a throwaway rehearsal) |
| **npm** | Week 4, publish | Free | Token or 2FA for the **first** publish only, then none |
| **Vercel** | Only if you build the web UI | Free tier | None — sign in with GitHub |
| Domain registrar | Never for v1 | ~$12/yr | — |

## Keys you will NEVER need ★

No OpenAI key. No AWS key. No Anthropic, Google, Stripe, or Slack key.

SecSentry detects those tokens by **shape**, locally. It never calls a vendor to ask "is this key live?" That is the product's differentiator, not an oversight. [[ADR-009 No live secret verification]]

If a future task ever asks you to add a vendor API key to make detection work, that task is wrong.

`.env.example` stays empty. The only commented entry is a **later, optional** GitHub App.

---

## 1. GitHub — done

Repo: `umeraamir69/secsentry`.

- Do **not** create a Personal Access Token for the Action. `${{ secrets.GITHUB_TOKEN }}` exists automatically in every workflow run.
- The workflow already declares the permissions it needs: `contents: read`, `pull-requests: write`, `checks: write`.
- Only needed later, for the optional GitHub **App** (private repos): App ID + private key `.pem`. Not in v1. [[GitHub integration]]

## 2. PyPI — the Python half

Account `umeraamir45` exists. Remaining steps:

1. [x] Register
2. [ ] Enable 2FA (required — you cannot upload without it)
3. [ ] Choose a publishing method:

**Trusted Publishing (recommended, no token stored anywhere)**

PyPI supports a **pending publisher**, which creates the project on first upload — you do not need to upload manually first to "prime" the name.

- Go to Account settings → **Publishing** → add a pending publisher
- Fill in: PyPI project name `secsentry`, owner `umeraamir69`, repo `secsentry`, workflow filename `release.yml`, environment `pypi` (optional but recommended)
- Workflow needs `permissions: id-token: write`
- Use `pypa/gh-action-pypi-publish`

Caveat: a pending publisher does **not reserve** the name. It is claimed on first successful upload. If someone registers `secsentry` before you publish, the pending publisher is invalidated.

**API token (fallback)**

Account settings → API tokens → create token → store as GitHub repo secret `PYPI_API_TOKEN`. Scope it to the project once it exists. Tokens start with `pypi-`.

## 3. TestPyPI — rehearsal only

Separate site, **separate account**, separate password, separate token: [test.pypi.org](https://test.pypi.org/account/register/).

Use an API token here (`TEST_PYPI_API_TOKEN`); it is a throwaway rehearsal, not worth the OIDC setup.

TestPyPI does **not** reserve the name on production PyPI. Publishing to TestPyPI claims nothing.

## 4. npm — the Node half

Account `umeraamir69` exists. Enable 2FA if you have not.

> [!important] npm cannot publish the **first** version via OIDC.
> Trusted Publishing is configured on a package's settings page, so the package has to exist before you can attach it. PyPI solved this with pending publishers; npm has not ([npm/cli#8544](https://github.com/npm/cli/issues/8544) is still open).
>
> Order of operations:
> 1. Publish `secsentry@0.1.0` **manually** from your machine: `npm publish --access public`, approve the 2FA prompt
> 2. Attach the Trusted Publisher on the package settings page
> 3. Every release after that runs from CI with no token
>
> Run `npm publish --dry-run` first and read the file list. You get one shot at the first publish looking right.

**Trusted Publishing (for release 2 onward, no `NPM_TOKEN`)**

Package settings on npmjs.com → **Trusted Publisher** → GitHub Actions. Fields are case-sensitive and exact:

| Field | Value |
|---|---|
| Organization or user | `umeraamir69` |
| Repository | `secsentry` |
| Workflow filename | `release.yml` (filename only, with extension) |
| Environment | blank, or your GitHub environment name |

Known gotchas that waste an afternoon:

- Requires **Node 24+** and **npm 11.5.1+**. Older Node silently falls back to token auth.
- Workflow needs `permissions: id-token: write`.
- `package.json` must have a `repository.url` matching the GitHub repo.
- If `actions/setup-node` writes an `.npmrc` with `_authToken=${NODE_AUTH_TOKEN}` and no token is set, npm skips OIDC entirely and fails with `ENEEDAUTH` or `E404`. Remove the `.npmrc` or unset `NODE_AUTH_TOKEN` before publishing.
- GitHub-hosted runners only; self-hosted is not supported.

**Granular access token (fallback)**

npmjs.com → Access Tokens → Granular Access → read+write on `secsentry` → store as GitHub secret `NPM_TOKEN`.

## 5. Vercel — only if the web UI happens

Sign in with GitHub, import the repo, deploy. No API key to store. You get `secsentry.vercel.app`.

`secsentry.com` is taken. A domain is out of the critical path. [[Name availability]]

---

## GitHub repo secrets — target state

| Secret | Needed? |
|---|---|
| `GITHUB_TOKEN` | Automatic, never create it |
| `PYPI_API_TOKEN` | Only if you skip Trusted Publishing |
| `TEST_PYPI_API_TOKEN` | Yes, for the TestPyPI rehearsal |
| `NPM_TOKEN` | Only if you skip Trusted Publishing |

Best case: **one** secret in the whole repo (`TEST_PYPI_API_TOKEN`), and zero after the rehearsal.

## Rules

- Never paste a token into a note, a commit, or `.env.example`
- Tokens live in GitHub repo **Settings → Secrets and variables → Actions**, or your password manager
- Prefer OIDC over long-lived tokens — it is what SecSentry's own README preaches
- If a token leaks, revoke first, rotate second — [[Threat model]]

## Related

- [[Tasks]]
- [[Dual packaging]]
- [[PyPI publishing]]
- [[ADR-009 No live secret verification]]
- [[GitHub integration]]
