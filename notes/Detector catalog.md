---
tags:
  - architecture
  - detection
  - research
---

# Detector catalog

Research base: public **Gitleaks default config** (221 rule IDs, retrieved 2026-09-04 from `gitleaks/gitleaks` `config/gitleaks.toml`) plus extra LLM prefixes Gitleaks does not list (Groq, xAI, DeepSeek, Together).

We **do not copy their TOML**. We implement our own Python detectors with the same *service coverage* and **fake** fixtures only. Prefixes below are publicly documented vendor formats.

Honest limit: “as many as we can” means **known prefixes + generic entropy**, not magic. Unknown vendors still hit `generic-api-key`. [[API key detectors]]

Go engine 1.3.0 (pack 1): Slack webhooks, Discord bot tokens, Telegram bot tokens, Azure storage account keys, Datadog API keys, DigitalOcean `dop_v1_`, Basic auth, JDBC/NATS/SQLAlchemy URLs. Still not: generic passwords in prose, unlabeled high-entropy, live verify.

## Coverage tiers (build in this order)

### P0 — week 1 (must demo)

| ID | Service |
|---|---|
| `private-key` | PEM / OpenSSH / PGP |
| `aws-access-token` | AWS `AKIA…` |
| `github-pat` / `github-fine-grained-pat` / `github-oauth` / `github-app-token` | GitHub |
| `openai-api-key` | OpenAI / ChatGPT |
| `anthropic-api-key` / `anthropic-admin-api-key` | Claude |
| `gcp-api-key` | Google / Gemini `AIza…` |
| `stripe-access-token` | Stripe |
| `slack-bot-token` / `slack-user-token` / `slack-webhook-url` | Slack |
| `jwt` | JWTs |
| `generic-api-key` | `*_API_KEY=` + entropy |
| `postgres` / `mysql` / `mongodb` URLs | DB connection strings (user:pass@) |

### P1 — week 1–2 (LLM + cloud students actually leak)

| ID | Service |
|---|---|
| `huggingface-access-token` | Hugging Face `hf_…` |
| `perplexity-api-key` | `pplx-…` |
| `cohere-api-token` | Cohere |
| `groq-api-key` | Groq `gsk_…` (not in Gitleaks default — we add) |
| `xai-api-key` | xAI `xai-…` (we add) |
| `deepseek-api-key` | DeepSeek `sk-` near `DEEPSEEK` (we add) |
| `together-api-key` | Together.ai (we add) |
| `gitlab-pat` + main GitLab tokens | GitLab |
| `azure-ad-client-secret` | Azure |
| `digitalocean-pat` / `digitalocean-access-token` | DigitalOcean |
| `heroku-api-key` | Heroku |
| `twilio-api-key` | Twilio |
| `sendgrid-api-token` | SendGrid |
| `mailgun-private-api-token` | Mailgun |
| `npm-access-token` | npm |
| `pypi-upload-token` | PyPI `pypi-…` |
| `discord-api-token` | Discord bots |
| `telegram-bot-api-token` | Telegram |
| `databricks-api-token` | Databricks |
| `hashicorp-tf-api-token` | Terraform Cloud |
| `vault-service-token` | HashiCorp Vault |
| `cloudflare-api-key` / `cloudflare-global-api-key` | Cloudflare |
| `doppler-api-token` | Doppler |

### P2 — week 2–3 (breadth for the README “200+”)

Implement as **data-driven rules** (YAML of prefix + entropy + keywords), not 200 Python files. One `rules/*.yml` loader. That is how we get Gitleaks-scale coverage without 200 modules.

Full Gitleaks ID list (for the YAML backlog):

1password-secret-key, 1password-service-account-token, adafruit-api-key, adobe-client-id, adobe-client-secret, age-secret-key, airtable-api-key, airtable-personnal-access-token, algolia-api-key, alibaba-access-key-id, alibaba-secret-key, anthropic-admin-api-key, anthropic-api-key, artifactory-api-key, artifactory-reference-token, asana-client-id, asana-client-secret, atlassian-api-token, authress-service-client-access-key, aws-access-token, aws-amazon-bedrock-api-key-long-lived, aws-amazon-bedrock-api-key-short-lived, azure-ad-client-secret, beamer-api-token, bitbucket-client-id, bitbucket-client-secret, bittrex-access-key, bittrex-secret-key, cisco-meraki-api-key, clickhouse-cloud-api-secret-key, clojars-api-token, cloudflare-api-key, cloudflare-global-api-key, cloudflare-origin-ca-key, codecov-access-token, cohere-api-token, coinbase-access-token, confluent-access-token, confluent-secret-key, contentful-delivery-api-token, curl-auth-header, curl-auth-user, databricks-api-token, datadog-access-token, defined-networking-api-token, digitalocean-access-token, digitalocean-pat, digitalocean-refresh-token, discord-api-token, discord-client-id, discord-client-secret, doppler-api-token, droneci-access-token, dropbox-api-token, dropbox-long-lived-api-token, dropbox-short-lived-api-token, duffel-api-token, dynatrace-api-token, easypost-api-token, easypost-test-api-token, etsy-access-token, facebook-access-token, facebook-page-access-token, facebook-secret, fastly-api-token, finicity-api-token, finicity-client-secret, finnhub-access-token, flickr-access-token, flutterwave-encryption-key, flutterwave-public-key, flutterwave-secret-key, flyio-access-token, frameio-api-token, freemius-secret-key, freshbooks-access-token, gcp-api-key, generic-api-key, github-app-token, github-fine-grained-pat, github-oauth, github-pat, github-refresh-token, gitlab-cicd-job-token, gitlab-deploy-token, gitlab-feature-flag-client-token, gitlab-feed-token, gitlab-incoming-mail-token, gitlab-kubernetes-agent-token, gitlab-oauth-app-secret, gitlab-pat, gitlab-pat-routable, gitlab-ptt, gitlab-rrt, gitlab-runner-authentication-token, gitlab-runner-authentication-token-routable, gitlab-scim-token, gitlab-session-cookie, gitter-access-token, gocardless-api-token, grafana-api-key, grafana-cloud-api-token, grafana-service-account-token, harness-api-key, hashicorp-tf-api-token, hashicorp-tf-password, heroku-api-key, heroku-api-key-v2, hubspot-api-key, huggingface-access-token, huggingface-organization-api-token, infracost-api-token, intercom-api-key, intra42-client-secret, jfrog-api-key, jfrog-identity-token, jwt, jwt-base64, kraken-access-token, kubernetes-secret-yaml, kucoin-access-token, kucoin-secret-key, launchdarkly-access-token, linear-api-key, linear-client-secret, linkedin-client-id, linkedin-client-secret, lob-api-key, lob-pub-api-key, looker-client-id, looker-client-secret, mailchimp-api-key, mailgun-private-api-token, mailgun-pub-key, mailgun-signing-key, mapbox-api-token, mattermost-access-token, maxmind-license-key, messagebird-api-token, messagebird-client-id, microsoft-teams-webhook, netlify-access-token, new-relic-browser-api-token, new-relic-insert-key, new-relic-user-api-id, new-relic-user-api-key, notion-api-token, npm-access-token, nuget-config-password, octopus-deploy-api-key, okta-access-token, openai-api-key, openshift-user-token, perplexity-api-key, pkcs12-file, plaid-api-token, plaid-client-id, plaid-secret-key, planetscale-api-token, planetscale-oauth-token, planetscale-password, postman-api-token, prefect-api-token, private-key, privateai-api-token, pulumi-api-token, pypi-upload-token, rapidapi-access-token, readme-api-token, rubygems-api-token, scalingo-api-token, sendbird-access-id, sendbird-access-token, sendgrid-api-token, sendinblue-api-token, sentry-access-token, sentry-org-token, sentry-user-token, settlemint-application-access-token, settlemint-personal-access-token, settlemint-service-access-token, shippo-api-token, shopify-access-token, shopify-custom-access-token, shopify-private-app-access-token, shopify-shared-secret, sidekiq-secret, sidekiq-sensitive-url, slack-app-token, slack-bot-token, slack-config-access-token, slack-config-refresh-token, slack-legacy-bot-token, slack-legacy-token, slack-legacy-workspace-token, slack-user-token, slack-webhook-url, snyk-api-token, sonar-api-token, sourcegraph-access-token, square-access-token, squarespace-access-token, stripe-access-token, sumologic-access-id, sumologic-access-token, telegram-bot-api-token, travisci-access-token, twilio-api-key, twitch-api-token, twitter-access-secret, twitter-access-token, twitter-api-key, twitter-api-secret, twitter-bearer-token, typeform-api-token, vault-batch-token, vault-service-token, yandex-access-token, yandex-api-key, yandex-aws-access-token, zendesk-secret-key.

Plus our extras: `groq-api-key`, `xai-api-key`, `deepseek-api-key`, `together-api-key`, `mistral-api-key`.

**Target for v1.0 README:** P0+P1 with tests (~20–40 families) and an honest generic catch-all. Do **not** market “221 rules.” That is Gitleaks; copying it is not unique. [[What makes this real and unique]]

## Rule file shape (P2)

```yaml
id: groq-api-key
severity: HIGH
prefix: gsk_
min_length: 50
entropy: 3.5
keywords: [groq, GROQ_API_KEY]
```

Each rule: at least one **true-positive fixture** and one **false-positive** (docs example / UUID).

## Related

- [[Detection engine]]
- [[API key detectors]]
- [[Complete plan]]
- [[False positives]]
