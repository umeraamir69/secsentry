---
tags:
  - architecture
  - detection
---

# Detection engine

Detectors are plugins. Each returns the same [[Finding model]].

## Families (v1)

| Detector | Examples | Default severity |
|---|---|---|
| Private keys | `BEGIN PRIVATE KEY`, SSH, PGP | CRITICAL |
| AWS | `AKIA…`, secret key near access key | CRITICAL |
| OpenAI | `sk-proj-…`, long `sk-…` | HIGH |
| Anthropic / Claude | `sk-ant-…` | HIGH |
| Groq / Hugging Face / others | `gsk_…`, `hf_…`, `pplx-…`, `xai-…` | HIGH |
| GitHub | `ghp_`, `github_pat_` | HIGH |
| Google | `AIza…` (Maps, Gemini, GCP) | HIGH |
| Stripe | `sk_live_`, `sk_test_` | HIGH |
| Slack | `xoxb-` … | HIGH |
| JWT | three base64url segments | HIGH / MEDIUM |
| Generic API key | `API_KEY=` / `*_API_KEY=` + high entropy | MEDIUM–HIGH |
| Entropy | random-looking strings with context | LOW–MEDIUM |

Provider list and generic rules: [[API key detectors]].

Do **not** classify Stripe `sk_live_` as OpenAI. Prefix tables must be tested against each other.

## Confidence formula (conceptual)

```
regex match
+ entropy
+ context keywords
+ secret length
+ known format prefix
= confidence (0–1) and severity
```

Context **up**: password, secret, api_key, access_token, credential.

Context **down**: id, name, version, hash, uuid.

Nearby AWS access key + secret key increases confidence.

Do not treat `password = "password"` as production HIGH.

## Entropy

Shannon entropy:

`H(X) = -Σ p(x) log2 p(x)`

Workflow: extract candidates → min length → entropy → character set → context → confidence → finding.

Skip or downrank: hashes, UUIDs, minified JS. See [[False positives]].

## Masking and fingerprint

Never print the full secret.

- Display: `ghp_••••••••••••91Kd`
- Store: `fingerprint = SHA-256(secret)`

Same fingerprint = same secret across files and commits. [[ADR-004 Mask secrets never print them]]

## Related

- [[API key detectors]]
- [[Finding model]]
- [[False positives]]
- [[Git history scanner]]
