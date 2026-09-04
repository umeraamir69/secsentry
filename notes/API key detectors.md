---
tags:
  - architecture
  - detection
---

# API key detectors (LLM and the rest)

Yes — we detect **OpenAI, Claude/Anthropic, and other provider keys**, plus a **generic** path for keys that do not match a known prefix.

We cannot honestly say “any API key in the universe.” Unknown keys are caught by **prefix OR (keyword + entropy)**. Random `id = "abc123"` must not become HIGH. [[False positives]]

## Known prefixes (HIGH, week 1)

These are stable, testable, good for LinkedIn (“we catch ChatGPT keys”).

| Provider | Typical pattern | Notes |
|---|---|---|
| OpenAI | `sk-proj-…`, `sk-…` (long) | Also org/service-account variants as they appear. Do not treat Stripe `sk_live_` as OpenAI. |
| Anthropic / Claude | `sk-ant-…` | Claude API keys are Anthropic keys |
| Google Gemini / GCP | `AIza…` | Shared with [[Detection engine]] Google detector |
| Groq | `gsk_…` | |
| Hugging Face | `hf_…` | |
| Cohere | long tokens near `COHERE` / `cohere` | Prefixes change; pair with keyword |
| Mistral | near `MISTRAL_API_KEY` | Keyword + entropy if no stable prefix |
| Perplexity | `pplx-…` | |
| xAI | `xai-…` | |
| Azure OpenAI | long keys near `AZURE_OPENAI` / `api-key` headers | Keyword + entropy |
| AWS | `AKIA…` | Already planned |
| GitHub | `ghp_`, `github_pat_` | Already planned |
| Stripe | `sk_live_`, `sk_test_`, `rk_live_` | Not OpenAI |
| Slack | `xoxb-`, `xoxp-`, `xoxa-` | |
| Twilio | `SK` + 32 hex near `TWILIO` | Easy to false-positive; require context |

Fixtures use **fake** strings that match the shape (`sk-ant-api03-TESTONLY…`), never live keys.

## Generic “any API key” (MEDIUM unless entropy+keyword is strong)

Fire when **all** of:

1. Assignment or env-style: `API_KEY`, `api_key`, `apikey`, `SECRET_KEY`, `access_token`, `bearer`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `CLAUDE_API_KEY`, `*_API_KEY`
2. Value length above a minimum (e.g. 20+)
3. Shannon entropy high enough
4. Not an obvious placeholder (`your-key-here`, `xxx`, `changeme`, `sk-test-placeholder`)

Then bump to HIGH if a **known prefix** also matches.

This is how you catch a vendor we have not listed yet: `VENDOR_API_KEY=n8f2…` with high entropy.

## What we will miss (say this in the README)

- Keys split across strings (`"sk-" + "abc"`)
- Keys only in binaries or images
- Vendor keys with no prefix and a boring-looking value
- Encrypted or vault references (`${AWS_SECRET}`) — those are not leaks

## Module layout

```
detectors/
  openai.py
  anthropic.py      # Claude
  groq.py
  huggingface.py
  google.py
  aws.py
  github.py
  stripe.py
  slack.py
  jwt.py
  private_keys.py
  generic.py        # keyword + entropy
```

Week 1 minimum: OpenAI, Anthropic, AWS, GitHub, Google, Stripe, PEM, generic. Add Groq/HF/Slack in the same week if tests are cheap (they are).

## Related

- [[Detection engine]]
- [[Finding model]]
- [[Roadmap]]
