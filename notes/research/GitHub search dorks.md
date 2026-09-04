---
tags:
  - research
  - detection
  - threat-model
---

# GitHub search dorks for leaked secrets

Source: a public gist cataloguing GitHub code-search queries that surface hardcoded credentials. Useful to us as **defenders** — the queries show how attackers find leaks, and the token signatures feed our detectors. We take the methodology, not the keys.

## Why this matters for SecSentry

Attackers find leaked keys with GitHub code search in seconds. The dork shape is:

```
(path:*.env OR path:*.yml OR path:*.json OR …)   ← where secrets get committed
AND (api_key OR secret_key OR access_token OR …) ← the variable names around them
AND ("sk-ant-" OR "AIza" OR "shpat_" OR …)       ← the vendor signature
```

Every part of that maps onto something we already do or should do:

| Dork component | SecSentry equivalent |
|---|---|
| File extensions | We scan all text files, so we are not limited to a path list |
| Keyname list (`api_key`, `authsecret`, …) | Our `generic_api_key` rule + context scoring in `classify/features.py` |
| Vendor signatures (`sk-ant-`, `sq0atp-`, …) | Our prefix rules in `detectors/patterns.py` |
| "already revoked, still leaking" | Exactly our history + `still_in_head` story |

The last row is the point of the whole product: a key can be revoked by the vendor and **still sitting in git history**, which is where these searches find them.

## Signatures worth having (public prefixes, not secrets)

A token *prefix* is documentation, not a credential. From the gist and its comments:

| Vendor | Prefix | In SecSentry |
|---|---|---|
| OpenAI | `sk-`, `sk-proj-` + `T3BlbkFJ` | yes |
| Anthropic | `sk-ant-api03-` | yes |
| GitHub | `ghp_ gho_ ghu_ ghs_ ghr_` | yes (ghp_, fine-grained) |
| Google | `AIza` | yes |
| Slack | `xox[baprs]-` | yes (widened) |
| Stripe | `sk_live_` | yes |
| Square | `sq0atp- sq0csp- EAAA` | **added v1.0** |
| Shopify | `shpss_ shpat_ shpca_ shppa_` | **added v1.0** |
| SendGrid | `SG.` | **added v1.0** |
| Twilio | `SK` + 32 hex | **added v1.0** |
| GitLab | `glpat-` | **added v1.0** |
| npm | `npm_` | **added v1.0** |
| PyPI | `pypi-AgEIcHlwaS` | **added v1.0** |

## What we deliberately do NOT do

The gist's comment thread is full of people asking for **working keys** and pasting **"free API keys"** (which are dummy `sk-...` strings anyway). One request was to harvest "already revoked" keys and test SecSentry against them.

We reject that, for reasons that are also the product's thesis:

1. **We cannot verify a key is revoked.** "It's dead, trust me" is how you end up using someone's live credential — unauthorised access, plainly illegal.
2. **Testing against real leaked keys means storing real leaked keys.** That violates [[ADR-004 Mask secrets never print them]] and [[Threat model]]: fake values only, in the repo, the corpus, and the demo.
3. **We never transmit a discovered key to a vendor** to see if it works. That is the exact behaviour we differentiate against. [[ADR-009 No live secret verification]]
4. **Our corpus is generated, seeded, and fake** — and it exercises the detectors perfectly well without touching anyone's account. [[Benchmark results]]

So: harvest the *signatures* (public), never the *secrets* (someone else's property). The corpus grew from 19 to 25 planted fakes when these vendors were added, and the benchmark still runs on values that were issued by nobody.

## Defensive takeaways to put in the README / thesis

- Leaked keys are found by search in seconds; deleting the file does not help.
- Rotation, not history rewriting, is the fix — assume anyone could have cloned it.
- Pre-commit + CI catch it before it is ever searchable. [[Pre-commit hook]]

## Related

- [[Detector catalog]]
- [[API key detectors]]
- [[Benchmark results]]
- [[Threat model]]
- [[ADR-009 No live secret verification]]
