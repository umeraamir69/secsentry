# Evaluation corpus

```bash
python -m secsentry.eval.build_corpus   # generate eval/.data/planted-repo
python -m secsentry.eval.benchmark      # score SecSentry, Gitleaks, TruffleHog
python -m secsentry.eval.train          # optional sklearn model, needs .[ml]
```

`eval/.data/` is generated and gitignored. Results land in `eval/results/benchmark.json`.

## What the corpus contains

Three commits, mirroring how a leak actually happens:

1. Project scaffold — negatives only
2. Credentials wired in — 19 planted secrets
3. "Move credentials to environment variables" — deleted from the tree, still in history

Positives cover AWS, GitHub (classic and fine-grained), OpenAI, Groq, HuggingFace, Google, Stripe, Slack, three database URL flavours, generic assignments, a JWT, and two private key formats.

Negatives are the traps: UUIDs, git SHAs, SHA-256/MD5/bcrypt hashes, a `sha512-` lockfile integrity value, base64 prose, an SRI hash, `password = "password"`, `YOUR_API_KEY_HERE`, `CHANGEME`, and `AKIAIOSFODNN7EXAMPLE` from AWS's own documentation.

## Everything is fake

Values are generated from a fixed seed (`20260904`), so the corpus is reproducible. They are structurally valid — correct prefix, correct length, so scanners fire — but were issued by nobody and authenticate to nothing.

## Why high entropy matters

The first version of this corpus used readable filler: `ghp_TESTONLY` followed by repeated characters. That quietly rigged the benchmark. Gitleaks applies entropy thresholds to most of its rules and discarded those strings, scoring 0.32 recall. SecSentry has no such gate on prefixed rules, so it caught them all.

Switching to random high-entropy bodies moved Gitleaks to 0.68 and TruffleHog from 0.11 to 0.37. Nothing about either tool changed — only the fixtures did.

## Scoring

A true positive means the tool reported the correct file and line. The detector name is ignored, so no tool is punished for its own taxonomy. A false positive is only counted where a label explicitly says the line is not a secret, which avoids penalising tools for finding things this corpus never labeled.

Two caveats worth stating out loud:

- The corpus was written alongside SecSentry's detector list, which is a real home-field advantage.
- TruffleHog is designed around verifying live credentials. Planted keys can never verify, so this benchmark measures the part of TruffleHog that matters least to it. We pass `--results=verified,unknown,unverified`; without that flag it reports almost nothing here.
