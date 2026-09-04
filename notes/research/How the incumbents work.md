---
tags:
  - research
  - competitors
---

# How Gitleaks, Betterleaks, and TruffleHog actually work

Read 2026-09-04 from the public READMEs. Stars at that date: Gitleaks **29.1k**, TruffleHog **27.7k**, Betterleaks **1.8k**.

Gitleaks is **feature complete**. The original author is shifting to [Betterleaks](https://github.com/betterleaks/betterleaks). Competing with Gitleaks on features is competing with a frozen product. The live race on *coverage + live verify* is Betterleaks vs TruffleHog vs **[Prowl](https://github.com/Lercas/prowl)**. We do not join that race. [[Prowl]]

## How each one works

### Gitleaks — detect, dump, ignore

- **Engine:** regex catalog + Shannon entropy + keyword prefilter. Rules live in `.gitleaks.toml`.
- **Git:** `git log -p`. It looks at **patches (additions)**, not unique blobs. That is why identical secrets across branches get re-scanned as diffs.
- **Modes:** `git`, `dir`, `stdin`.
- **Noise control:** per-rule and global allowlists, `gitleaks:allow` comments, `.gitleaksignore` by fingerprint, **baselines** (old report = ignore those findings next time).
- **Clever extras:** recursive **decode** (base64 / hex / percent), **archive** walk (`zip!inner.env`), composite “required nearby” rules.
- **Output:** JSON, CSV, JUnit, SARIF. Default **prints the full secret**. `--redact` is opt-in.
- **Fingerprint:** `commit:file:rule:line` — occurrence identity, not secret identity.

Thesis line: Gitleaks is a *finder*. It answers “is there a match on this line?” It does not answer “is this the same secret as yesterday, still in HEAD, and who first put it there?”

### Betterleaks — Gitleaks, next generation

Same authors. Same regex core, then four upgrades:

| Upgrade | What it is | Relates to us |
|---|---|---|
| **Expr filters** | Contextual allowlists: path, git author, entropy, secret contents, in one expression | We have hardcoded heuristics. They have a language. |
| **Validation** | Rule embeds `http.get(vendor, Authorization: secret)`. Async. Also `betterleaks validate` on a known token. | **ADR-009. We never do this.** |
| **Token efficiency** | BPE tokenization: is this string *rare* (machine) or *common* (English)? “Rare not random.” | Distinct from Shannon entropy. Worth stealing **locally**. |
| **Sources** | GitHub, GitLab, Hugging Face, S3, stdin — not just a local clone | Out of v1 scope. |

Also: Aho-Corasick keyword skip before regex, RE2, parallel workers. Go binary, fast.

They still validate by **sending the secret to the vendor**. The Expr just makes it prettier.

### TruffleHog — find, then log in as the secret

Four-stage product, 800+ detectors:

1. **Discover** — git, GitHub, GitLab, Docker, S3, GCS, Jenkins, Elasticsearch, Postman, Hugging Face, stdin, even Cross-Fork Object References (deleted / hidden GitHub commits).
2. **Classify** — map the blob to an identity (AWS user, Stripe key, …).
3. **Validate** — call the vendor API with the found secret. Status: verified / unverified / unknown.
4. **Analyze** — for ~20 types, enumerate permissions (“what can this key do?”).

Default output includes the **raw** secret. `--results=verified` is how they sell low false-positives: only show keys that still work. That is also how they **use** leaked credentials.

AGPL. Enterprise SaaS funds the open source.

Our planted-corpus recall of 0.40 for TruffleHog is expected: fake keys never verify, and verification is the product.

## Feature matrix (honest)

| Capability | Gitleaks | Betterleaks | TruffleHog | SecSentry today |
|---|---|---|---|---|
| Local git working tree | yes | yes | yes | **yes** |
| Git history | patches | patches + sources | git + hidden commits | **unique blobs, still_in_HEAD** |
| Rule catalog size | huge, frozen | growing | 800+ | ~20 P0 prefixes |
| Entropy | Shannon on capture group | Shannon + **BPE rarity** | Shannon filter on unverified | Shannon |
| Live vendor check | no | **yes (Expr http)** | **yes (core pitch)** | **never** ★ |
| Mask by default | no (`--redact`) | not the pitch | no (raw in JSON) | **always** ★ |
| One secret, many occurrences | occurrence fingerprint | occurrence | occurrence | **SHA-256 secret fingerprint** ★ |
| Who introduced it | author on the *hit* | git attributes | email on the hit | **earliest commit for that fingerprint** ★ |
| Still in HEAD vs history-only | no | no | no | **yes** ★ |
| Rotation next step | no | no | analyze = permissions | **yes** ★ |
| Explainable why | RuleID + entropy | Rule + Expr | DetectorType | **rule + structural + entropy + path** ★ |
| Dashboard / People | no | no | enterprise | **localhost Overview/People/Timeline** ★ |
| pip + npm same engine | no | no | no | **yes** ★ |
| Decode / archives | yes | inherited | yes | **yes (v1.1)** — still masked |
| SARIF / JUnit | yes | likely | yes | **no** |
| Baseline / ignore comments | yes | Expr + ignore | `trufflehog:ignore` | fingerprint allowlist only |
| Keyword prefilter | yes | Aho-Corasick | detector keywords | **no** — we regex every line |
| Sources beyond local git | stdin, dir | GH/GL/HF/S3 | many | local path only |
| Speed / binary | Go | Go | Go | Python |
| License | MIT | MIT | AGPL | MIT |

★ = keep. Do not give these up to “catch up.”

## What we are missing (and should steal)

These improve the tool **without** becoming a Gitleaks clone or a TruffleHog clone.

### Steal soon (v1.1, still unique)

1. **Keyword prefilter.** Before regex, require `AKIA` / `ghp_` / `sk-` / `xox` in the chunk. This is how Gitleaks stays fast. Ours currently runs every rule on every line.
2. **`gitleaks:allow`-style comment.** One-line override next to a test fixture. Faster than fingerprint allowlist for developers.
3. **Decode pass.** Base64 / hex wrappers. Lots of “leaks” are `echo SECRET | base64` in CI scripts. Local, no network.
4. **Archive walk.** `.env` inside `deploy.zip`. Optional, depth-limited.
5. **SARIF output.** GitHub code scanning understands it. Cheap portfolio win next to our Action.
6. **GitHub token family.** We have `ghp_` and `github_pat_`. Gitleaks also has `gho_` `ghu_` `ghs_` `ghr_`. Public prefixes, add them.
7. **BPE / “rare not random.”** Betterleaks’ actual research contribution. Shannon says “high entropy.” BPE says “not English.” Together they kill UUID/lockfile FPs better than either alone. Still fully local. Thesis gold.

### Steal later (v1.x, not the pitch)

- stdin mode
- Docker image / single binary (PyInstaller or just document `pipx`)
- Baseline file (JSON of fingerprints to ignore on the next scan — we almost have this)
- `--since-commit` for PR diffs (TruffleHog CI pattern). Our Action already scans full history; a cheap mode for “only this PR” would be faster.
- Composite rules: AWS key **and** secret within N lines. Powerful, easy to overfit.

### Do not steal

| Feature | Why not |
|---|---|
| 800 rules / “we copied Gitleaks TOML” | Frozen catalog, not a thesis. P0 quality. |
| Live `http.get` validation | [[ADR-009]]. Betterleaks and TruffleHog already own this. Also illegal-adjacent if you “test” someone else’s key. |
| `trufflehog analyze` (use the key to list IAM) | Same, worse: you are *using* the stolen credential. |
| Scan all of GitHub / S3 / Jenkins | Different product (Betterleaks/TruffleHog Enterprise). |
| Print the raw secret | [[ADR-004]]. Their default is a leak channel. |

## How we stay unique (double down)

Do not try to be “Gitleaks but Python.” The gap they cannot copy without changing product is the **incident**:

```
One fingerprint
  → N occurrences (file:line:column, commit)
  → introduced_by = author of the earliest commit
  → still_in_head true | false
  → rotation one-liner
  → why[] the detector can defend in an interview
  → never the raw value
```

Pitch against each:

| Them | One sentence |
|---|---|
| **Gitleaks** | They dump matching lines. We dump a case file: same secret across files, still in HEAD or not, who first committed it, how to rotate. |
| **Betterleaks** | They added live HTTP validation and a filter language. We stay offline and explainable. Token-efficiency (BPE) we can adopt without phoning home. |
| **TruffleHog** | They prove a key works by logging in as it. We refuse. A rotated key is still an incident: it was in git, clones exist, rotate *and* assume exposure. |

The [testKeys](https://github.com/umeraamir69/testKeys) demo is the proof Gitleaks’ default `dir` scan cannot show: clean tree, dirty history, `still_in_head=false`.

## What would actually make a Master’s examiner sit up

Not “25 regexes.” These three:

1. **Blob-level history + still-in-HEAD** as a first-class state, not a footnote.
2. **Fingerprint identity** so People / Timeline / allowlist are about *secrets*, not lines.
3. **Local rarity classifier** (entropy + BPE + structural) with an honest benchmark vs Gitleaks/TruffleHog that admits corpus bias.

If you add one research-shaped piece after v1, make it **#3**, not another vendor prefix. Do not try to out-Prowl Prowl on multilingual prose or `--verify`.

## Related

- [[What makes this real and unique]]
- [[Competitor landscape]]
- [[ADR-009 No live secret verification]]
- [[Benchmark results]]
- [[GitHub search dorks]]
- [[Prowl]]
