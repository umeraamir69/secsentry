# SecSentry

Python Git **incident** scanner: leaked secrets in the working tree and in **history**, with **blob-level dedup** so identical Git objects are not scanned twice across branches.

Not a Gitleaks clone. Not live-key verification (we never send a secret to OpenAI, AWS, or GitHub to “see if it works”).

```
pip install secsentry          # later
npx secsentry scan .           # later (wrapper)
secsentry scan . --history     # CLI
```

On GitHub, a pull request shows a **check** named `SecSentry / secrets` (same sidebar slot as Vercel). See [GitHub integration](notes/GitHub%20integration.md).

Custom domain is **not required**. Use Vercel or GitHub Pages when the website exists.

---

## Complete plan

### Problem

Deleting a key from `config.py` does not remove it from `git log`. Teams need a **case file**: what leaked, who first committed it, whether it is still in HEAD, why we think it is a secret, how to rotate — with the value **masked**.

### What we ship (v1)

| Layer | What it does |
|---|---|
| Scanner core | Working tree + git history. Unique **blob OID** scanned once; findings attached to every commit/path that contains that blob |
| Structural verify | JWT/PEM/prefix/length/entropy checks **locally**. Zero exfiltration |
| Context classifier | Heuristic + optional sklearn model on a **labeled planted corpus** |
| Benchmark | Precision/recall vs Gitleaks and TruffleHog on that corpus |
| Install | `pip` + `npm` same version, one Python engine |
| GitHub | Action → PR check + masked comment. App later |

### Four weeks

1. **CLI + P0 detectors** (OpenAI, Claude, AWS, GitHub, Google, Stripe, Slack, PEM, JWT, generic `*_API_KEY`) + mask + why  
2. **History + blob dedup + still-in-HEAD + who introduced** + demo repo (commit fakes → delete → still found)  
3. **Hook + GitHub Action check** + simple report UI (Next.js or JSON)  
4. **Eval corpus, train classifier, benchmark numbers**, TestPyPI + npm  

Never cut: history demo, masking, explainable score, blob dedup.

Cut first: extra YAML rules, GitHub App, email, custom domain.

### Honest limits

- We will not detect every possible API key. Unknown vendors: keyword + entropy.  
- We will not claim “221 Gitleaks rules.”  
- We will not verify keys against vendor APIs.  
- We will not do SQLi/XSS/CVE scanning.

Full positioning: [notes/What makes this real and unique.md](notes/What%20makes%20this%20real%20and%20unique.md)  
Directory map: [STRUCTURE.md](STRUCTURE.md)  
Obsidian vault: [notes/00 Home.md](notes/00%20Home.md)

---

## Repo layout (this is the project)

```
secsentry/
├── README.md                 ← you are here
├── STRUCTURE.md              ← folder-by-folder
├── LICENSE                   MIT
├── VERSION                   0.1.0 (pip + npm stay in sync)
├── pyproject.toml            Python package
├── action.yml                GitHub Action (PR check like Vercel)
├── SECURITY.md
│
├── src/secsentry/            ★ Python engine (only detector implementation)
│   ├── cli.py
│   ├── models.py             Finding, mask, fingerprint
│   ├── git/blobs.py          Unique blob walk (dedup across branches)
│   ├── scan/                 working tree, staged, history, engine
│   ├── detectors/            regex + entropy
│   ├── verify/structural.py  local format checks
│   ├── classify/             heuristic + ML
│   ├── reports/
│   ├── hooks/
│   └── eval/                 corpus, train, benchmark
│
├── packages/npm/             npx wrapper → Python CLI
├── web/                      Next.js site (later)
├── tests/
├── eval/                     generated corpus lives in eval/.data (gitignored)
├── examples/vulnerable-repo/ history-scan demo
├── .github/workflows/        CI using ./ action
└── notes/                    Obsidian project brain
```

---

## Commands (target)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

secsentry scan .
secsentry scan . --history
secsentry scan --staged
secsentry install-hook

python -m secsentry.eval.build_corpus
python -m secsentry.eval.train
python -m secsentry.eval.benchmark
```

GitHub: other repos `uses: <you>/secsentry@v0.1.0` with `fetch-depth: 0`.

---

## License

MIT. Planted eval secrets are **fake** (structurally valid, not live). Never commit real keys.
