"""Precision / recall against Gitleaks and TruffleHog on the planted corpus.

Scoring is deliberately generous to the competition: a tool gets credit for a
true positive if it reports the right file and line, regardless of what it
calls the secret. Tools that are not installed are reported as skipped rather
than as a score of zero.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from secsentry.eval.build_corpus import DATA, REPO_NAME, build
from secsentry.scan.engine import run_scan

TIMEOUT = 300


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
    }


def score(pred: set[tuple[str, int]], gold: set[tuple[str, int]], negatives: set[tuple[str, int]]) -> dict:
    tp = len(pred & gold)
    fn = len(gold - pred)
    # Only count a false positive where we have a label saying "not a secret".
    fp = len((pred - gold) & negatives)
    return prf(tp, fp, fn)


def _norm(path: str, repo: Path) -> str:
    p = str(path).replace("\\", "/")
    root = str(repo).replace("\\", "/")
    if p.startswith(root):
        p = p[len(root) :]
    return p.lstrip("./")


def run_secsentry(repo: Path) -> set[tuple[str, int]]:
    report = run_scan(repo, history=True)
    return {(_norm(f.path, repo), f.line) for f in report.findings}


def run_gitleaks(repo: Path) -> set[tuple[str, int]] | None:
    if not shutil.which("gitleaks"):
        return None
    out = repo / ".gitleaks-report.json"
    # `gitleaks git` scans history; `detect` is the pre-8.19 spelling.
    subprocess.run(
        ["gitleaks", "git", ".", "--report-format", "json",
         "--report-path", str(out), "--no-banner", "--exit-code", "0"],
        cwd=repo, capture_output=True, timeout=TIMEOUT,
    )
    if not out.exists():
        return set()
    try:
        data = json.loads(out.read_text() or "[]")
    except json.JSONDecodeError:
        return set()
    finally:
        out.unlink(missing_ok=True)
    return {(_norm(d.get("File", ""), repo), int(d.get("StartLine", 0))) for d in data}


def run_trufflehog(repo: Path) -> set[tuple[str, int]] | None:
    if not shutil.which("trufflehog"):
        return None
    # TruffleHog reports only *verified* secrets by default. Planted keys can
    # never verify, so we must ask for unverified results too or the comparison
    # is meaningless.
    proc = subprocess.run(
        ["trufflehog", "git", f"file://{repo}", "--json", "--no-update",
         "--results=verified,unknown,unverified"],
        capture_output=True, text=True, timeout=TIMEOUT,
    )
    found = set()
    for line in proc.stdout.splitlines():
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = (d.get("SourceMetadata") or {}).get("Data") or {}
        git_meta = meta.get("Git") or meta.get("Filesystem") or {}
        path = git_meta.get("file") or ""
        line_no = git_meta.get("line") or 0
        if path:
            found.add((_norm(path, repo), int(line_no)))
    return found


def main() -> None:
    dest = DATA if (DATA / "labels.jsonl").exists() else build()
    repo = dest / REPO_NAME
    if not repo.exists():
        dest = build()
        repo = dest / REPO_NAME

    labels = [json.loads(x) for x in (dest / "labels.jsonl").read_text().splitlines() if x]
    gold = {(x["path"], x["line"]) for x in labels if x["label"] == 1}
    negatives = {(x["path"], x["line"]) for x in labels if x["label"] == 0}

    results: dict[str, dict | str] = {}
    for name, runner in (
        ("secsentry", run_secsentry),
        ("gitleaks", run_gitleaks),
        ("trufflehog", run_trufflehog),
    ):
        try:
            pred = runner(repo)
        except Exception as exc:
            results[name] = f"error: {exc}"
            continue
        if pred is None:
            results[name] = "not installed"
        else:
            results[name] = score(pred, gold, negatives)

    payload = {
        "corpus": {
            "repo": str(repo),
            "planted_secrets": len(gold),
            "negative_lines": len(negatives),
        },
        "results": results,
    }

    out_dir = dest.parent / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "benchmark.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Corpus: {len(gold)} planted secrets, {len(negatives)} negative lines\n")
    print(f"{'tool':<12} {'precision':>10} {'recall':>8} {'f1':>7} {'tp':>4} {'fp':>4} {'fn':>4}")
    print("-" * 55)
    for name, res in results.items():
        if isinstance(res, str):
            print(f"{name:<12} {res:>10}")
        else:
            print(
                f"{name:<12} {res['precision']:>10.2f} {res['recall']:>8.2f} "
                f"{res['f1']:>7.2f} {res['tp']:>4} {res['fp']:>4} {res['fn']:>4}"
            )
    print(f"\nWrote {out_dir / 'benchmark.json'}")


if __name__ == "__main__":
    main()
