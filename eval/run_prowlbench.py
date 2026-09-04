#!/usr/bin/env python3
"""Score SecSentry (+ optional Gitleaks / TruffleHog) on ProwlBench.

Protocol matches https://github.com/Lercas/prowlbench :
snippet-level detection (flag >= 1 secret), realistic extensions per source,
overall P/R/F1 plus per-tier recall and T4 FP-rate.

Dataset: https://huggingface.co/datasets/Podric/prowl-secrets-corpus (prowlbench.parquet)
License: CC BY-NC 4.0 — research / non-commercial only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path

from huggingface_hub import hf_hub_download
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT_DIR = ROOT / "eval" / "results"
EXT = {"code": ".py", "jira": ".md", "confluence": ".md", "log": ".log", "slack": ".txt"}


def load_cases() -> list[dict]:
    path = hf_hub_download(
        repo_id="Podric/prowl-secrets-corpus",
        filename="prowlbench.parquet",
        repo_type="dataset",
    )
    df = pd.read_parquet(path)
    cases = []
    for row in df.itertuples(index=False):
        cases.append(
            {
                "id": row.id,
                "text": row.text,
                "label": int(row.label),
                "type": row.type,
                "tier": row.tier,
                "source": row.source,
                "lang": row.lang,
                "origin": row.origin,
            }
        )
    return cases


def write_jsonl(cases: list[dict], path: Path) -> None:
    with path.open("w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps({"id": c["id"], "text": c["text"], "source": c["source"]}, ensure_ascii=False) + "\n")


def materialize(cases: list[dict], d: Path) -> None:
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True)
    for c in cases:
        ext = EXT.get(c["source"], ".txt")
        (d / f"{c['id']}{ext}").write_text(c["text"], encoding="utf-8", errors="replace")


def ids_from_paths(paths) -> set[str]:
    out = set()
    for p in paths:
        stem = Path(str(p)).stem
        if stem.startswith("pb-"):
            out.add(stem)
    return out


def run_secsentry(jsonl: Path) -> set[str]:
    proc = subprocess.run(
        ["go", "run", "./eval/cmd/prowlbench"],
        cwd=ROOT,
        stdin=jsonl.open("rb"),
        capture_output=True,
        timeout=600,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.decode() or "secsentry scorer failed")
    return set(json.loads(proc.stdout.decode() or "[]"))


def run_gitleaks(d: Path) -> set[str] | None:
    if not shutil.which("gitleaks"):
        return None
    rep = Path(tempfile.mktemp(suffix=".json"))
    subprocess.run(
        ["gitleaks", "dir", str(d), "-f", "json", "-r", str(rep), "--no-banner", "--exit-code", "0"],
        capture_output=True,
        timeout=1800,
    )
    try:
        data = json.loads(rep.read_text() or "[]")
    except (json.JSONDecodeError, FileNotFoundError):
        return set()
    finally:
        rep.unlink(missing_ok=True)
    return ids_from_paths(x.get("File", "") for x in data)


def run_trufflehog(d: Path) -> set[str] | None:
    if not shutil.which("trufflehog"):
        return None
    proc = subprocess.run(
        ["trufflehog", "filesystem", str(d), "--json", "--no-update", "--no-verification"],
        capture_output=True,
        text=True,
        timeout=3600,
    )
    ids = set()
    for line in proc.stdout.splitlines():
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        f = (
            j.get("SourceMetadata", {})
            .get("Data", {})
            .get("Filesystem", {})
            .get("file", "")
        )
        if Path(f).stem.startswith("pb-"):
            ids.add(Path(f).stem)
    return ids


def prf(detected: set[str], cases: list[dict]) -> dict:
    tp = sum(1 for c in cases if c["id"] in detected and c["label"])
    fp = sum(1 for c in cases if c["id"] in detected and not c["label"])
    fn = sum(1 for c in cases if c["id"] not in detected and c["label"])
    tn = sum(1 for c in cases if c["id"] not in detected and not c["label"])
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    return {
        "precision": round(p, 4),
        "recall": round(r, 4),
        "f1": round(f1, 4),
        "accuracy": round((tp + tn) / len(cases), 4),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
    }


def breakdown(detected: set[str], cases: list[dict]) -> dict:
    tiers = sorted({c["tier"] for c in cases})
    per_tier = {}
    for tier in tiers:
        sub = [c for c in cases if c["tier"] == tier]
        if tier.startswith("T4"):
            per_tier[tier] = {
                "fp_rate": round(sum(1 for c in sub if c["id"] in detected) / len(sub), 4),
                "n": len(sub),
            }
        else:
            npos = max(sum(c["label"] for c in sub), 1)
            per_tier[tier] = {
                "recall": round(sum(1 for c in sub if c["id"] in detected and c["label"]) / npos, 4),
                "n": int(npos),
            }
    per_lang = {}
    for lg in sorted({c["lang"] for c in cases}):
        sub = [c for c in cases if c["lang"] == lg and c["label"]]
        if sub:
            per_lang[lg] = {
                "recall": round(sum(1 for c in sub if c["id"] in detected) / len(sub), 4),
                "n": len(sub),
            }
    per_source = {}
    for src in sorted({c["source"] for c in cases}):
        sub = [c for c in cases if c["source"] == src and c["label"]]
        if sub:
            per_source[src] = {
                "recall": round(sum(1 for c in sub if c["id"] in detected) / len(sub), 4),
                "n": len(sub),
            }
    # top miss types for positives
    miss = defaultdict(int)
    hit = defaultdict(int)
    for c in cases:
        if not c["label"]:
            continue
        if c["id"] in detected:
            hit[c["type"]] += 1
        else:
            miss[c["type"]] += 1
    return {
        "per_tier": per_tier,
        "per_language": per_lang,
        "per_source": per_source,
        "top_miss_types": sorted(miss.items(), key=lambda x: -x[1])[:15],
        "top_hit_types": sorted(hit.items(), key=lambda x: -x[1])[:15],
    }


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print("Loading ProwlBench parquet…", flush=True)
    cases = load_cases()
    pos = sum(c["label"] for c in cases)
    print(f"ProwlBench: {len(cases)} cases ({pos} pos / {len(cases) - pos} neg)", flush=True)

    jsonl = OUT_DIR / "prowlbench_cases.jsonl"
    write_jsonl(cases, jsonl)

    results: dict[str, set[str]] = {}
    print("Running SecSentry…", flush=True)
    results["secsentry"] = run_secsentry(jsonl)
    print(f"  flagged {len(results['secsentry'])}", flush=True)

    files_dir = ROOT / "eval" / ".data" / "prowlbench_files"
    print("Materializing files for Gitleaks / TruffleHog…", flush=True)
    materialize(cases, files_dir)

    print("Running Gitleaks…", flush=True)
    gl = run_gitleaks(files_dir)
    if gl is not None:
        results["gitleaks"] = gl
        print(f"  flagged {len(gl)}", flush=True)
    else:
        print("  skipped (not installed)", flush=True)

    print("Running TruffleHog (no verification)…", flush=True)
    th = run_trufflehog(files_dir)
    if th is not None:
        results["trufflehog"] = th
        print(f"  flagged {len(th)}", flush=True)
    else:
        print("  skipped (not installed)", flush=True)

    tools = {}
    print(f"\n{'tool':<12} {'prec':>7} {'recall':>7} {'F1':>7} {'acc':>7}")
    print("-" * 44)
    for name, det in results.items():
        m = prf(det, cases)
        b = breakdown(det, cases)
        tools[name] = {**m, **b}
        print(
            f"{name:<12} {m['precision']:>7.3f} {m['recall']:>7.3f} {m['f1']:>7.3f} {m['accuracy']:>7.3f}"
        )

    print("\nper-tier recall (T4 = FP-rate):")
    tiers = sorted(next(iter(tools.values()))["per_tier"])
    print(f"{'tool':<12} " + " ".join(f"{t.split('_')[0]:>6}" for t in tiers))
    for name, entry in tools.items():
        cells = []
        for t in tiers:
            cell = entry["per_tier"][t]
            val = cell.get("fp_rate", cell.get("recall", 0))
            cells.append(f"{val:>6.2f}")
        print(f"{name:<12} " + " ".join(cells))

    artifact = {
        "_meta": {
            "dataset": "Podric/prowl-secrets-corpus",
            "file": "prowlbench.parquet",
            "url": "https://huggingface.co/datasets/Podric/prowl-secrets-corpus",
            "license": "CC BY-NC 4.0",
            "n_cases": len(cases),
            "n_positive": pos,
            "n_negative": len(cases) - pos,
            "protocol": "snippet-level flag>=1; extensions per source; secsentry uses Detect+verify+classify+decode",
            "published_leaderboard_note": "Prowl cascade F1~0.883 on this set (from prowlbench README); not re-run here",
        },
        "tools": tools,
    }
    out = OUT_DIR / "prowlbench_leaderboard.json"
    out.write_text(json.dumps(artifact, indent=2))
    print(f"\nWrote {out}")


if __name__ == "__main__":
    main()
