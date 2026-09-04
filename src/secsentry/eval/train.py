"""Train optional sklearn model on eval/.data labels. Requires secsentry[ml]."""

from __future__ import annotations

import json
from pathlib import Path

from secsentry.eval.build_corpus import DATA, build


def main() -> None:
    dest = DATA if (DATA / "labels.jsonl").exists() else build()
    try:
        import joblib
        import numpy as np
        from sklearn.linear_model import LogisticRegression
    except ImportError:
        print("Install extras: pip install -e '.[ml]'")
        return

    from secsentry.classify.features import features
    from secsentry.classify.ml import MODEL_PATH
    from secsentry.scan.working_tree import iter_text_files
    from secsentry.detectors.patterns import detect
    from secsentry.verify.structural import structural_ok

    labels = [json.loads(l) for l in (dest / "labels.jsonl").read_text().splitlines() if l]
    by = {(x["path"], x["line"]): x["label"] for x in labels}
    repo = dest / "planted-repo"
    X, y = [], []
    for rel, text, _ in iter_text_files(repo):
        for hit in detect(text, rel):
            lab = by.get((rel, hit.line))
            if lab is None:
                continue
            feat = features(rel, hit.secret, hit.secret_type, structural_ok(hit.secret_type, hit.secret))
            keys = sorted(feat)
            X.append([feat[k] for k in keys])
            y.append(lab)
    if len(set(y)) < 2:
        print("Need both positive and negative labels in the corpus.")
        return
    clf = LogisticRegression(max_iter=200)
    clf.fit(np.array(X), np.array(y))
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "keys": keys}, MODEL_PATH)
    print(f"Wrote {MODEL_PATH} on {len(y)} rows")


if __name__ == "__main__":
    main()
