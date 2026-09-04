"""Optional sklearn classifier. Train with python -m secsentry.eval.train."""

from __future__ import annotations

from pathlib import Path

MODEL_PATH = Path(__file__).with_name("model.joblib")


def predict_proba(feat: dict[str, float]) -> float | None:
    if not MODEL_PATH.exists():
        return None
    try:
        import joblib
    except ImportError:
        return None
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"] if isinstance(bundle, dict) else bundle
    keys = bundle.get("keys") if isinstance(bundle, dict) else sorted(feat)
    import numpy as np

    x = np.array([[feat[k] for k in keys]])
    return float(model.predict_proba(x)[0, 1])
