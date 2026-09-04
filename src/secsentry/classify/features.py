"""Feature extraction for the optional sklearn model."""

from __future__ import annotations

from secsentry.detectors.entropy import shannon


def features(path: str, secret: str, secret_type: str, structural: bool) -> dict[str, float]:
    low = path.lower().replace("\\", "/")
    return {
        "entropy": shannon(secret),
        "length": float(len(secret)),
        "structural": 1.0 if structural else 0.0,
        "is_test": 1.0 if "/test" in low or low.startswith("test") else 0.0,
        "is_docs": 1.0 if low.endswith(".md") or "/docs/" in low else 0.0,
        "is_lock": 1.0 if "lock" in low else 0.0,
        "known_prefix": 1.0 if secret_type != "generic_api_key" else 0.0,
    }
