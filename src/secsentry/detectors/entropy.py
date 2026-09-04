"""Shannon entropy for unknown high-randomness strings."""

from __future__ import annotations

from collections import Counter
from math import log2


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in Counter(s).values())
