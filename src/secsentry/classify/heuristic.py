"""Heuristic keep/drop before optional ML."""

from __future__ import annotations

from dataclasses import dataclass, field

from secsentry.detectors.entropy import shannon


@dataclass
class Decision:
    keep: bool
    confidence: float
    why: list[str] = field(default_factory=list)


DOC_PATHS = (".md", "docs/", "test/", "tests/", "example")
LOCKFILES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock")


def classify(*, path: str, secret_type: str, secret: str, structural: bool) -> Decision:
    why: list[str] = [f"rule={secret_type}"]
    low = path.lower().replace("\\", "/")
    conf = 0.55
    if structural:
        conf += 0.2
        why.append("structural_ok")
    ent = shannon(secret)
    why.append(f"entropy={ent:.2f}")
    if ent >= 3.5:
        conf += 0.1
    if any(low.endswith(x) or x in low for x in LOCKFILES):
        return Decision(False, 0.1, why + ["lockfile"])
    if any(x in low for x in DOC_PATHS) and secret_type == "generic_api_key":
        conf -= 0.25
        why.append("docs_or_tests")
    keep = conf >= 0.5
    if secret_type in ("private_key", "aws_access_key") and structural:
        keep = True
        conf = max(conf, 0.9)
    return Decision(keep, min(conf, 0.99), why)
