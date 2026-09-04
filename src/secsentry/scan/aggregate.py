"""Collapse occurrences into unique secrets.

One fingerprint is one secret, however many files and commits contain it.
A report that lists 500 identical lines is not a report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from secsentry.models import Finding
from secsentry.rotation import rotation_hint

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def rank(severity: str) -> int:
    return SEVERITY_RANK.get(severity.lower(), 0)


def _parse(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


@dataclass
class Secret:
    """One unique credential and everywhere it appears."""

    fingerprint: str
    secret_type: str
    severity: str
    masked: str
    confidence: float
    occurrences: list[Finding] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    introduced_by: str = ""
    introduced_email: str = ""
    introduced_commit: str = ""
    still_in_head: bool | None = None
    age_days: int | None = None
    rotation: str = ""
    why: list[str] = field(default_factory=list)

    @property
    def paths(self) -> list[str]:
        seen: list[str] = []
        for o in self.occurrences:
            if o.path not in seen:
                seen.append(o.path)
        return seen

    def to_dict(self) -> dict:
        return {
            "fingerprint": self.fingerprint,
            "secret_type": self.secret_type,
            "severity": self.severity,
            "masked": self.masked,
            "confidence": round(self.confidence, 3),
            "still_in_head": self.still_in_head,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "age_days": self.age_days,
            "introduced_by": self.introduced_by,
            "introduced_email": self.introduced_email,
            "introduced_commit": self.introduced_commit,
            "rotation": self.rotation,
            "why": self.why,
            "occurrence_count": len(self.occurrences),
            "paths": self.paths,
            "occurrences": [o.to_dict() for o in self.occurrences],
        }


def group(findings: list[Finding]) -> list[Secret]:
    by_fp: dict[str, Secret] = {}

    for f in findings:
        s = by_fp.get(f.fingerprint)
        if s is None:
            s = Secret(
                fingerprint=f.fingerprint,
                secret_type=f.secret_type,
                severity=f.severity,
                masked=f.masked,
                confidence=f.confidence,
                why=list(f.why),
                rotation=rotation_hint(f.secret_type),
            )
            by_fp[f.fingerprint] = s
        s.occurrences.append(f)
        if rank(f.severity) > rank(s.severity):
            s.severity = f.severity
        s.confidence = max(s.confidence, f.confidence)
        if f.still_in_head:
            s.still_in_head = True
        elif s.still_in_head is None and f.still_in_head is False:
            s.still_in_head = False

    now = datetime.now(timezone.utc)
    for s in by_fp.values():
        dated = [(o, _parse(o.timestamp)) for o in s.occurrences]
        dated = [(o, d) for o, d in dated if d is not None]
        if dated:
            dated.sort(key=lambda pair: pair[1])
            earliest, first_dt = dated[0]
            latest, last_dt = dated[-1]
            s.first_seen = earliest.timestamp
            s.last_seen = latest.timestamp
            s.introduced_by = earliest.author
            s.introduced_email = earliest.author_email
            s.introduced_commit = earliest.commit
            s.age_days = max((now - first_dt).days, 0)

    return sorted(
        by_fp.values(),
        key=lambda s: (-rank(s.severity), -s.confidence, s.secret_type),
    )
