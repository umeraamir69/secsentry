from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256


def fingerprint(secret: str) -> str:
    return sha256(secret.encode("utf-8", errors="replace")).hexdigest()


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "•" * len(secret)
    return f"{secret[:4]}{'•' * min(12, len(secret) - 8)}{secret[-4:]}"


@dataclass
class Finding:
    secret_type: str
    severity: str
    confidence: float
    path: str
    line: int
    column: int
    masked: str
    fingerprint: str
    blob_oid: str = ""
    commit: str = ""
    author: str = ""
    author_email: str = ""
    timestamp: str = ""
    still_in_head: bool | None = None
    structural_ok: bool | None = None
    entropy: float = 0.0
    why: list[str] = field(default_factory=list)
    source: str = "working-tree"  # working-tree | history

    def to_dict(self) -> dict:
        return asdict(self)
