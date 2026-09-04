"""P0 regex rules. Fixtures must be fake."""

from __future__ import annotations

import re
from dataclasses import dataclass

from secsentry.detectors.entropy import shannon


@dataclass
class Hit:
    secret_type: str
    severity: str
    secret: str
    line: int
    column: int
    entropy: float


# Prefix-oriented P0 rules. Do not treat Stripe sk_live as OpenAI.
RULES: list[tuple[str, str, str]] = [
    ("aws_access_key", "CRITICAL", r"\bAKIA[0-9A-Z]{16}\b"),
    ("github_pat", "HIGH", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("github_fine_grained", "HIGH", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    ("openai_api_key", "HIGH", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b"),
    ("openai_api_key", "HIGH", r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b"),
    ("anthropic_api_key", "HIGH", r"\bsk-ant-(?:api03|admin01)-[A-Za-z0-9\-_]{80,}AA\b"),
    ("google_api_key", "HIGH", r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ("stripe_live", "HIGH", r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ("slack_bot", "HIGH", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    ("groq_api_key", "HIGH", r"\bgsk_[A-Za-z0-9]{20,}\b"),
    ("huggingface_token", "HIGH", r"\bhf_[A-Za-z0-9]{20,}\b"),
    ("square_token", "HIGH", r"\b(?:sq0atp-|sq0csp-|EAAA)[0-9A-Za-z\-_]{22,}\b"),
    ("shopify_token", "HIGH", r"\bshp(?:ss|at|ca|pa)_[0-9a-fA-F]{32}\b"),
    ("gitlab_pat", "HIGH", r"\bglpat-[0-9A-Za-z\-_]{20,}\b"),
    ("sendgrid_key", "HIGH", r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"),
    ("twilio_key", "HIGH", r"\bSK[0-9a-fA-F]{32}\b"),
    ("npm_token", "HIGH", r"\bnpm_[0-9A-Za-z]{36}\b"),
    ("pypi_token", "HIGH", r"\bpypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,}\b"),
    ("private_key", "CRITICAL", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ("jwt", "MEDIUM", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    (
        "generic_api_key",
        "MEDIUM",
        r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]([A-Za-z0-9_\-./+=]{20,})['\"]",
    ),
    (
        "db_url",
        "HIGH",
        r"(?i)\b(?:postgres|mysql|mongodb(?:\+srv)?)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
    ),
]

COMPILED = [(tid, sev, re.compile(rx)) for tid, sev, rx in RULES]

PLACEHOLDERS = (
    "YOUR_",
    "CHANGEME",
    "EXAMPLE",
    "xxxxxx",
    "placeholder",
    "AKIAIOSFODNN7EXAMPLE",
)


def detect(text: str, path: str = "") -> list[Hit]:
    hits: list[Hit] = []
    lines = text.splitlines()
    for i, line in enumerate(lines, start=1):
        if any(p.lower() in line.lower() for p in PLACEHOLDERS) and "AKIAIOSFODNN7EXAMPLE" in line:
            continue
        for tid, sev, cre in COMPILED:
            for m in cre.finditer(line):
                secret = m.group(1) if m.lastindex else m.group(0)
                if any(p.lower() in secret.lower() for p in ("example", "placeholder", "changeme", "your-")):
                    continue
                hits.append(
                    Hit(
                        secret_type=tid,
                        severity=sev,
                        secret=secret,
                        line=i,
                        column=m.start() + 1,
                        entropy=shannon(secret),
                    )
                )
    return hits
