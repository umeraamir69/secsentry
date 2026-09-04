"""Local structural checks. Never contacts a vendor."""

from __future__ import annotations

import base64
import json
import re


def _b64url(part: str) -> bytes | None:
    pad = "=" * (-len(part) % 4)
    try:
        return base64.urlsafe_b64decode(part + pad)
    except Exception:
        return None


def structural_ok(secret_type: str, secret: str) -> bool:
    if secret_type == "aws_access_key":
        return bool(re.fullmatch(r"AKIA[0-9A-Z]{16}", secret))
    if secret_type == "github_pat":
        return secret.startswith("ghp_") and len(secret) == 40
    if secret_type.startswith("openai"):
        return "T3BlbkFJ" in secret  # base64("OpenAI")
    if secret_type.startswith("anthropic"):
        return secret.startswith("sk-ant-") and len(secret) > 40
    if secret_type == "jwt":
        parts = secret.split(".")
        if len(parts) != 3:
            return False
        raw = _b64url(parts[0])
        if not raw:
            return False
        try:
            header = json.loads(raw)
        except json.JSONDecodeError:
            return False
        return "alg" in header
    if secret_type == "private_key":
        return "BEGIN" in secret and "PRIVATE KEY" in secret
    if secret_type == "google_api_key":
        return secret.startswith("AIza") and len(secret) == 39
    if secret_type == "stripe_live":
        return secret.startswith("sk_live_") and len(secret) >= 32
    if secret_type == "shopify_token":
        return bool(re.fullmatch(r"shp(?:ss|at|ca|pa)_[0-9a-fA-F]{32}", secret))
    if secret_type == "sendgrid_key":
        return secret.startswith("SG.") and secret.count(".") == 2
    if secret_type == "twilio_key":
        return bool(re.fullmatch(r"SK[0-9a-fA-F]{32}", secret))
    if secret_type == "npm_token":
        return secret.startswith("npm_") and len(secret) == 40
    return True
