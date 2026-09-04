"""What to actually do about a leaked credential.

A finding without a next step is just noise. Every detector maps to one
concrete revocation action.
"""

from __future__ import annotations

ROTATION = {
    "aws_access_key": "IAM → Users → Security credentials → deactivate, then delete this key. Check CloudTrail for use.",
    "github_pat": "github.com/settings/tokens → revoke. Audit the account's recent activity.",
    "github_fine_grained": "github.com/settings/tokens → revoke the fine-grained token.",
    "openai_api_key": "platform.openai.com/api-keys → revoke. Check usage for unexpected spend.",
    "anthropic_api_key": "console.anthropic.com → API keys → revoke.",
    "google_api_key": "console.cloud.google.com → APIs & Services → Credentials → delete the key.",
    "stripe_live": "dashboard.stripe.com/apikeys → roll the key immediately. This is a live payments credential.",
    "slack_bot": "api.slack.com/apps → your app → OAuth & Permissions → revoke and reinstall.",
    "groq_api_key": "console.groq.com/keys → delete the key.",
    "huggingface_token": "huggingface.co/settings/tokens → revoke.",
    "private_key": "Generate a new keypair, replace it on every host, then remove the old public key from authorized_keys.",
    "jwt": "Rotate the signing secret so every issued token is invalidated.",
    "db_url": "Change the database password and update your secret store. Review connection logs.",
    "generic_api_key": "Revoke this credential with whichever provider issued it, then move it to an environment variable.",
}

FALLBACK = "Revoke this credential with the issuing provider and move it out of source control."


def rotation_hint(secret_type: str) -> str:
    return ROTATION.get(secret_type, FALLBACK)


PURGE_NOTE = (
    "Rotating is the fix. Rewriting history (git filter-repo / BFG) is optional cleanup — "
    "assume anyone who cloned the repo already has the old value."
)
