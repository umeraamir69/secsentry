"""Build a labeled corpus of planted secrets in a multi-commit git repo.

Every value is fake — generated from a fixed seed, issued by nobody, and
authenticating to nothing — but deliberately **high entropy**. An earlier
version used readable filler like "TESTONLY" plus repeated characters, which
quietly rigged the benchmark: Gitleaks applies entropy thresholds and threw
those out, so SecSentry looked far better than it was. Random bodies keep the
comparison honest.

Positives are planted deliberately. Negatives are the strings that make naive
regex scanners embarrassing: UUIDs, hashes, lockfile integrity, placeholders.
"""

from __future__ import annotations

import json
import random
import shutil
import string
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "eval" / ".data"
REPO_NAME = "planted-repo"
SEED = 20260904

_rng = random.Random(SEED)
_ALNUM = string.ascii_letters + string.digits


def _rand(n: int, alphabet: str = _ALNUM) -> str:
    return "".join(_rng.choice(alphabet) for _ in range(n))


def _build_values() -> dict[str, str]:
    """Structurally valid, high-entropy, and not issued by anyone."""
    _rng.seed(SEED)
    return {
        "aws1": "AKIA" + _rand(16, string.ascii_uppercase + string.digits),
        "aws2": "AKIA" + _rand(16, string.ascii_uppercase + string.digits),
        "ghp1": "ghp_" + _rand(36),
        "ghp2": "ghp_" + _rand(36),
        "ghfine": "github_pat_" + _rand(24),
        "openai": "sk-" + _rand(20) + "T3BlbkFJ" + _rand(20),
        "groq": "gsk_" + _rand(32),
        "hf": "hf_" + _rand(32),
        "google": "AIza" + _rand(35),
        "stripe": "sk_live_" + _rand(28),
        "slack": "xoxb-9876543210-1234567890-" + _rand(28),
        "square": "sq0atp-" + _rand(22, string.ascii_letters + string.digits + "-_"),
        "shopify": "shpat_" + _rand(32, string.hexdigits.lower()[:16]),
        "sendgrid": "SG." + _rand(22) + "." + _rand(43),
        "twilio": "SK" + _rand(32, string.hexdigits.lower()[:16]),
        "gitlab": "glpat-" + _rand(20, string.ascii_letters + string.digits + "-_"),
        "npm": "npm_" + _rand(36),
        "pg_pw": _rand(20),
        "my_pw": _rand(20),
        "mongo_pw": _rand(20),
        "api": _rand(32),
        "secret": _rand(32),
        "pem": _rand(64),
        "ssh": _rand(64),
    }


def _positives(v: dict[str, str]) -> list[tuple[str, str, list[tuple[int, str]]]]:
    return [
        (
            "services/aws.py",
            f'REGION = "us-east-1"\nACCESS_KEY = "{v["aws1"]}"\nBACKUP_KEY = "{v["aws2"]}"\n',
            [(2, "aws_access_key"), (3, "aws_access_key")],
        ),
        (
            "services/github.py",
            f'TOKEN = "{v["ghp1"]}"\nCI_TOKEN = "{v["ghp2"]}"\nFINE = "{v["ghfine"]}"\n',
            [(1, "github_pat"), (2, "github_pat"), (3, "github_fine_grained")],
        ),
        (
            "services/llm.py",
            f'OPENAI = "{v["openai"]}"\nGROQ = "{v["groq"]}"\nHF = "{v["hf"]}"\n',
            [(1, "openai_api_key"), (2, "groq_api_key"), (3, "huggingface_token")],
        ),
        (
            "services/vendors.py",
            f'GOOGLE = "{v["google"]}"\nSTRIPE = "{v["stripe"]}"\nSLACK = "{v["slack"]}"\n',
            [(1, "google_api_key"), (2, "stripe_live"), (3, "slack_bot")],
        ),
        (
            "services/commerce.py",
            f'SQUARE = "{v["square"]}"\nSHOPIFY = "{v["shopify"]}"\nSENDGRID = "{v["sendgrid"]}"\n',
            [(1, "square_token"), (2, "shopify_token"), (3, "sendgrid_key")],
        ),
        (
            "services/ci.py",
            f'TWILIO = "{v["twilio"]}"\nGITLAB = "{v["gitlab"]}"\nNPM = "{v["npm"]}"\n',
            [(1, "twilio_key"), (2, "gitlab_pat"), (3, "npm_token")],
        ),
        (
            "config/database.yml",
            "production:\n"
            f'  url: "postgres://svc:{v["pg_pw"]}@prod-db.internal:5432/app"\n'
            f'  replica: "mysql://reader:{v["my_pw"]}@replica.internal:3306/app"\n'
            f'  mongo: "mongodb+srv://root:{v["mongo_pw"]}@cluster0.internal/app"\n',
            [(2, "db_url"), (3, "db_url"), (4, "db_url")],
        ),
        (
            "config/settings.py",
            f'api_key = "{v["api"]}"\n'
            f'secret_key = "{v["secret"]}"\n'
            'JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdmMtYWNjb3VudCJ9.'
            f'{_rand(43, string.ascii_letters + string.digits + "-_")}"\n',
            [(1, "generic_api_key"), (2, "generic_api_key"), (3, "jwt")],
        ),
        (
            "deploy/service_key.pem",
            f'-----BEGIN RSA PRIVATE KEY-----\n{v["pem"]}\n-----END RSA PRIVATE KEY-----\n',
            [(1, "private_key")],
        ),
        (
            "deploy/ed25519",
            f'-----BEGIN OPENSSH PRIVATE KEY-----\n{v["ssh"]}\n-----END OPENSSH PRIVATE KEY-----\n',
            [(1, "private_key")],
        ),
    ]


# Files where a naive scanner fires but nothing has actually leaked.
NEGATIVES: list[tuple[str, str]] = [
    (
        "README.md",
        "# Example app\n\n"
        "Set your key: `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`\n"
        "Use `export API_KEY=YOUR_API_KEY_HERE` before running.\n"
        'Then set `password = "changeme"` in the config.\n',
    ),
    (
        "package-lock.json",
        '{\n  "dependencies": {\n'
        '    "left-pad": {\n'
        '      "integrity": "sha512-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",\n'
        '      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"\n'
        "    }\n  }\n}\n",
    ),
    (
        "app/ids.py",
        'REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"\n'
        'TRACE_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"\n'
        'COMMIT = "6d0b145a9f3c21e8b7d40f5c2a1e9b8d7c6f5e4a"\n'
        'TREE = "ce0b792d4e8a1b3c5f7091a2b4c6d8e0f2a4b6c8"\n',
    ),
    (
        "app/defaults.py",
        'password = "password"\n'
        'api_key = "placeholder"\n'
        'token = "your-token-here"\n'
        'secret_key = "CHANGEME"\n',
    ),
    (
        "app/hashes.py",
        'SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"\n'
        'MD5 = "d41d8cd98f00b204e9800998ecf8427e"\n'
        'BCRYPT = "$2b$12$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMN"\n',
    ),
    (
        "app/encoded.py",
        'BASE64_DOC = "VGhpcyBpcyBqdXN0IGEgYmFzZTY0IGVuY29kZWQgc2VudGVuY2Uu"\n'
        'CSS_HASH = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"\n',
    ),
]

GIT_ENV = {
    "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    "GIT_AUTHOR_NAME": "SecSentry Eval",
    "GIT_AUTHOR_EMAIL": "eval@secsentry.local",
    "GIT_COMMITTER_NAME": "SecSentry Eval",
    "GIT_COMMITTER_EMAIL": "eval@secsentry.local",
}


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True, env=GIT_ENV)


def build(dest: Path | None = None) -> Path:
    dest = dest or DATA
    dest.mkdir(parents=True, exist_ok=True)
    repo = dest / REPO_NAME
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)
    _git(repo, "init", "-b", "main")

    labels: list[dict] = []
    positives = _positives(_build_values())

    # Commit 1: negatives only. A clean-looking baseline.
    for name, content in NEGATIVES:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        for i in range(1, len(content.splitlines()) + 1):
            labels.append({"path": name, "line": i, "label": 0, "type": "negative"})
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "Initial project scaffold")

    # Commit 2: the leak.
    for name, content, marks in positives:
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        for line, stype in marks:
            labels.append({"path": name, "line": line, "label": 1, "type": stype})
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "Wire up service credentials")

    # Commit 3: the false fix — gone from the tree, still in history.
    for name, _content, _marks in positives:
        (repo / name).unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "Move credentials to environment variables")

    (dest / "labels.jsonl").write_text(
        "\n".join(json.dumps(x) for x in labels) + "\n", encoding="utf-8"
    )

    n_pos = sum(1 for x in labels if x["label"] == 1)
    print(f"Built {repo}")
    print(f"  3 commits, {n_pos} planted secrets, {len(labels) - n_pos} negative lines")
    print(f"  seed={SEED} (deterministic, high entropy, none are live)")
    return dest


if __name__ == "__main__":
    build()
