"""Which files to skip, and which findings the user has accepted.

Inside a git repo we ask git itself which files are ignored, so `.gitignore`
is honoured exactly rather than reimplemented. `.secsentryignore` adds
scanner-only patterns on top, and the allowlist suppresses findings by
fingerprint — never by storing the secret.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

from secsentry.git.run import git

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".secsentry",
}

IGNORE_FILE = ".secsentryignore"
ALLOWLIST_FILE = ".secsentryallow"


def _read_patterns(path: Path) -> list[str]:
    if not path.is_file():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


class Ignores:
    def __init__(self, repo: Path) -> None:
        self.patterns = _read_patterns(repo / IGNORE_FILE)

    def match(self, rel: str) -> bool:
        rel = rel.replace("\\", "/")
        for pat in self.patterns:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(Path(rel).name, pat):
                return True
            if pat.endswith("/") and rel.startswith(pat):
                return True
        return False


def load_allowlist(repo: Path) -> set[str]:
    """Accepted findings, identified by SHA-256 fingerprint prefix."""
    return {p.split()[0].lower() for p in _read_patterns(repo / ALLOWLIST_FILE)}


def is_allowlisted(fingerprint: str, allowed: set[str]) -> bool:
    return any(fingerprint.startswith(a) for a in allowed if a)


def git_tracked_files(repo: Path) -> list[str] | None:
    """Files git would show: tracked plus untracked, minus everything ignored."""
    try:
        out = git(repo, "ls-files", "--cached", "--others", "--exclude-standard")
    except Exception:
        return None
    return [line for line in out.splitlines() if line.strip()]
