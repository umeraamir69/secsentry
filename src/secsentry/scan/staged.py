"""Scan git diff --cached (pre-commit)."""

from __future__ import annotations

from pathlib import Path

from secsentry.git.run import GitError, git


def staged_text(repo: Path) -> list[tuple[str, str]]:
    """Return (path, patch_or_content) for staged files."""
    try:
        names = git(repo, "diff", "--cached", "--name-only", "--diff-filter=ACMR")
    except GitError:
        return []
    out: list[tuple[str, str]] = []
    for name in names.splitlines():
        name = name.strip()
        if not name:
            continue
        try:
            blob = git(repo, "show", f":{name}")
        except GitError:
            continue
        out.append((name, blob))
    return out
