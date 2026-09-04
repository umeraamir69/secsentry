"""Enumerate unique Git blobs so the same object is not scanned twice across branches."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from secsentry.git.run import git


@dataclass(frozen=True)
class BlobRef:
    oid: str
    path: str
    commit: str
    author: str
    author_email: str
    timestamp: str


def is_git_repo(repo: Path) -> bool:
    return (repo / ".git").exists() or (repo / ".git").is_file()


def unique_blobs_for_history(repo: Path) -> tuple[dict[str, bytes], list[BlobRef]]:
    """
    Return (oid -> content, list of blob occurrences).
    Content is loaded once per oid.
    """
    if not is_git_repo(repo):
        return {}, []

    log = git(
        repo,
        "log",
        "--all",
        "--format=%H%x00%an%x00%ae%x00%aI",
    )
    commits: list[tuple[str, str, str, str]] = []
    for block in log.split("\n"):
        if not block.strip():
            continue
        parts = block.split("\0")
        if len(parts) >= 4:
            commits.append((parts[0], parts[1], parts[2], parts[3]))

    contents: dict[str, bytes] = {}
    refs: list[BlobRef] = []
    for sha, author, email, ts in commits:
        tree = git(repo, "ls-tree", "-r", "--full-tree", sha)
        for line in tree.splitlines():
            # 100644 blob <oid>\t<path>
            meta, _, path = line.partition("\t")
            bits = meta.split()
            if len(bits) < 3 or bits[1] != "blob":
                continue
            oid = bits[2]
            refs.append(
                BlobRef(
                    oid=oid,
                    path=path,
                    commit=sha,
                    author=author,
                    author_email=email,
                    timestamp=ts,
                )
            )
            if oid not in contents:
                raw = git(repo, "cat-file", "blob", oid)
                contents[oid] = raw.encode("utf-8", errors="replace")
    return contents, refs
