"""Walk candidate files: skip junk dirs, ignored paths, and binaries."""

from __future__ import annotations

from pathlib import Path

from secsentry.git.blobs import is_git_repo
from secsentry.scan.ignore import SKIP_DIRS, Ignores, git_tracked_files

MAX_FILE_BYTES = 1_000_000


def _readable_text(path: Path) -> tuple[str, bytes] | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    try:
        return data.decode("utf-8"), data
    except UnicodeDecodeError:
        return None


def _candidate_paths(root: Path) -> list[str]:
    if is_git_repo(root):
        tracked = git_tracked_files(root)
        if tracked is not None:
            return tracked
    out = []
    for path in root.rglob("*"):
        if path.is_file() and not any(part in SKIP_DIRS for part in path.parts):
            out.append(str(path.relative_to(root)))
    return out


def iter_text_files(root: Path):
    root = root.resolve()
    ignores = Ignores(root)
    for rel in _candidate_paths(root):
        if any(part in SKIP_DIRS for part in Path(rel).parts):
            continue
        if ignores.match(rel):
            continue
        got = _readable_text(root / rel)
        if got is None:
            continue
        text, data = got
        yield rel, text, data
