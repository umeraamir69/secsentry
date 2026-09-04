"""Git history scan using unique blob OIDs."""

from __future__ import annotations

from pathlib import Path

from secsentry.git.blobs import unique_blobs_for_history
from secsentry.scan.engine import ScanContext, findings_from_text


def scan_history(ctx: ScanContext, repo: Path) -> None:
    contents, refs = unique_blobs_for_history(repo)
    blob_hits: dict[str, list] = {}
    ctx.blobs_scanned += len(contents)
    ctx.commits_scanned += len({r.commit for r in refs})
    for oid, data in contents.items():
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        blob_hits[oid] = findings_from_text(ctx, path="(blob)", text=text, blob_oid=oid)

    for ref in refs:
        for f in blob_hits.get(ref.oid, []):
            ctx.add_occurrence(
                f,
                path=ref.path,
                commit=ref.commit,
                author=ref.author,
                author_email=ref.author_email,
                timestamp=ref.timestamp,
                source="history",
            )
