"""JSON report: the CI artifact and the dashboard's data source."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from secsentry import __version__
from secsentry.rotation import PURGE_NOTE
from secsentry.scan.engine import ScanReport


def report_payload(report: ScanReport) -> dict:
    secrets = report.secrets
    return {
        "tool": "secsentry",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": report.repo,
        "files_scanned": report.files_scanned,
        "commits_scanned": report.commits_scanned,
        "blobs_scanned": report.blobs_scanned,
        "allowlisted": report.allowlisted,
        "counts": report.counts(),
        "secret_count": len(secrets),
        "occurrence_count": len(report.findings),
        "note": PURGE_NOTE,
        "secrets": [s.to_dict() for s in secrets],
        "findings": [f.to_dict() for f in report.findings],
    }


def dump_report(report: ScanReport) -> str:
    return json.dumps(report_payload(report), indent=2)
