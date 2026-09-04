"""Plain-text report. One block per unique secret, not per line hit."""

from __future__ import annotations

import os
import sys

from secsentry.scan.engine import ScanReport

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
COLOR = {
    "critical": "\033[91m",
    "high": "\033[93m",
    "medium": "\033[96m",
    "low": "\033[90m",
}


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def print_report(report: ScanReport) -> None:
    color = _use_color()
    secrets = report.secrets
    counts = report.counts()

    scanned = f"files={report.files_scanned}"
    if report.commits_scanned:
        scanned += f"  commits={report.commits_scanned}  blobs={report.blobs_scanned}"

    print(_paint("SecSentry", BOLD, color) + f"  {scanned}")
    summary = "  ".join(f"{n} {name}" for name, n in counts.items() if n)
    print(f"{len(secrets)} unique secret(s), {len(report.findings)} occurrence(s)" + (f"  —  {summary}" if summary else ""))
    if report.allowlisted:
        print(f"{report.allowlisted} finding(s) suppressed by .secsentryallow")
    print("-" * 70)

    if not secrets:
        print("No findings.")
        return

    for s in secrets:
        sev = s.severity.upper()
        head = _paint(f"[{sev}]", COLOR.get(s.severity.lower(), ""), color)
        print(f"{head} {_paint(s.secret_type, BOLD, color)}  {s.masked}  confidence={s.confidence:.2f}")

        for occ in s.occurrences[:10]:
            loc = f"{occ.path}:{occ.line}:{occ.column}"
            extra = f"  {occ.commit[:8]}" if occ.commit else ""
            print(f"    {loc}{extra}")
        if len(s.occurrences) > 10:
            print(f"    … {len(s.occurrences) - 10} more occurrence(s)")

        if s.introduced_by:
            when = s.first_seen[:10]
            age = f", {s.age_days}d ago" if s.age_days is not None else ""
            print(f"    introduced by {s.introduced_by} on {when}{age}")
        if s.still_in_head is not None:
            state = "still in HEAD" if s.still_in_head else "deleted from HEAD, still in history"
            print(f"    {state}")
        if s.why:
            print(_paint(f"    why: {'; '.join(s.why)}", DIM, color))
        print(_paint(f"    fix: {s.rotation}", DIM, color))
        print()
