"""Command-line entry: scan, serve, hooks."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secsentry import __version__

CACHE_DIR = ".secsentry"
CACHE_FILE = "last-scan.json"
SEVERITIES = ["low", "medium", "high", "critical"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secsentry",
        description="Find leaked secrets in a Git working tree and its history. Runs entirely locally.",
        epilog="Secrets are always masked. SecSentry never sends a credential to a vendor API.",
    )
    parser.add_argument("--version", action="version", version=f"secsentry {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_scan_flags(p: argparse.ArgumentParser) -> None:
        p.add_argument("path", nargs="?", default=".", help="Repository path")
        p.add_argument("--history", action="store_true", help="Scan every commit (blob-deduped)")
        p.add_argument("--severity", choices=SEVERITIES, help="Only report at or above this severity")
        p.add_argument("--type", dest="types", action="append", help="Only this detector family (repeatable)")

    scan = sub.add_parser("scan", help="Scan a repository")
    add_scan_flags(scan)
    scan.add_argument("--staged", action="store_true", help="Scan git diff --cached only")
    scan.add_argument("--format", choices=["text", "json", "html"], default="text")
    scan.add_argument("--fail-on", default="high", choices=SEVERITIES)
    scan.add_argument("--output", "-o", help="Write the report to this path")
    scan.add_argument("--no-cache", action="store_true", help="Do not write .secsentry/last-scan.json")

    serve = sub.add_parser("serve", help="Scan, then open the dashboard on 127.0.0.1")
    add_scan_flags(serve)
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--no-browser", action="store_true")

    hook = sub.add_parser("install-hook", help="Install .git/hooks/pre-commit")
    hook.add_argument("path", nargs="?", default=".")
    unhook = sub.add_parser("uninstall-hook", help="Remove the pre-commit hook")
    unhook.add_argument("path", nargs="?", default=".")

    return parser


def _write_cache(repo: Path, payload: dict) -> None:
    import json

    try:
        cache = repo / CACHE_DIR
        cache.mkdir(parents=True, exist_ok=True)
        (cache / CACHE_FILE).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except OSError:
        pass


def _run_scan(args) -> tuple:
    from secsentry.scan.engine import run_scan

    repo = Path(args.path).resolve()
    report = run_scan(
        repo,
        history=getattr(args, "history", False),
        staged=getattr(args, "staged", False),
        severity=getattr(args, "severity", None),
        types=getattr(args, "types", None),
    )
    return repo, report


def cmd_scan(args) -> int:
    from secsentry.reports.html import render
    from secsentry.reports.json_report import dump_report, report_payload
    from secsentry.reports.terminal import print_report

    repo, report = _run_scan(args)
    payload = report_payload(report)

    if args.output:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        content = render(payload) if args.format == "html" else dump_report(report)
        out.write_text(content, encoding="utf-8")
        print(f"Wrote {out}")
        print_report(report)
    elif args.format == "json":
        print(dump_report(report))
    elif args.format == "html":
        print(render(payload))
    else:
        print_report(report)

    if not args.no_cache and not args.staged:
        _write_cache(repo, payload)

    return 1 if report.should_fail(args.fail_on) else 0


def cmd_serve(args) -> int:
    from secsentry.reports.json_report import report_payload
    from secsentry.reports.serve import serve

    _repo, report = _run_scan(args)
    serve(report_payload(report), port=args.port, open_browser=not args.no_browser)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.cmd == "scan":
        return cmd_scan(args)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "install-hook":
        from secsentry.hooks.pre_commit import install

        install(Path(args.path).resolve())
        return 0
    if args.cmd == "uninstall-hook":
        from secsentry.hooks.pre_commit import uninstall

        uninstall(Path(args.path).resolve())
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
