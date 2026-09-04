#!/usr/bin/env python3
"""Fail the build if VERSION, the Go const, and package.json disagree."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    go = (ROOT / "internal" / "version" / "version.go").read_text(encoding="utf-8")
    go_match = re.search(r'const Version = "([^"]+)"', go)
    package = json.loads((ROOT / "packages" / "npm" / "package.json").read_text(encoding="utf-8"))
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    py_match = re.search(r'^version = "([^"]+)"', pyproject, re.M)

    found = {
        "VERSION": version,
        "internal/version/version.go": go_match.group(1) if go_match else "missing",
        "packages/npm/package.json": package["version"],
        "pyproject.toml": py_match.group(1) if py_match else "missing",
    }

    if len(set(found.values())) == 1:
        print(f"Version sync OK: {version}")
        return 0

    print("Version mismatch:", file=sys.stderr)
    for where, value in found.items():
        flag = " " if value == version else "<-"
        print(f"  {flag} {where}: {value}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
