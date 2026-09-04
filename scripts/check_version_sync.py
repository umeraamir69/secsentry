#!/usr/bin/env python3
"""Fail the build if VERSION, pyproject, package.json and __init__ disagree.

Shipping pip 1.0.0 alongside npm 0.9.0 is the kind of mistake you only make
once, in public.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package = json.loads((ROOT / "packages" / "npm" / "package.json").read_text(encoding="utf-8"))
    init = (ROOT / "src" / "secsentry" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r'__version__\s*=\s*"([^"]+)"', init)

    found = {
        "VERSION": version,
        "pyproject.toml": pyproject["project"]["version"],
        "packages/npm/package.json": package["version"],
        "src/secsentry/__init__.py": match.group(1) if match else "missing",
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
