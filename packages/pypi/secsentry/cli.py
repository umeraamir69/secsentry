"""Spawn the Go CLI. Does not reimplement detectors."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

_INSTALL = "go install github.com/umeraamir69/secsentry/cmd/secsentry@latest"


def _path_without_wrapper() -> str:
    here = os.path.dirname(os.path.realpath(sys.argv[0]))
    parts = []
    for p in os.environ.get("PATH", "").split(os.pathsep):
        if not p:
            continue
        try:
            if os.path.realpath(p) == here:
                continue
        except OSError:
            pass
        parts.append(p)
    return os.pathsep.join(parts)


def main() -> None:
    env = os.environ.copy()
    env["PATH"] = _path_without_wrapper()
    exe = shutil.which("secsentry", path=env["PATH"])
    if exe is None:
        print(
            "SecSentry needs the Go binary on PATH. Install with:\n  " + _INSTALL,
            file=sys.stderr,
        )
        raise SystemExit(1)
    raise SystemExit(subprocess.run([exe, *sys.argv[1:]], env=env).returncode)
