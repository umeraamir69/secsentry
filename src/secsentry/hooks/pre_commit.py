"""Pre-commit hook: block a commit that stages a credential."""

from __future__ import annotations

from pathlib import Path

MARKER = "SecSentry pre-commit"

HOOK = f"""#!/bin/sh
# {MARKER}
# Blocks commits that stage a HIGH or CRITICAL secret.
# Bypass (logged in history, use sparingly): git commit --no-verify

secsentry scan --staged --fail-on high || {{
  echo ""
  echo "SecSentry blocked this commit."
  echo "Rotate anything real, then remove it from the staged change."
  echo "Values above are masked; the file and line show you where to look."
  exit 1
}}
"""


def install(repo: Path) -> None:
    hook = repo / ".git" / "hooks" / "pre-commit"
    if hook.exists() and MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        backup = hook.with_suffix(".secsentry-backup")
        backup.write_text(hook.read_text(encoding="utf-8", errors="replace"), encoding="utf-8")
        print(f"Existing hook backed up to {backup}")
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text(HOOK, encoding="utf-8")
    hook.chmod(0o755)
    print(f"Installed {hook}")


def uninstall(repo: Path) -> None:
    hook = repo / ".git" / "hooks" / "pre-commit"
    if not hook.exists():
        print("No pre-commit hook found.")
        return
    if MARKER not in hook.read_text(encoding="utf-8", errors="replace"):
        print("Pre-commit hook was not installed by SecSentry; leaving it alone.")
        return
    hook.unlink()
    print(f"Removed {hook}")
