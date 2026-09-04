import subprocess
from pathlib import Path

import pytest

ENV = {
    "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
    "GIT_AUTHOR_NAME": "Test Author",
    "GIT_AUTHOR_EMAIL": "test@example.com",
    "GIT_COMMITTER_NAME": "Test Author",
    "GIT_COMMITTER_EMAIL": "test@example.com",
}


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=ENV)


@pytest.fixture
def leaky_repo(tmp_path: Path) -> Path:
    """A repo where a secret was committed, then deleted."""
    repo = tmp_path / "leaky"
    repo.mkdir()
    git(repo, "init", "-b", "main")

    (repo / "config.py").write_text(
        'AWS = "AKIATESTONLYZZZZZZZZ"\nDEBUG = True\n', encoding="utf-8"
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "add config")

    (repo / "config.py").write_text(
        'import os\nAWS = os.environ["AWS"]\nDEBUG = True\n', encoding="utf-8"
    )
    git(repo, "add", ".")
    git(repo, "commit", "-m", "remove hardcoded key")
    return repo
