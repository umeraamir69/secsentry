import json

import pytest

from secsentry import __version__
from secsentry.cli import main


def test_no_subcommand_exits_2():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_clean_scan_exits_zero(leaky_repo):
    assert main(["scan", str(leaky_repo), "--no-cache"]) == 0


def test_history_scan_fails_the_build(leaky_repo):
    assert main(["scan", str(leaky_repo), "--history", "--no-cache"]) == 1


def test_fail_on_critical_still_trips(leaky_repo):
    assert main(["scan", str(leaky_repo), "--history", "--fail-on", "critical", "--no-cache"]) == 1


def test_json_output_is_valid_and_masked(leaky_repo, capsys):
    main(["scan", str(leaky_repo), "--history", "--format", "json", "--no-cache"])
    out = capsys.readouterr().out
    assert "AKIATESTONLYZZZZZZZZ" not in out
    payload = json.loads(out)
    assert payload["tool"] == "secsentry"
    assert payload["secret_count"] >= 1
    assert payload["secrets"][0]["rotation"]


def test_output_file_is_written(leaky_repo, tmp_path):
    out = tmp_path / "nested" / "report.json"
    main(["scan", str(leaky_repo), "--history", "-o", str(out), "--no-cache"])
    assert json.loads(out.read_text())["secret_count"] >= 1


def test_html_output(leaky_repo, tmp_path):
    out = tmp_path / "report.html"
    main(["scan", str(leaky_repo), "--history", "--format", "html", "-o", str(out), "--no-cache"])
    assert "<!doctype html>" in out.read_text()


def test_scan_writes_the_cache(leaky_repo):
    main(["scan", str(leaky_repo), "--history"])
    cache = leaky_repo / ".secsentry" / "last-scan.json"
    assert json.loads(cache.read_text())["secret_count"] >= 1


def test_install_and_uninstall_hook(leaky_repo, capsys):
    assert main(["install-hook", str(leaky_repo)]) == 0
    hook = leaky_repo / ".git" / "hooks" / "pre-commit"
    assert hook.exists()
    assert hook.stat().st_mode & 0o111

    assert main(["uninstall-hook", str(leaky_repo)]) == 0
    assert not hook.exists()


def test_uninstall_leaves_a_foreign_hook_alone(leaky_repo):
    hook = leaky_repo / ".git" / "hooks" / "pre-commit"
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_text("#!/bin/sh\necho someone elses hook\n", encoding="utf-8")
    main(["uninstall-hook", str(leaky_repo)])
    assert hook.exists()
