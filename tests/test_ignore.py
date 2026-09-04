from secsentry.models import fingerprint
from secsentry.scan.engine import run_scan
from secsentry.scan.ignore import is_allowlisted, load_allowlist
from secsentry.scan.working_tree import iter_text_files

SECRET = "AKIATESTONLYZZZZZZZZ"


def test_gitignored_file_is_not_scanned(leaky_repo):
    (leaky_repo / ".gitignore").write_text("secrets.txt\n", encoding="utf-8")
    (leaky_repo / "secrets.txt").write_text(f'KEY = "{SECRET}"\n', encoding="utf-8")
    assert run_scan(leaky_repo).findings == []


def test_secsentryignore_skips_a_path(leaky_repo):
    (leaky_repo / "vendor.py").write_text(f'KEY = "{SECRET}"\n', encoding="utf-8")
    assert run_scan(leaky_repo).findings

    (leaky_repo / ".secsentryignore").write_text("vendor.py\n", encoding="utf-8")
    assert run_scan(leaky_repo).findings == []


def test_allowlist_suppresses_by_fingerprint(leaky_repo):
    (leaky_repo / "known.py").write_text(f'KEY = "{SECRET}"\n', encoding="utf-8")
    assert run_scan(leaky_repo).findings

    (leaky_repo / ".secsentryallow").write_text(
        f"{fingerprint(SECRET)}  # rotated 2026-09-04\n", encoding="utf-8"
    )
    report = run_scan(leaky_repo)
    assert report.findings == []
    assert report.allowlisted > 0


def test_allowlist_matches_on_prefix():
    fp = fingerprint(SECRET)
    assert is_allowlisted(fp, {fp[:12]})
    assert not is_allowlisted(fp, {"deadbeef"})


def test_load_allowlist_ignores_comments(tmp_path):
    (tmp_path / ".secsentryallow").write_text("# a note\n\nabc123\n", encoding="utf-8")
    assert load_allowlist(tmp_path) == {"abc123"}


def test_binary_and_oversized_files_are_skipped(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01\x02" + SECRET.encode())
    (tmp_path / "big.txt").write_text("x" * 1_000_001, encoding="utf-8")
    (tmp_path / "ok.py").write_text("value = 1\n", encoding="utf-8")
    names = {rel for rel, _t, _d in iter_text_files(tmp_path)}
    assert names == {"ok.py"}
