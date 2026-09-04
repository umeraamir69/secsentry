"""The core promise: deleting a secret does not remove it."""

from secsentry.scan.engine import run_scan


def test_clean_tree_reports_nothing(leaky_repo):
    report = run_scan(leaky_repo)
    assert report.findings == []


def test_history_still_finds_the_deleted_secret(leaky_repo):
    report = run_scan(leaky_repo, history=True)
    types = {f.secret_type for f in report.findings}
    assert "aws_access_key" in types


def test_deleted_secret_is_flagged_as_gone_from_head(leaky_repo):
    report = run_scan(leaky_repo, history=True)
    aws = [f for f in report.findings if f.secret_type == "aws_access_key"]
    assert aws and all(f.still_in_head is False for f in aws)


def test_history_records_who_introduced_it(leaky_repo):
    secrets = run_scan(leaky_repo, history=True).secrets
    aws = next(s for s in secrets if s.secret_type == "aws_access_key")
    assert aws.introduced_by == "Test Author"
    assert aws.introduced_email == "test@example.com"
    assert aws.introduced_commit
    assert aws.age_days is not None


def test_report_never_contains_the_raw_secret(leaky_repo):
    from secsentry.reports.json_report import dump_report

    raw = "AKIATESTONLYZZZZZZZZ"
    assert raw not in dump_report(run_scan(leaky_repo, history=True))


def test_html_never_contains_the_raw_secret(leaky_repo):
    from secsentry.reports.html import render
    from secsentry.reports.json_report import report_payload

    raw = "AKIATESTONLYZZZZZZZZ"
    assert raw not in render(report_payload(run_scan(leaky_repo, history=True)))


def test_severity_filter_excludes_lower_findings(leaky_repo):
    assert run_scan(leaky_repo, history=True, severity="critical").findings
    assert not run_scan(leaky_repo, history=True, types=["stripe"]).findings
