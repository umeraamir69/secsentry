from secsentry.models import Finding
from secsentry.scan.engine import ScanReport


def _finding(severity: str) -> Finding:
    return Finding(
        secret_type="aws_access_key",
        severity=severity,
        confidence=0.9,
        path="config.py",
        line=1,
        column=1,
        masked="AKIA••••ZZZZ",
        fingerprint="0" * 64,
    )


def test_fail_on_matches_uppercase_severity():
    report = ScanReport(findings=[_finding("CRITICAL")])
    assert report.should_fail("high") is True
    assert report.should_fail("critical") is True


def test_fail_on_below_threshold_passes():
    report = ScanReport(findings=[_finding("MEDIUM")])
    assert report.should_fail("high") is False
    assert report.should_fail("low") is True


def test_no_findings_never_fails():
    assert ScanReport().should_fail("low") is False
