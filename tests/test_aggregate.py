from secsentry.models import Finding
from secsentry.scan.aggregate import group


def occurrence(**kw) -> Finding:
    base = dict(
        secret_type="aws_access_key",
        severity="CRITICAL",
        confidence=0.9,
        path="config.py",
        line=1,
        column=1,
        masked="AKIA••••ZZZZ",
        fingerprint="a" * 64,
    )
    base.update(kw)
    return Finding(**base)


def test_same_fingerprint_collapses_into_one_secret():
    secrets = group([occurrence(path="a.py"), occurrence(path="b.py", line=7)])
    assert len(secrets) == 1
    assert len(secrets[0].occurrences) == 2
    assert secrets[0].paths == ["a.py", "b.py"]


def test_different_fingerprints_stay_separate():
    assert len(group([occurrence(), occurrence(fingerprint="b" * 64)])) == 2


def test_earliest_commit_is_the_introducer():
    secrets = group(
        [
            occurrence(author="Later Dev", timestamp="2026-06-01T10:00:00+00:00", commit="bbb"),
            occurrence(author="First Dev", timestamp="2024-01-15T10:00:00+00:00", commit="aaa", line=2),
        ]
    )
    s = secrets[0]
    assert s.introduced_by == "First Dev"
    assert s.introduced_commit == "aaa"
    assert s.first_seen.startswith("2024-01-15")
    assert s.last_seen.startswith("2026-06-01")
    assert s.age_days > 365


def test_secret_keeps_the_highest_severity_seen():
    secrets = group([occurrence(severity="LOW"), occurrence(severity="CRITICAL", line=2)])
    assert secrets[0].severity == "CRITICAL"


def test_still_in_head_is_true_if_any_occurrence_survives():
    secrets = group(
        [occurrence(still_in_head=False), occurrence(still_in_head=True, line=2)]
    )
    assert secrets[0].still_in_head is True


def test_secrets_sort_by_severity():
    secrets = group(
        [
            occurrence(severity="MEDIUM", fingerprint="b" * 64),
            occurrence(severity="CRITICAL", fingerprint="a" * 64),
            occurrence(severity="HIGH", fingerprint="c" * 64),
        ]
    )
    assert [s.severity for s in secrets] == ["CRITICAL", "HIGH", "MEDIUM"]


def test_every_secret_carries_rotation_guidance():
    assert group([occurrence()])[0].rotation
