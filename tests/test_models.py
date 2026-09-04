from secsentry.models import Finding, fingerprint, mask_secret


def test_mask_and_fingerprint():
    s = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    assert mask_secret(s).startswith("ghp_")
    assert "•" in mask_secret(s)
    assert len(fingerprint(s)) == 64


def test_finding_reports_location_not_raw_secret():
    s = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    f = Finding(
        secret_type="github_pat",
        severity="HIGH",
        confidence=0.9,
        path="config.py",
        line=42,
        column=18,
        masked=mask_secret(s),
        fingerprint=fingerprint(s),
    )
    d = f.to_dict()
    assert d["path"] == "config.py"
    assert d["line"] == 42
    assert d["column"] == 18
    assert "secret" not in d
    assert s not in d["masked"]
    assert s not in str(d)

