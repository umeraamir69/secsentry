"""Strings that look secret-shaped but are not. These must stay quiet."""

import pytest

from secsentry.classify.heuristic import classify
from secsentry.detectors.patterns import detect
from secsentry.verify.structural import structural_ok

BENIGN = [
    ("uuid", 'REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"'),
    ("git_sha", 'COMMIT = "6d0b145a9f3c21e8b7d40f5c2a1e9b8d7c6f5e4a"'),
    ("sha256", 'H = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"'),
    ("md5", 'H = "d41d8cd98f00b204e9800998ecf8427e"'),
    ("aws_docs_example", 'KEY = "AKIAIOSFODNN7EXAMPLE"'),
    ("placeholder_password", 'password = "password"'),
    ("placeholder_your", 'api_key = "YOUR_API_KEY_HERE"'),
    ("changeme", 'secret_key = "CHANGEME"'),
    ("plain_url", 'URL = "https://api.example.com/v1/users"'),
    ("semver", 'VERSION = "1.0.0"'),
]


@pytest.mark.parametrize("name,line", BENIGN, ids=[n for n, _ in BENIGN])
def test_benign_line_produces_no_kept_finding(name, line):
    kept = []
    for hit in detect(line, "app/config.py"):
        ok = structural_ok(hit.secret_type, hit.secret)
        if classify(path="app/config.py", secret_type=hit.secret_type, secret=hit.secret, structural=ok).keep:
            kept.append(hit)
    assert kept == [], f"{name} was reported as a secret: {[h.secret_type for h in kept]}"


def test_lockfile_hash_is_dropped():
    line = '"integrity": "sha512-' + "a" * 64 + '"'
    for hit in detect(line, "package-lock.json"):
        decision = classify(
            path="package-lock.json",
            secret_type=hit.secret_type,
            secret=hit.secret,
            structural=structural_ok(hit.secret_type, hit.secret),
        )
        assert decision.keep is False
