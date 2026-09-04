from secsentry.detectors.patterns import detect


def test_aws_and_skip_example():
    text = 'k = "AKIAZZZZZZZZZZZZZZZZ"\nexample = "AKIAIOSFODNN7EXAMPLE"\n'
    hits = detect(text)
    types = {h.secret_type for h in hits}
    assert "aws_access_key" in types
    assert not any("EXAMPLE" in h.secret for h in hits)
