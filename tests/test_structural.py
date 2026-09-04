from secsentry.verify.structural import structural_ok


def test_jwt_header():
    # {"alg":"HS256"} as jwt header eyJhbGciOiJIUzI1NiJ9
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.deadbeefdeadbeef"
    assert structural_ok("jwt", token) is True
    assert structural_ok("aws_access_key", "AKIAZZZZZZZZZZZZZZZZ") is True
    assert structural_ok("aws_access_key", "not-an-aws-key") is False
