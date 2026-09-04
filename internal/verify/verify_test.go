package verify

import "testing"

func TestAWSAndJWT(t *testing.T) {
	if !OK("aws_access_key", "AKIATESTONLYZZZZZZZZ") {
		t.Fatal("aws")
	}
	if OK("aws_access_key", "AKIA_TOO_SHORT") {
		t.Fatal("short aws")
	}
	if !OK("jwt", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig") {
		t.Fatal("jwt header with alg should pass")
	}
}
