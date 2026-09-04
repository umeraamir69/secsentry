package model

import "testing"

func TestMaskNeverShowsMiddle(t *testing.T) {
	secret := "AKIATESTONLYZZZZZZZZ"
	m := Mask(secret)
	if m == secret {
		t.Fatal("mask returned the raw secret")
	}
	if Mask("abcd") != "••••" {
		t.Fatalf("short secrets should be fully dotted, got %q", Mask("abcd"))
	}
}

func TestFingerprintStable(t *testing.T) {
	a := Fingerprint("AKIATESTONLYZZZZZZZZ")
	b := Fingerprint("AKIATESTONLYZZZZZZZZ")
	if a != b || len(a) != 64 {
		t.Fatalf("fingerprint %q", a)
	}
	if a == Fingerprint("other") {
		t.Fatal("different secrets must not share a fingerprint")
	}
}

func TestRankCaseInsensitive(t *testing.T) {
	if Rank("CRITICAL") != 4 || Rank("high") != 3 {
		t.Fatal("rank table")
	}
}
