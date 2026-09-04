package classify

import "testing"

func TestLockfileDropped(t *testing.T) {
	d := Classify("package-lock.json", "generic_api_key", "abcdefghijklmnopqrstuvwxyz012345", true)
	if d.Keep {
		t.Fatal("lockfile should be dropped")
	}
}

func TestPrivateKeyKeptWhenStructural(t *testing.T) {
	d := Classify("id_rsa", "private_key", "-----BEGIN PRIVATE KEY-----", true)
	if !d.Keep || d.Confidence < 0.9 {
		t.Fatalf("%+v", d)
	}
}

func TestRarityHighForRandom(t *testing.T) {
	if Rarity("ghp_abcdefghijklmnopqrstuvwxyz0123456789") < 0.4 {
		t.Fatal("API token should look rare")
	}
	if Rarity("password") > Rarity("x7Q9mK2pL") {
		t.Fatal("english word should be less rare than random")
	}
}
