package verify

import (
	"strings"
	"testing"
)

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
	if !OK("discord_bot_token", "MTExMjIyMzMzNDQ0NTU1NjY2.GHijkl."+strings.Repeat("m", 32)) {
		t.Fatal("discord")
	}
	if OK("discord_bot_token", "eyJhbGciOiJIUzI1NiIs.aaaaaa.bbbbbbbbbbbbbbbbbbbbbbbbbbb") {
		t.Fatal("jwt-shaped should not pass as discord")
	}
	if !OK("telegram_bot_token", "123456789:AA"+strings.Repeat("t", 33)) {
		t.Fatal("telegram")
	}
	if !OK("digitalocean_token", "dop_v1_"+strings.Repeat("a", 64)) {
		t.Fatal("do")
	}
	if !OK("basic_auth", "dGVzdHVzZXI6TjB0QVBsYWNlaG9sZGVyUHdk") {
		t.Fatal("basic")
	}
	if OK("basic_auth", "not-base64") {
		t.Fatal("junk basic")
	}
}
