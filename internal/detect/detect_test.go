package detect

import (
	"strings"
	"testing"
)

const aws = "AKIATESTONLYZZZZZZZZ"
const ghp = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

func TestDetectsAWSAndGitHub(t *testing.T) {
	hits := Detect("key=" + aws + "\ntoken=" + ghp + "\n")
	types := map[string]bool{}
	for _, h := range hits {
		types[h.Type] = true
		if h.Secret == aws && h.Column < 1 {
			t.Fatal("column must be 1-based")
		}
	}
	if !types["aws_access_key"] || !types["github_pat"] {
		t.Fatalf("missing detectors: %+v", types)
	}
}

func TestSkipsAWSExample(t *testing.T) {
	if hits := Detect("AKIAIOSFODNN7EXAMPLE\n"); len(hits) != 0 {
		t.Fatalf("example key should be ignored, got %+v", hits)
	}
}

func TestKeywordPrefilterSkipsBoringText(t *testing.T) {
	if HasKeyword("hello world nothing here") {
		t.Fatal("prefilter should miss boring text")
	}
	if Detect("hello world nothing here") != nil {
		t.Fatal("detect should not run regex on boring text")
	}
}

func TestSecretScannerFixturesAreFound(t *testing.T) {
	// Synthetic keys from ~/Downloads/secret-scanner/tests/test_validators.py
	aws := "AKIAABCDEFGHIJKLMNOP"
	asia := "ASIAABCDEFGHIJKLMNOP"
	ghp := "ghp_" + strings.Repeat("a", 36)
	skLive := "sk_live_" + strings.Repeat("a", 24)
	skTest := "sk_test_" + strings.Repeat("a", 24)
	pkTest := "pk_test_" + strings.Repeat("a", 24)
	slack := "xoxb-123456-789012-" + strings.Repeat("a", 24)
	whsec := "whsec_" + strings.Repeat("b", 32)
	secret := "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

	blob := strings.Join([]string{aws, asia, ghp, skLive, skTest, pkTest, slack, whsec, secret}, "\n")
	hits := Detect(blob)
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Type] = true
		if strings.Contains(h.Secret, "EXAMPLEKEY") && h.Type == "aws_secret_access_key" {
			t.Fatal("placeholder AWS secret should be skipped")
		}
	}
	for _, want := range []string{"aws_access_key", "aws_session_key", "github_pat", "stripe_live", "stripe_test", "slack_bot", "stripe_webhook"} {
		if !got[want] {
			t.Fatalf("missing %s in %+v", want, got)
		}
	}
	for _, h := range hits {
		if strings.HasPrefix(h.Secret, "pk_") {
			t.Fatal("Stripe publishable keys are public and must not be reported")
		}
	}
}

func TestGCPServiceAccountJSON(t *testing.T) {
	text := `{
  "type": "service_account",
  "project_id": "demo",
  "private_key_id": "abc",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
  "client_email": "bot@demo.iam.gserviceaccount.com",
  "client_id": "1",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token"
}`
	hits := Detect(text)
	if !hasType(hits, "gcp_service_account") {
		t.Fatalf("gcp missed: %+v", hits)
	}
}

func hasType(hits []Hit, typ string) bool {
	for _, h := range hits {
		if h.Type == typ {
			return true
		}
	}
	return false
}

func containsSecret(hits []Hit, s string) bool {
	for _, h := range hits {
		if h.Secret == s {
			return true
		}
	}
	return false
}

func TestDBPlaceholderAndRedis(t *testing.T) {
	if hits := Detect("postgres://root:changeme@localhost/dev\n"); hasType(hits, "db_url") {
		t.Fatal("placeholder db password should not be a finding")
	}
	hits := Detect("redis://user:S3cr3tP@ss@cache.internal:6379/0\n")
	if !hasType(hits, "db_url") {
		t.Fatal("redis URL with a real password should be a finding")
	}
}

func TestTwilioAccountSIDIsNotASecret(t *testing.T) {
	if hits := Detect("TWILIO_ACCOUNT_SID=AC" + strings.Repeat("a", 32) + "\n"); hasType(hits, "twilio_key") {
		t.Fatal("Account SID is a public identifier")
	}
}

func TestPEMHeaderAloneIsNotAFinding(t *testing.T) {
	if hits := Detect("see -----BEGIN PRIVATE KEY-----\n"); hasType(hits, "private_key") {
		t.Fatal("a bare PEM header is not a key")
	}
	block := "-----BEGIN PRIVATE KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PRIVATE KEY-----\n"
	if !hasType(Detect(block), "private_key") {
		t.Fatal("a PEM with a body should still fire")
	}
}

func TestLocationIsFileLineColumn(t *testing.T) {
	hits := Detect("prefix " + aws + "\n")
	if len(hits) == 0 {
		t.Fatal("expected a hit")
	}
	if hits[0].Line != 1 || hits[0].Column != 8 {
		t.Fatalf("got line=%d col=%d", hits[0].Line, hits[0].Column)
	}
}

func TestVendorPrefixesPack1(t *testing.T) {
	slack := "https://hooks.slack.com/services/T111AAA111/B111AAA111/abcdefghijklmnopqrstuvwx"
	discord := "MTExMjIyMzMzNDQ0NTU1NjY2.GHijkl." + strings.Repeat("m", 32)
	telegram := "123456789:AA" + strings.Repeat("t", 33)
	azure := "AccountKey=" + strings.Repeat("Ab", 43) + "=="
	datadog := "DATADOG_API_KEY lautet 0123456789abcdef0123456789abcdef"
	do := "dop_v1_" + strings.Repeat("a", 64)
	twilioHex := "TWILIO_AUTH_TOKEN=abcdef0123456789abcdef0123456789"
	basic := "Authorization: Basic dGVzdHVzZXI6TjB0QVBsYWNlaG9sZGVyUHdk"
	nats := "nats://app:S3cr3tPass99@127.0.0.1:4222"
	jdbc := "jdbc:derby://localhost:1527/app;user=app;password=S3cr3tPass99"

	blob := strings.Join([]string{slack, discord, telegram, azure, datadog, do, twilioHex, basic, nats, jdbc}, "\n")
	hits := Detect(blob)
	got := map[string]bool{}
	for _, h := range hits {
		got[h.Type] = true
	}
	for _, want := range []string{
		"slack_webhook", "discord_bot_token", "telegram_bot_token",
		"azure_storage_key", "datadog_api_key", "digitalocean_token",
		"twilio_key", "basic_auth", "db_url",
	} {
		if !got[want] {
			t.Fatalf("missing %s in %+v", want, got)
		}
	}
}

func TestAWSSecretIsAndPaired(t *testing.T) {
	sec := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYTestOnlyXX"
	if len(sec) != 40 {
		t.Fatalf("fixture must be 40 chars, got %d", len(sec))
	}
	if !hasType(Detect("the aws_secret_access_key is "+sec+"\n"), "aws_secret_access_key") {
		t.Fatal("labeled secret with 'is' should fire")
	}
	paired := aws + "\n" + sec + "\n"
	if !hasType(Detect(paired), "aws_secret_access_key") {
		t.Fatal("40-char secret on the line after AKIA should fire")
	}
	if hasType(Detect("commit "+strings.Repeat("a", 40)+"\n"), "aws_secret_access_key") {
		t.Fatal("a free-floating git sha must not be an AWS secret")
	}
}

func TestPEMOneLineAndEncrypted(t *testing.T) {
	oneLine := "-----BEGIN PRIVATE KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgK-----END PRIVATE KEY-----\n"
	if !hasType(Detect(oneLine), "private_key") {
		t.Fatal("PEM header and body on one line should fire")
	}
	enc := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END ENCRYPTED PRIVATE KEY-----\n"
	if !hasType(Detect(enc), "private_key") {
		t.Fatal("ENCRYPTED PRIVATE KEY with a body should fire")
	}
	if hasType(Detect("-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----\n"), "private_key") {
		t.Fatal("a public certificate is not a private key")
	}
}

func TestGCPJSONDoesNotNeedEveryField(t *testing.T) {
	snippet := `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PRIVATE KEY-----"}`
	if !hasType(Detect(snippet), "gcp_service_account") {
		t.Fatal("truncated service-account JSON should still flag")
	}
}

func TestKeywordPrefilterIgnoresEnglishProductNames(t *testing.T) {
	if HasKeyword("we use discord and telegram for asia support") {
		t.Fatal("product names without a token must not disable the prefilter")
	}
}
