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

func TestLocationIsFileLineColumn(t *testing.T) {
	hits := Detect("prefix " + aws + "\n")
	if len(hits) == 0 {
		t.Fatal("expected a hit")
	}
	if hits[0].Line != 1 || hits[0].Column != 8 {
		t.Fatalf("got line=%d col=%d", hits[0].Line, hits[0].Column)
	}
}
