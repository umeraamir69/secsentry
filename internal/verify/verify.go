package verify

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

var (
	reAWS     = regexp.MustCompile(`^A[KS]IA[0-9A-Z]{16}$`)
	reAWSSec  = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
	reShopify = regexp.MustCompile(`^shp(?:ss|at|ca|pa)_[0-9a-fA-F]{32}$`)
	reTwilio  = regexp.MustCompile(`^SK[0-9a-fA-F]{32}$`)
	reStripe  = regexp.MustCompile(`^(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,}$`)
	reWhsec   = regexp.MustCompile(`^whsec_[0-9A-Za-z]{32,}$`)
)

func OK(secretType, secret string) bool {
	switch {
	case secretType == "aws_access_key" || secretType == "aws_session_key":
		return reAWS.MatchString(secret)
	case secretType == "aws_secret_access_key":
		return reAWSSec.MatchString(secret)
	case secretType == "github_pat" || secretType == "github_oauth" || secretType == "github_user" ||
		secretType == "github_server" || secretType == "github_refresh":
		return strings.HasPrefix(secret, "gh") && len(secret) == 40
	case strings.HasPrefix(secretType, "openai"):
		return strings.Contains(secret, "T3BlbkFJ")
	case strings.HasPrefix(secretType, "anthropic"):
		return strings.HasPrefix(secret, "sk-ant-") && len(secret) > 40
	case secretType == "jwt":
		return jwtOK(secret)
	case secretType == "private_key":
		return strings.Contains(secret, "BEGIN") && strings.Contains(secret, "PRIVATE KEY")
	case secretType == "google_api_key":
		return strings.HasPrefix(secret, "AIza") && len(secret) == 39
	case secretType == "stripe_live" || secretType == "stripe_test" || secretType == "stripe_restricted":
		return reStripe.MatchString(secret)
	case secretType == "stripe_webhook":
		return reWhsec.MatchString(secret)
	case secretType == "gcp_service_account":
		return strings.Contains(secret, "iam.gserviceaccount.com") || secret == "gcp-service-account-json"
	case secretType == "shopify_token":
		return reShopify.MatchString(secret)
	case secretType == "sendgrid_key":
		return strings.HasPrefix(secret, "SG.") && strings.Count(secret, ".") == 2
	case secretType == "twilio_key":
		return reTwilio.MatchString(secret)
	case secretType == "npm_token":
		return strings.HasPrefix(secret, "npm_") && len(secret) == 40
	default:
		return true
	}
}

func jwtOK(secret string) bool {
	parts := strings.Split(secret, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		pad := parts[0] + strings.Repeat("=", (4-len(parts[0])%4)%4)
		raw, err = base64.URLEncoding.DecodeString(pad)
		if err != nil {
			return false
		}
	}
	var header map[string]any
	if json.Unmarshal(raw, &header) != nil {
		return false
	}
	_, ok := header["alg"]
	return ok
}
