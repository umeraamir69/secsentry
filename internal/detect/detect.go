package detect

import (
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Hit struct {
	Type     string
	Severity string
	Secret   string
	Line     int
	Column   int
	Entropy  float64
}

type rule struct {
	id, sev string
	re      *regexp.Regexp
	capture int
	keys    []string
}

var rules []rule

// Keywords used to skip a chunk before any regex runs.
var Keywords = []string{
	"akia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"sk-", "sk-ant-", "t3blbkfj", "aiza", "sk_live_", "xox",
	"gsk_", "hf_", "sq0atp-", "sq0csp-", "eaaa", "shpss_", "shpat_",
	"shpca_", "shppa_", "glpat-", "sg.", "npm_", "pypi-",
	"begin ", "private key", "eyj",
	"api_key", "api-key", "apikey", "secret_key", "access_token",
	"postgres://", "mysql://", "mongodb",
	"sk_test_", "rk_live_", "rk_test_", "whsec_",
	"aws_secret_access_key", "service_account",
}

var reExtraPrefix = regexp.MustCompile(`\bASIA[0-9A-Z]{16}\b`)

func init() {
	add := func(id, sev, rx string, capture int, keys ...string) {
		rules = append(rules, rule{id, sev, regexp.MustCompile(rx), capture, keys})
	}
	add("aws_access_key", "CRITICAL", `\bAKIA[0-9A-Z]{16}\b`, 0, "AKIA")
	add("aws_session_key", "HIGH", `\bASIA[0-9A-Z]{16}\b`, 0, "ASIA")
	add("aws_secret_access_key", "CRITICAL", `(?i)(?:aws_)?secret_access_key\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?`, 1, "secret_access_key")
	add("github_pat", "HIGH", `\bghp_[A-Za-z0-9]{36}\b`, 0, "ghp_")
	add("github_oauth", "HIGH", `\bgho_[A-Za-z0-9]{36}\b`, 0, "gho_")
	add("github_user", "HIGH", `\bghu_[A-Za-z0-9]{36}\b`, 0, "ghu_")
	add("github_server", "HIGH", `\bghs_[A-Za-z0-9]{36}\b`, 0, "ghs_")
	add("github_refresh", "HIGH", `\bghr_[A-Za-z0-9]{36}\b`, 0, "ghr_")
	add("github_fine_grained", "HIGH", `\bgithub_pat_[A-Za-z0-9_]{20,}\b`, 0, "github_pat_")
	add("openai_api_key", "HIGH", `\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b`, 0, "sk-", "T3BlbkFJ")
	add("openai_api_key", "HIGH", `\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b`, 0, "sk-", "T3BlbkFJ")
	add("anthropic_api_key", "HIGH", `\bsk-ant-(?:api03|admin01)-[A-Za-z0-9\-_]{80,}AA\b`, 0, "sk-ant-")
	add("google_api_key", "HIGH", `\bAIza[0-9A-Za-z\-_]{35}\b`, 0, "AIza")
	add("stripe_live", "HIGH", `\bsk_live_[0-9a-zA-Z]{24,}\b`, 0, "sk_live_")
	add("stripe_test", "MEDIUM", `\bsk_test_[0-9a-zA-Z]{24,}\b`, 0, "sk_test_")
	add("stripe_restricted", "HIGH", `\brk_(?:live|test)_[0-9a-zA-Z]{24,}\b`, 0, "rk_live_", "rk_test_")
	add("stripe_webhook", "HIGH", `\bwhsec_[0-9A-Za-z]{32,}\b`, 0, "whsec_")
	add("slack_bot", "HIGH", `\bxox[baprs]-[0-9A-Za-z-]{10,}\b`, 0, "xox")
	add("groq_api_key", "HIGH", `\bgsk_[A-Za-z0-9]{20,}\b`, 0, "gsk_")
	add("huggingface_token", "HIGH", `\bhf_[A-Za-z0-9]{20,}\b`, 0, "hf_")
	add("square_token", "HIGH", `\b(?:sq0atp-|sq0csp-|EAAA)[0-9A-Za-z\-_]{22,}\b`, 0, "sq0", "EAAA")
	add("shopify_token", "HIGH", `\bshp(?:ss|at|ca|pa)_[0-9a-fA-F]{32}\b`, 0, "shp")
	add("gitlab_pat", "HIGH", `\bglpat-[0-9A-Za-z\-_]{20,}\b`, 0, "glpat-")
	add("sendgrid_key", "HIGH", `\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`, 0, "SG.")
	add("twilio_key", "HIGH", `\bSK[0-9a-fA-F]{32}\b`, 0, "SK")
	add("npm_token", "HIGH", `\bnpm_[0-9A-Za-z]{36}\b`, 0, "npm_")
	add("pypi_token", "HIGH", `\bpypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,}\b`, 0, "pypi-")
	add("private_key", "CRITICAL", `-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----`, 0, "BEGIN", "PRIVATE KEY")
	add("jwt", "MEDIUM", `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, 0, "eyJ")
	add("generic_api_key", "MEDIUM", `(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{20,})['"]`, 1, "api_key", "secret_key", "access_token")
	add("db_url", "HIGH", `(?i)\b(?:postgres|mysql|mongodb(?:\+srv)?)://[^\s'"]+:[^\s'"]+@[^\s'"]+`, 0, "postgres://", "mysql://", "mongodb")
}

func HasKeyword(text string) bool {
	low := strings.ToLower(text)
	for _, k := range Keywords {
		if strings.Contains(low, k) {
			return true
		}
	}
	return reExtraPrefix.MatchString(text)
}

func Shannon(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(utf8.RuneCountInString(s))
	var h float64
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func Detect(text string) []Hit {
	if !HasKeyword(text) {
		return nil
	}
	var hits []Hit
	for i, line := range strings.Split(text, "\n") {
		low := strings.ToLower(line)
		if strings.Contains(line, "AKIAIOSFODNN7EXAMPLE") {
			continue
		}
		for _, r := range rules {
			ok := false
			for _, k := range r.keys {
				if strings.Contains(low, strings.ToLower(k)) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
			for _, m := range r.re.FindAllStringSubmatchIndex(line, -1) {
				secret := line[m[0]:m[1]]
				if r.capture > 0 && len(m) >= (r.capture+1)*2 {
					secret = line[m[r.capture*2]:m[r.capture*2+1]]
				}
				sl := strings.ToLower(secret)
				if strings.Contains(sl, "example") || strings.Contains(sl, "placeholder") ||
					strings.Contains(sl, "changeme") || strings.Contains(sl, "your-") {
					continue
				}
				col := utf8.RuneCountInString(line[:m[0]]) + 1
				hits = append(hits, Hit{
					Type: r.id, Severity: r.sev, Secret: secret,
					Line: i + 1, Column: col, Entropy: Shannon(secret),
				})
			}
		}
	}
	hits = append(hits, gcpServiceAccount(text)...)
	return hits
}

var reGCPEmail = regexp.MustCompile(`[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com`)

func gcpServiceAccount(text string) []Hit {
	if !strings.Contains(text, "service_account") || !strings.Contains(text, "BEGIN PRIVATE KEY") {
		return nil
	}
	if !strings.Contains(text, "iam.gserviceaccount.com") {
		return nil
	}
	secret := "gcp-service-account-json"
	if m := reGCPEmail.FindString(text); m != "" {
		secret = m
	}
	for i, line := range strings.Split(text, "\n") {
		if strings.Contains(line, "service_account") {
			col := strings.Index(line, "service_account") + 1
			return []Hit{{
				Type: "gcp_service_account", Severity: "CRITICAL", Secret: secret,
				Line: i + 1, Column: col, Entropy: Shannon(secret),
			}}
		}
	}
	return nil
}
