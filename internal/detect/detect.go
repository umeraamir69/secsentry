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
// Keep these token-shaped. Do not add English words (asia, discord, telegram).
var Keywords = []string{
	"akia", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
	"sk-", "sk-ant-", "t3blbkfj", "aiza", "sk_live_", "xox",
	"gsk_", "hf_", "sq0atp-", "sq0csp-", "eaaa", "shpss_", "shpat_",
	"shpca_", "shppa_", "glpat-", "sg.", "npm_", "pypi-",
	"begin ", "private key", "eyj",
	"api_key", "api-key", "apikey", "secret_key", "access_token",
	"postgres://", "mysql://", "mongodb", "postgresql://", "redis://", "amqp://",
	"sk_test_", "rk_live_", "rk_test_", "whsec_",
	"aws_secret_access_key", "secret_access_key", "service_account",
	"hooks.slack.com", "dop_v1_", "doo_v1_", "dor_v1_",
	"accountkey", "datadog", "dd_api", "dd_app",
	"jdbc:", "nats://", "sqlserver://", "mysql+", "postgresql+",
	"twilio",
}

// extraPrefix catches tokens that have no safe English-word keyword.
var extraPrefix = []*regexp.Regexp{
	regexp.MustCompile(`\bA[KS]IA[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b`),
	regexp.MustCompile(`\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b`),
	regexp.MustCompile(`(?i)authorization.{0,12}basic\s+`),
}

var (
	reAWSID         = regexp.MustCompile(`\bA[KS]IA[0-9A-Z]{16}\b`)
	reAWSSecretBare = regexp.MustCompile(`\b[A-Za-z0-9/+=]{40}\b`)
	reGCPEmail      = regexp.MustCompile(`[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com`)
)

func init() {
	add := func(id, sev, rx string, capture int, keys ...string) {
		rules = append(rules, rule{id, sev, regexp.MustCompile(rx), capture, keys})
	}
	add("aws_access_key", "CRITICAL", `\bAKIA[0-9A-Z]{16}\b`, 0, "AKIA")
	add("aws_session_key", "HIGH", `\bASIA[0-9A-Z]{16}\b`, 0, "ASIA")
	add("aws_secret_access_key", "CRITICAL", `(?i)(?:aws_)?secret_access_key.{0,32}['"]?([A-Za-z0-9/+=]{40})['"]?`, 1, "secret_access_key")
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
	add("slack_bot", "HIGH", `\bxox[baprs]-[0-9]+-[0-9]+(?:-[0-9]+)?-[A-Za-z0-9]{20,40}\b`, 0, "xox")
	add("slack_bot", "HIGH", `\bxox[baprs]-[A-Za-z0-9]{8,}(?:-[A-Za-z0-9]{8,})+\b`, 0, "xox")
	add("slack_webhook", "HIGH", `hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}`, 0, "hooks.slack.com")
	add("discord_bot_token", "HIGH", `\b[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}\b`, 0)
	add("telegram_bot_token", "HIGH", `\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b`, 0)
	add("azure_storage_key", "CRITICAL", `(?i)AccountKey=([A-Za-z0-9+/]{86}={0,2})`, 1, "AccountKey")
	add("datadog_api_key", "HIGH", `(?i)(?:datadog[_-]?api[_-]?key|dd[_-]?(?:api|app)[_-]?key).{0,32}([a-f0-9]{32})`, 1, "datadog", "dd_api", "dd_app")
	add("digitalocean_token", "HIGH", `\bdop_v1_[a-f0-9]{64}\b`, 0, "dop_v1_")
	add("digitalocean_token", "HIGH", `\bdo[or]_v1_[a-f0-9]{64}\b`, 0, "doo_v1_", "dor_v1_")
	add("groq_api_key", "HIGH", `\bgsk_[A-Za-z0-9]{20,}\b`, 0, "gsk_")
	add("huggingface_token", "HIGH", `\bhf_[A-Za-z0-9]{20,}\b`, 0, "hf_")
	add("square_token", "HIGH", `\b(?:sq0atp-|sq0csp-|EAAA)[0-9A-Za-z\-_]{22,}\b`, 0, "sq0", "EAAA")
	add("shopify_token", "HIGH", `\bshp(?:ss|at|ca|pa)_[0-9a-fA-F]{32}\b`, 0, "shp")
	add("gitlab_pat", "HIGH", `\bglpat-[0-9A-Za-z\-_]{20,}\b`, 0, "glpat-")
	add("sendgrid_key", "HIGH", `\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b`, 0, "SG.")
	add("twilio_key", "HIGH", `\bSK[0-9a-fA-F]{32}\b`, 0, "SK")
	add("twilio_key", "HIGH", `(?i)twilio[_-]?(?:api[_-]?key|auth[_-]?token).{0,24}([0-9a-fA-F]{32})`, 1, "twilio")
	add("npm_token", "HIGH", `\bnpm_[0-9A-Za-z]{36}\b`, 0, "npm_")
	add("pypi_token", "HIGH", `\bpypi-AgEIcHlwaS[0-9A-Za-z\-_]{50,}\b`, 0, "pypi-")
	add("private_key", "CRITICAL", `-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`, 0, "BEGIN", "PRIVATE KEY")
	add("jwt", "MEDIUM", `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`, 0, "eyJ")
	add("basic_auth", "HIGH", `(?i)authorization.{0,12}basic\s+["']?([A-Za-z0-9+/=]{16,})`, 1, "authorization")
	add("generic_api_key", "MEDIUM", `(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['"]([A-Za-z0-9_\-./+=]{20,})['"]`, 1, "api_key", "secret_key", "access_token")
	add("db_url", "HIGH", `(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|nats|sqlserver|(?:mysql|postgresql)\+[a-z0-9]+)://[^\s'"]+:[^\s'"]+@[^\s'"]+`, 0, "postgres://", "postgresql://", "mysql://", "mongodb", "redis://", "amqp://", "nats://", "sqlserver://", "mysql+", "postgresql+")
	add("db_url", "HIGH", `(?i)jdbc:[a-z0-9]+:(?://)?[^\s'"]+`, 0, "jdbc:")
}

func HasKeyword(text string) bool {
	low := strings.ToLower(text)
	for _, k := range Keywords {
		if strings.Contains(low, k) {
			return true
		}
	}
	for _, re := range extraPrefix {
		if re.MatchString(text) {
			return true
		}
	}
	return false
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
	lines := strings.Split(text, "\n")
	var hits []Hit
	for i, line := range lines {
		low := strings.ToLower(line)
		if strings.Contains(line, "AKIAIOSFODNN7EXAMPLE") {
			continue
		}
		for _, r := range rules {
			if len(r.keys) > 0 {
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
			}
			for _, m := range r.re.FindAllStringSubmatchIndex(line, -1) {
				secret := line[m[0]:m[1]]
				if r.capture > 0 && len(m) >= (r.capture+1)*2 {
					secret = line[m[r.capture*2]:m[r.capture*2+1]]
				}
				if skipSecret(secret) {
					continue
				}
				if r.id == "db_url" && (dbPasswordPlaceholder(secret) || jdbcWithoutPassword(secret)) {
					continue
				}
				if r.id == "private_key" && !pemHasBody(lines, i) {
					continue
				}
				if r.id == "aws_secret_access_key" && !looksLikeAWSSecret(secret) {
					continue
				}
				if r.id == "discord_bot_token" && strings.HasPrefix(secret, "eyJ") {
					continue
				}
				if r.id == "twilio_key" && strings.HasPrefix(strings.ToUpper(secret), "AC") {
					continue
				}
				col := utf8.RuneCountInString(line[:m[0]]) + 1
				if r.capture > 0 {
					col = utf8.RuneCountInString(line[:m[r.capture*2]]) + 1
				}
				hits = append(hits, Hit{
					Type: r.id, Severity: r.sev, Secret: secret,
					Line: i + 1, Column: col, Entropy: Shannon(secret),
				})
			}
		}
	}
	hits = append(hits, awsPairedSecrets(lines)...)
	hits = append(hits, gcpServiceAccount(text)...)
	return hits
}

func skipSecret(secret string) bool {
	sl := strings.ToLower(secret)
	return strings.Contains(sl, "example") || strings.Contains(sl, "placeholder") ||
		strings.Contains(sl, "changeme") || strings.Contains(sl, "your-")
}

func pemHasBody(lines []string, beginIdx int) bool {
	line := lines[beginIdx]
	const marker = "PRIVATE KEY-----"
	if idx := strings.Index(line, marker); idx >= 0 {
		rest := line[idx+len(marker):]
		rest = strings.ReplaceAll(rest, `\n`, "\n")
		if pemRestLooksLikeBody(rest) {
			return true
		}
	}
	end := beginIdx + 8
	if end > len(lines) {
		end = len(lines)
	}
	if beginIdx+1 >= end {
		return false
	}
	for _, line := range lines[beginIdx+1 : end] {
		if pemRestLooksLikeBody(line) {
			return true
		}
		s := strings.TrimSpace(strings.ReplaceAll(line, `\n`, ""))
		if len(s) >= 16 && !strings.HasPrefix(s, "-----") {
			return true
		}
	}
	return false
}

func pemRestLooksLikeBody(s string) bool {
	if strings.Contains(s, "END") && strings.Contains(s, "PRIVATE KEY") {
		return true
	}
	compact := strings.ReplaceAll(strings.TrimSpace(s), "\n", "")
	compact = strings.ReplaceAll(compact, `\n`, "")
	return len(compact) >= 16
}

func dbPasswordPlaceholder(url string) bool {
	low := strings.ToLower(url)
	if strings.Contains(low, "password=") {
		pass := jdbcPassword(url)
		return placeholderPassword(pass)
	}
	at := strings.LastIndex(url, "@")
	if at < 0 {
		return true
	}
	head := url[:at]
	colon := strings.LastIndex(head, ":")
	if colon < 0 {
		return true
	}
	return placeholderPassword(head[colon+1:])
}

func jdbcWithoutPassword(url string) bool {
	low := strings.ToLower(url)
	if !strings.HasPrefix(low, "jdbc:") {
		return false
	}
	if strings.Contains(url, "@") && strings.Contains(url[:strings.LastIndex(url, "@")+1], ":") {
		return false
	}
	return !strings.Contains(low, "password=")
}

func jdbcPassword(url string) string {
	low := strings.ToLower(url)
	i := strings.Index(low, "password=")
	if i < 0 {
		return ""
	}
	rest := url[i+len("password="):]
	if cut := strings.IndexAny(rest, ";& \t\"'"); cut >= 0 {
		rest = rest[:cut]
	}
	return rest
}

func placeholderPassword(pass string) bool {
	pass = strings.ToLower(pass)
	switch pass {
	case "", "password", "changeme", "xxx", "xxxxxxxx", "<password>",
		"yourpassword", "example", "test", "secret", "postgres", "root", "admin":
		return true
	}
	return false
}

func looksLikeAWSSecret(s string) bool {
	if len(s) != 40 {
		return false
	}
	sl := strings.ToLower(s)
	if strings.Contains(sl, "example") || strings.Contains(sl, "placeholder") {
		return false
	}
	for _, p := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "akia", "asia"} {
		if strings.HasPrefix(sl, p) {
			return false
		}
	}
	hexOnly := true
	hasUpper, hasLower, hasSym := false, false, false
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
			if c > 'F' {
				hexOnly = false
			}
		case c >= 'a' && c <= 'z':
			hasLower = true
			if c > 'f' {
				hexOnly = false
			}
		case c >= '0' && c <= '9':
		case c == '/' || c == '+' || c == '=':
			hasSym = true
			hexOnly = false
		default:
			return false
		}
	}
	if hexOnly && !hasUpper {
		return false
	}
	if Shannon(s) < 3.5 {
		return false
	}
	return (hasUpper && hasLower) || hasSym
}

func awsPairedSecrets(lines []string) []Hit {
	var hits []Hit
	for i, line := range lines {
		if !reAWSID.MatchString(line) || strings.Contains(line, "AKIAIOSFODNN7EXAMPLE") {
			continue
		}
		end := i + 3
		if end > len(lines) {
			end = len(lines)
		}
		for j := i; j < end; j++ {
			if strings.Contains(strings.ToLower(lines[j]), "secret_access_key") {
				continue
			}
			for _, m := range reAWSSecretBare.FindAllStringIndex(lines[j], -1) {
				secret := lines[j][m[0]:m[1]]
				if !looksLikeAWSSecret(secret) {
					continue
				}
				col := utf8.RuneCountInString(lines[j][:m[0]]) + 1
				hits = append(hits, Hit{
					Type: "aws_secret_access_key", Severity: "CRITICAL", Secret: secret,
					Line: j + 1, Column: col, Entropy: Shannon(secret),
				})
			}
		}
	}
	return hits
}

func gcpServiceAccount(text string) []Hit {
	if !strings.Contains(text, "service_account") {
		return nil
	}
	hasPEM := strings.Contains(text, "BEGIN") && strings.Contains(text, "PRIVATE KEY")
	hasEmail := strings.Contains(text, "iam.gserviceaccount.com")
	if !hasPEM && !hasEmail {
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
