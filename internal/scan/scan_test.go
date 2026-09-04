package scan

import (
	"archive/zip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/umeraamir69/secsentry/internal/model"
)

const aws = "AKIATESTONLYZZZZZZZZ"
const ghp = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

func TestShouldFailMatchesUppercaseSeverity(t *testing.T) {
	rep := Report{Findings: []model.Finding{{Severity: "CRITICAL"}}}
	if !rep.ShouldFail("high") || !rep.ShouldFail("critical") {
		t.Fatal("CRITICAL should fail on high")
	}
	rep = Report{Findings: []model.Finding{{Severity: "MEDIUM"}}}
	if rep.ShouldFail("high") {
		t.Fatal("MEDIUM should not fail on high")
	}
	if (Report{}).ShouldFail("low") {
		t.Fatal("empty report should not fail")
	}
}

func TestGroupCollapsesFingerprint(t *testing.T) {
	f := func(path string, line int, fp string) model.Finding {
		return model.Finding{
			SecretType: "aws_access_key", Severity: "CRITICAL", Confidence: 0.9,
			Path: path, Line: line, Column: 1, Masked: "AKIA••••ZZZZ", Fingerprint: fp,
		}
	}
	secrets := Group([]model.Finding{f("a.py", 1, strings.Repeat("a", 64)), f("b.py", 7, strings.Repeat("a", 64))})
	if len(secrets) != 1 || len(secrets[0].Occurrences) != 2 {
		t.Fatalf("got %+v", secrets)
	}
	if got := secrets[0].Paths(); len(got) != 2 || got[0] != "a.py" || got[1] != "b.py" {
		t.Fatalf("paths %v", got)
	}
}

func TestGroupIntroducerIsEarliestCommit(t *testing.T) {
	base := model.Finding{
		SecretType: "aws_access_key", Severity: "CRITICAL", Confidence: 0.9,
		Path: "config.py", Line: 1, Column: 1, Masked: "AKIA••••ZZZZ", Fingerprint: strings.Repeat("a", 64),
	}
	later := base
	later.Author = "Later Dev"
	later.Timestamp = "2026-06-01T10:00:00+00:00"
	later.Commit = "bbb"
	first := base
	first.Author = "First Dev"
	first.Timestamp = "2024-01-15T10:00:00+00:00"
	first.Commit = "aaa"
	first.Line = 2
	s := Group([]model.Finding{later, first})[0]
	if s.IntroducedBy != "First Dev" || s.IntroducedCommit != "aaa" {
		t.Fatalf("introducer %+v", s)
	}
	if !strings.HasPrefix(s.FirstSeen, "2024-01-15") || !strings.HasPrefix(s.LastSeen, "2026-06-01") {
		t.Fatalf("dates %s %s", s.FirstSeen, s.LastSeen)
	}
	if s.AgeDays == nil || *s.AgeDays < 365 {
		t.Fatalf("age %+v", s.AgeDays)
	}
	if s.Rotation == "" {
		t.Fatal("missing rotation")
	}
}

func TestGroupHighestSeverityAndStillInHead(t *testing.T) {
	f := func(sev string, line int, head *bool) model.Finding {
		return model.Finding{
			SecretType: "aws_access_key", Severity: sev, Confidence: 0.9,
			Path: "c.py", Line: line, Column: 1, Masked: "AKIA••••ZZZZ",
			Fingerprint: strings.Repeat("a", 64), StillInHead: head,
		}
	}
	no, yes := false, true
	s := Group([]model.Finding{f("LOW", 1, &no), f("CRITICAL", 2, &yes)})[0]
	if s.Severity != "CRITICAL" || s.StillInHead == nil || !*s.StillInHead {
		t.Fatalf("%+v", s)
	}
}

func TestBase64AndHexUnwrap(t *testing.T) {
	wrapped := base64.StdEncoding.EncodeToString([]byte(aws))
	layers := iterDecoded("TOKEN=" + wrapped + "\n")
	found := false
	for _, c := range layers {
		if strings.Contains(c.Text, aws) {
			found = true
		}
	}
	if !found {
		t.Fatalf("base64 not unwrapped: %+v", layers)
	}
	hx := hex.EncodeToString([]byte(aws))
	layers = iterDecoded("hex=" + hx + "\n")
	found = false
	for _, c := range layers {
		if strings.Contains(c.Text, aws) {
			found = true
		}
	}
	if !found {
		t.Fatalf("hex not unwrapped: %+v", layers)
	}
}

func TestScanFindsPlainAndEncodedAndZip(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte(`AWS = "`+aws+`"`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(rep, "aws_access_key") {
		t.Fatal("plain AWS key missed")
	}

	dir2 := t.TempDir()
	wrapped := base64.StdEncoding.EncodeToString([]byte(aws))
	if err := os.WriteFile(filepath.Join(dir2, "ci.sh"), []byte("export KEY=$(echo "+wrapped+" | base64 -d)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = Run(dir2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Findings {
		if f.SecretType == "aws_access_key" {
			found = true
			if !strings.Contains(strings.Join(f.Why, ";"), "decoded:base64") {
				t.Fatalf("expected decoded:base64 in why: %v", f.Why)
			}
			if strings.Contains(f.Masked, aws) || f.Path != "ci.sh" {
				t.Fatalf("mask/path %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("base64-hidden AWS key missed")
	}

	dir3 := t.TempDir()
	zpath := filepath.Join(dir3, "deploy.zip")
	zf, err := os.Create(zpath)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(zf)
	fw, err := w.Create("secrets/.env")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("GITHUB_TOKEN=" + ghp + "\n"))
	_ = w.Close()
	_ = zf.Close()
	rep, err = Run(dir3, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found = false
	for _, f := range rep.Findings {
		if f.SecretType == "github_pat" && strings.Contains(f.Path, "deploy.zip!secrets/.env") {
			found = true
		}
		blob, _ := json.Marshal(rep.Findings)
		if strings.Contains(string(blob), ghp) {
			t.Fatal("raw token leaked into report")
		}
	}
	if !found {
		t.Fatalf("zip-hidden token missed: %+v", typesOf(rep))
	}
}

func TestHistoryFindsDeletedSecret(t *testing.T) {
	dir := leakyRepo(t)
	clean, err := Run(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Findings) != 0 {
		t.Fatalf("working tree should be clean, got %+v", clean.Findings)
	}
	hist, err := Run(dir, Options{History: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasType(hist, "aws_access_key") {
		t.Fatalf("history missed aws: %v", typesOf(hist))
	}
	for _, f := range hist.Findings {
		if f.SecretType == "aws_access_key" && (f.StillInHead == nil || *f.StillInHead) {
			t.Fatal("deleted secret should be still_in_head=false")
		}
	}
	secrets := hist.Secrets()
	var awsSecret *Secret
	for i := range secrets {
		if secrets[i].SecretType == "aws_access_key" {
			awsSecret = &secrets[i]
		}
	}
	if awsSecret == nil || awsSecret.IntroducedBy != "Test Author" || awsSecret.IntroducedEmail != "test@example.com" {
		t.Fatalf("introducer %+v", awsSecret)
	}
	dump, _ := json.Marshal(hist.Findings)
	if strings.Contains(string(dump), aws) {
		t.Fatal("JSON contained raw secret")
	}
	crit, err := Run(dir, Options{History: true, Severity: "critical"})
	if err != nil || len(crit.Findings) == 0 {
		t.Fatal("severity filter dropped critical")
	}
	none, err := Run(dir, Options{History: true, Types: []string{"stripe"}})
	if err != nil || len(none.Findings) != 0 {
		t.Fatal("type filter should exclude aws")
	}
}

func hasType(r Report, typ string) bool {
	for _, f := range r.Findings {
		if f.SecretType == typ {
			return true
		}
	}
	return false
}

func typesOf(r Report) []string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.SecretType)
	}
	return out
}

func leakyRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test Author",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test Author",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s (%v)", args, out, err)
		}
	}
	run("init")
	run("config", "user.name", "Test Author")
	run("config", "user.email", "test@example.com")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("AWS_ACCESS_KEY_ID="+aws+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".env")
	run("commit", "-m", "plant")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("AWS_ACCESS_KEY_ID=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".env")
	run("commit", "-m", "delete")
	return dir
}
