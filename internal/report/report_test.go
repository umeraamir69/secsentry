package report

import (
	"strings"
	"testing"

	"github.com/umeraamir69/secsentry/internal/model"
	"github.com/umeraamir69/secsentry/internal/scan"
)

func TestReportsNeverContainRawSecret(t *testing.T) {
	raw := "AKIATESTONLYZZZZZZZZ"
	rep := scan.Report{
		Repo: "/tmp/demo",
		Findings: []model.Finding{{
			SecretType:  "aws_access_key",
			Severity:    "CRITICAL",
			Confidence:  0.9,
			Path:        "config.py",
			Line:        1,
			Column:      1,
			Masked:      model.Mask(raw),
			Fingerprint: model.Fingerprint(raw),
			Why:         []string{"rule=aws_access_key"},
		}},
	}
	if strings.Contains(JSON(rep), raw) {
		t.Fatal("JSON contained raw secret")
	}
	if strings.Contains(Render(Build(rep)), raw) {
		t.Fatal("HTML contained raw secret")
	}
	sarif := SARIF(rep)
	if strings.Contains(sarif, raw) {
		t.Fatal("SARIF contained raw secret")
	}
	if !strings.Contains(sarif, `"version": "2.1.0"`) {
		t.Fatal("SARIF version")
	}
}
