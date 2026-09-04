package report

import (
	"encoding/json"
	"strings"

	"github.com/umeraamir69/secsentry/internal/scan"
	"github.com/umeraamir69/secsentry/internal/version"
)

func sarifLevel(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}

func SARIF(rep scan.Report) string {
	type region struct {
		StartLine   int `json:"startLine"`
		StartColumn int `json:"startColumn,omitempty"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type phys struct {
		ArtifactLocation artifact `json:"artifactLocation"`
		Region           region   `json:"region"`
	}
	type location struct {
		PhysicalLocation phys `json:"physicalLocation"`
	}
	type message struct {
		Text string `json:"text"`
	}
	type result struct {
		RuleID       string            `json:"ruleId"`
		Level        string            `json:"level"`
		Message      message           `json:"message"`
		Locations    []location        `json:"locations"`
		Fingerprints map[string]string `json:"fingerprints"`
		Properties   map[string]any    `json:"properties"`
	}
	type rule struct {
		ID               string  `json:"id"`
		ShortDescription message `json:"shortDescription"`
	}
	type driver struct {
		Name           string `json:"name"`
		Version        string `json:"version"`
		InformationURI string `json:"informationUri"`
		Rules          []rule `json:"rules,omitempty"`
	}
	type run struct {
		Tool    struct{ Driver driver } `json:"tool"`
		Results []result                `json:"results"`
	}
	type doc struct {
		Version string `json:"version"`
		Schema  string `json:"$schema"`
		Runs    []run  `json:"runs"`
	}

	seenRule := map[string]bool{}
	var rules []rule
	var results []result
	for _, f := range rep.Findings {
		if !seenRule[f.SecretType] {
			seenRule[f.SecretType] = true
			rules = append(rules, rule{
				ID:               f.SecretType,
				ShortDescription: message{Text: "Possible leaked " + f.SecretType},
			})
		}
		results = append(results, result{
			RuleID:  f.SecretType,
			Level:   sarifLevel(f.Severity),
			Message: message{Text: f.SecretType + " at " + f.Path + " (masked: " + f.Masked + ")"},
			Locations: []location{{
				PhysicalLocation: phys{
					ArtifactLocation: artifact{URI: f.Path},
					Region:           region{StartLine: f.Line, StartColumn: f.Column},
				},
			}},
			Fingerprints: map[string]string{"sha256": f.Fingerprint},
			Properties: map[string]any{
				"masked":        f.Masked,
				"severity":      f.Severity,
				"confidence":    f.Confidence,
				"still_in_head": f.StillInHead,
				"source":        f.Source,
				"why":           f.Why,
			},
		})
	}

	out := doc{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []run{{
			Tool:    struct{ Driver driver }{Driver: driver{Name: "SecSentry", Version: version.Version, InformationURI: "https://github.com/umeraamir69/secsentry", Rules: rules}},
			Results: results,
		}},
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b)
}
