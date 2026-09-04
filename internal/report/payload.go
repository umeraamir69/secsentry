package report

import (
	"encoding/json"
	"math"
	"time"

	"github.com/umeraamir69/secsentry/internal/rotate"
	"github.com/umeraamir69/secsentry/internal/scan"
	"github.com/umeraamir69/secsentry/internal/version"
)

type secretJSON struct {
	Fingerprint      string   `json:"fingerprint"`
	SecretType       string   `json:"secret_type"`
	Severity         string   `json:"severity"`
	Masked           string   `json:"masked"`
	Confidence       float64  `json:"confidence"`
	StillInHead      *bool    `json:"still_in_head"`
	FirstSeen        string   `json:"first_seen"`
	LastSeen         string   `json:"last_seen"`
	AgeDays          *int     `json:"age_days"`
	IntroducedBy     string   `json:"introduced_by"`
	IntroducedEmail  string   `json:"introduced_email"`
	IntroducedCommit string   `json:"introduced_commit"`
	Rotation         string   `json:"rotation"`
	Why              []string `json:"why"`
	OccurrenceCount  int      `json:"occurrence_count"`
	Paths            []string `json:"paths"`
	Occurrences      any      `json:"occurrences"`
}

type Payload struct {
	Tool            string         `json:"tool"`
	Version         string         `json:"version"`
	GeneratedAt     string         `json:"generated_at"`
	Repository      string         `json:"repository"`
	FilesScanned    int            `json:"files_scanned"`
	CommitsScanned  int            `json:"commits_scanned"`
	BlobsScanned    int            `json:"blobs_scanned"`
	Allowlisted     int            `json:"allowlisted"`
	Counts          map[string]int `json:"counts"`
	SecretCount     int            `json:"secret_count"`
	OccurrenceCount int            `json:"occurrence_count"`
	Note            string         `json:"note"`
	Secrets         []secretJSON   `json:"secrets"`
	Findings        any            `json:"findings"`
}

func Build(rep scan.Report) Payload {
	secrets := rep.Secrets()
	out := make([]secretJSON, 0, len(secrets))
	for _, s := range secrets {
		out = append(out, secretJSON{
			Fingerprint:      s.Fingerprint,
			SecretType:       s.SecretType,
			Severity:         s.Severity,
			Masked:           s.Masked,
			Confidence:       math.Round(s.Confidence*1000) / 1000,
			StillInHead:      s.StillInHead,
			FirstSeen:        s.FirstSeen,
			LastSeen:         s.LastSeen,
			AgeDays:          s.AgeDays,
			IntroducedBy:     s.IntroducedBy,
			IntroducedEmail:  s.IntroducedEmail,
			IntroducedCommit: s.IntroducedCommit,
			Rotation:         s.Rotation,
			Why:              s.Why,
			OccurrenceCount:  s.OccurrenceCount(),
			Paths:            s.Paths(),
			Occurrences:      s.Occurrences,
		})
	}
	return Payload{
		Tool:            "secsentry",
		Version:         version.Version,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339Nano),
		Repository:      rep.Repo,
		FilesScanned:    rep.FilesScanned,
		CommitsScanned:  rep.CommitsScanned,
		BlobsScanned:    rep.BlobsScanned,
		Allowlisted:     rep.Allowlisted,
		Counts:          rep.Counts(),
		SecretCount:     len(secrets),
		OccurrenceCount: len(rep.Findings),
		Note:            rotate.PurgeNote,
		Secrets:         out,
		Findings:        rep.Findings,
	}
}

func JSON(rep scan.Report) string {
	b, _ := json.MarshalIndent(Build(rep), "", "  ")
	return string(b)
}
