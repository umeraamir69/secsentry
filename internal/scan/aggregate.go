package scan

import (
	"sort"
	"time"

	"github.com/umeraamir69/secsentry/internal/model"
	"github.com/umeraamir69/secsentry/internal/rotate"
)

type Secret struct {
	Fingerprint      string          `json:"fingerprint"`
	SecretType       string          `json:"secret_type"`
	Severity         string          `json:"severity"`
	Masked           string          `json:"masked"`
	Confidence       float64         `json:"confidence"`
	Occurrences      []model.Finding `json:"occurrences"`
	FirstSeen        string          `json:"first_seen"`
	LastSeen         string          `json:"last_seen"`
	IntroducedBy     string          `json:"introduced_by"`
	IntroducedEmail  string          `json:"introduced_email"`
	IntroducedCommit string          `json:"introduced_commit"`
	StillInHead      *bool           `json:"still_in_head"`
	AgeDays          *int            `json:"age_days"`
	Rotation         string          `json:"rotation"`
	Why              []string        `json:"why"`
}

func (s Secret) Paths() []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range s.Occurrences {
		if !seen[o.Path] {
			seen[o.Path] = true
			out = append(out, o.Path)
		}
	}
	return out
}

func (s Secret) OccurrenceCount() int { return len(s.Occurrences) }

func parseTS(ts string) (time.Time, bool) {
	if ts == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339, time.RFC3339Nano, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, ts); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func Group(findings []model.Finding) []Secret {
	byFP := map[string]*Secret{}
	order := []string{}
	for _, f := range findings {
		s, ok := byFP[f.Fingerprint]
		if !ok {
			s = &Secret{
				Fingerprint: f.Fingerprint,
				SecretType:  f.SecretType,
				Severity:    f.Severity,
				Masked:      f.Masked,
				Confidence:  f.Confidence,
				Why:         append([]string{}, f.Why...),
				Rotation:    rotate.Hint(f.SecretType),
			}
			byFP[f.Fingerprint] = s
			order = append(order, f.Fingerprint)
		}
		s.Occurrences = append(s.Occurrences, f)
		if model.Rank(f.Severity) > model.Rank(s.Severity) {
			s.Severity = f.Severity
		}
		if f.Confidence > s.Confidence {
			s.Confidence = f.Confidence
		}
		if f.StillInHead != nil && *f.StillInHead {
			t := true
			s.StillInHead = &t
		} else if s.StillInHead == nil && f.StillInHead != nil && !*f.StillInHead {
			fval := false
			s.StillInHead = &fval
		}
	}

	now := time.Now().UTC()
	out := make([]Secret, 0, len(order))
	for _, fp := range order {
		s := byFP[fp]
		type pair struct {
			f model.Finding
			t time.Time
		}
		var dated []pair
		for _, o := range s.Occurrences {
			if t, ok := parseTS(o.Timestamp); ok {
				dated = append(dated, pair{o, t})
			}
		}
		if len(dated) > 0 {
			sort.Slice(dated, func(i, j int) bool { return dated[i].t.Before(dated[j].t) })
			earliest, latest := dated[0], dated[len(dated)-1]
			s.FirstSeen = earliest.f.Timestamp
			s.LastSeen = latest.f.Timestamp
			s.IntroducedBy = earliest.f.Author
			s.IntroducedEmail = earliest.f.AuthorEmail
			s.IntroducedCommit = earliest.f.Commit
			age := int(now.Sub(earliest.t).Hours() / 24)
			if age < 0 {
				age = 0
			}
			s.AgeDays = &age
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := model.Rank(out[i].Severity), model.Rank(out[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].SecretType < out[j].SecretType
	})
	return out
}
