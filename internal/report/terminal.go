package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/umeraamir69/secsentry/internal/scan"
)

const (
	reset = "\033[0m"
	bold  = "\033[1m"
	dim   = "\033[2m"
)

var sevColor = map[string]string{
	"critical": "\033[91m",
	"high":     "\033[93m",
	"medium":   "\033[96m",
	"low":      "\033[90m",
}

func useColor() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

func paint(text, code string, on bool) string {
	if !on {
		return text
	}
	return code + text + reset
}

func Print(rep scan.Report) {
	color := useColor()
	secrets := rep.Secrets()
	counts := rep.Counts()

	scanned := fmt.Sprintf("files=%d", rep.FilesScanned)
	if rep.CommitsScanned > 0 {
		scanned += fmt.Sprintf("  commits=%d  blobs=%d", rep.CommitsScanned, rep.BlobsScanned)
	}
	fmt.Println(paint("SecSentry", bold, color) + "  " + scanned)

	var parts []string
	for _, name := range []string{"critical", "high", "medium", "low"} {
		if n := counts[name]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, name))
		}
	}
	line := fmt.Sprintf("%d unique secret(s), %d occurrence(s)", len(secrets), len(rep.Findings))
	if len(parts) > 0 {
		line += "  —  " + strings.Join(parts, "  ")
	}
	fmt.Println(line)
	if rep.Allowlisted > 0 {
		fmt.Printf("%d finding(s) suppressed by .secsentryallow\n", rep.Allowlisted)
	}
	fmt.Println(strings.Repeat("-", 70))
	if len(secrets) == 0 {
		fmt.Println("No findings.")
		return
	}
	for _, s := range secrets {
		head := paint("["+strings.ToUpper(s.Severity)+"]", sevColor[strings.ToLower(s.Severity)], color)
		fmt.Printf("%s %s  %s  confidence=%.2f\n", head, paint(s.SecretType, bold, color), s.Masked, s.Confidence)
		limit := len(s.Occurrences)
		if limit > 10 {
			limit = 10
		}
		for _, occ := range s.Occurrences[:limit] {
			loc := fmt.Sprintf("%s:%d:%d", occ.Path, occ.Line, occ.Column)
			extra := ""
			if occ.Commit != "" {
				c := occ.Commit
				if len(c) > 8 {
					c = c[:8]
				}
				extra = "  " + c
			}
			fmt.Printf("    %s%s\n", loc, extra)
		}
		if len(s.Occurrences) > 10 {
			fmt.Printf("    … %d more occurrence(s)\n", len(s.Occurrences)-10)
		}
		if s.IntroducedBy != "" {
			when := s.FirstSeen
			if len(when) > 10 {
				when = when[:10]
			}
			age := ""
			if s.AgeDays != nil {
				age = fmt.Sprintf(", %dd ago", *s.AgeDays)
			}
			fmt.Printf("    introduced by %s on %s%s\n", s.IntroducedBy, when, age)
		}
		if s.StillInHead != nil {
			if *s.StillInHead {
				fmt.Println("    still in HEAD")
			} else {
				fmt.Println("    deleted from HEAD, still in history")
			}
		}
		if len(s.Why) > 0 {
			fmt.Println(paint("    why: "+strings.Join(s.Why, "; "), dim, color))
		}
		fmt.Println(paint("    fix: "+s.Rotation, dim, color))
		fmt.Println()
	}
}
