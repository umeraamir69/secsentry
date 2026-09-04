package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type Finding struct {
	SecretType   string   `json:"secret_type"`
	Severity     string   `json:"severity"`
	Confidence   float64  `json:"confidence"`
	Path         string   `json:"path"`
	Line         int      `json:"line"`
	Column       int      `json:"column"`
	Masked       string   `json:"masked"`
	Fingerprint  string   `json:"fingerprint"`
	BlobOID      string   `json:"blob_oid,omitempty"`
	Commit       string   `json:"commit,omitempty"`
	Author       string   `json:"author,omitempty"`
	AuthorEmail  string   `json:"author_email,omitempty"`
	Timestamp    string   `json:"timestamp,omitempty"`
	StillInHead  *bool    `json:"still_in_head,omitempty"`
	StructuralOK *bool    `json:"structural_ok,omitempty"`
	Entropy      float64  `json:"entropy"`
	Why          []string `json:"why"`
	Source       string   `json:"source"`
	Rotation     string   `json:"rotation,omitempty"`
}

func Fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func Mask(secret string) string {
	n := len(secret)
	if n <= 8 {
		return strings.Repeat("•", n)
	}
	dots := n - 8
	if dots > 12 {
		dots = 12
	}
	return secret[:4] + strings.Repeat("•", dots) + secret[n-4:]
}

func Rank(severity string) int {
	switch strings.ToLower(severity) {
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	default:
		return 0
	}
}
