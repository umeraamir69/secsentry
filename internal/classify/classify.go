package classify

import (
	"fmt"
	"strings"

	"github.com/umeraamir69/secsentry/internal/detect"
)

type Decision struct {
	Keep       bool
	Confidence float64
	Why        []string
}

func Classify(path, secretType, secret string, structural bool) Decision {
	why := []string{"rule=" + secretType}
	conf := 0.55
	low := strings.ToLower(strings.ReplaceAll(path, "\\", "/"))

	if structural {
		conf += 0.2
		why = append(why, "structural_ok")
	}
	ent := detect.Shannon(secret)
	why = append(why, fmt.Sprintf("entropy=%.2f", ent))
	if ent >= 3.5 {
		conf += 0.1
	}

	rar := Rarity(secret)
	why = append(why, fmt.Sprintf("bpe_rarity=%.2f", rar))
	if rar >= 0.55 {
		conf += 0.08
	} else if rar < 0.35 && (secretType == "generic_api_key" || secretType == "generic_password") {
		conf -= 0.25
		why = append(why, "english_like")
	}

	for _, lock := range []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"} {
		if strings.HasSuffix(low, lock) || strings.Contains(low, lock) {
			return Decision{false, 0.1, append(why, "lockfile")}
		}
	}
	if secretType == "generic_api_key" || secretType == "generic_password" {
		for _, p := range []string{".md", "docs/", "test/", "tests/", "example"} {
			if strings.Contains(low, p) {
				conf -= 0.25
				why = append(why, "docs_or_tests")
				break
			}
		}
	}
	keep := conf >= 0.5
	if (secretType == "private_key" || secretType == "aws_access_key" || secretType == "gcp_service_account") && structural {
		keep = true
		if conf < 0.9 {
			conf = 0.9
		}
	}
	if conf > 0.99 {
		conf = 0.99
	}
	return Decision{keep, conf, why}
}
