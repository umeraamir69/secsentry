package classify

import "unicode"

// Local BPE-style rarity. English merges collapse common pairs; a password
// or API key stays as many short tokens. tokens/runes is high for secrets
// and low for "password" / "example". No network, no vendor model.
var merges = []string{
	"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
	"ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
	"st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
	"ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
	"ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
	"the", "ing", "and", "ion", "ent", "her", "for", "tha", "ter",
	"res", "con", "all", "ers", "ate", "ver", "pro", "ted", "ess",
	"key", "api", "tok", "sec", "pass", "word", "user", "name",
	"example", "placeholder", "changeme", "password", "secret",
}

func Rarity(s string) float64 {
	if s == "" {
		return 0
	}
	runes := []rune(s)
	n := float64(len(runes))
	low := make([]rune, len(runes))
	for i, r := range runes {
		low[i] = unicode.ToLower(r)
	}
	text := string(low)
	tokens := 0
	i := 0
	for i < len(text) {
		matched := 1
		for _, m := range merges {
			if len(m) > matched && i+len(m) <= len(text) && text[i:i+len(m)] == m {
				matched = len(m)
			}
		}
		tokens++
		i += matched
	}
	return float64(tokens) / n
}
