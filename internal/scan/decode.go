package scan

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

const maxDecodeDepth = 3
const maxDecoded = 64000

var (
	reB64    = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)
	reB64URL = regexp.MustCompile(`[A-Za-z0-9_-]{20,}={0,2}`)
	reHex    = regexp.MustCompile(`(?:0x)?([0-9A-Fa-f]{32,})`)
	rePct    = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){8,}`)
)

type decodedChunk struct {
	Text      string
	Encodings []string
	Line, Col int
}

func printable(raw []byte) string {
	if len(raw) == 0 || len(raw) > maxDecoded || bytesContainNUL(raw) {
		return ""
	}
	if !utf8.Valid(raw) {
		return ""
	}
	s := string(raw)
	ctrl := 0
	for _, r := range s {
		if r < 32 && r != '\n' && r != '\t' && r != '\r' {
			ctrl++
		}
	}
	if float64(ctrl)/float64(len(s)+1) > 0.05 {
		return ""
	}
	return s
}

func bytesContainNUL(b []byte) bool {
	n := len(b)
	if n > 4096 {
		n = 4096
	}
	for _, c := range b[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}

func tryB64(token string) string {
	pad := strings.Repeat("=", (4-len(token)%4)%4)
	blob := token + pad
	if raw, err := base64.StdEncoding.DecodeString(blob); err == nil {
		if t := printable(raw); t != "" && t != token {
			return t
		}
	}
	if raw, err := base64.URLEncoding.DecodeString(blob); err == nil {
		if t := printable(raw); t != "" && t != token {
			return t
		}
	}
	return ""
}

func tryHex(token string) string {
	body := token
	if strings.HasPrefix(strings.ToLower(body), "0x") {
		body = body[2:]
	}
	if len(body)%2 == 1 {
		return ""
	}
	raw, err := hex.DecodeString(body)
	if err != nil {
		return ""
	}
	return printable(raw)
}

func tryPct(token string) string {
	raw, err := url.QueryUnescape(token)
	if err != nil {
		return ""
	}
	return printable([]byte(raw))
}

func iterDecoded(text string) []decodedChunk {
	type item struct {
		payload string
		chain   []string
		line    int
		col     int
	}
	var queue []item
	seenTok := map[string]bool{}
	enqueue := func(tok, kind string, line, col int, decode func(string) string) {
		if seenTok[tok] {
			return
		}
		if d := decode(tok); d != "" {
			seenTok[tok] = true
			queue = append(queue, item{d, []string{kind}, line, col})
		}
	}
	for i, line := range strings.Split(text, "\n") {
		for _, m := range reB64.FindAllStringIndex(line, -1) {
			enqueue(line[m[0]:m[1]], "base64", i+1, utf8.RuneCountInString(line[:m[0]])+1, tryB64)
		}
		for _, m := range reB64URL.FindAllStringIndex(line, -1) {
			enqueue(line[m[0]:m[1]], "base64", i+1, utf8.RuneCountInString(line[:m[0]])+1, tryB64)
		}
		for _, m := range reHex.FindAllStringSubmatchIndex(line, -1) {
			if len(m) < 4 {
				continue
			}
			enqueue(line[m[2]:m[3]], "hex", i+1, utf8.RuneCountInString(line[:m[2]])+1, tryHex)
		}
		for _, m := range rePct.FindAllStringIndex(line, -1) {
			enqueue(line[m[0]:m[1]], "percent", i+1, utf8.RuneCountInString(line[:m[0]])+1, tryPct)
		}
	}
	seen := map[string]bool{}
	var out []decodedChunk
	for len(queue) > 0 {
		it := queue[0]
		queue = queue[1:]
		if seen[it.payload] || len(it.chain) > maxDecodeDepth {
			continue
		}
		seen[it.payload] = true
		out = append(out, decodedChunk{it.payload, it.chain, it.line, it.col})
		if len(it.chain) >= maxDecodeDepth {
			continue
		}
		for _, m := range reB64.FindAllString(it.payload, -1) {
			if d := tryB64(m); d != "" && !seen[d] {
				queue = append(queue, item{d, append(append([]string{}, it.chain...), "base64"), it.line, it.col})
			}
		}
	}
	return out
}

// DecodedTexts returns printable layers unwrapped from base64/hex/percent encodings.
func DecodedTexts(text string) []string {
	chunks := iterDecoded(text)
	out := make([]string, 0, len(chunks))
	for _, c := range chunks {
		out = append(out, c.Text)
	}
	return out
}
