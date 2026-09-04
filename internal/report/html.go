package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

const css = `
:root {
  --bg: #0f1115; --panel: #171a21; --line: #262b36; --text: #e6e9ef;
  --dim: #8b93a7; --crit: #ff6b6b; --high: #ffa94d; --med: #4dabf7; --low: #6c7383;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.55 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color: inherit; }
header { padding: 28px 32px 20px; border-bottom: 1px solid var(--line); }
h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -.01em; }
.sub { color: var(--dim); font-size: 13px; }
main { padding: 24px 32px 64px; max-width: 1100px; }
h2 { font-size: 15px; margin: 34px 0 12px; letter-spacing: .02em;
  text-transform: uppercase; color: var(--dim); }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; }
.card .n { font-size: 26px; font-weight: 600; }
.card .l { color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
.crit .n { color: var(--crit); } .high .n { color: var(--high); }
.med .n { color: var(--med); } .low .n { color: var(--low); }
table { width: 100%; border-collapse: collapse; background: var(--panel);
  border: 1px solid var(--line); border-radius: 10px; overflow: hidden; }
th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--line);
  vertical-align: top; font-size: 13px; }
th { color: var(--dim); font-weight: 500; text-transform: uppercase;
  font-size: 11px; letter-spacing: .05em; }
tr:last-child td { border-bottom: none; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: .04em; }
.pill.critical { background: rgba(255,107,107,.15); color: var(--crit); }
.pill.high { background: rgba(255,169,77,.15); color: var(--high); }
.pill.medium { background: rgba(77,171,247,.15); color: var(--med); }
.pill.low { background: rgba(108,115,131,.2); color: var(--low); }
.tag { display: inline-block; padding: 1px 7px; border-radius: 5px;
  border: 1px solid var(--line); color: var(--dim); font-size: 11px; }
.tag.gone { color: var(--high); border-color: rgba(255,169,77,.4); }
.dim { color: var(--dim); }
.loc { display: block; }
.empty { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 40px; text-align: center; color: var(--dim); }
footer { padding: 20px 32px; border-top: 1px solid var(--line); color: var(--dim); font-size: 12px; }
`

func e(v any) string { return html.EscapeString(fmt.Sprint(v)) }

func card(n int, label, cls string) string {
	return fmt.Sprintf(`<div class="card %s"><div class="n">%d</div><div class="l">%s</div></div>`, cls, n, e(label))
}

func asInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return 0
	}
}

type occLoc struct {
	Path   string `json:"path"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
	Commit string `json:"commit"`
}

func renderOccs(s secretJSON) string {
	list := extractOccs(s.Occurrences)
	var b strings.Builder
	limit := len(list)
	if limit > 25 {
		limit = 25
	}
	for _, o := range list[:limit] {
		loc := fmt.Sprintf("%s:%d:%d", o.Path, o.Line, o.Column)
		suffix := ""
		if o.Commit != "" {
			c := o.Commit
			if len(c) > 8 {
				c = c[:8]
			}
			suffix = ` <span class="dim">` + e(c) + `</span>`
		}
		b.WriteString(`<span class="loc mono">` + e(loc) + suffix + `</span>`)
	}
	if extra := len(list) - 25; extra > 0 {
		b.WriteString(fmt.Sprintf(`<span class="dim">… %d more</span>`, extra))
	}
	return b.String()
}

func extractOccs(v any) []occLoc {
	var out []occLoc
	if items, ok := v.([]occLoc); ok {
		return items
	}
	raw, err := jsonBytes(v)
	if err != nil {
		return out
	}
	var generic []map[string]any
	if err := unmarshalJSON(raw, &generic); err != nil {
		return out
	}
	for _, m := range generic {
		out = append(out, occLoc{
			Path:   fmt.Sprint(m["path"]),
			Line:   asInt(m["line"]),
			Column: asInt(m["column"]),
			Commit: str(m["commit"]),
		})
	}
	return out
}

func str(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprint(v)
	if s == "<nil>" {
		return ""
	}
	return s
}

func secretsTable(secrets []secretJSON) string {
	if len(secrets) == 0 {
		return `<div class="empty">No secrets found.</div>`
	}
	var rows strings.Builder
	for _, s := range secrets {
		sev := strings.ToLower(s.Severity)
		state := ""
		if s.StillInHead != nil && *s.StillInHead {
			state = `<span class="tag">in HEAD</span>`
		} else if s.StillInHead != nil && !*s.StillInHead {
			state = `<span class="tag gone">history only</span>`
		}
		byline := `<span class="dim">—</span>`
		if s.IntroducedBy != "" {
			when := s.FirstSeen
			if len(when) > 10 {
				when = when[:10]
			}
			byline = e(s.IntroducedBy) + `<br><span class="dim">` + e(when) + `</span>`
		}
		rows.WriteString("<tr>")
		rows.WriteString(`<td><span class="pill ` + sev + `">` + e(sev) + `</span></td>`)
		rows.WriteString(`<td>` + e(s.SecretType) + `<br><span class="dim mono">` + e(s.Masked) + `</span></td>`)
		rows.WriteString(`<td>` + renderOccs(s) + `</td>`)
		rows.WriteString(`<td>` + byline + `</td>`)
		rows.WriteString(`<td>` + state + `</td>`)
		rows.WriteString(`<td class="dim">` + e(s.Rotation) + `</td>`)
		rows.WriteString("</tr>")
	}
	return `<table><thead><tr><th>Severity</th><th>Secret</th><th>Where it leaked</th>` +
		`<th>Introduced by</th><th>State</th><th>How to fix</th></tr></thead>` +
		`<tbody>` + rows.String() + `</tbody></table>`
}

func peopleTable(secrets []secretJSON) string {
	people := map[string][]secretJSON{}
	for _, s := range secrets {
		if s.IntroducedBy != "" {
			people[s.IntroducedBy] = append(people[s.IntroducedBy], s)
		}
	}
	if len(people) == 0 {
		return `<div class="empty">No commit authorship available. Run with <code>--history</code>.</div>`
	}
	type row struct {
		who   string
		items []secretJSON
	}
	var rows []row
	for who, items := range people {
		rows = append(rows, row{who, items})
	}
	sort.Slice(rows, func(i, j int) bool { return len(rows[i].items) > len(rows[j].items) })
	var b strings.Builder
	for _, r := range rows {
		kinds := map[string]struct{}{}
		email := ""
		for _, i := range r.items {
			kinds[i.SecretType] = struct{}{}
			if email == "" && i.IntroducedEmail != "" {
				email = i.IntroducedEmail
			}
		}
		var kindList []string
		for k := range kinds {
			kindList = append(kindList, k)
		}
		sort.Strings(kindList)
		b.WriteString("<tr>")
		b.WriteString(`<td>` + e(r.who) + `<br><span class="dim mono">` + e(email) + `</span></td>`)
		b.WriteString(fmt.Sprintf(`<td>%d</td>`, len(r.items)))
		b.WriteString(`<td class="dim">` + e(strings.Join(kindList, ", ")) + `</td>`)
		b.WriteString("</tr>")
	}
	return `<table><thead><tr><th>Author</th><th>Secrets introduced</th><th>Types</th></tr></thead>` +
		`<tbody>` + b.String() + `</tbody></table>` +
		`<p class="dim">Introduced by = author of the earliest commit containing that secret. ` +
		`It is a starting point for a conversation, not proof of fault.</p>`
}

func timelineTable(secrets []secretJSON) string {
	var dated []secretJSON
	for _, s := range secrets {
		if s.FirstSeen != "" {
			dated = append(dated, s)
		}
	}
	if len(dated) == 0 {
		return `<div class="empty">No dates available. Run with <code>--history</code>.</div>`
	}
	sort.Slice(dated, func(i, j int) bool { return dated[i].FirstSeen < dated[j].FirstSeen })
	var b strings.Builder
	for _, s := range dated {
		age := ""
		if s.AgeDays != nil {
			age = fmt.Sprintf("%d days ago", *s.AgeDays)
		}
		when := s.FirstSeen
		if len(when) > 10 {
			when = when[:10]
		}
		c := s.IntroducedCommit
		if len(c) > 8 {
			c = c[:8]
		}
		b.WriteString("<tr>")
		b.WriteString(`<td class="mono">` + e(when) + `</td>`)
		b.WriteString(`<td>` + e(s.SecretType) + ` <span class="dim mono">` + e(s.Masked) + `</span></td>`)
		b.WriteString(`<td class="dim">` + e(age) + `</td>`)
		b.WriteString(`<td class="mono dim">` + e(c) + `</td>`)
		b.WriteString("</tr>")
	}
	return `<table><thead><tr><th>First seen</th><th>Secret</th><th>Age</th><th>Commit</th></tr></thead>` +
		`<tbody>` + b.String() + `</tbody></table>`
}

func filesTable(secrets []secretJSON) string {
	counter := map[string]int{}
	for _, s := range secrets {
		for _, p := range extractOccs(s.Occurrences) {
			counter[p.Path]++
		}
	}
	if len(counter) == 0 {
		return `<div class="empty">No files affected.</div>`
	}
	type kv struct {
		path string
		n    int
	}
	var list []kv
	for p, n := range counter {
		list = append(list, kv{p, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].path < list[j].path
	})
	if len(list) > 40 {
		list = list[:40]
	}
	var b strings.Builder
	for _, x := range list {
		b.WriteString(`<tr><td class="mono">` + e(x.path) + `</td><td>` + fmt.Sprint(x.n) + `</td></tr>`)
	}
	return `<table><thead><tr><th>File</th><th>Occurrences</th></tr></thead><tbody>` + b.String() + `</tbody></table>`
}

func Render(p Payload) string {
	counts := p.Counts
	if counts == nil {
		counts = map[string]int{}
	}
	generated := p.GeneratedAt
	if len(generated) > 19 {
		generated = strings.Replace(generated[:19], "T", " ", 1)
	}
	cards := card(p.SecretCount, "unique secrets", "") +
		card(p.OccurrenceCount, "occurrences", "") +
		card(counts["critical"], "critical", "crit") +
		card(counts["high"], "high", "high") +
		card(counts["medium"], "medium", "med") +
		card(counts["low"], "low", "low") +
		card(p.FilesScanned, "files scanned", "") +
		card(p.CommitsScanned, "commits scanned", "")

	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecSentry — ` + e(p.Repository) + `</title><style>` + css + `</style></head>
<body>
<header>
  <h1>SecSentry</h1>
  <div class="sub mono">` + e(p.Repository) + `</div>
  <div class="sub">Scanned ` + e(generated) + ` UTC · secrets are masked · no vendor APIs were contacted</div>
</header>
<main>
  <h2>Overview</h2>
  <div class="cards">` + cards + `</div>
  <h2>Secrets</h2>
  ` + secretsTable(p.Secrets) + `
  <h2>People</h2>
  ` + peopleTable(p.Secrets) + `
  <h2>Timeline</h2>
  ` + timelineTable(p.Secrets) + `
  <h2>Files</h2>
  ` + filesTable(p.Secrets) + `
</main>
<footer>` + e(p.Note) + ` · secsentry v` + e(p.Version) + `</footer>
</body></html>
`
}
