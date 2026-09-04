"""Render a scan into a single self-contained HTML page.

No template engine, no CDN, no JavaScript fetches — the page is the report.
Values are masked before they reach this module; nothing here can unmask them.
"""

from __future__ import annotations

import html
import json
from collections import Counter, defaultdict

SEVERITY_ORDER = ["critical", "high", "medium", "low"]

CSS = """
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
details summary { cursor: pointer; color: var(--dim); font-size: 12px; }
.empty { background: var(--panel); border: 1px solid var(--line); border-radius: 10px;
  padding: 40px; text-align: center; color: var(--dim); }
footer { padding: 20px 32px; border-top: 1px solid var(--line); color: var(--dim); font-size: 12px; }
"""


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _card(n: int, label: str, cls: str = "") -> str:
    return f'<div class="card {cls}"><div class="n">{n}</div><div class="l">{_e(label)}</div></div>'


def _occurrences(secret: dict) -> str:
    rows = []
    for occ in secret.get("occurrences", [])[:25]:
        loc = f"{occ.get('path','')}:{occ.get('line','')}:{occ.get('column','')}"
        commit = occ.get("commit") or ""
        suffix = f' <span class="dim">{_e(commit[:8])}</span>' if commit else ""
        rows.append(f'<span class="loc mono">{_e(loc)}{suffix}</span>')
    extra = len(secret.get("occurrences", [])) - 25
    if extra > 0:
        rows.append(f'<span class="dim">… {extra} more</span>')
    return "".join(rows)


def _secrets_table(secrets: list[dict]) -> str:
    if not secrets:
        return '<div class="empty">No secrets found.</div>'
    rows = []
    for s in secrets:
        sev = str(s.get("severity", "")).lower()
        head = s.get("still_in_head")
        if head is True:
            state = '<span class="tag">in HEAD</span>'
        elif head is False:
            state = '<span class="tag gone">history only</span>'
        else:
            state = ""
        who = s.get("introduced_by") or ""
        when = (s.get("first_seen") or "")[:10]
        byline = f'{_e(who)}<br><span class="dim">{_e(when)}</span>' if who else '<span class="dim">—</span>'
        rows.append(
            "<tr>"
            f'<td><span class="pill {sev}">{_e(sev)}</span></td>'
            f'<td>{_e(s.get("secret_type"))}<br><span class="dim mono">{_e(s.get("masked"))}</span></td>'
            f"<td>{_occurrences(s)}</td>"
            f"<td>{byline}</td>"
            f"<td>{state}</td>"
            f'<td class="dim">{_e(s.get("rotation"))}</td>'
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Severity</th><th>Secret</th><th>Where it leaked</th>"
        "<th>Introduced by</th><th>State</th><th>How to fix</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _people_table(secrets: list[dict]) -> str:
    people: dict[str, list[dict]] = defaultdict(list)
    for s in secrets:
        who = s.get("introduced_by")
        if who:
            people[who].append(s)
    if not people:
        return '<div class="empty">No commit authorship available. Run with <code>--history</code>.</div>'
    rows = []
    for who, items in sorted(people.items(), key=lambda kv: -len(kv[1])):
        kinds = ", ".join(sorted({str(i.get("secret_type")) for i in items}))
        email = next((i.get("introduced_email") for i in items if i.get("introduced_email")), "")
        rows.append(
            "<tr>"
            f'<td>{_e(who)}<br><span class="dim mono">{_e(email)}</span></td>'
            f"<td>{len(items)}</td>"
            f'<td class="dim">{_e(kinds)}</td>'
            "</tr>"
        )
    return (
        "<table><thead><tr><th>Author</th><th>Secrets introduced</th><th>Types</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
        '<p class="dim">Introduced by = author of the earliest commit containing that secret. '
        "It is a starting point for a conversation, not proof of fault.</p>"
    )


def _timeline(secrets: list[dict]) -> str:
    dated = [s for s in secrets if s.get("first_seen")]
    if not dated:
        return '<div class="empty">No dates available. Run with <code>--history</code>.</div>'
    dated.sort(key=lambda s: s["first_seen"])
    rows = []
    for s in dated:
        age = s.get("age_days")
        age_txt = f"{age} days ago" if age is not None else ""
        rows.append(
            "<tr>"
            f'<td class="mono">{_e(s["first_seen"][:10])}</td>'
            f'<td>{_e(s.get("secret_type"))} <span class="dim mono">{_e(s.get("masked"))}</span></td>'
            f'<td class="dim">{_e(age_txt)}</td>'
            f'<td class="mono dim">{_e(str(s.get("introduced_commit") or "")[:8])}</td>'
            "</tr>"
        )
    return (
        "<table><thead><tr><th>First seen</th><th>Secret</th><th>Age</th><th>Commit</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _files_table(secrets: list[dict]) -> str:
    counter: Counter[str] = Counter()
    for s in secrets:
        for occ in s.get("occurrences", []):
            counter[occ.get("path", "")] += 1
    if not counter:
        return '<div class="empty">No files affected.</div>'
    rows = "".join(
        f'<tr><td class="mono">{_e(path)}</td><td>{n}</td></tr>'
        for path, n in counter.most_common(40)
    )
    return f"<table><thead><tr><th>File</th><th>Occurrences</th></tr></thead><tbody>{rows}</tbody></table>"


def render(payload: dict) -> str:
    secrets = payload.get("secrets", [])
    counts = payload.get("counts", {})
    repo = payload.get("repository", "")
    generated = payload.get("generated_at", "")[:19].replace("T", " ")

    cards = "".join(
        [
            _card(payload.get("secret_count", 0), "unique secrets"),
            _card(payload.get("occurrence_count", 0), "occurrences"),
            _card(counts.get("critical", 0), "critical", "crit"),
            _card(counts.get("high", 0), "high", "high"),
            _card(counts.get("medium", 0), "medium", "med"),
            _card(counts.get("low", 0), "low", "low"),
            _card(payload.get("files_scanned", 0), "files scanned"),
            _card(payload.get("commits_scanned", 0), "commits scanned"),
        ]
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecSentry — {_e(repo)}</title><style>{CSS}</style></head>
<body>
<header>
  <h1>SecSentry</h1>
  <div class="sub mono">{_e(repo)}</div>
  <div class="sub">Scanned {_e(generated)} UTC · secrets are masked · no vendor APIs were contacted</div>
</header>
<main>
  <h2>Overview</h2>
  <div class="cards">{cards}</div>

  <h2>Secrets</h2>
  {_secrets_table(secrets)}

  <h2>People</h2>
  {_people_table(secrets)}

  <h2>Timeline</h2>
  {_timeline(secrets)}

  <h2>Files</h2>
  {_files_table(secrets)}
</main>
<footer>{_e(payload.get("note", ""))} · secsentry v{_e(payload.get("version", ""))}</footer>
</body></html>
"""


def render_json(payload: dict) -> str:
    return json.dumps(payload, indent=2)
