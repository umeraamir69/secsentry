---
tags:
  - backup
  - cursor
---

# Cursor chat backup

Full agent transcripts for this workspace, copied from Cursor’s local project folder so a new machine / new clone still has the conversation history.

**This does not restore the Cursor Chat sidebar.** Chat UI lives in your Cursor account. These files are the backup an agent can *read*.

On a new device:

1. Sign into the same Cursor account (sidebar chats may sync).
2. Clone this repo.
3. Open the folder in Cursor. The rule in `.cursor/rules/prior-chats.mdc` tells the agent to use `notes/chats/CONTEXT.md` and the transcripts below.

## Files

| Path | What |
|---|---|
| `CONTEXT.md` | Distilled product memory — start here |
| `INDEX.md` | Chat ids and first/last turns |
| `agent-transcripts/*.jsonl` | Raw Cursor agent logs (fake detector keys redacted so GitHub push protection allows the backup) |

Refresh this backup by copying again from:

`~/.cursor/projects/Users-<you>-Documents-secsentry/agent-transcripts/`
