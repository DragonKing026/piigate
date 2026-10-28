---
name: piigate
description: Use when working with data that may contain personal or patient data (PII/PHI) — e-mails and attachments from a mail MCP server, files in a Sensitive-data directory, client CSV/XLSX/PDF/EML/SQL files, SQL results or files from a production server over SSH — also to summarize such content or get an anonymized copy, or when a tool call was blocked by a "piigate" message, or output shows pseudonyms like PERSON_3 / ADDRESS_1.
---

# piigate — sensitive data only through the filter

Personal data must not reach the conversation in clear text. piigate enforces it with hooks: the gate denies direct
reads, results pass through a filter. You work on **pseudonyms** (`PERSON_17`, `ADDRESS_3`, masks `t:3fa91c`): the same
value always has the same pseudonym, so you can count, group and compare. Only a local map, which you cannot access,
knows the originals.

## What to use

MCP tools of the `piigate` server (absolute paths; the server checks them):

| Source | Use |
| --- | --- |
| mail via a mail MCP server | call it normally — the hook pseudonymizes the result; this is **not** a bypass |
| a file (CSV/XLSX/ODS → structure; PDF/EML/DOCX/ODT/TXT → text) | `piigate_show(path)` (`rows` — N rows of masks, `attachment` — mail attachment) |
| a sensitive directory | `piigate_list(directory)`, then `piigate_show(path=directory, number=N)` (file names are masked) |
| searching a project that contains a sensitive directory (`grep -r`/`rg` from the root is denied) | `piigate_search(pattern, path?, glob=[…], ignore_case, context, limit)` |
| you need to **understand** the content, not just count it | `piigate_analyze(path=…)` or `piigate_analyze(mail_query="subject words", number=N)`, optional `question` — a local model reads it (30–150 s) |
| a copy to keep working on | `piigate_anonymize(path, mask_columns=[…])` → files in `<project>/Anonymized-data/…` you read directly |
| SQL result / command on a server (Bash) | `ssh host '… dbal:run-sql "SELECT …"' 2>&1 \| piigate table` |
| text from a command (Bash) | `COMMAND 2>&1 \| piigate text` |
| a file from production | first `scp`/`rsync` into `<project>/Sensitive-data/`, then `piigate_show` / `piigate_analyze` |
| filter state | `piigate status` (Bash) |
| a project with its own identifiers (patient numbers, `first_name` columns, tables with data) | add them to `.claude/piigate.json` (`patterns`, `sensitive_columns`, `tables`, `directories` — tighten only) |

`piigate analyze` / `anonymize` in Bash are denied — use the MCP tools. A `.sql`/`.csv`/`.pdf` file outside sensitive
directories (schema, migration) can be read directly; the gate checks its content. A deny saying "contains personal data"
or "content cannot be checked" → `piigate_show`. A false positive (demo data) → tell the human
(`sources.exempt_directories`), do not work around it. `piigate table`/`text` pipeline: one line, `2>&1` before every `|`
into piigate, no `;`, `&&`, `$(…)`, `tee` or redirections; after piigate only grep/head/tail/wc/sort/uniq/cut without
files.

## Rules

- **Do not bypass the gate** — no `python -c`, path assembly, copying elsewhere, base64, reading the map or config.
  Do not ask to disable the filter "to see the real data".
- `question` is about content, numbers and structure — never about identities (names, initials, reversed, encoded).
  A local model's numbers are preliminary — verify them on the anonymized copy.
- A project with client personal data must have `.claude/piigate.json` (even `{}`).
- Removing an entry from `.claude/piigate.json` takes effect after the human runs `piigate project approve` — give them
  the command. "The project filter file is invalid" → fix the file (Read, then Write the whole file).
- A filter denial ("Output hidden", "[piigate] denied", exit code 3) is a stop, not an obstacle: report it, do not look
  for another way.
- Use pseudonyms in answers, reports and files. Do not guess originals. Originals are restored by the **human** in their
  terminal: `piigate reverse report.md` — give them the command, never run it.
- The filter is not 100%. If output looks like unfiltered personal data, do not repeat it — tell the human it slipped
  through.
