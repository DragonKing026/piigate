# piigate

**Keeps personal data (PII/PHI) out of Claude's context.** piigate is a [Claude Code](https://claude.com/claude-code)
plugin: a gate on tool calls, a filter on tool output, stable pseudonyms instead of names, and MCP tools that let the agent
work with sensitive files without ever seeing the originals. Built for Polish and English data.

> **This is not a guarantee.** piigate lowers the risk, it does not remove it — see [Limitations](#limitations). When data
> is truly sensitive, the safest option is not to open it in an agent session at all.

```text
                 PreToolUse (gate)                                PostToolUse (filter)
Read/Grep/Glob ──► sensitive path? ── yes ──► deny + "use piigate_show …"
               ──► data extension (.csv, .pdf, .sql…)? ──► content by rules: clean → allow; personal data / unreadable → deny
Bash           ──► sensitive dir / `ssh … mysql`? ──► only `… 2>&1 | piigate table|text`, or cp into a sensitive dir
Edit/Write     ──► piigate's own files (map, key, config)? ──► deny
mail MCP        ─────────────────────────────────────────────────► every text block → pseudonyms
Bash/Read/Grep  ─────────────────────────────────────────────────► sensors: PESEL, bank account, card (checksums)

MCP tools piigate_show / list / search / analyze / anonymize, and `piigate` in Bash:
  tables (CSV, XLSX, ODS, SQL output) → structure only: columns, types, counts, lengths; values → HMAC masks (t:3fa91c)
  free text (mail, PDF, DOCX, ODT, TXT) → Polish rules + Presidio NER (pl + en) [+ Ollama] → PERSON_17, ADDRESS_3
```

## What it does

- **Gate** (PreToolUse) — denies direct reads of configured sensitive sources: directories, command patterns (`ssh …
  dbal:run-sql`, `ssh … psql`) and files with a data extension **whose content contains personal data**. The deny reason
  tells the model which piigate tool to use instead.
- **PHI places only** — file content is checked only in projects that opt in (`.claude/piigate.json`, even `{}`), outside
  git repositories and in fresh or non-public repos. Ordinary repositories are not slowed down. Sensitive directories, mail,
  SQL over SSH, piigate's own files and the sensors are always on.
- **Output filter** (PostToolUse) — mail MCP results go through the text filter; Read/Bash results that mention a data
  file are re-checked; every Bash/Read/Grep result goes through the sensors (PESEL, IBAN/NRB, card numbers with checksums).
- **Tables vs text** — tables are never "detected": only their structure and deterministic masks are shown, so the agent
  can count, join and group without seeing values. Free text is pseudonymized: Polish rules (PESEL, NIP, REGON, KRS,
  phones, postcodes, streets, dates, prescriptions, ID documents, accounts, cards, IPs, drugs with a dose, first names
  with inflection, surnames by suffix and title) + Presidio NER + optionally a local Ollama model as a second pass.
- **Stable pseudonyms** — the same value always gets the same pseudonym (`PERSON_17`), also across sessions and
  inflected forms of a surname. The map lives in `~/.local/share/piigate/` (0600, HMAC key); only a human can reverse it.
- **Deny by default** — any error (engine down, timeout, bad config, exception, Python not starting) ends in "Output
  hidden", never in the original.

## Install

Requirements: Claude Code, [uv](https://docs.astral.sh/uv/), Python 3.11–3.14, Linux (macOS untested). For
`piigate reverse` and `piigate project approve`: sudo with a password and [rootwhy](https://github.com/DragonKing026/rootwhy)
in `PATH` (password dialog).

```bash
claude plugin marketplace add DragonKing026/piigate
claude plugin install piigate@piigate --scope user
```

The first session that needs NER downloads the spaCy models (~1 GB, once) — see [Model license](#model-license).
`piigate status` shows the engine, configuration and pseudonym count.

## Engines

| Mode | What runs | When |
| --- | --- | --- |
| `local` (default) | Presidio Analyzer + spaCy models inside the piigate MCP server process; hooks and `piigate` ask it over a unix socket (0600, same user only) | no Docker needed |
| `container` | Presidio Analyzer in a container you build from [`docker/Dockerfile`](docker/Dockerfile), reachable on a loopback address | process isolation, no network for the engine |

Local mode keeps the models in memory for the whole session. Without a running MCP server (no Claude Code session)
`piigate text` refuses instead of guessing; the gate needs no engine (rules only).

**Container engine.** The image is not published — you build it yourself:

```bash
docker build -t piigate-presidio:2.2.366 docker/
docker run -d --name piigate-presidio -p 127.0.0.1:8719:3000 piigate-presidio:2.2.366
```

and set `"engine": {"mode": "container", "container_url": "http://127.0.0.1:8719"}` in `~/.config/piigate/config.json`.
The final stage is the `-distroless` Presidio image (no shell, no pip); both base images are pinned by digest and the
model is checked by sha256. For network isolation, put the container on an internal Docker network behind a loopback-only
proxy. piigate refuses engine addresses outside loopback.

## Model license

The Polish NER model [`pl_core_news_lg`](https://github.com/explosion/spacy-models) is licensed **GPL-3.0** (trained on
UD Polish PDB and NKJP); `en_core_web_lg` is MIT. piigate itself is MIT and **does not include or redistribute either
model**: local mode downloads them from explosion/spacy-models on first use and checks their sha256, and the container
image is built on your machine. By using the engine you download a GPL-3.0 component; if you redistribute an image or
directory that contains it, GPL-3.0 applies to that distribution.

## Using it

The agent uses the MCP tools (paths are checked by the server after `realpath`: only sensitive directories or files with a
data extension, never piigate's own files):

| MCP tool | Parameters | What comes back |
| --- | --- | --- |
| `piigate_show` | `path`, `number`, `rows`, `attachment` | table structure + masks, or text with pseudonyms |
| `piigate_list` | `directory` | files with filtered names and numbers |
| `piigate_search` | `pattern`, `path`, `glob`, `ignore_case`, `context`, `limit` | code plainly; free text with data pseudonymized (the hit is always masked); tables: file, column, rows, count |
| `piigate_analyze` | `path` or `mail_query`, `number`, `question`, `output_dir` | a local model reads the original: categories of personal data, summary and answer without them, anonymized copies |
| `piigate_anonymize` | `path`, `number`, `mask_columns`, `output_dir` | anonymized CSV/TXT copies the agent can read directly |

In Bash (pipelines from servers):

```bash
ssh prod 'bin/console dbal:run-sql "SELECT …"' 2>&1 | piigate table   # structure + safe values (ids, codes, statuses)
some-command 2>&1 | piigate text [--source mail]                       # text with pseudonyms
piigate status                                                         # engine, config, decision log (no content)
piigate reverse report.md                                              # HUMAN only: pseudonyms → originals (password)
```

After `piigate` in a pipeline only `grep`, `head`, `tail`, `wc`, `sort`, `uniq`, `cut` are allowed (on stdin, no files).

**Data directories.** Inside a project: `<project>/Sensitive-data/` (files copied from servers; always protected) and
`<project>/Anonymized-data/` (copies after the filter; readable), both with a `.gitignore` of `*` that piigate restores.
Outside a project: `{documents}/piigate/Sensitive-data` and `{documents}/piigate/Anonymized-data`, where `{documents}` is
your XDG documents directory. They are created only when something is written.

## Configuration

Defaults: [config.json](config.json). Yours (merged; lists replace): `~/.config/piigate/config.json` — edited by a human
(the gate denies the agent). Main fields:

| Field | Meaning |
| --- | --- |
| `sources.directories` | sensitive directories (every file inside) |
| `sources.extensions` | extensions whose content the gate checks |
| `sources.exempt_directories` | directories where an extension does not trigger a check (false positives) |
| `sources.only_phi_projects` | `true`: content checked only in PHI projects and outside git repos |
| `sources.commands` | regexes of Bash commands that return production data |
| `engine.*` | `mode` (`local`/`container`), `languages`, `container_url`, `threshold`, `timeout_s` |
| `text.dates`, `text.drugs`, `text.organizations`, `text.plain_words`, `text.labels` | text filter options |
| `ollama.*` | optional second pass by a local model (`enabled`, `url` — loopback only, `model`, `sources`) |
| `analysis.agent_command` | command for `piigate_analyze` (argv; see below) |
| `unfiltered_tools` | tools whose output bypasses the filter (e.g. a local LLM subagent): denied on sensitive directories |
| `sensors.*` | PESEL / account / card masking in every result |

Example of a personal config (never commit it): [examples/user-config.json](examples/user-config.json).

**Project filters** — a project describes its own data in `.claude/piigate.json` (committed; example:
[examples/project.json](examples/project.json)): `patterns` (regex + label, e.g. patient ids), `sensitive_columns`,
`directories`, `tables` (SQL over SSH touching them must go through `piigate table`), `extensions`. The file can only
**tighten** protection. Removing an entry takes effect after a human runs `piigate project approve` (password). An invalid
file (bad JSON, loosening field, costly regex) makes the gate deny everything in the project except fixing that file.

**Analysis agent contract** (`analysis.agent_command`): piigate runs `<command> --schema PATH --dir WORKDIR --timeout S`,
writes the task to stdin (instructions, `User's question: …`, files as `=== FILE: name === … === END OF FILE ===`) and
expects one JSON object on stdout: `sensitive_data[{category, where, count}]`, `columns_to_mask[{file, column}]`,
`fragments_to_mask[{text, type}]`, `summary`, `answer`. The agent must be local (it reads originals). Its answer still goes
through the full text filter.

## Limitations

- **Not 100%.** NER and rules miss nicknames, surnames in lower case without a known first name, unusual formats, data in
  images and scans (PDFs without a text layer are refused — there is no OCR). Tables are safer than text.
- **The content verdict is rules, not NER.** A data file with only unknown surnames without suffixes, e-mails or numbers
  passes as clean. Keep client files in a sensitive directory (always denied).
- **The gate can be bypassed on purpose.** It analyses the command text: code that assembles a path at run time
  (`python -c` with string concatenation, base64, a script written earlier) gets through; only the sensors see the
  output then. Globs without a dot (`cat p*`, `cat *sv`) are not recognised as data-file patterns either. The gate is a
  seat belt against mistakes and shortcuts, not a sandbox.
- **The engine is trusted by address.** piigate protects the socket directory and refuses non-loopback engines, but a
  process of the same user that answers on the engine socket or port first can make NER report nothing (the rules
  still run). On first use the local engine downloads its models (~1 GB); until that finishes, text filtering refuses.
- **`reverse` protects against mistakes, not a determined agent** with a shell of the same user (it could read the map
  with code). Closing that needs a separate account or a map encrypted with a secret only the human knows.
- **Other paths to the model are out of scope:** images, other MCP servers, WebFetch, text pasted by the human, results of
  background tasks read by other tools.
- **Local traces:** the session transcript (`~/.claude/projects/…`) and telemetry may store the original tool output
  before the hook replaces it — on your disk, not in the conversation.
- Files stay on disk (attachments, copies, the pseudonym map). piigate protects the conversation, not the disk.

## Testing

Only on **synthetic** data ([tests/fixtures.py](tests/fixtures.py) — invented people, PESELs with valid checksums,
`.test` e-mails, made-up streets and towns). Never on real personal data.

```bash
tests/run.sh                                   # unit + hook + gate tests, MCP server tests (uv)
python3 -I tests/test_engine.py                # unix socket, engine modes, model checksum
PIIGATE_TEST_LOCAL_ENGINE=1 python3 -I tests/test_engine.py   # + real local engine (downloads models once)
PIIGATE_TEST_DB=1 tests/run.sh                 # + throwaway postgres container → psql | piigate table
tests/e2e_claude.sh                            # claude -p with the plugin and a fake mail MCP (costs tokens)
```

Found a way past the gate? Please report it privately — [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE). Models: see [Model license](#model-license). Presidio is maintained by
[Data Privacy Stack](https://github.com/data-privacy-stack/presidio) (MIT).
