#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.15"
# dependencies = ["mcp>=2.3,<3", "presidio-analyzer==2.2.366", "spacy==3.8.18"]
# ///
"""piigate MCP server — tools instead of `piigate …` commands in Bash, stdio transport.

A thin layer over the `lib/piigate` library (the same as the `piigate` CLI): typed parameters, paths checked here
(`files.source`: after realpath only the sensitive directories from config.json or files with a sensitive-data
extension, never filter files), result — the filtered report (text) + the same data in structuredContent. Raw data
never leaves the server: the library reads it, and the local model (`analysis.agent_command`) gets it through stdin.
`piigate table` / `piigate text` (pipes, e.g. from ssh) stay in Bash, `piigate reverse` — only a human in a terminal.
An analysis takes 30–150 s (up to `analysis.timeout_s`) — the plugin's .mcp.json sets the server `timeout` to 20 min.

Local engine (`engine.mode` = local, the default): this process holds Presidio + spaCy in memory and serves it to the
hooks and the CLI on a private Unix socket (engine_socket.py). The models load on the first analysis (the first use
downloads them, sha256-checked, into the data directory). With several Claude Code sessions the first server hosts
the engine, the others are clients and take over when it exits. Logs go to stderr only (stdout is the MCP channel).

PIIGATE_FAKE_ENGINE=1 — TEST ONLY: a tiny regex analyzer replaces Presidio (no models). Never set it in real use.
"""

import atexit
import os
import re
import sys
import threading
from pathlib import Path
from typing import Annotated

sys.path.insert(0, str(Path(__file__).resolve().parent / "lib"))

from piigate import FilterError, analysis, anonymization, config, engine_socket, engines, files, project, search
from piigate.pseudonym_map import PseudonymMap
from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent
from pydantic import Field

INSTRUCTIONS = (
    "Sensitive data (PHI/PII: Thunderbird mail, files in the configured sensitive directories such as ~/Sensitive-data, "
    "CSV/XLSX/PDF/EML from clients) — only through these tools; the result is already filtered (pseudonyms PERSON_3, "
    "ADDRESS_1). piigate_analyze: a local model reads the original and returns the categories of sensitive data, a summary "
    "without them, the answer to a question and anonymized copies (you then read those directly, Read). piigate_search: "
    "search the project including sensitive directories — code in plain text, free text with pseudonyms, tables without "
    "values. Ask only about content, numbers and structure — never about the identity of people. A denial means stop: "
    "do not look for another way to the original. Details: the piigate skill."
)

PathParam = Annotated[str, Field(description="absolute path (or ~/…) of a file in a sensitive directory", max_length=4096)]
NumberParam = Annotated[int | None, Field(description="file number from piigate_list (then path = the same directory)", ge=1)]
QuestionParam = Annotated[
    str, Field(description="about content, numbers, structure — not about the identity of people; empty = summary only", max_length=2000)
]
OutputDirParam = Annotated[
    str | None,
    Field(
        description="directory for the copies: by default <project>/Anonymized-data/<date>-<name> (outside a project "
        "~/Anonymized-data); only there or in a sensitive directory"
    ),
]


def _result(text: str, data: dict) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=text)], structured_content=data)


def log(message: str) -> None:
    print(f"[piigate] {message}", file=sys.stderr, flush=True)


def fake_analyze(text: str, language: str, threshold: float) -> list[dict]:
    """TEST ONLY (PIIGATE_FAKE_ENGINE=1): two capitalized words → PERSON, 11 digits → PL_PESEL."""
    hits = [
        {"entity_type": "PERSON", "start": m.start(), "end": m.end(), "score": 0.85}
        for m in re.finditer(r"\b[A-ZĄĆĘŁŃÓŚŹŻ][a-ząćęłńóśźż]+ [A-ZĄĆĘŁŃÓŚŹŻ][a-ząćęłńóśźż]+\b", text)
    ]
    hits += [
        {"entity_type": "PL_PESEL", "start": m.start(), "end": m.end(), "score": 1.0}
        for m in re.finditer(r"\b\d{11}\b", text)
    ]
    return [h for h in hits if h["score"] >= threshold]


class LocalEngine:
    """Hosts the local engine on the socket when nobody else does; retries in the background (takeover)."""

    RETRY_S = 5

    def __init__(self, cfg: dict):
        e = engines.engine_cfg(cfg)
        if os.environ.get("PIIGATE_FAKE_ENGINE") == "1":
            log("PIIGATE_FAKE_ENGINE=1: test-only regex analyzer instead of Presidio")
            analyze, status = fake_analyze, lambda: "loaded (fake engine, test only)"
        else:
            from piigate.local_engine import LocalAnalyzer  # needs presidio-analyzer, only this process imports it

            analyzer = LocalAnalyzer(list(e["languages"]), log=log)
            analyze, status = analyzer.analyze, analyzer.status
        self.host = engine_socket.Host(analyze, status)
        self._stop = threading.Event()

    def try_bind(self) -> bool:
        if self.host.bound:
            return True
        try:
            if self.host.try_bind():
                log(f"local engine socket: {self.host.path}")
                return True
        except (OSError, engine_socket.EngineUnavailable) as err:
            log(f"cannot host the local engine: {err}")
        return False

    def start(self) -> None:
        if not self.try_bind():
            log("another piigate server hosts the local engine — using it")
        threading.Thread(target=self._watch, daemon=True, name="piigate-engine-watch").start()

    def _watch(self) -> None:
        while not self._stop.wait(self.RETRY_S):
            if not self.host.bound and not engine_socket.alive(self.host.path):
                self.try_bind()

    def close(self) -> None:
        self._stop.set()
        self.host.close()


def start_local_engine() -> LocalEngine | None:
    """In local mode: host the engine (or be a client of the server that does). Never blocks on model loading."""
    try:
        cfg = config.load(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        if engines.engine_cfg(cfg)["mode"] != "local":
            return None
        engine = LocalEngine(cfg)
    except Exception as err:  # noqa: BLE001 — the tools still deny without an engine; the server must start
        log(f"local engine not started: {type(err).__name__}: {err}")
        return None
    engine.start()
    atexit.register(engine.close)
    return engine


def _run(fn) -> CallToolResult:
    try:
        cfg = config.load(os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd())
        project.require_valid(cfg)
        return fn(cfg)
    except FilterError as e:
        raise ToolError(f"[piigate] denied: {e}") from None
    except FileNotFoundError:
        raise ToolError("[piigate] denied: no such file") from None
    except ToolError:
        raise
    except Exception as e:  # noqa: BLE001 — a foreign exception message may quote data
        raise ToolError(f"[piigate] denied: error {type(e).__name__} (details hidden — they may contain data)") from None


def create_server() -> MCPServer:
    mcp = MCPServer("piigate", instructions=INSTRUCTIONS)

    @mcp.tool()
    def piigate_list(directory: PathParam) -> CallToolResult:
        """Files of a sensitive directory (2 levels) with numbers; names filtered. Preview: piigate_show(directory, number)."""

        def f(cfg):
            folder = files.source(directory, cfg, directory=True)
            text = files.file_list(folder, cfg)
            for cli in ("piigate",):
                text = text.replace(f"{cli} show <directory> --number N", "piigate_show(path=directory, number=N)")
            return _result(text, {"directory": str(folder), "report": text})

        return _run(f)

    @mcp.tool()
    def piigate_show(
        path: PathParam,
        number: NumberParam = None,
        rows: Annotated[int | None, Field(description="how many rows of masks to show (tables)", ge=0, le=50)] = None,
        attachment: Annotated[int | None, Field(description="mail attachment number (EML)", ge=1)] = None,
    ) -> CallToolResult:
        """A file through the filter: CSV/XLSX/ODS → structure (columns, types, counts); PDF/EML/DOCX/ODT/TXT → text with pseudonyms."""

        def f(cfg):
            file = files.source(path, cfg, number=number)
            source = "mail" if file.suffix.casefold() == ".eml" else "files"
            text = files.describe_file(file, cfg, source=source, rows=rows, attachment=attachment)
            return _result(text, {"report": text})

        return _run(f)

    @mcp.tool()
    def piigate_anonymize(
        path: PathParam,
        number: NumberParam = None,
        mask_columns: Annotated[
            list[str], Field(description="columns to mask that the rules did not recognize (names from piigate_show)")
        ] = [],  # noqa: B006 — pydantic copies the default
        output_dir: OutputDirParam = None,
    ) -> CallToolResult:
        """Anonymized copy (CSV/TXT, the same pseudonyms as piigate_show) — then read it directly (Read)."""

        def f(cfg):
            file = files.source(path, cfg, number=number)
            mask = {k.strip() for k in mask_columns if k.strip()}
            w = anonymization.anonymize(file.name, file.read_bytes(), cfg, dest=output_dir, mask=mask)
            data = anonymization.result_data(w)
            return _result(anonymization.report_data(data), data)

        return _run(f)

    @mcp.tool()
    def piigate_analyze(
        path: Annotated[str | None, Field(description="a file in a sensitive directory — OR mail", max_length=4096)] = None,
        mail_query: Annotated[
            str | None,
            Field(description="words from the subject/sender of a Thunderbird mail (joined with AND) — OR path", max_length=500),
        ] = None,
        number: Annotated[
            int | None, Field(description="mail: message number from the choice list; file: number from piigate_list", ge=1)
        ] = None,
        question: QuestionParam = "",
        output_dir: OutputDirParam = None,
    ) -> CallToolResult:
        """A local model (nothing is sent to Anthropic) reads the original file or mail with attachments and returns:
        which sensitive data is inside, a summary without it, the answer to the question and anonymized copies.
        Takes 30–150 s. The model's output is a first draft — check numbers against the copy."""

        def f(cfg):
            if (path is None) == (mail_query is None):
                raise FilterError("give exactly one of: path or mail_query")
            pseudonym_map = PseudonymMap()
            if mail_query is not None:
                if not mail_query.strip():
                    raise FilterError("empty mail query")
                mail = analysis.fetch_mail(mail_query, number, cfg, pseudonym_map, choice="piigate_analyze(mail_query=…, number=N)")
                if isinstance(mail, str):  # several messages — a list to choose from (filtered)
                    return _result(mail, {"needs_choice": True, "report": mail})
                name, data = mail
            else:
                file = files.source(path, cfg, number=number)
                name, data = file.name, file.read_bytes()
            result = analysis.analyze_data(name, data, cfg, question=question, dest=output_dir, pseudonym_map=pseudonym_map)
            return _result(analysis.report(result), {"needs_choice": False, **result})

        return _run(f)

    @mcp.tool()
    def piigate_search(
        pattern: Annotated[str, Field(description="regular expression (rg syntax)", min_length=1, max_length=1000)],
        path: Annotated[
            str | None, Field(description="directory or file (absolute, ~/…); defaults to the project directory", max_length=4096)
        ] = None,
        glob: Annotated[
            list[str], Field(description="name filters like rg --glob, e.g. ['*.php', '!vendor/**']", max_length=50)
        ] = [],  # noqa: B006 — pydantic copies the default
        ignore_case: Annotated[bool, Field(description="case-insensitive (rg -i)")] = False,
        context: Annotated[int, Field(description="context lines around a hit (rg -C)", ge=0, le=5)] = 0,
        limit: Annotated[int, Field(description="max. lines with a hit (code + text) and table entries", ge=1, le=1000)] = 200,
    ) -> CallToolResult:
        """Searches the project TOGETHER with the sensitive directories (instead of grep -r / rg / Grep, which the gate
        denies). Code and ordinary files → lines in plain text; free text with data (EML/PDF/DOCX/TXT in sensitive
        directories or with data according to the rules) → lines with pseudonyms (the word with a hit → MATCH_n);
        tables (CSV/XLSX/ODS/SQL) → only file, column, row numbers and hit count. The pattern is not echoed back."""

        def f(cfg):
            directory = path or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
            g = [x.strip() for x in glob if x.strip()]
            data = search.search(
                pattern, cfg, path=directory, glob=g, ignore_case=ignore_case, context=context, limit=limit
            )
            return _result(data["report"], data)

        return _run(f)

    return mcp


if __name__ == "__main__":
    local_engine = start_local_engine()
    try:
        create_server().run()
    finally:
        if local_engine is not None:
            local_engine.close()
