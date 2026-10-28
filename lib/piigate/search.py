"""Project search without personal data in the result — MCP tool `piigate_search`.

Hits are split by location:
1. code and ordinary files (outside sensitive directories, no data extension, clean content verdict) → plain text,
   like `rg -n`;
2. free text in sensitive directories, with a data extension (EML, PDF, DOCX, ODT, TXT…) or with data according to
   the rules (PHI verdict) → lines with context through `text.filter_text` (shared pseudonym map); the word containing
   a pattern hit is always masked (MATCH_n or the person's pseudonym) — the pattern may be a surname;
3. tables (CSV/TSV/XLSX/ODS, SQL dumps) and files that cannot be checked → no content: file, table, column,
   row numbers, hit count; the values only through piigate_show.
The pattern never appears in the result ("pattern 1"). `rg` deliberately searches sensitive and ignored directories
too (`--no-ignore --hidden`), but not `.git` and not the filter files (protected — excluded by glob and by realpath);
it does not follow symlinks. A text filter failure (Presidio) → only group 2 is denied.
"""

import base64
import hashlib
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import FilterError, config, files, project, table, text, verdict
from .pseudonym_map import PseudonymMap
from .rules import Fragment

TABLE_EXTS = {".csv", ".tsv", ".xlsx", ".xlsm", ".ods"}
DUMPS = {".sql", ".dump"}
DOCUMENTS = {".pdf", ".docx", ".odt", ".eml"}
NO_EXTRACTION = {".xls", ".doc", ".msg"}
SPECIAL = TABLE_EXTS | DUMPS | DOCUMENTS | NO_EXTRACTION  # not through `rg` — read by our own code
MAX_FILES = 200_000
TIMEOUT_S = 60
MAX_ROWS = 20  # row numbers in one group-3 entry
SEPARATOR = "\n⁣⁣⁣\n"  # between group-2 blocks filtered in a single call
INSERT_RE = re.compile(r"(?is)\s*INSERT\s+INTO\s+(\S+?)\s*(?:\(([^)]*)\))?\s*VALUES\s*(.*)")
COPY_RE = re.compile(r"(?is)\s*COPY\s+(\S+)\s*\(([^)]*)\)\s*FROM\s+stdin")


@dataclass
class Line:
    number: int
    text: str
    matches: list[tuple[int, int]] = field(default_factory=list)  # character ranges; empty = context line


@dataclass
class Result:
    plain: list[dict] = field(default_factory=list)
    text: list[dict] = field(default_factory=list)
    text_denied: str | None = None
    tables: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    truncated: bool = False


def _in(p: str, directories: list[str]) -> bool:
    return any(p == k or p.startswith(k.rstrip("/") + "/") for k in directories)


def _root(path: str, cfg: dict) -> str:
    p = config.expand_tilde(path)
    if not os.path.isabs(p):
        raise FilterError("the path must be absolute (or start with ~/)")
    real = os.path.realpath(p)
    if _in(real, config.protected_dirs(cfg)):
        raise FilterError("filter files (map, key, configuration) — not accessible")
    if not os.path.exists(real):
        raise FilterError("no such path")
    return real


def _rg_args(root: str, glob: list[str], cfg: dict) -> list[str]:
    arg = ["--no-config", "--hidden", "--no-ignore", "--glob", "!.git"]
    for g in glob:
        arg += ["--glob", g]
    if os.path.isdir(root):  # after the user's globs — a later glob takes precedence
        for k in config.protected_dirs(cfg):
            if _in(k, [root]) and k != root:
                arg += ["--glob", f"!/{os.path.relpath(k, root)}/**"]
    return arg


def _rg(arguments: list[str], time_limit_s: float = TIMEOUT_S) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(["rg", *arguments], capture_output=True, timeout=time_limit_s, check=False)
    except FileNotFoundError:
        raise FilterError("rg (ripgrep) not found") from None
    except subprocess.TimeoutExpired:
        raise FilterError(f"the search takes over {time_limit_s} s — narrow the path or glob") from None


def _rg_path(obj: dict) -> str:
    if "text" in obj:
        return obj["text"]
    return os.fsdecode(base64.b64decode(obj.get("bytes", "")))


def _rg_text(obj: dict) -> tuple[str, bytes]:
    if "text" in obj:
        t = obj["text"]
        return t, t.encode("utf-8")
    b = base64.b64decode(obj.get("bytes", ""))
    return b.decode("utf-8", "replace"), b


def _chars(raw_bytes: bytes, offset: int) -> int:
    return len(raw_bytes[:offset].decode("utf-8", "replace"))


def _search_text_files(
    pattern: str, root: str, arg: list[str], *, ignore: bool, context: int, limit: int
) -> tuple[dict[str, list[Line]], bool]:
    """`rg --json` over text files (no special formats): file → lines with hits and context."""
    command = ["rg", "--json", "--sort", "path", "--max-columns", "500", "--max-columns-preview", *arg]
    command += [a for e in sorted(SPECIAL) for a in ("--iglob", f"!*{e}")]
    command += ["-i"] if ignore else []
    command += ["-C", str(context)] if context else []
    command += ["-e", pattern, "--", root]
    result: dict[str, list[Line]] = {}
    hit_count, truncated = 0, False
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        for raw_line in proc.stdout:
            event = json.loads(raw_line)
            type_, d = event.get("type"), event.get("data", {})
            if type_ not in ("match", "context"):
                continue
            if type_ == "match" and hit_count >= limit:
                truncated = True
                break
            t, b = _rg_text(d["lines"])
            t = t.rstrip("\r\n")
            ranges = []
            if type_ == "match":
                hit_count += 1
                ranges = [(_chars(b, s["start"]), _chars(b, s["end"])) for s in d.get("submatches", [])]
            result.setdefault(_rg_path(d["path"]), []).append(Line(d["line_number"], t, ranges))
        proc.kill()
    return result, truncated


class _Verdicts:
    """Content verdict of a text file outside the sensitive directories (rules as in the gate, cached by sha256)."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.limit = verdict.settings(cfg)["limit_mb"] * 1024 * 1024
        self.cache = verdict.VerdictCache()

    def file(self, path: str) -> verdict.Verdict:
        try:
            if os.path.getsize(path) > self.limit:
                return verdict.Verdict(verdict.UNKNOWN, "file too large to check its content")
            data = Path(path).read_bytes()
        except OSError as e:
            return verdict.Verdict(verdict.UNKNOWN, f"cannot read the file ({type(e).__name__})")
        sha = "search:" + hashlib.sha256(data).hexdigest()
        if proj := self.cfg.get("project"):
            sha += ":" + proj.get("digest", "")
        if cached := self.cache.get(sha):
            return cached
        try:
            counter = verdict.check_text(table._decode(data), self.cfg)
        except Exception as e:  # noqa: BLE001 — type only
            return verdict.Verdict(verdict.UNKNOWN, f"cannot check the content ({type(e).__name__})")
        w = verdict.Verdict(verdict.PERSONAL, verdict.describe_counter(counter)) if counter else verdict.Verdict(verdict.CLEAN)
        self.cache.save(sha, w)
        return w


def _matching_lines(t: str, regex: re.Pattern, context: int) -> list[Line]:
    lines = t.splitlines()
    matched = {
        i: [(m.start(), m.end()) for m in regex.finditer(ln) if m.end() > m.start()] for i, ln in enumerate(lines)
    }
    matched = {i: z for i, z in matched.items() if z}
    selected = sorted({j for i in matched for j in range(max(0, i - context), min(len(lines), i + context + 1))})
    return [Line(i + 1, lines[i], matched.get(i, [])) for i in selected]


def _document_text(path: str, ext: str) -> str:
    if os.path.getsize(path) > files.FILE_LIMIT:
        raise FilterError("file over 100 MB")
    if ext == ".pdf":
        return files.pdf_text(Path(path))
    data = Path(path).read_bytes()
    if ext == ".docx":
        return files.docx_text(data)
    if ext == ".odt":
        return files.odt_text(data)
    (headers, content), _ = files.mail(data)  # .eml: headers and body, no attachments
    return "\n".join(f"{k}: {v}" for k, v in headers) + "\n\n" + content


def _sql_values(rest: str) -> list[list[str]]:
    """`(1, 'a,b', NULL), (2, 'O''Brien', 3)` → value tuples (quotes '…' with '' and \\', no parentheses in numbers)."""
    tuples: list[list[str]] = []
    current_tuple: list[str] | None = None
    value, quote, i = "", None, 0
    while i < len(rest):
        z = rest[i]
        if quote:
            if z == "\\" and i + 1 < len(rest):
                value += rest[i + 1]
                i += 2
                continue
            if z == quote:
                if rest[i + 1 : i + 2] == quote:
                    value += z
                    i += 2
                    continue
                quote = None
            else:
                value += z
        elif z in "'\"" and current_tuple is not None:
            quote = z
        elif z == "(" and current_tuple is None:
            current_tuple, value = [], ""
        elif z == "," and current_tuple is not None:
            current_tuple.append(value.strip())
            value = ""
        elif z == ")" and current_tuple is not None:
            current_tuple.append(value.strip())
            tuples.append(current_tuple)
            current_tuple, value = None, ""
        elif current_tuple is not None:
            value += z
        i += 1
    return tuples


def _column_names(file_list: str | None) -> list[str]:
    return [n.strip(" `\"'[]\n\t") for n in file_list.split(",")] if file_list else []


def _sql_matches(path: str, regex: re.Pattern) -> dict[tuple[str | None, str | None], list[int]]:
    """SQL dump line by line: (table, column) → numbers of lines with a hit; the column from the INSERT/COPY list."""
    result: dict[tuple[str | None, str | None], list[int]] = {}
    copy: tuple[str, list[str]] | None = None
    with open(path, "rb") as f:
        for number, raw_line in enumerate(f, 1):
            line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
            if copy:
                if line == "\\.":
                    copy = None
                    continue
                for i, cell in enumerate(line.split("\t")):
                    if regex.search(cell):
                        col = copy[1][i] if i < len(copy[1]) else f"column_{i + 1}"
                        result.setdefault((copy[0], col), []).append(number)
                continue
            if m := COPY_RE.match(line):
                copy = (m.group(1).strip('`"[]'), _column_names(m.group(2)))
                if not regex.search(line):
                    continue
            if not regex.search(line):
                continue
            keys: set[tuple[str | None, str | None]] = set()
            m = INSERT_RE.match(line) or COPY_RE.match(line)
            tab = m.group(1).strip('`"[]') if m else None
            if m and m.re is INSERT_RE:
                names = _column_names(m.group(2))
                for value_tuple in _sql_values(m.group(3)):
                    for i, v in enumerate(value_tuple):
                        if regex.search(v):
                            keys.add((tab, names[i] if i < len(names) else f"column_{i + 1}"))
                if regex.search(line[: m.start(3)]):
                    keys.add((tab, None))  # hit in a table or column name
            if not keys:
                keys.add((tab, None))  # schema, comment or unrecognized INSERT
            for k in keys:
                result.setdefault(k, []).append(number)
    return result


def _table_matches(path: str, ext: str, regex: re.Pattern) -> tuple[list[table.Table], dict]:
    """(tables, (table no., column no.) → row numbers) — row 1 is the header when the file has one."""
    if os.path.getsize(path) > files.FILE_LIMIT:
        raise FilterError("file over 100 MB")
    data = Path(path).read_bytes()
    if ext in (".xlsx", ".xlsm"):
        tables = table.from_xlsx(data, Path(path).name)
    elif ext == ".ods":
        tables = table.from_ods(data)
    else:
        tables = [table.from_csv(table._decode(data), Path(path).name, "\t" if ext == ".tsv" else None)]
    result: dict[tuple[int, int], list[int]] = {}
    for nt, tab in enumerate(tables):
        has_header = not (tab.headers and tab.headers[0] == "column_1")
        rows = ([tab.headers] if has_header else []) + tab.rows
        for nw, w in enumerate(rows, 1):
            for nk, cell in enumerate(w):
                if regex.search(cell):
                    result.setdefault((nt, nk), []).append(nw)
    return tables, result


def _table_entry(file: str, tab: str | None, column: str | None, rows: list[int], description: str) -> dict:
    return {
        "file": file,
        "table": tab,
        "column": column,
        "rows": rows[:MAX_ROWS],
        "count": len(rows),
        "description": description,
    }


def _mask_matches(block: str, ranges: list[tuple[int, int]]) -> list[Fragment]:
    """The whole word containing a pattern hit → MATCH fragment (weight 1: a person pseudonym from NER/rules wins)."""
    result = []
    for s, k in ranges:
        while s > 0 and block[s - 1].isalnum():
            s -= 1
        while k < len(block) and block[k].isalnum():
            k += 1
        if k > s:
            result.append(Fragment(s, k, "MATCH", 1))
    return result


def _blocks(lines: list[Line]) -> list[list[Line]]:
    blocks: list[list[Line]] = []
    for ln in sorted(lines, key=lambda x: x.number):
        if blocks and ln.number == blocks[-1][-1].number + 1:
            blocks[-1].append(ln)
        else:
            blocks.append([ln])
    return blocks


def _filter_group_2(group2_files: list[tuple[str, list[Line]]], cfg: dict, pseudonym_map: PseudonymMap) -> list[dict]:
    """All blocks in a single filter call (shared person stems → the same pseudonyms across the whole result)."""
    blocks: list[tuple[str, list[Line]]] = [(p, b) for p, lines in group2_files for b in _blocks(lines)]
    texts, extra, shift = [], [], 0
    for _, b in blocks:
        t = "\n".join(ln.text for ln in b)
        pos = 0
        for ln in b:
            extra += [
                Fragment(f.start + shift, f.end + shift, f.type_, f.weight)
                for f in _mask_matches(t, [(pos + s, pos + k) for s, k in ln.matches])
            ]
            pos += len(ln.text) + 1
        texts.append(t)
        shift += len(t) + len(SEPARATOR)
    whole = SEPARATOR.join(texts)
    cfg = {**cfg, "text": {**cfg["text"], "labels": {"MATCH": "MATCH", **cfg["text"]["labels"]}}}
    filtered, _ = text.filter_text(whole, cfg, source="files", pseudonym_map=pseudonym_map, extra=extra, stems={})
    parts = filtered.split(SEPARATOR)
    if len(parts) != len(blocks):
        raise FilterError("the text filter changed the block split — result hidden")
    return [
        {
            "file": file,
            "lines": [b[0].number, b[-1].number],
            "hits": [ln.number for ln in b if ln.matches],
            "fragment": part,
        }
        for (file, b), part in zip(blocks, parts)
    ]


def search(
    pattern: str,
    cfg: dict,
    *,
    path: str,
    glob: list[str] | tuple[str, ...] = (),
    ignore_case: bool = False,
    context: int = 0,
    limit: int = 200,
    pseudonym_map: PseudonymMap | None = None,
) -> dict:
    """Result: plain, text (+ text_denied), tables, skipped, truncated, report — without the pattern and data values."""
    project.require_valid(cfg)
    if not pattern:
        raise FilterError("empty pattern")
    root = _root(path, cfg)
    base = root if os.path.isdir(root) else os.path.dirname(root)
    arg = _rg_args(root, list(glob), cfg)
    if _rg(["--no-config", "--quiet", "-e", pattern, "--", os.devnull], 10).returncode == 2:
        raise FilterError("invalid pattern (rg regex syntax) — pattern text hidden")
    try:
        py_regex: re.Pattern | None = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error:
        py_regex = None
    pseudonym_map = pseudonym_map or PseudonymMap()
    protected = config.protected_dirs(cfg)
    sensitive = config.sensitive_dirs(cfg)
    extensions = tuple(e.casefold() for e in cfg["sources"]["extensions"])
    w = Result()

    file_list = _rg(["--files", "--null", "--sort", "path", *arg, "--", root])
    if file_list.returncode not in (0, 1):
        raise FilterError(f"rg --files: exit code {file_list.returncode} (bad glob?)")
    all_paths = [os.fsdecode(p) for p in file_list.stdout.split(b"\0") if p]
    if len(all_paths) > MAX_FILES:
        raise FilterError(f"over {MAX_FILES} files — narrow the path or glob")

    def relative(p: str) -> str:
        return os.path.relpath(p, base)

    def name(p: str, forbidden: set[str] | None = None) -> str:
        """Path for groups 2–3: the part below the sensitive directory goes through the name filter; the configured
        directory and paths outside sensitive directories — plain (code file names are visible in Glob/ls anyway)."""
        rel = relative(p)
        folder = max((k for k in sensitive if _in(p, [k]) and _in(k, [base]) and k != base), key=len, default=None)
        if folder:
            before = os.path.relpath(folder, base)
            return f"{before}/{text.filter_name(os.path.relpath(p, folder), cfg, pseudonym_map, forbidden)}"
        if _in(p, sensitive):  # search inside a sensitive directory
            return text.filter_name(rel, cfg, pseudonym_map, forbidden)
        return rel

    def is_allowed(p: str) -> bool:
        return not _in(os.path.realpath(p), protected)

    def is_sensitive(p: str) -> bool:
        r = os.path.realpath(p)
        return _in(r, sensitive) or r.casefold().endswith(extensions)

    # groups 1 and 2 — text files through rg
    matched, w.truncated = _search_text_files(
        pattern, root, arg, ignore=ignore_case, context=context, limit=limit
    )
    judge = _Verdicts(cfg)
    group_2: list[tuple[str, list[Line]]] = []
    for p, lines in matched.items():
        if not is_allowed(p):
            continue
        if is_sensitive(p):
            group_2.append((p, lines))
            continue
        vd = judge.file(p)
        if vd.result == verdict.CLEAN:
            w.plain += [
                {"file": relative(p), "line": ln.number, "text": ln.text, "hit": bool(ln.matches)}
                for ln in lines
            ]
        elif vd.result == verdict.PERSONAL:
            group_2.append((p, lines))
        else:
            number = [ln.number for ln in lines if ln.matches]
            w.tables.append(_table_entry(name(p), None, None, number, f"no content: {vd.description}"))

    # special formats: documents → group 2, tables and dumps → group 3
    for p in all_paths:
        ext = Path(p).suffix.casefold()
        if ext not in SPECIAL or not is_allowed(p) or os.path.islink(p):
            continue
        if len(w.tables) >= limit:
            w.truncated = True
            break
        if ext in NO_EXTRACTION:
            w.skipped.append({"file": name(p), "reason": f"format {ext} has no text extraction — not searched"})
            continue
        if py_regex is None:
            w.skipped.append(
                {"file": name(p), "reason": "the pattern does not compile in Python (re) — not searched"}
            )
            continue
        try:
            if ext in DOCUMENTS:
                lines = _matching_lines(_document_text(p, ext), py_regex, context)
                if lines:
                    group_2.append((p, lines))
            elif ext in DUMPS:
                for (tab, col), number in _sql_matches(p, py_regex).items():
                    w.tables.append(
                        _table_entry(
                            name(p),
                            table._safe_header(tab, pseudonym_map, cfg, set()) if tab else None,
                            table._safe_header(col, pseudonym_map, cfg, set()) if col else None,
                            number,
                            "SQL dump: line numbers" + ("" if col else " (outside data or column not recognized)"),
                        )
                    )
            else:
                tables, hits = _table_matches(p, ext, py_regex)
                forbidden = table.table_tokens(tables)
                for (nt, nk), number in hits.items():
                    tab = tables[nt]
                    header = tab.headers[nk] if nk < len(tab.headers) else f"column_{nk + 1}"
                    w.tables.append(
                        _table_entry(
                            name(p, forbidden),
                            text.filter_name(tab.name, cfg, pseudonym_map, forbidden)
                            if ext in (".xlsx", ".xlsm", ".ods")
                            else None,
                            table._safe_header(header, pseudonym_map, cfg, forbidden),
                            number,
                            "table: row numbers (1 = header, if present)",
                        )
                    )
        except FilterError as e:
            w.skipped.append({"file": name(p), "reason": str(e)})
        except Exception as e:  # noqa: BLE001 — a foreign exception message may quote data
            w.skipped.append({"file": name(p), "reason": f"cannot read ({type(e).__name__})"})

    if group_2:
        try:
            entries = _filter_group_2(group_2, cfg, pseudonym_map)
            for entry in entries:
                entry["file"] = name(entry["file"])
            w.text = entries
        except Exception as e:  # noqa: BLE001 — FilterError (Presidio) or another error: group 2 denied by default
            reason = str(e) if isinstance(e, FilterError) else type(e).__name__
            w.text_denied = (
                f"the text filter (Presidio) failed: {reason} — hits in free text hidden "
                f"({len(group_2)} files). Check that the Presidio container is running (see README) and retry"
            )
    data = {
        "root": root,
        "plain": w.plain,
        "text": w.text,
        "text_denied": w.text_denied,
        "tables": w.tables,
        "skipped": w.skipped,
        "truncated": w.truncated,
    }
    data["report"] = report(data, limit)
    return data


def report(d: dict, limit: int) -> str:
    n_text = len({t["file"] for t in d["text"]})
    rows = [
        f"[piigate] piigate_search: pattern 1 in {d['root']} — code and ordinary files: {len(d['plain'])} lines; "
        f"free text with data: {'DENIED' if d['text_denied'] else f'{n_text} files'}; "
        f"tables and dumps: {len(d['tables'])} entries; skipped: {len(d['skipped'])}"
        + (f"; RESULT TRUNCATED to the limit of {limit}" if d["truncated"] else "")
    ]
    if d["plain"]:
        rows.append("\n## Code and ordinary files (plain, like rg -n)\n")
        rows += [
            f"{t['file']}{':' if t['hit'] else '-'}{t['line']}{':' if t['hit'] else '-'}{t['text']}"
            for t in d["plain"]
        ]
    if d["text_denied"]:
        rows.append(f"\n## Free text with data — DENIED\n\n{d['text_denied']}")
    elif d["text"]:
        rows.append("\n## Free text with data (pseudonyms; the word with a hit → MATCH_n or the person's pseudonym)")
        for t in d["text"]:
            line_from, line_to = t["lines"]
            matches = ", ".join(map(str, t["hits"]))
            rows.append(f"\n### {t['file']} — lines {line_from}–{line_to} (hits: {matches})\n\n{t['fragment']}")
    if d["tables"]:
        rows.append("\n## Tables, dumps and files without content (values only through piigate_show)\n")
        rows.append("| file | table | column | rows/lines | hits | notes |")
        rows.append("| --- | --- | --- | --- | --- | --- |")
        for t in d["tables"]:
            number = ", ".join(map(str, t["rows"])) + (" …" if t["count"] > len(t["rows"]) else "")
            rows.append(
                f"| {t['file']} | {t['table'] or '—'} | {t['column'] or '—'} | {number} | {t['count']} | {t['description']} |"
            )
    if d["skipped"]:
        rows.append("\n## Skipped\n")
        rows += [f"- {p['file']}: {p['reason']}" for p in d["skipped"]]
    if not (d["plain"] or d["text"] or d["text_denied"] or d["tables"] or d["skipped"]):
        rows.append("\nNo hits.")
    return "\n".join(rows) + "\n"
