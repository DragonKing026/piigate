"""Anonymized copies of files (`piigate anonymize`, `piigate analyze`): the same pseudonyms as `piigate show`, map → `piigate reverse`.

The copy is produced deterministically (rules + Presidio + lists given from outside), not by having a model rewrite
it. Tables: a personal column (by header, value type or pointed out) → the whole cell becomes a pseudonym; numbers →
plain; other text → the text filter in every cell. Documents and mails → text with pseudonyms (.txt). Written only to
the anonymized or a sensitive directory (0700/0600).
"""

import csv
import datetime
import io
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import FilterError, config, files, project, table, text
from .pseudonym_map import PseudonymMap
from .rules import Fragment

# column header → pseudonym type for the whole cell (order matters: "Data urodzenia" before "Data");
# the regexes are detection vocabulary (Polish and English header words)
PERSONAL_HEADERS = [
    (r"pesel", "PESEL"),
    (r"urodz|birth|\bdob\b", "DATE"),
    (r"telef|kom[oó]rk|\bgsm\b|\btel\b|phone|mobile", "PHONE"),
    (r"e-?mail|\bpoczta\b", "EMAIL"),
    (r"adres|ulica|\bul\b|miasto|miejscow|kod.?poczt|wojew|powiat|gmina|address|street|city|\bzip\b", "ADDRESS"),
    (r"recept", "PRESCRIPTION"),
    (r"\bnip\b", "NIP"),
    (r"konto|iban|rachun", "ACCOUNT"),
    (r"dow[oó]d|paszport|nr.?dok|ubezpiecz|legityma", "DOCUMENT"),
    (r"\blek|medykament|preparat|\bdrug|substancj", "DRUG"),
    (r"imi[eęo]|nazwisk|pacjent|klient|osob|lekarz|opiekun|nadawc|odbiorc|\bname\b|surname|patient|kontakt", "PERSON"),
]
PERSONAL_VALUE_TYPE = {"PESEL": "PESEL", "phone": "PHONE", "email": "EMAIL"}
NUMBER_TYPES = {"integer", "decimal", "boolean", "NULL"}
DATE_TYPES = {"date", "datetime", "time"}
NAME_RE = re.compile(r"[^\W\d_][^\W\d_'’.-]*(?:[ -][^\W\d_][^\W\d_'’.-]*){0,3}")
FRAGMENT_TYPES = {"PERSON", "ADDRESS", "PHONE", "EMAIL", "PESEL", "DATE", "NUMBER", "DRUG", "ORG", "PRESCRIPTION", "DOCUMENT"}


@dataclass
class Result:
    directory: Path
    files: list[tuple[str, str]] = field(default_factory=list)  # (output file name, description without data)
    skipped: list[str] = field(default_factory=list)
    counter: dict[str, int] = field(default_factory=dict)

    def add_counts(self, counts: dict[str, int]) -> None:
        for k, v in counts.items():
            self.counter[k] = self.counter.get(k, 0) + v


def results_dir(cfg: dict) -> Path:
    """In a project session <project>/Anonymized-data, outside a project the global directory."""
    return Path(config.anonymized_dirs(cfg)[0])


def _in_dirs(p: Path, directories: list[str]) -> bool:
    s = os.path.realpath(p)
    return any(s == k or s.startswith(k.rstrip("/") + "/") for k in directories)


def prepare_dir(dest: str | None, name: str, cfg: dict) -> Path:
    """Output directory: by default <anonymized dir>/<date>-<name>; -o only into the anonymized or a sensitive
    directory. Data directories inside a project get a `.gitignore` with `*`."""
    root = results_dir(cfg)
    if dest:
        path = Path(config.expand(dest))
        if not _in_dirs(path, config.anonymized_dirs(cfg) + config.sensitive_dirs(cfg)):
            raise FilterError(f"output directory (-o) only inside {root} or a sensitive directory")
    else:
        path = root / f"{datetime.datetime.now():%Y%m%d-%H%M%S}-{name}"
    if _in_dirs(path, config.protected_dirs(cfg)):
        raise FilterError("filter directory (map, key, configuration) — not accessible")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    config.ensure_project_gitignore(cfg)
    return path


def safe_name(name: str, cfg: dict, pseudonym_map: PseudonymMap, forbidden: set[str] | None = None) -> str:
    n = text.filter_name(name, cfg, pseudonym_map, forbidden)
    n = re.sub(r"[^\w.-]+", "_", n).strip("._") or "file"
    return n[:100]


def fragments_in(t: str, fragments: list[tuple[str, str]]) -> list[Fragment]:
    """Occurrences of literally given strings (from the local model) — only those that really are in the text."""
    result = []
    for snippet, type_ in fragments:
        if len(snippet.strip()) < 3:
            continue
        type_ = type_ if type_ in FRAGMENT_TYPES else "NUMBER"
        for m in re.finditer(re.escape(snippet.strip()), t):
            result.append(Fragment(m.start(), m.end(), type_, 4))
    return result


def filter_fragments(t: str, cfg: dict, pseudonym_map: PseudonymMap, fragments: list[tuple[str, str]], **kw) -> tuple[str, dict]:
    return text.filter_text(t, cfg, pseudonym_map=pseudonym_map, extra=fragments_in(t, fragments), **kw)


# --- tables ---------------------------------------------------------------------------------------


def header_kind(header: str) -> str | None:
    n = header.casefold()
    for regex, type_ in PERSONAL_HEADERS:
        if re.search(regex, n):
            return type_
    return None


def column_decisions(tab: table.Table, cfg: dict, mask: set[str]) -> list[tuple[str, str | None]]:
    """For every column: ('plain'|'pseudonym'|'date'|'text', pseudonym type)."""
    plain = {k.casefold() for k in cfg["tables"].get("plain_columns", [])}
    sensitive = project.columns(cfg)
    dates = cfg["text"].get("dates", "all")
    widths = max([len(tab.headers)] + [len(w) for w in tab.rows]) if (tab.headers or tab.rows) else 0
    result = []
    for i in range(widths):
        hdr = tab.headers[i] if i < len(tab.headers) else f"column_{i + 1}"
        values = [w[i].strip() for w in tab.rows if i < len(w) and w[i].strip()]
        src_types = [tz[i] if i < len(tz) else "" for tz in tab.source_types] if tab.source_types else []
        type_list = {(src_types[k] if k < len(src_types) and src_types[k] else table.value_type(v)) for k, v in enumerate(values)}
        header_type = header_kind(hdr)
        if hdr.casefold() in plain:
            result.append(("plain", None))
        elif hdr.casefold() in sensitive:  # project filters: always a pseudonym, no exception for amounts
            result.append(("pseudonym", header_type or "VALUE"))
        elif (hdr.casefold() in mask or hdr in mask) and not (
            not header_type and type_list <= {"decimal", "NULL"} and all(re.search(r"\d[.,]\d", v) for v in values)
        ):  # amounts with decimals (pointed out by the model) do not identify a person — they stay plain
            result.append(("pseudonym", header_type or "VALUE"))
        elif personal := [PERSONAL_VALUE_TYPE[t] for t in type_list if t in PERSONAL_VALUE_TYPE]:
            result.append(("pseudonym", personal[0]))
        elif header_type:
            result.append(("pseudonym", header_type))
        elif not values:
            result.append(("plain", None))
        elif type_list <= NUMBER_TYPES and all(len(re.sub(r"\D", "", v)) <= 8 for v in values):
            result.append(("plain", None))  # amounts, quantities, flags; longer numbers are usually identifiers
        elif type_list <= DATE_TYPES | {"NULL"}:
            result.append(("date", "DATE") if dates == "all" else ("plain", None))
        elif (
            len({v for v in values if NAME_RE.fullmatch(v) and v[0].isupper()}) >= max(2, 0.5 * len(set(values)))
            and len(set(values)) >= 0.3 * len(values)
        ):
            result.append(("pseudonym", "PERSON"))  # capitalized words only, many distinct — person names
        else:
            result.append(("text", None))
    return result


def anonymize_tables(
    tables: list[table.Table],
    name: str,
    directory: Path,
    cfg: dict,
    pseudonym_map: PseudonymMap,
    result: Result,
    *,
    mask: set[str],
    fragments: list[tuple[str, str]],
    separator: str = ",",
) -> None:
    labels = cfg["text"]["labels"]
    forbidden = table.table_tokens(tables)
    base = safe_name(Path(name).stem, cfg, pseudonym_map, forbidden)
    for number, tab in enumerate(tables, 1):
        decisions = column_decisions(tab, cfg, mask)
        cache: dict[tuple[int, str], str] = {}
        counts: dict[str, int] = {}

        def cell(i: int, v: str) -> str:
            if not v.strip():
                return v
            kind, type_ = decisions[i]
            if kind == "plain":
                return v
            cache_key = (i, v)
            if cache_key not in cache:
                if kind in ("pseudonym", "date"):
                    label = labels.get(type_, type_)
                    cache[cache_key] = pseudonym_map.pseudonym(type_, label, v.strip())
                    counts[label] = counts.get(label, 0) + 1
                else:
                    cache[cache_key], l2 = filter_fragments(v, cfg, pseudonym_map, fragments)
                    for k, n in l2.items():
                        counts[k] = counts.get(k, 0) + n
            return cache[cache_key]

        headers = [
            table._safe_header(n, pseudonym_map, cfg, forbidden)
            for n in (tab.headers or [f"column_{i + 1}" for i in range(len(decisions))])
        ]
        buffer = io.StringIO()
        w = csv.writer(buffer, delimiter=separator, lineterminator="\n")
        w.writerow(headers)
        for row in tab.rows:
            w.writerow([cell(i, v) for i, v in enumerate(row)])
        sheet = "" if len(tables) == 1 else "-" + safe_name(tab.name, cfg, pseudonym_map, forbidden)
        file = directory / f"{base}{sheet}.{'tsv' if separator == chr(9) else 'csv'}"
        save(file, buffer.getvalue())
        description = ", ".join(
            f"{headers[i]}: {r if r != 'pseudonym' else 'pseudonyms ' + labels.get(t, t)}"
            for i, (r, t) in enumerate(decisions)
        )
        result.files.append((file.name, f"table {number}, rows {len(tab.rows)}; columns — {description}"))
        result.add_counts(counts)


# --- files ----------------------------------------------------------------------------------------


def save(file: Path, content: str) -> None:
    # O_NOFOLLOW: a symlink planted in the -o directory (e.g. pointing at the filter map) → error instead of overwriting
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)


def anonymize_data(
    name: str,
    data: bytes,
    directory: Path,
    cfg: dict,
    *,
    pseudonym_map: PseudonymMap,
    result: Result,
    mask: set[str] | None = None,
    fragments: list[tuple[str, str]] | None = None,
    name_prefix: str = "",
) -> None:
    mask = mask or set()
    fragments = fragments or []
    ext = Path(name).suffix.casefold()
    if ext in files.TABULAR:
        if ext in (".xlsx", ".xlsm"):
            tables, sep = table.from_xlsx(data, name), ","
        elif ext == ".ods":
            tables, sep = table.from_ods(data), ","
        else:
            sep = "\t" if ext == ".tsv" else None
            tables = [table.from_csv(table._decode(data), Path(name).name, sep)]
            sep = sep or ","
        anonymize_tables(
            tables, name_prefix + name, directory, cfg, pseudonym_map, result, mask=mask, fragments=fragments, separator=sep
        )
        return
    if ext == ".eml":
        (headers, content), att = files.mail(data)
        shared: dict[str, str] = {}
        t, counts = filter_fragments(content, cfg, pseudonym_map, fragments, source="mail", stems=shared)
        lines = []
        for k, v in headers:
            fv, lv = filter_fragments(v, cfg, pseudonym_map, fragments, source="mail", stems=shared)
            lines.append(f"{k}: {fv}")
            for a, b in lv.items():
                counts[a] = counts.get(a, 0) + b
        forbidden = set().union(*(files._attachment_forbidden(n, d) for n, _, d in att))
        file_list = [f"  {i}. {text.filter_name(n, cfg, pseudonym_map, forbidden)}" for i, (n, _, _) in enumerate(att, 1)]
        result_content = "\n".join(lines) + "\n\n" + t + ("\n\nAttachments:\n" + "\n".join(file_list) if file_list else "") + "\n"
        file = directory / f"{name_prefix}{safe_name(Path(name).stem, cfg, pseudonym_map, forbidden)}.txt"
        save(file, result_content)
        result.files.append((file.name, f"mail: headers and body, attachments: {len(att)}"))
        result.add_counts(counts)
        for i, (n, _, d) in enumerate(att, 1):
            try:
                anonymize_data(
                    n, d, directory, cfg, pseudonym_map=pseudonym_map, result=result, mask=mask, fragments=fragments,
                    name_prefix=f"{name_prefix}attachment-{i}-",
                )
            except FilterError as e:
                result.skipped.append(f"attachment {i}: {e}")
        return
    t = document_text(name, data)
    res, counts = filter_fragments(t, cfg, pseudonym_map, fragments)
    file = directory / f"{name_prefix}{safe_name(Path(name).stem, cfg, pseudonym_map)}.txt"
    save(file, res if res.endswith("\n") else res + "\n")
    result.files.append((file.name, f"text ({ext.lstrip('.') or 'no extension'}), characters: {len(res)}"))
    result.add_counts(counts)


def document_text(name: str, data: bytes) -> str:
    """Raw document text (PDF, DOCX, ODT, TXT, HTML) — only for further filtering or for the local model."""
    ext = Path(name).suffix.casefold()
    if ext in files.IMAGES:
        raise FilterError("image — OCR is not supported")
    if ext in (".xls", ".doc", ".msg", ".rtf"):
        raise FilterError(f"format {ext} is not supported — save it as XLSX/CSV/DOCX/EML")
    if ext in (".sql", ".dump"):
        raise FilterError("database dump — load it into a local database and use `piigate table`")
    if ext == ".pdf":
        import tempfile

        with tempfile.NamedTemporaryFile(suffix=".pdf") as tmp:
            tmp.write(data)
            tmp.flush()
            return files.pdf_text(Path(tmp.name))
    if ext == ".docx":
        return files.docx_text(data)
    if ext == ".odt":
        return files.odt_text(data)
    if b"\0" in data[:8192]:
        raise FilterError("binary file of unknown type")
    t = table._decode(data)
    return files.strip_html(t) if ext in (".html", ".htm") else t


def anonymize(
    name: str,
    data: bytes,
    cfg: dict,
    *,
    dest: str | None = None,
    mask: set[str] | None = None,
    fragments: list[tuple[str, str]] | None = None,
    pseudonym_map: PseudonymMap | None = None,
) -> Result:
    pseudonym_map = pseudonym_map or PseudonymMap()
    directory = prepare_dir(dest, safe_name(Path(name).stem, cfg, pseudonym_map), cfg)
    result = Result(directory)
    anonymize_data(name, data, directory, cfg, pseudonym_map=pseudonym_map, result=result, mask=mask, fragments=fragments)
    return result


def result_data(w: Result) -> dict:
    """Anonymization result as data (file names and descriptions are already free of personal data)."""
    return {
        "directory": str(w.directory),
        "files": [{"file": n, "description": o} for n, o in w.files],
        "skipped": list(w.skipped),
        "pseudonyms": dict(w.counter),
    }


def report_data(d: dict) -> str:
    lines = [f"[piigate] anonymized copies: {d['directory']}", text.summary(d["pseudonyms"]), ""]
    lines += [f"- {p['file']} — {p['description']}" for p in d["files"]]
    lines += [f"- skipped: {p}" for p in d["skipped"]]
    lines.append(
        "\nThe files can be read directly (Read). The filter does not catch 100% — if you see personal data in a copy, "
        "tell the human. Only a human restores the originals: piigate reverse FILE."
    )
    return "\n".join(lines) + "\n"


def report(w: Result) -> str:
    return report_data(result_data(w))
