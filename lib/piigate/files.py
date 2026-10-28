"""File → filtered description: spreadsheets → structure, documents and mails → text with pseudonyms."""

import datetime
import email
import email.policy
import html
import os
import re
import subprocess
import tempfile
from pathlib import Path
from xml.etree import ElementTree as ET  # expat: no external entities

from . import FilterError, config, table, text
from .pseudonym_map import PseudonymMap

TABULAR = {".csv", ".tsv", ".xlsx", ".xlsm", ".ods"}
IMAGES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".tif", ".tiff", ".heic", ".svg"}
FILE_LIMIT = 100 * 1024 * 1024


def strip_html(t: str) -> str:
    t = re.sub(r"(?is)<(script|style|head)\b.*?</\1>", " ", t)
    t = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>|</li>|</h\d>", "\n", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    return re.sub(r"[ \t]+", " ", html.unescape(t))


def pdf_text(path: Path) -> str:
    try:
        result = subprocess.run(
            ["pdftotext", "-layout", "-enc", "UTF-8", str(path), "-"], capture_output=True, timeout=120, check=False
        )
    except FileNotFoundError:
        raise FilterError("pdftotext not found (package poppler-utils)") from None
    except subprocess.TimeoutExpired:
        raise FilterError("pdftotext: timed out") from None
    if result.returncode != 0:
        raise FilterError(f"pdftotext: exit code {result.returncode} (PDF damaged or encrypted?)")
    t = result.stdout.decode("utf-8", "replace")
    if len(t.strip()) < 20:
        raise FilterError("PDF without a text layer (scan?) — OCR is not supported, and the image must not be shown to the model")
    return t


def docx_text(data: bytes) -> str:
    z = table._zip(data, "DOCX")
    xml = z.read("word/document.xml")
    paragraphs = []
    w = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
    for p in ET.fromstring(xml).iter(f"{w}p"):
        paragraphs.append("".join(t.text or "" for t in p.iter(f"{w}t")))
    return "\n".join(paragraphs)


def odt_text(data: bytes) -> str:
    z = table._zip(data, "ODT")
    root = ET.fromstring(z.read("content.xml"))
    ns = "{urn:oasis:names:tc:opendocument:xmlns:text:1.0}"
    return "\n".join("".join(p.itertext()) for p in root.iter() if p.tag in (f"{ns}p", f"{ns}h"))


def mail(data: bytes) -> tuple[tuple[list[tuple[str, str]], str], list[tuple[str, str, bytes]]]:
    """Mail .eml → ((headers [(key, value)], body), attachments [(name, type, data)])."""
    msg = email.message_from_bytes(data, policy=email.policy.default)
    headers = [(k, str(msg.get(k))) for k in ("From", "To", "Cc", "Date", "Subject") if msg.get(k)]
    content = msg.get_body(preferencelist=("plain", "html"))
    t = ""
    if content is not None:
        t = content.get_content()
        t = strip_html(t) if content.get_content_type() == "text/html" else t
    attachments = []
    for z in msg.iter_attachments():
        attachments.append((z.get_filename() or "unnamed", z.get_content_type(), z.get_payload(decode=True) or b""))
    return (headers, t), attachments


RFC2822 = re.compile(r"(?im)^(?:mime-version|content-type|content-transfer-encoding|received|message-id):")


def looks_like_raw_mail(t: str) -> bool:
    """The RFC 2822 source of a message (e.g. a mail MCP server's `rawSource`): headers, then a blank line."""
    head = t[:20000].split("\n\n", 1)[0].split("\r\n\r\n", 1)[0]
    return bool(RFC2822.search(head))


def raw_mail_bytes(t: str) -> bytes:
    """Mail MCP servers pass the RFC 2822 source as a Latin-1 string (bytes 1:1); a decoded string falls back to UTF-8."""
    try:
        return t.encode("latin-1")
    except UnicodeEncodeError:
        return t.encode("utf-8")


def _attachment_forbidden(name: str, data: bytes) -> set[str]:
    """Words from the cells of a spreadsheet attachment — a surname in the file name (Recepty_Kowalska.xlsx) is data too."""
    ext = Path(name).suffix.casefold()
    try:
        if ext in (".xlsx", ".xlsm"):
            return table.table_tokens(table.from_xlsx(data, name))
        if ext == ".ods":
            return table.table_tokens(table.from_ods(data))
        if ext in (".csv", ".tsv"):
            return table.table_tokens([table.from_csv(table._decode(data))])
    except FilterError:
        pass
    return set()


def describe_data(
    name: str,
    data: bytes,
    cfg: dict,
    *,
    source: str,
    rows: int | None = None,
    attachment: int | None = None,
    pseudonym_map: PseudonymMap | None = None,
) -> str:
    pseudonym_map = pseudonym_map or PseudonymMap()
    ext = Path(name).suffix.casefold()
    header = text.filter_name(Path(name).name, cfg, pseudonym_map)
    if ext in IMAGES:
        raise FilterError("image — the filter does not show images (OCR is not supported); ask a human to describe it")
    if ext in (".xls", ".doc", ".msg", ".rtf"):
        raise FilterError(f"format {ext} is not supported — a human can save the file as XLSX/CSV/DOCX/EML")
    if ext in (".sql", ".dump"):
        raise FilterError("database dump — load it into a local database and view query results through `piigate table`")
    if ext in TABULAR:
        if ext in (".xlsx", ".xlsm"):
            tables = table.from_xlsx(data, name)
        elif ext == ".ods":
            tables = table.from_ods(data)
        else:
            tables = [table.from_csv(table._decode(data), Path(name).name, "\t" if ext == ".tsv" else None)]
        header = text.filter_name(Path(name).name, cfg, pseudonym_map, table.table_tokens(tables))
        return f"File: {header}\n" + table.describe(tables, cfg, source=source, sample_rows=rows, pseudonym_map=pseudonym_map)
    if ext == ".eml":
        content, att = mail(data)
        if attachment is not None:
            if not 1 <= attachment <= len(att):
                raise FilterError(f"the mail has {len(att)} attachments")
            n, _, d = att[attachment - 1]
            return describe_data(n, d, cfg, source=source, rows=rows, pseudonym_map=pseudonym_map)
        headers, content = content
        shared: dict[str, str] = {}  # body first: full names → the same pseudonyms in the headers
        result, counts = text.filter_text(content, cfg, source="mail", pseudonym_map=pseudonym_map, stems=shared)
        n_rows = []
        for k, v in headers:
            fv, lv = text.filter_text(v, cfg, source="mail", pseudonym_map=pseudonym_map, stems=shared)
            n_rows.append(f"{k}: {fv}")
            for a, b in lv.items():
                counts[a] = counts.get(a, 0) + b
        result = "\n".join(n_rows) + "\n\n" + result
        file_list = [
            f"  {i}. {text.filter_name(n, cfg, pseudonym_map, _attachment_forbidden(n, d))} ({type_}, {len(d)} B)"
            for i, (n, type_, d) in enumerate(att, 1)
        ]
        note = ("\nAttachments (piigate show FILE --attachment N):\n" + "\n".join(file_list)) if file_list else ""
        return f"File: {header}\n{text.summary(counts)}\n\n{result}{note}\n"
    if ext == ".pdf":
        with tempfile.NamedTemporaryFile(suffix=".pdf") as tmp:
            tmp.write(data)
            tmp.flush()
            t = pdf_text(Path(tmp.name))
    elif ext == ".docx":
        t = docx_text(data)
    elif ext == ".odt":
        t = odt_text(data)
    else:
        if b"\0" in data[:8192]:
            raise FilterError("binary file of unknown type — it cannot be filtered")
        t = table._decode(data)
        if ext in (".html", ".htm"):
            t = strip_html(t)
    result, counts = text.filter_text(t, cfg, source=source, pseudonym_map=pseudonym_map)
    return f"File: {header}\n{text.summary(counts)}\n\n{result}\n"


def _is_protected(path: Path, cfg: dict) -> bool:
    p = os.path.realpath(path)
    return any(p == k or p.startswith(k.rstrip("/") + "/") for k in config.protected_dirs(cfg))


def describe_file(path: Path, cfg: dict, **kw) -> str:
    if _is_protected(path, cfg):
        raise FilterError("filter file (map, key, configuration) — not accessible")
    if not path.is_file():
        raise FilterError("no such file (or it is a directory — use piigate list)")
    if path.stat().st_size > FILE_LIMIT:
        raise FilterError("file over 100 MB — split it or filter it in parts (piigate table < part)")
    return describe_data(path.name, path.read_bytes(), cfg, **kw)


def _dir_files(directory: Path, cfg: dict) -> list[Path]:
    return sorted(
        p
        for p in directory.rglob("*")
        if p.is_file() and len(p.relative_to(directory).parts) <= 2 and not _is_protected(p, cfg)
    )


def file_from_list(directory: Path, number: int, cfg: dict) -> Path:
    if not directory.is_dir():
        raise FilterError("--number needs a directory (the same as in piigate list)")
    files = _dir_files(directory, cfg)
    if not 1 <= number <= len(files):
        raise FilterError(f"the directory has {len(files)} files")
    return files[number - 1]


def file_list(directory: Path, cfg: dict, pseudonym_map: PseudonymMap | None = None) -> str:
    """Files in a directory (2 levels) with numbers and names passed through the name filter."""
    pseudonym_map = pseudonym_map or PseudonymMap()
    if not directory.is_dir():
        raise FilterError("not a directory")
    rows = ["| no. | file (filtered name) | size | modified |", "| --- | --- | --- | --- |"]
    files = _dir_files(directory, cfg)
    for i, p in enumerate(files[:500], 1):
        name = text.filter_name(str(p.relative_to(directory)), cfg, pseudonym_map)
        mtime = datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
        rows.append(f"| {i} | {name} | {p.stat().st_size} B | {mtime} |")
    if len(files) > 500:
        rows.append(f"| | … and {len(files) - 500} more | | |")
    return f"[piigate] {len(files)} files; preview: piigate show <directory> --number N\n" + "\n".join(rows) + "\n"


def _in(p: str, directories: list[str]) -> bool:
    return any(p == k or p.startswith(k.rstrip("/") + "/") for k in directories)


def source(path: str, cfg: dict, *, number: int | None = None, directory: bool = False) -> Path:
    """MCP tool input (piigate_*): an absolute path that, after `realpath`, is inside a sensitive directory — or (a file)
    has a sensitive-data extension from the configuration; never a filter file. A symlink from a sensitive directory
    to the outside loses that permission. `number` — file no. N from the directory listing (like
    `piigate show DIR --number N`); `directory=True` — a directory is required (`piigate_list`)."""
    p = Path(config.expand_tilde(path))
    if not p.is_absolute():
        raise FilterError("the path must be absolute (or start with ~/)")
    if _is_protected(p, cfg):
        raise FilterError("filter file (map, key, configuration) — not accessible")
    sensitive = config.sensitive_dirs(cfg)
    real = os.path.realpath(p)
    if directory or number is not None:
        if not _in(real, sensitive):
            raise FilterError(f"directory outside the sensitive directories ({', '.join(cfg['sources']['directories'])})")
        if not os.path.isdir(real):
            raise FilterError("not a directory")
        if directory:
            return Path(real)
        p = file_from_list(Path(real), number, cfg)
        real = os.path.realpath(p)
    extensions = tuple(e.casefold() for e in cfg["sources"]["extensions"])
    if not _in(real, sensitive) and not real.casefold().endswith(extensions):
        raise FilterError(
            "file outside the sensitive directories and without a sensitive-data extension — read such a file directly (Read)"
        )
    if _is_protected(Path(real), cfg):
        raise FilterError("filter file (map, key, configuration) — not accessible")
    if not os.path.isfile(real):
        raise FilterError("no such file (or it is a directory — use piigate_list and number)")
    if os.path.getsize(real) > FILE_LIMIT:
        raise FilterError("file over 100 MB")
    return Path(real)
