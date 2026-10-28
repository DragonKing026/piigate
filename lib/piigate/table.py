"""Tabular data (CSV, XLSX, ODS, SQL results): structure only + deterministic masks, no detection.

No cell value leaves in plain text (unless its column is listed in `tables.plain_columns` in the user
configuration). Headers go through the Polish rules — a header that looks like data is replaced.
"""

import csv
import io
import re
import zipfile
from dataclasses import dataclass, field
from xml.etree import ElementTree as ET  # expat: no external entities, "billion laughs" protection (≥ 2.4.1)

from . import FilterError, project, rules
from . import text as text_mod
from .pseudonym_map import PseudonymMap


@dataclass
class Table:
    name: str
    headers: list[str]
    rows: list[list[str]]
    format: str
    source_types: list[list[str]] = field(default_factory=list)  # cell types from the file (XLSX: number/date/text)


# --- value type recognition (without revealing the value) ----------------------------------------

TYPES = [
    ("integer", re.compile(r"[-+]?\d{1,18}")),
    ("decimal", re.compile(r"[-+]?(?:\d{1,3}(?:[ \u00a0]\d{3})+|\d+)(?:[.,]\d+)?")),
    ("date", re.compile(r"\d{4}-\d{2}-\d{2}|\d{1,2}[./]\d{1,2}[./]\d{4}")),
    ("datetime", re.compile(r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?")),
    ("time", re.compile(r"\d{1,2}:\d{2}(?::\d{2})?")),
    ("boolean", re.compile(r"(?i)true|false|prawda|fałsz|tak|nie")),
    ("email", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")),
    ("NULL", re.compile(r"(?i)null|nil|none")),
]
CLASSES = {
    "integer": "n",
    "decimal": "n",
    "date": "d",
    "datetime": "d",
    "time": "d",
    "boolean": "b",
    "email": "e",
    "NULL": "0",
}


def value_type(w: str) -> str:
    w = w.strip()
    if not w:
        return "empty"
    if re.fullmatch(r"(?:\+48[ -]?)?\d{3}[ -]\d{3}[ -]\d{3}|\+48\d{9}|\(?\d{2}\)?[ -]\d{3}[ -]\d{2}[ -]\d{2}", w):
        return "phone"
    for name, regex in TYPES:
        if regex.fullmatch(w):
            if name == "integer" and len(w) == 11 and rules.pesel_valid(w):
                return "PESEL"
            return name
    return "text"


# --- parsers --------------------------------------------------------------------------------------


def _decode(data: bytes) -> str:
    for code in ("utf-8-sig", "cp1250", "iso-8859-2"):
        try:
            return data.decode(code)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def from_csv(content: str, name: str = "CSV", separator: str | None = None) -> Table:
    if separator is None:
        sample = content[:20000]
        try:
            separator = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
        except csv.Error:
            separator = max(",;\t|", key=sample.count)
    rows = [w for w in csv.reader(io.StringIO(content), delimiter=separator)]
    return _from_rows(name, rows, "csv" if separator != "\t" else "tsv")


def _from_rows(name: str, rows: list[list[str]], fmt: str, type_list: list[list[str]] | None = None) -> Table:
    rows = [w for w in rows if any(c.strip() for c in w)]
    if not rows:
        return Table(name, [], [], fmt)
    if _looks_like_header(rows):
        return Table(name, rows[0], rows[1:], fmt, (type_list or [])[1:])
    return Table(name, [f"column_{i + 1}" for i in range(max(map(len, rows)))], rows, fmt, type_list or [])


def _looks_like_header(rows: list[list[str]]) -> bool:
    first = rows[0]
    if not first or any(not c.strip() for c in first) or len(set(first)) < len(first):
        return False
    if any(value_type(c) != "text" or len(c) > 60 for c in first):
        return False
    if len(rows) == 1:
        return True
    # at least one column whose data has a different type than the header, or short labels
    return any(value_type(w[i]) != "text" for w in rows[1:6] for i in range(min(len(w), len(first)))) or all(
        len(c) <= 30 for c in first
    )


NS = {
    "m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "rel": "http://schemas.openxmlformats.org/package/2006/relationships",
}
BUILTIN_DATE_FORMATS = set(range(14, 23)) | set(range(45, 48))
UNZIP_LIMIT = 300 * 1024 * 1024


def _zip(data: bytes, kind: str) -> zipfile.ZipFile:
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise FilterError(f"{kind}: file is damaged or encrypted (password) — it cannot be filtered") from None
    if sum(i.file_size for i in z.infolist()) > UNZIP_LIMIT:
        raise FilterError(f"{kind}: over 300 MB after unpacking — denied (ZIP bomb?)")
    return z


def _column(ref: str) -> int:
    n = 0
    for ch in re.match(r"[A-Z]+", ref).group():
        n = n * 26 + ord(ch) - 64
    return n - 1


def from_xlsx(data: bytes, file_name: str = "XLSX") -> list[Table]:
    z = _zip(data, "XLSX")
    names = set(z.namelist())
    shared: list[str] = []
    if "xl/sharedStrings.xml" in names:
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS):
            shared.append("".join(t.text or "" for t in si.iter(f"{{{NS['m']}}}t")))
    date_styles: set[int] = set()
    if "xl/styles.xml" in names:
        st = ET.fromstring(z.read("xl/styles.xml"))
        custom_dates = {
            int(f.get("numFmtId"))
            for f in st.findall("m:numFmts/m:numFmt", NS)
            if re.search(r"[dmyhs]", re.sub(r'"[^"]*"|\[[^\]]*\]', "", f.get("formatCode", "")), re.IGNORECASE)
        }
        for i, xf in enumerate(st.findall("m:cellXfs/m:xf", NS)):
            if int(xf.get("numFmtId", 0)) in BUILTIN_DATE_FORMATS | custom_dates:
                date_styles.add(i)
    workbook = ET.fromstring(z.read("xl/workbook.xml"))
    rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))}
    tables = []
    for sheet in workbook.findall("m:sheets/m:sheet", NS):
        dest = rels[sheet.get(f"{{{NS['r']}}}id")].lstrip("/")
        dest = dest if dest.startswith("xl/") else "xl/" + dest
        rows: list[list[str]] = []
        type_list: list[list[str]] = []
        for row_el in ET.fromstring(z.read(dest)).iter(f"{{{NS['m']}}}row"):
            row: dict[int, str] = {}
            cell_types: dict[int, str] = {}
            for i, c in enumerate(row_el.findall("m:c", NS)):
                col = _column(c.get("r")) if c.get("r") else i
                t = c.get("t", "n")
                v = c.find("m:v", NS)
                if t == "s" and v is not None:  # text: value_type decides (PESEL, phone, amount…)
                    value, type_ = shared[int(v.text)], ""
                elif t == "inlineStr":
                    value, type_ = "".join(x.text or "" for x in c.iter(f"{{{NS['m']}}}t")), ""
                elif v is None:
                    continue
                elif t == "b":
                    value, type_ = v.text or "", "boolean"
                elif t in ("str", "e"):
                    value, type_ = v.text or "", "text" if t == "str" else "error"
                elif t == "d" or int(c.get("s", 0)) in date_styles:
                    value, type_ = v.text or "", "date"
                else:
                    value, type_ = v.text or "", ""  # number — value_type decides
                row[col], cell_types[col] = value, type_
            if row:
                widths = max(row) + 1
                rows.append([row.get(k, "") for k in range(widths)])
                type_list.append([cell_types.get(k, "") for k in range(widths)])
        tables.append(_from_rows(sheet.get("name") or file_name, rows, "xlsx", type_list))
    return tables


def from_ods(data: bytes) -> list[Table]:
    ns = {
        "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
        "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
        "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
    }
    try:
        root = ET.fromstring(_zip(data, "ODS").read("content.xml"))
    except KeyError:
        raise FilterError("ODS: no content.xml (file damaged or encrypted)") from None
    tables = []
    repeated_attr = f"{{{ns['table']}}}number-columns-repeated"
    for t in root.iter(f"{{{ns['table']}}}table"):
        rows = []
        for row_el in t.iter(f"{{{ns['table']}}}table-row"):
            w = []
            for c in row_el:
                txt = "\n".join("".join(p.itertext()) for p in c.findall("text:p", ns))
                w += [txt] * min(int(c.get(repeated_attr, 1)), 1000)
            while w and not w[-1]:
                w.pop()
            rows.append(w)
        tables.append(_from_rows(t.get(f"{{{ns['table']}}}name") or "ODS", rows, "ods"))
    return tables


# SQL results printed in a terminal


def _symfony(lines: list[str]) -> list[list[str]] | None:
    """SymfonyStyle::table (dbal:run-sql): ' ---- ------ ' / header / ' ---- ------ ' / rows / ' ---- '."""
    dash_lines = [i for i, ln in enumerate(lines) if re.fullmatch(r"\s*-{2,}(?:\s+-{2,})*\s*", ln)]
    if len(dash_lines) < 2:
        return None
    regex = lines[dash_lines[0]]
    ranges = [(m.start(), m.end()) for m in re.finditer(r"-+", regex)]
    result = []
    for ln in lines[dash_lines[0] + 1 : dash_lines[-1]]:
        if ln in (lines[k] for k in dash_lines) or re.fullmatch(r"\s*-{2,}(?:\s+-{2,})*\s*", ln):
            continue
        result.append(
            [
                ln[s : (ranges[j + 1][0] if j + 1 < len(ranges) else len(ln))].strip()
                for j, (s, _) in enumerate(ranges)
            ]
        )
    return result or None


def _framed(lines: list[str]) -> list[list[str]] | None:
    """mysql (+----+) and psql (----+----, rows with |)."""
    if not any(re.fullmatch(r"\s*\+?-+(?:\+-+)+\+?\s*", ln) for ln in lines):
        return None
    result = []
    for ln in lines:
        if "|" not in ln or re.fullmatch(r"\s*\+?-+(?:\+-+)+\+?\s*", ln):
            continue
        ln = ln.strip()
        ln = ln.removeprefix("|")
        ln = ln.removesuffix("|")
        result.append([c.strip() for c in ln.split("|")])
    return result or None


VAR_DUMP_RE = re.compile(
    r'\["?([^"\]]+)"?\]\s*=>\s*\n?\s*(?:(string)\(\d+\)\s*"(.*?)"|(int|float|bool)\((.*?)\)|(NULL))', re.DOTALL
)
PRINT_R_RE = re.compile(r"^\s*\[([^\]]+)\]\s*=>\s?(.*)$", re.MULTILINE)


def _records(pairs: list[tuple[str, str]]) -> list[list[str]] | None:
    """(key, value) pairs from var_dump/print_r → rows (a new record when a key repeats)."""
    if len(pairs) < 2:
        return None
    keys: list[str] = []
    records: list[dict[str, str]] = [{}]
    for k, v in pairs:
        if k.isdigit() and not keys:
            continue  # row index of the outer array
        if k.isdigit() and k not in keys:
            continue
        if k in records[-1]:
            records.append({})
        records[-1][k] = v
        if k not in keys:
            keys.append(k)
    if not keys:
        return None
    return [keys] + [[r.get(k, "") for k in keys] for r in records if r]


def from_text(content: str, name: str = "result") -> list[Table]:
    """Recognises a table in command output. Not recognized → FilterError (no guessing, the text is not returned)."""
    lines = content.splitlines()
    for parser, fmt in ((_symfony, "symfony"), (_framed, "framed")):
        rows = parser(lines)
        if rows:
            return [Table(name, rows[0], rows[1:], fmt)]
    pairs = [
        (m.group(1), m.group(3) if m.group(2) else m.group(5) if m.group(4) else "NULL")
        for m in VAR_DUMP_RE.finditer(content)
    ]
    if rows := _records(pairs):
        return [Table(name, rows[0], rows[1:], "var_dump")]
    pairs = [
        (m.group(1).strip(), m.group(2).strip())
        for m in PRINT_R_RE.finditer(content)
        if not m.group(2).strip().startswith("Array")
    ]
    if rows := _records(pairs):
        return [Table(name, rows[0], rows[1:], "print_r")]
    non_empty = [ln for ln in lines if ln.strip()]
    if non_empty and all("\t" in ln for ln in non_empty):
        return [from_csv(content, name, "\t")]
    if len(non_empty) >= 2 and len({ln.count(",") for ln in non_empty[:20]}) == 1 and "," in non_empty[0]:
        return [from_csv(content, name, ",")]
    if len(non_empty) >= 2 and len({ln.count(";") for ln in non_empty[:20]}) == 1 and ";" in non_empty[0]:
        return [from_csv(content, name, ";")]
    raise FilterError(
        f"no table recognized in the output ({len(lines)} lines, {len(content)} characters) — values hidden. "
        "Formats: Symfony table (dbal:run-sql), mysql/psql, var_dump, print_r, CSV/TSV (mysql -B)"
    )


# --- summary ---------------------------------------------------------------------------------


def _safe_header(header: str, pseudonym_map: PseudonymMap, cfg: dict, forbidden: set[str]) -> str:
    """Column name: rules + words that also occur in the values (a header that is data)."""
    if not header.strip():
        return "(empty)"
    return text_mod.filter_text(
        header, cfg, rules_only=True, pseudonym_map=pseudonym_map, extra=text_mod.forbidden_words(header, forbidden)
    )[0]


def table_tokens(tables: list[Table]) -> set[str]:
    return text_mod.tokens(v for t in tables for w in t.rows for v in w)


# --- schema query results (information_schema, SHOW TABLES/COLUMNS, DESCRIBE) -----------------------
# The values are table and column names and types — metadata, not data. Recognised by the headers (all of them
# must be metadata columns); a value is shown in plain text only when it looks like an identifier / type / number
# and the rules find nothing in it; anything else (e.g. a column comment, a default text value) is masked.

SCHEMA_COLUMNS = {
    # information_schema.columns / tables / statistics / key_column_usage (MySQL, PostgreSQL)
    "table_catalog", "table_schema", "table_name", "column_name", "ordinal_position", "column_default",
    "is_nullable", "data_type", "character_maximum_length", "character_octet_length", "numeric_precision",
    "numeric_scale", "datetime_precision", "character_set_name", "collation_name", "column_type", "column_key",
    "extra", "privileges", "udt_name", "is_identity", "is_generated", "generation_expression", "table_type",
    "engine", "table_rows", "auto_increment", "table_collation", "index_name", "non_unique", "seq_in_index",
    "index_type", "constraint_name", "constraint_type", "referenced_table_schema", "referenced_table_name",
    "referenced_column_name", "schema_name", "default_character_set_name", "default_collation_name",
    "schemaname", "tablename", "indexname", "indexdef", "attname", "atttypid", "typname", "relname",
    # SHOW COLUMNS / DESCRIBE / SHOW INDEX (MySQL)
    "field", "type", "null", "key", "default", "table", "key_name", "collation", "cardinality",
    "sub_part", "packed", "visible", "expression",
}
# at least one of these — "type", "key", "default" alone may be columns of an ordinary table
SCHEMA_NAME_COLUMNS = {
    "table_name", "column_name", "schema_name", "index_name", "constraint_name", "field", "key_name",
    "tablename", "indexname", "attname", "relname",
}
SCHEMA_VALUE_RE = re.compile(
    r"[A-Za-z_][\w$]{0,63}(?:\.[A-Za-z_][\w$]{0,63})?"  # name (also schema.table)
    r"|[a-z ]+(?:\(\d+(?:,\s?\d+)?\))?(?: unsigned| zerofill| with(?:out)? time zone)*"  # type: varchar(255)
    r"|[-+]?\d+(?:\.\d+)?"
    r"|(?i:current_timestamp|now)(?:\(\d*\))?(?: on update current_timestamp(?:\(\d*\))?)?"
)


def _schema_result(tab: Table) -> bool:
    headers = {n.casefold() for n in tab.headers}
    tables = {n for n in headers if n.startswith("tables_in_")}  # SHOW TABLES
    return bool(headers) and headers - tables <= SCHEMA_COLUMNS and bool(headers & SCHEMA_NAME_COLUMNS or tables)


def _schema_value(v: str, cfg: dict, pseudonym_map: PseudonymMap) -> str:
    v = v.strip()
    if not v:
        return ""
    if SCHEMA_VALUE_RE.fullmatch(v) and text_mod.filter_text(v, cfg, rules_only=True, pseudonym_map=PseudonymMap())[0] == v:
        return v
    return pseudonym_map.mask_value(v, CLASSES.get(value_type(v), "t"))


def _describe_schema(tab: Table, cfg: dict, pseudonym_map: PseudonymMap) -> list[str]:
    widths = max([len(tab.headers)] + [len(w) for w in tab.rows])
    output = [
        (
            f"\n## {tab.name} — schema query result (format {tab.format}), rows: {len(tab.rows)}: "
            "names and types in plain text, other values masked\n"
        ),
        "| " + " | ".join(tab.headers) + " |",
        "|" + " --- |" * widths,
    ]
    for w in tab.rows:
        cells = [_schema_value(w[i] if i < len(w) else "", cfg, pseudonym_map) for i in range(widths)]
        output.append("| " + " | ".join(k.replace("|", "\\|") for k in cells) + " |")
    return output


# --- safe values in command output (piigate table) ---------------------------------------------------
# Plain text only for what cannot be linked to a person: NULL, booleans, short numbers (IDs, quantities, amounts),
# timestamps from technical columns (created_at…) and codes/statuses (active, refill_pending, RX_SENT). A column whose
# name suggests personal data or free text is masked entirely; every text value also goes through the rules and the
# first-name list. The keyword lists below are detection vocabulary (Polish and English column names).

PERSONAL_COLUMN_WORDS = (
    "imie", "imię", "imiona", "nazwisk", "name", "first", "last", "surname", "patient", "pacjent", "doctor", "lekarz",
    "email", "mail", "phone", "telefon", "tel", "mobile", "fax", "address", "adres", "street", "ulica", "city",
    "miasto", "zip", "postal", "poczt", "pesel", "ssn", "nip", "birth", "urodz", "dob", "gender", "plec", "płeć",
    "note", "notat", "comment", "komentarz", "opis", "description", "message", "wiadomo", "content", "tresc",
    "treść", "text", "body", "subject", "temat", "diagnos", "symptom", "objaw", "chorob", "disease", "allerg",
    "drug", "medic", "lek", "dawk", "dose", "ip", "login", "user", "username", "password", "haslo", "hasło", "token",
    "secret", "iban", "account", "konto", "card", "karta", "document", "dokument", "passport", "paszport", "license",
)
TECHNICAL_SUFFIXES = {"id", "uuid", "count", "type", "status", "code", "kod", "flag", "at", "nr", "no"}
TIME_COLUMN_RE = re.compile(r"(?i).*(?:_at|_on|created|updated|modified|deleted|sent|synced|timestamp)")
CODE_RE = re.compile(r"[a-z][a-z0-9]*(?:[_.-][a-z0-9]+){0,5}|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+){1,5}")


def _column_words(name: str) -> list[str]:
    return [s.casefold() for s in re.findall(r"[A-ZĄĆĘŁŃÓŚŹŻ]?[a-ząćęłńóśźż]+|[A-ZĄĆĘŁŃÓŚŹŻ]+(?![a-z])|\d+", name)]


def is_personal_column(name: str) -> bool:
    words = _column_words(name)
    if not words or words[-1] in TECHNICAL_SUFFIXES:
        return False
    return any(s.startswith(PERSONAL_COLUMN_WORDS) if len(s) > 3 else s in PERSONAL_COLUMN_WORDS for s in words)


def _safe_value(v: str, column: str, cfg: dict) -> bool:
    v = v.strip()
    type_ = value_type(v)
    if type_ in ("NULL", "boolean"):
        return True
    if type_ in ("integer", "decimal"):
        return len(re.sub(r"\D", "", v.split(".")[0].split(",")[0])) <= 8
    if type_ in ("date", "datetime", "time"):
        return bool(TIME_COLUMN_RE.fullmatch(column))
    if type_ != "text" or len(v) > 40 or not CODE_RE.fullmatch(v):
        return False
    if any(s in rules.first_names() or rules.SURNAME_SUFFIXES.fullmatch(s.capitalize()) for s in re.split(r"[_.-]", v.casefold())):
        return False
    return all(text_mod.filter_text(w, cfg, rules_only=True, pseudonym_map=PseudonymMap())[0] == w for w in (v, v.capitalize()))


def describe(
    tables: list[Table],
    cfg: dict,
    *,
    source: str,
    sample_rows: int | None = None,
    pseudonym_map: PseudonymMap | None = None,
    safe_plain: bool = False,
) -> str:
    """`safe_plain` (piigate table): safe values in the rows are shown in plain text, the rest masked; 50 rows by default."""
    pseudonym_map = pseudonym_map or PseudonymMap()
    table_cfg = cfg["tables"]
    default_rows = table_cfg.get("result_rows", 50) if safe_plain else table_cfg.get("sample_rows", 0)
    n_sample = default_rows if sample_rows is None else sample_rows
    plain = {k.casefold() for k in table_cfg.get("plain_columns", [])}
    sensitive = project.columns(cfg)
    forbidden = table_tokens(tables)
    output = [
        f"[piigate] {source}: "
        + ("structure and safe values (numbers, codes, statuses), " if safe_plain else "structure only, ")
        + "other values masked (same value → same mask)."
    ]
    for number, tab in enumerate(tables, 1):
        if _schema_result(tab):
            output += _describe_schema(tab, cfg, pseudonym_map)
            continue
        name = text_mod.filter_name(tab.name, cfg, pseudonym_map, forbidden)
        widths = max([len(tab.headers)] + [len(w) for w in tab.rows]) if (tab.headers or tab.rows) else 0
        headers = [(tab.headers[i] if i < len(tab.headers) else f"column_{i + 1}") for i in range(widths)]
        output.append(
            f"\n## Table {number}: {name} — format {tab.format}, data rows: {len(tab.rows)}, columns: {widths}\n"
        )
        if not widths:
            output.append("(empty)")
            continue
        output.append("| # | column | type | empty | unique | length min–max | notes |")
        output.append("| --- | --- | --- | --- | --- | --- | --- |")
        for i in range(widths):
            values = [w[i] if i < len(w) else "" for w in tab.rows]
            src_types = [tz[i] if i < len(tz) else "" for tz in tab.source_types] if tab.source_types else []
            type_list = [tz or value_type(v) for v, tz in zip(values, src_types or [""] * len(values))]
            non_empty = [(v, t) for v, t in zip(values, type_list) if t != "empty" and v.strip()]
            counts: dict[str, int] = {}
            for _, t in non_empty:
                counts[t] = counts.get(t, 0) + 1
            if counts:
                dominant = max(counts, key=counts.get)
                col_type = (
                    dominant
                    if counts[dominant] >= 0.9 * len(non_empty)
                    else "mixed ("
                    + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda x: -x[1]))
                    + ")"
                )
            else:
                col_type = "empty"
            lengths = [len(v) for v, _ in non_empty]
            notes = []
            if any(t in ("PESEL", "email", "phone") for t in counts):
                notes.append("personal data: " + ", ".join(t for t in counts if t in ("PESEL", "email", "phone")))
            col_name = _safe_header(headers[i], pseudonym_map, cfg, forbidden)
            if headers[i].casefold() in plain:
                notes.append("plain column (configuration)")
            if headers[i].casefold() in sensitive:
                notes.append("sensitive column (project filters)")
            output.append(
                f"| {i + 1} | {col_name} | {col_type} | {len(values) - len(non_empty)} | "
                f"{len({v for v, _ in non_empty})} | {(str(min(lengths)) + '–' + str(max(lengths))) if lengths else '—'} | "
                f"{'; '.join(notes) or '—'} |"
            )
        if n_sample:
            personal = {i for i in range(widths) if headers[i].casefold() in sensitive or is_personal_column(headers[i])}
            output.append(
                f"\nFirst {min(n_sample, len(tab.rows))} rows ("
                + ("numbers, codes and statuses in plain text, the rest — " if safe_plain else "")
                + "masks; n: number, d: date, t: text, e: e-mail, b: boolean):\n"
            )
            output.append("| " + " | ".join(_safe_header(n, pseudonym_map, cfg, forbidden) for n in headers) + " |")
            output.append("|" + " --- |" * widths)
            for w in tab.rows[:n_sample]:
                cells = []
                for i in range(widths):
                    v = w[i] if i < len(w) else ""
                    if not v.strip():
                        cells.append("")
                    elif headers[i].casefold() in plain:
                        cells.append(v.replace("|", "\\|").replace("\n", " "))
                    elif safe_plain and i not in personal and _safe_value(v, headers[i], cfg):
                        cells.append(v.strip())
                    else:
                        cells.append(pseudonym_map.mask_value(v, CLASSES.get(value_type(v), "t")))
                output.append("| " + " | ".join(cells) + " |")
    return "\n".join(output) + "\n"


__all__ = ["Table", "_decode", "describe", "from_csv", "from_ods", "from_text", "from_xlsx"]
