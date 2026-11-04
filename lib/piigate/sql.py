"""SQL scripts: telling a script from a data dump, and SQL identifiers from data (issue #28).

Two questions, both answered from the content, never from the file name:

- `is_script(data)`: a `.sql` file without data records (no INSERT ... VALUES, no COPY ... FROM stdin with rows) is
  code — statements such as UPDATE, DELETE, TRUNCATE — and may be read like any other code. Anything that cannot be
  judged (too large, binary or compressed, not text) is treated as a dump: fail closed.
- `drop_identifiers(text, fragments)`: in a text that is a SQL script, table and column names (`wp_users`,
  `user_email`) are not names of people or places. A hit of type PERSON / ADDRESS / ORG is kept only where it lies in
  a string literal or a comment — that is where the data of a script is.

Standard library only; no import of the rules (fragments are rebuilt with `dataclasses.replace`).
"""

import bisect
import dataclasses
import re

# --- scanning ---------------------------------------------------------------------------------------

# A linear scanner (str.find, no regex loops over single characters): an unclosed quote in a large text must not cost
# memory — a `(?:''|[^'])*` loop keeps one backtracking state per character (~285 MB per MB of text).
# Backslash escapes inside literals (`'it\\'s'`) exist in MySQL but not in standard SQL; the two readings can split the
# text into literals differently, so the data regions of both are used (more data = more filtering).
_START = re.compile(r"--|#|/\*|\$|'|\"|`")
_DOLLAR = re.compile(r"\$(?:[A-Za-z_]\w*)?\$")
_QUOTE_OR_BACKSLASH = re.compile(r"['\\]")


def _quoted_end(text: str, i: int, quote: str, backslash: bool) -> int:
    """End of the quoted region that opens at text[i] (a doubled quote is an escaped quote); unclosed — end of text."""
    j = i + 1
    if backslash and quote == "'":
        while m := _QUOTE_OR_BACKSLASH.search(text, j):
            j = m.end()
            if m.group() == "\\":
                j += 1  # the escaped character
            elif text.startswith("'", j):
                j += 1  # ''
            else:
                return j
        return len(text)
    while (j := text.find(quote, j)) >= 0:
        if text.startswith(quote, j + 1):
            j += 2
        else:
            return j + 1
    return len(text)


def _regions(text: str, backslash: bool) -> list[tuple[int, int, str]]:
    regions: list[tuple[int, int, str]] = []
    pos = 0
    while m := _START.search(text, pos):
        i, token = m.start(), m.group()
        if token in ("--", "#"):
            end, kind = text.find("\n", i), "comment"
            end = len(text) if end < 0 else end
        elif token == "/*":
            end, kind = text.find("*/", i + 2), "comment"
            end = len(text) if end < 0 else end + 2
        elif token == "$":
            d = _DOLLAR.match(text, i)
            if not d:
                pos = i + 1
                continue
            end, kind = text.find(d.group(), d.end()), "quoted"
            end = len(text) if end < 0 else end + len(d.group())
        elif token == "`":
            end, kind = _quoted_end(text, i, "`", backslash), "ident"
        elif token == '"':
            end, kind = _quoted_end(text, i, '"', backslash), "double"
        else:
            end, kind = _quoted_end(text, i, "'", backslash), "literal"
        regions.append((i, end, kind))
        pos = end
    return regions


# data: a string literal, a comment, a dollar-quoted body, a double-quoted string (MySQL: a literal)
DATA_KINDS = {"comment", "quoted", "double", "literal"}


def data_spans(text: str) -> list[tuple[int, int]]:
    """Merged character ranges that carry data (literals, comments) under either reading of the quotes."""
    spans = sorted((s, k) for backslash in (True, False) for s, k, kind in _regions(text, backslash) if kind in DATA_KINDS)
    merged: list[tuple[int, int]] = []
    for s, k in spans:
        if merged and s <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], k))
        else:
            merged.append((s, k))
    return merged


# --- is the text a SQL script? ----------------------------------------------------------------------

_ID = r"(?:[\w.$]+|`[^`]*`|\"~\"|'~')"
_STATEMENTS = tuple(
    re.compile(p, re.IGNORECASE | re.DOTALL)
    for p in (
        rf"UPDATE\s+(?:LOW_PRIORITY\s+|IGNORE\s+|ONLY\s+)*{_ID}(?:\s+(?:AS\s+)?\w+)?\s+SET\b",
        rf"DELETE\s+FROM\s+(?:ONLY\s+)?{_ID}",
        rf"TRUNCATE\s+TABLE\s+{_ID}",
        r"TRUNCATE\s+[\w.$`]*[_.`][\w.$`]*(?:\s*,\s*[\w.$`]+)*\s*$",  # TRUNCATE wp_options
        r"(?:INSERT|REPLACE)\s+(?:LOW_PRIORITY\s+|DELAYED\s+|HIGH_PRIORITY\s+|IGNORE\s+)*INTO\b",
        r"SET\s+(?:SESSION\s+|GLOBAL\s+|LOCAL\s+)?(?:@@?[\w.]+|[\w.]+)\s*(?:=|:=|TO\b)",
        r"SET\s+(?:NAMES|CHARACTER\s+SET|TIME\s+ZONE|FOREIGN_KEY_CHECKS|SQL_MODE)\b",
        r"ALTER\s+(?:TABLE|DATABASE|SCHEMA|INDEX|SEQUENCE|VIEW)\b",
        r"CREATE\s+(?:OR\s+REPLACE\s+)?(?:TEMP(?:ORARY)?\s+|UNIQUE\s+|UNLOGGED\s+)*"
        r"(?:TABLE|INDEX|VIEW|DATABASE|SCHEMA|SEQUENCE|EXTENSION)\b",
        r"DROP\s+(?:TABLE|INDEX|VIEW|DATABASE|SCHEMA|SEQUENCE|EXTENSION|TRIGGER)\b",
        r"(?:BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION|UNLOCK\s+TABLES)\s*$",
        r"LOCK\s+TABLES?\b",
        rf"USE\s+{_ID}\s*$",
        r"(?:ANALYZE|OPTIMIZE|VACUUM)\s+(?:TABLE\b|[\w.`]+\s*$|$)",
    )
)
_HINT = re.compile(r"(?i)\b(?:UPDATE|DELETE|TRUNCATE|INSERT|REPLACE|ALTER|CREATE|DROP|SET|BEGIN|COMMIT|USE|LOCK|UNLOCK)\b")


def _skeleton(text: str, spans: list[tuple[int, int]]) -> str:
    """The text without data: literals become '~', comments spaces — what is left is statements and identifiers."""
    out, pos = [], 0
    for s, k in spans:
        out.append(text[pos:s])
        piece = text[s:k]
        out.append(" " if piece[:1] in ("-", "#", "/") else '"~"' if piece[:1] == '"' else "'~'")
        pos = k
    out.append(text[pos:])
    return "".join(out)


def looks_like_script(text: str) -> bool:
    """Every statement of the text (split at `;` outside literals and comments) has the shape of a SQL statement:
    prose that happens to contain `UPDATE` or `SET` is not a script, so its words keep their filtering."""
    if ";" not in text and not text.lstrip().upper().startswith(("UPDATE", "DELETE", "TRUNCATE", "SET", "INSERT")):
        return False
    if not _HINT.search(text):
        return False
    skeleton = _skeleton(text, data_spans(text))
    statements = [s.strip() for s in skeleton.split(";") if s.strip()]
    # only the start of a statement is matched (bounded work); the patterns anchored at the end then fail on a long one
    return bool(statements) and all(any(r.match(s if len(s) <= 2000 else s[:2000] + "\0") for r in _STATEMENTS) for s in statements)


_IDENTIFIER = re.compile(r"[\w.$`]+")
_EDGE = " \t\r\n=,()<>;"  # whitespace and operators around an identifier


def drop_identifiers(text: str, fragments: list) -> list:
    """Fragments of type PERSON / ADDRESS / ORG (Fragment objects) cut to the parts that lie in literals and comments,
    when `text` is a SQL script; otherwise unchanged. What is outside them is code: keywords, table and column names —
    but only text shaped like an identifier (`wp_users`, `t.col`, `` `col` ``, no spaces) is dropped: a name written
    outside a literal (`SET name = Jan Kowalski`) keeps its hit, because "every statement starts with a keyword" is
    something a prepared text can imitate."""
    candidates = [f for f in fragments if f.type_ in ("PERSON", "ADDRESS", "ORG") and f.weight < 4]
    if not candidates or not looks_like_script(text):
        return fragments
    spans = data_spans(text)
    ends = [k for _, k in spans]
    chosen = {id(f) for f in candidates}
    result = [f for f in fragments if id(f) not in chosen]
    for f in candidates:
        inside: list[tuple[int, int]] = []
        outside: list[tuple[int, int]] = []
        position = f.start
        for i in range(bisect.bisect_right(ends, f.start), len(spans)):
            s, k = spans[i]
            if s >= f.end:
                break
            lo, hi = max(s, f.start), min(k, f.end)
            if lo > position:
                outside.append((position, lo))
            inside.append((lo, hi))
            position = hi
        if position < f.end:
            outside.append((position, f.end))
        if any((piece := text[lo:hi].strip(_EDGE)) and not _IDENTIFIER.fullmatch(piece) for lo, hi in outside):
            result.append(f)  # not an identifier outside a literal: the hit stays whole
            continue
        for lo, hi in inside:
            result.append(f if (lo, hi) == (f.start, f.end) else dataclasses.replace(f, start=lo, end=hi))
    return sorted(result, key=lambda f: (f.start, f.end))


# --- script or dump? --------------------------------------------------------------------------------

_BINARY_MAGIC = (b"\x1f\x8b", b"BZh", b"PK\x03\x04", b"\xfd7zXZ", b"7z\xbc\xaf", b"PGDMP", b"\x28\xb5\x2f\xfd", b"SQLite format")
# comments are removed only where no literal could be involved: a short block comment without quotes and semicolons
# (not /*! ... */, which MySQL executes) and a whole line that starts with `--`
_LINE_COMMENT = re.compile(r"^[ \t]*--[^'\";\n]*$", re.MULTILINE)
_MAX_COMMENT = 2000


def _strip_block_comments(text: str) -> str:
    """Linear: every `/*` is looked at once; an unclosed or long one stays in the text (it may hide a literal)."""
    out, pos, close = [], 0, -2
    while (i := text.find("/*", pos)) >= 0:
        if close < i + 2:
            close = text.find("*/", i + 2)
            if close < 0:
                break
        body = text[i + 2 : close]
        if close - i <= _MAX_COMMENT and not text.startswith("!", i + 2) and not re.search(r"['\";]", body):
            out += [text[pos:i], " "]
            pos = close + 2
        else:
            out.append(text[pos : i + 2])
            pos = i + 2
    out.append(text[pos:])
    return "".join(out)


_CONDITIONAL_OPEN = re.compile(r"/\*!\d*")
_COPY_WORD = re.compile(r"(?i)\bCOPY\b")
_FROM_STDIN = re.compile(r"(?i)\bFROM\s+stdin\b")
_NO_ROWS = re.compile(r"[^\n]*\r?\n\\\.")  # the line after COPY ... FROM stdin is the terminator
# INSERT, REPLACE INTO, and REPLACE without INTO followed by a table name and `(`, SET, VALUES or SELECT (not the
# function `REPLACE(a, b, c)`)
_INSERT = re.compile(
    r"(?i)\bINSERT\b|\bREPLACE\s+(?:(?:LOW_PRIORITY|DELAYED)\s+)?INTO\b"
    r"|\bREPLACE\s+(?:(?:LOW_PRIORITY|DELAYED)\s+)?(?!INTO\b)(?:[\w.$]+|`[^`]*`)\s*(?:\(|SET\b|VALUES\b|SELECT\b)"
)
_VALUES_CALL = re.compile(r"(?i)\bVALUES\s*(?:ROW\s*)?\(")


def _copy_from_stdin_with_rows(t: str) -> bool:
    """`COPY … FROM stdin` followed by rows, however long the column list is. Linear: each `FROM stdin` is matched with
    the nearest `COPY` before it (no `;` in between), and the text between them is scanned for `;` only once."""
    copies = [m.start() for m in _COPY_WORD.finditer(t)]
    if not copies:
        return False
    index, seen_to, has_semicolon, current = -1, 0, False, -1
    for m in _FROM_STDIN.finditer(t):
        while index + 1 < len(copies) and copies[index + 1] < m.start():
            index += 1
        if index < 0:
            continue
        if copies[index] != current:
            current, seen_to, has_semicolon = copies[index], copies[index], False
        if not has_semicolon and seen_to < m.start():
            has_semicolon = t.find(";", seen_to, m.start()) >= 0
            seen_to = m.start()
        if not has_semicolon and not _NO_ROWS.match(t, m.end()):
            return True
    return False


def has_data_records(text: str) -> bool:
    """INSERT / REPLACE with values (or a literal), COPY ... FROM stdin with rows, a VALUES list. When in doubt (an
    INSERT inside a comment that may be a literal) the answer is yes — fail closed."""
    t = _CONDITIONAL_OPEN.sub(" ", _strip_block_comments(_LINE_COMMENT.sub(" ", text)))
    if _VALUES_CALL.search(t) or _copy_from_stdin_with_rows(t):
        return True
    for m in _INSERT.finditer(t):
        end = t.find(";", m.end(), m.end() + 20000)
        if end < 0:  # no end of the statement within reach — cannot judge it: data
            return True
        statement = t[m.start() : end]
        # INSERT ... SET, DEFAULT VALUES, unrecognized, or a SELECT of literals (a double-quoted string is a literal in
        # MySQL); only a plain SELECT passes
        if re.search(r"(?i)\bSET\b", statement) or not re.search(r"(?i)\bSELECT\b", statement) or "'" in statement or '"' in statement:
            return True
    return False


SCRIPT_LIMIT = 10 * 1024 * 1024  # a larger .sql file is a dump until proven otherwise


def is_script(data: bytes, limit_bytes: int, decode) -> bool:
    """A `.sql` file that is code, not a dump: text, within the size limit, without data records. Everything else —
    too large, binary or compressed, undecodable — is a dump (fail closed)."""
    if len(data) > limit_bytes or b"\0" in data or data.startswith(_BINARY_MAGIC):
        return False
    try:
        text = decode(data)
    except Exception:  # noqa: BLE001 — any failure to read it as text: a dump
        return False
    return not has_data_records(text)
