"""Project filters: `.claude/piigate.json` in the project repo — knowledge about its data, tightening only.

The file is looked up in the nearest ancestor of the working directory (up to the home directory). The allowed
fields (`FIELDS`) only add protection: patterns with their own labels, columns and tables with personal data,
sensitive directories and extensions. A field outside the list (e.g. `exempt_directories`, `plain_words`,
`plain_columns`) makes the file invalid — exceptions are changed only by a human in the global configuration. The
file holds patterns, not values (a list of real surnames in the repo = personal data).

Removing an entry would also loosen protection, and the model can edit the file — so the filter keeps an approved
snapshot in its (protected) data directory and applies the UNION of the snapshot and the current file. A file that
only adds entries becomes the new snapshot by itself; removing or changing an entry is approved by a human
(`piigate project approve` in their own terminal).

Invalid file (JSON, a loosening field, a bad or expensive pattern) → `cfg["project"]["error"]`: the gate then denies
everything in the project except reading and editing the file itself, and the `piigate` CLI and the MCP server
refuse every operation (deny by default).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from . import FilterError, config
from .rules import Fragment

FILE = Path(".claude") / "piigate.json"
FIELDS = {"_description", "patterns", "sensitive_columns", "directories", "tables", "extensions"}
LIST_FIELDS = ("sensitive_columns", "directories", "tables", "extensions")
MAX_PATTERNS, MAX_LENGTH = 50, 200
LABEL_RE = re.compile(r"[A-Z][A-Z_]{0,28}[A-Z]")  # like pseudonyms in the map: LABEL_3
NAME_RE = re.compile(r"[\w$.-]{1,64}")  # column, table
EXTENSION_RE = re.compile(r"\.[\w-]{1,15}")
PROBE_TIMEOUT_S = 2
MAX_BOUND, MAX_PRODUCT, MAX_CHARS = 64, 1000, 64
MAX_FILE_SIZE = 64 * 1024


def _key(root: str) -> str:
    return hashlib.sha256(root.encode()).hexdigest()[:16]


def snapshot_dir() -> Path:
    return config.data_dir() / "projects"


def _snapshot_file(root: str) -> Path:
    return snapshot_dir() / f"{_key(root)}.json"


def find(cwd: str | None) -> str | None:
    """Project directory: the nearest ancestor with `.claude/piigate.json` or with an approved snapshot (file deleted)."""
    if not cwd:
        return None
    p = Path(os.path.realpath(cwd))
    home_dir = Path(config.home_dir())
    for folder in (p, *p.parents):
        if folder == home_dir or folder == Path("/"):
            break
        if (folder / FILE).is_file() or _snapshot_file(str(folder)).is_file():
            return str(folder)
    return None


# --- validation -----------------------------------------------------------------------------------


def _parser_module():
    try:
        from re import _constants as C
        from re import _parser as P
    except ImportError:
        return None, None
    return C, P


def _repeats(C) -> set:
    return {C.MAX_REPEAT, C.MIN_REPEAT} | ({C.POSSESSIVE_REPEAT} if hasattr(C, "POSSESSIVE_REPEAT") else set())


def _children(op, av, C) -> list | None:
    """Sub-sequences of a tree node; [] — a leaf; None — an opcode outside the allow-list (rejected, safe default)."""
    if op in (C.LITERAL, C.NOT_LITERAL, C.IN, C.ANY, C.AT, C.CATEGORY):
        return []
    if op in _repeats(C):
        return [av[2]]
    if op == C.SUBPATTERN:
        return [av[-1]]
    if op == C.BRANCH:
        return list(av[1])
    if op in (C.ASSERT, C.ASSERT_NOT):
        return [av[1]]
    if op == getattr(C, "ATOMIC_GROUP", object()):
        return [av]
    return None


def _safe_tree(pattern: str) -> str | None:
    """Static analysis of the expression tree (re._parser): None or the reason for rejection. Project identifiers have
    a fixed or nearly fixed length, so the number of ways to match from one position must be small:
    - only known tree opcodes (literals, classes, anchors, groups, alternation, repeats, lookahead, atomic groups);
    - every quantifier has an upper bound ≤ MAX_BOUND (`+`, `*`, `{n,}` — rejected);
    - the body of a repeat with a bound > 1 has a fixed width (no `{m,n}` with m≠n and no alternation inside — `(a+)+`,
      `(a|aa){1,64}`, `(?:a{1,10}){1,10}` rejected);
    - ambiguity (product of `max−min+1` in a sequence, sum over alternation branches) ≤ MAX_PRODUCT —
      `\\d{1,64}\\d{1,64}x` rejected, `\\b\\d{3}(?:-\\d{3}){2}\\b` and `(?:AB|CD)-\\d{6}` pass;
    - the pattern's character set (for probe texts) ≤ MAX_CHARS."""
    C, P = _parser_module()
    if C is None:
        return "cannot analyse the pattern with this Python version"

    class Rejected(Exception):
        pass

    def ambiguity(elements) -> int:
        """Number of ways to match the sequence from one position (upper bound); Rejected on a bad structure."""
        result = 1
        for op, av in elements:
            if op in (C.GROUPREF, C.GROUPREF_EXISTS):
                raise Rejected("backreference (\\1)")
            children = _children(op, av, C)
            if children is None:
                raise Rejected(f"construct {op} is not on the allow-list")
            if op in (C.ASSERT, C.ASSERT_NOT) and av[0] < 0:
                raise Rejected("lookbehind (?<=…)/(?<!…)")
            if op in _repeats(C):
                mn, mx, content = av
                if mx == C.MAXREPEAT or mx > MAX_BOUND:
                    raise Rejected(
                        f"quantifier without an upper bound or above {MAX_BOUND} (+, *, {{n,}}) — use {{1,{MAX_BOUND}}}"
                    )
                inner = ambiguity(content)
                if mx > 1 and (inner > 1 or _has_alternation(content, C)):
                    raise Rejected("repeat of a variable-width body ((a+)+, (a|aa){1,64}, (a{1,9}){1,9})")
                result *= (mx - mn + 1) * inner
            elif op == C.BRANCH:
                result *= sum(ambiguity(g) for g in children)
            else:
                for d in children:
                    result *= ambiguity(d)
            if result > MAX_PRODUCT:
                raise Rejected(f"too many ways to match (over {MAX_PRODUCT}) — narrow the quantifiers")
        return result

    try:
        ambiguity(P.parse(pattern))
        all_chars, _ = _pattern_chars(pattern)
    except Rejected as e:
        return str(e)
    except Exception as e:  # noqa: BLE001 — analysis error = rejection (deny by default)
        return f"cannot analyse the pattern ({type(e).__name__})"
    if len(all_chars) > MAX_CHARS:
        return f"over {MAX_CHARS} distinct characters in the pattern — narrow the character classes"
    return None


def _has_alternation(elements, C) -> bool:
    for op, av in elements:
        if op == C.BRANCH:
            return True
        if any(_has_alternation(d, C) for d in _children(op, av, C) or []):
            return True
    return False


def _pattern_chars(pattern: str) -> tuple[list[str], list[list[str]]]:
    """Characters the pattern matches (literals, range ends, representatives of categories and negations) — for the
    whole pattern and separately for the body of every repeat (probe texts are built per repeat)."""
    C, P = _parser_module()
    categories = {"CATEGORY_DIGIT": "1", "CATEGORY_WORD": "a", "CATEGORY_SPACE": " "}
    complement_chars = {"a", "1", " ", "!", "-"}  # representatives of complements ([^x], \D, \W, .)
    bodies: list[list[str]] = []

    def collect(elements) -> set[str]:
        chars: set[str] = set()
        for op, av in elements:
            if op == C.LITERAL:
                chars.add(chr(av))
            elif op == C.NOT_LITERAL:
                chars |= {chr(av)} | complement_chars
            elif op == C.IN:
                for op2, av2 in av:
                    if op2 == C.LITERAL:
                        chars.add(chr(av2))
                    elif op2 == C.RANGE:
                        chars.update({chr(av2[0]), chr(av2[1]), chr((av2[0] + av2[1]) // 2)})
                    elif op2 == C.CATEGORY:
                        chars |= {categories.get(str(av2), "a")} | (complement_chars if "NOT" in str(av2) else set())
                    elif op2 == C.NEGATE:
                        chars |= complement_chars
            elif op in (C.ANY, C.CATEGORY):
                chars |= complement_chars
            for d in _children(op, av, C) or []:
                inner = collect(d)
                if op in _repeats(C):
                    bodies.append(sorted(inner))
                chars |= inner
        return chars

    all_chars = set(collect(P.parse(pattern))) if C is not None else set()
    all_chars |= {ch for ch in pattern if ch.isalnum() or ch in "-_/.:@ "}
    return sorted(all_chars), bodies


PROBE_SCRIPT = r"""
import re, sys, json
data = json.loads(sys.stdin.read())
general = [c * 3000 + "!" for c in ("a", "A", "1", " ", "-", "aA1 ", "AB-", "_")]
for pattern, groups in data:
    r = re.compile(pattern)
    texts = list(general)
    for chars in groups:
        texts += [ch * 3000 + "!" for ch in chars]
        texts += ["".join(chars) * (3000 // max(1, len(chars))) + "!", "".join(reversed(chars)) * (3000 // max(1, len(chars)))]
    for t in texts:
        for _ in r.finditer(t):
            pass
"""


def _probe(patterns: list[str]) -> str | None:
    """Runs the patterns on adversarial texts (built from the characters of the whole pattern and of every repeat body)
    in a separate process with a time limit (re cannot be interrupted). The last line of defence is in
    hooks/run.sh: a filter timeout = output hidden."""
    data = []
    for w in patterns:
        all_chars, bodies = _pattern_chars(w)
        data.append((w, [all_chars, *bodies[:20]]))
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-c", PROBE_SCRIPT],
            input=json.dumps(data),
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"pattern too expensive (probe over {PROBE_TIMEOUT_S} s — backtracking)"
    except OSError as e:
        return f"cannot check the patterns ({type(e).__name__})"
    return None if result.returncode == 0 else "pattern probe failed"


def validate(data, source: str) -> dict:
    """Project file dict → canonical form (sorted lists); FilterError on anything suspicious."""
    if not isinstance(data, dict):
        raise FilterError(f"{source}: a JSON object expected")
    complement_chars = sorted(set(data) - FIELDS)
    if complement_chars:
        raise FilterError(
            f"{source}: fields {', '.join(complement_chars)} not allowed — a project file can only tighten protection "
            f"(allowed: {', '.join(sorted(FIELDS - {'_description'}))}); exceptions only in the human's global configuration"
        )
    result: dict = {k: [] for k in ("patterns", *LIST_FIELDS)}
    patterns = data.get("patterns", [])
    if not isinstance(patterns, list) or len(patterns) > MAX_PATTERNS:
        raise FilterError(f"{source}: `patterns` — a list of up to {MAX_PATTERNS} items")
    for i, w in enumerate(patterns, 1):
        if not isinstance(w, dict) or set(w) - {"pattern", "label", "description"}:
            raise FilterError(f"{source}: pattern {i} — an object with the fields pattern, label, description")
        pat, lbl = w.get("pattern"), w.get("label")
        if not isinstance(pat, str) or not pat or len(pat) > MAX_LENGTH:
            raise FilterError(f"{source}: pattern {i} — a string of 1–{MAX_LENGTH} characters")
        if not isinstance(lbl, str) or not LABEL_RE.fullmatch(lbl):
            raise FilterError(f"{source}: pattern {i} — label in CAPITALS and _ (2–30 characters), e.g. PATIENT_ID")
        try:
            r = re.compile(pat)
        except re.error as e:
            raise FilterError(f"{source}: pattern {i} — syntax error ({e.msg})") from None
        if r.search(""):
            raise FilterError(f"{source}: pattern {i} matches the empty string")
        if reason := _safe_tree(pat):
            raise FilterError(f"{source}: pattern {i} — {reason}")
        result["patterns"].append({"pattern": pat, "label": lbl})
    for field_name in LIST_FIELDS:
        values = data.get(field_name, [])
        if not isinstance(values, list) or not all(isinstance(v, str) and v for v in values):
            raise FilterError(f"{source}: `{field_name}` — a list of strings")
        for v in values:
            if field_name in ("sensitive_columns", "tables") and not NAME_RE.fullmatch(v):
                raise FilterError(f"{source}: `{field_name}` — name {v!r} outside [A-Za-z0-9_$.-]")
            if field_name == "extensions" and not EXTENSION_RE.fullmatch(v):
                raise FilterError(f"{source}: `extensions` — the form .ext")
        result[field_name] = sorted(set(values))
    result["patterns"] = sorted({(w["pattern"], w["label"]) for w in result["patterns"]})
    result["patterns"] = [{"pattern": w, "label": e} for w, e in result["patterns"]]
    return result


def total(a: dict, b: dict) -> dict:
    result = {field_name: sorted(set(a.get(field_name, [])) | set(b.get(field_name, []))) for field_name in LIST_FIELDS}
    pairs = {(w["pattern"], w["label"]) for w in a.get("patterns", []) + b.get("patterns", [])}
    result["patterns"] = [{"pattern": w, "label": e} for w, e in sorted(pairs)]
    return result


def missing(current: dict, snapshot: dict) -> dict:
    """What from the approved snapshot is missing in the current file (a loosening waiting for a human)."""
    result = {field_name: sorted(set(snapshot.get(field_name, [])) - set(current.get(field_name, []))) for field_name in LIST_FIELDS}
    present = {(w["pattern"], w["label"]) for w in current.get("patterns", [])}
    result["patterns"] = [w for w in snapshot.get("patterns", []) if (w["pattern"], w["label"]) not in present]
    return {k: v for k, v in result.items() if v}


def _digest(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def _save(file: Path, data: dict) -> None:
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, file)


def _verified(digest: str, patterns: list[str]) -> str | None:
    """Subprocess probe once per pattern set (the result is kept in the filter's data directory)."""
    file = snapshot_dir() / "verified.json"
    try:
        known = set(json.loads(file.read_text(encoding="utf-8")))
    except (OSError, ValueError, TypeError):
        known = set()
    if digest in known:
        return None
    if reason := _probe(patterns):
        return reason
    try:
        _save(file, sorted(known | {digest})[-500:])
    except OSError:
        pass
    return None


def load_current(root: str) -> dict:
    file = Path(root) / FILE
    if not file.is_file():
        return validate({}, str(file))
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise FilterError(f"{file}: unreadable JSON ({type(e).__name__})") from None
    return validate(data, str(file))


def load_snapshot(root: str) -> dict | None:
    file = _snapshot_file(root)
    if not file.is_file():
        return None
    try:
        return validate(json.loads(file.read_text(encoding="utf-8"))["approved"], "approved snapshot")
    except (OSError, ValueError, KeyError, TypeError):
        raise FilterError(f"approved snapshot {file} is corrupt — a human must run: piigate project approve") from None


def approve(root: str) -> dict:
    """The current file becomes the snapshot (removals take effect) — human only (the piigate CLI)."""
    current = load_current(root)
    _save(_snapshot_file(root), {"path": root, "approved": current})
    return current


def state(cwd: str | None) -> dict | None:
    """Effective project filters (the union) or {"error": …}; None — a project without a file and without a snapshot."""
    root = find(cwd)
    if root is None:
        return None
    file = str(Path(root) / FILE)
    try:
        current = load_current(root)
        snapshot = load_snapshot(root)
        if snapshot is None or not missing(current, snapshot):
            if snapshot != current:
                try:
                    _save(_snapshot_file(root), {"path": root, "approved": current})
                except OSError:
                    pass  # without the snapshot the union still applies in this call
            snapshot = current
        effective = total(current, snapshot)
        digest = _digest(effective)
        if effective["patterns"] and (reason := _verified(digest, [w["pattern"] for w in effective["patterns"]])):
            raise FilterError(f"{file}: {reason}")
    except FilterError as e:
        return {"root": root, "file": file, "error": str(e)}
    effective["patterns_re"] = [(re.compile(w["pattern"]), w["label"]) for w in effective["patterns"]]
    return {
        "root": root,
        "file": file,
        "digest": digest,
        "pending": missing(current, snapshot),
        **effective,
    }


def _dirs(p: dict) -> list[str]:
    return [k if k.startswith(("/", "~")) else str(Path(p["root"]) / k) for k in p["directories"]]


def merged_state(directories: list[str | None]) -> dict | None:
    """Union of the filters of several projects (cwd, which the agent changes with `cd`, and the session directory,
    which it cannot change). An error in one file does NOT drop the others' filters: valid ones still apply, and the
    error adds a denial (`error`, `file`)."""
    states, roots = [], set()
    for folder in directories:
        root = find(folder)
        if root and root not in roots:
            roots.add(root)
            if st := state(root):
                states.append(st)
    if not states:
        return None
    valid = [st for st in states if not st.get("error")]
    invalid = [st for st in states if st.get("error")]
    result: dict = {
        "root": (valid or invalid)[0]["root"],
        "file": (valid or invalid)[0]["file"],
        "patterns": [],
        **{field_name: [] for field_name in LIST_FIELDS},
        "patterns_re": [],
        "pending": {},
        "directories_abs": [],
    }
    for st in valid:
        result.update(total(result, st))
        result["patterns_re"] += [w for w in st["patterns_re"] if w not in result["patterns_re"]]
        result["pending"] = {**st["pending"], **result["pending"]}
        result["directories_abs"] += _dirs(st)
    if invalid:
        result["error"], result["file"], result["error_root"] = (invalid[0][k] for k in ("error", "file", "root"))
    result["digest"] = _digest({k: result[k] for k in ("patterns", *LIST_FIELDS, "directories_abs")})
    return result


def apply(cfg: dict, cwd: str | list[str | None] | None) -> dict:
    """The project layer of the configuration: directories, extensions, SSH commands with tables, labels, columns."""
    p = merged_state(cwd if isinstance(cwd, list) else [cwd])
    cfg["project"] = p
    if not p:
        return cfg  # on a file error the other projects' valid filters are still added (the gate adds the denial)
    z = cfg["sources"]
    z["directories"] = list(z["directories"]) + p["directories_abs"]
    z["extensions"] = list(z["extensions"]) + [e for e in p["extensions"] if e not in z["extensions"]]
    if p["tables"]:
        # only queries on a server (ssh) — local databases are sandboxes the agent fully controls anyway
        names = "|".join(re.escape(t) for t in p["tables"])
        z["commands"] = list(z["commands"]) + [
            rf"(?i)\bssh\b.*\b(?:from|join|update|into|table)\s+[`\"'\[]?(?:\w+\.)?(?:{names})\b"
        ]
    sensitive = {k.casefold() for k in p["sensitive_columns"]}
    t = cfg["tables"]
    t["plain_columns"] = [k for k in t.get("plain_columns", []) if k.casefold() not in sensitive]
    cfg["text"]["labels"] = {**{w["label"]: w["label"] for w in p["patterns"]}, **cfg["text"]["labels"]}
    return cfg


# --- use in detection -----------------------------------------------------------------------------


def fragments(text: str, cfg: dict) -> list[Fragment]:
    p = cfg.get("project")
    if not p:
        return []
    result = []
    for r, label in p["patterns_re"]:
        for m in r.finditer(text):
            if m.end() > m.start():
                result.append(Fragment(m.start(), m.end(), label, 3))
    return result


def labels(cfg: dict) -> set[str]:
    p = cfg.get("project")
    return {w["label"] for w in p["patterns"]} if p else set()


def columns(cfg: dict) -> set[str]:
    p = cfg.get("project")
    return {k.casefold() for k in p["sensitive_columns"]} if p else set()


INSERT_RE = re.compile(r"(?is)\b(?:INSERT\s+INTO|COPY)\s+[^\s(]+\s*\(([^)]{1,4000})\)\s*(?:VALUES|FROM\s+stdin)")
SEPARATORS = re.compile(r"[,;\t|]")


def columns_in_text(text: str, cfg: dict) -> int:
    """Project sensitive columns with data: the INSERT/COPY column list, or a CSV header row followed by rows."""
    sensitive = columns(cfg)
    if not sensitive:
        return 0
    counter = 0
    for m in INSERT_RE.finditer(text):
        names = {n.strip(" `\"'[]\n\t").casefold() for n in m.group(1).split(",")}
        counter += len(names & sensitive)
    lines = text.splitlines()
    for i, line in enumerate(lines[:-1]):
        cells = {k.strip(" \"'`").casefold() for k in SEPARATORS.split(line)}
        if len(cells) > 1 and cells & sensitive and lines[i + 1].strip():
            counter += len(cells & sensitive)
    return counter


def is_exempt(p: dict, s: str, cwd: str) -> bool:
    """Whether `s` is the invalid project file itself, which may be read and fixed: a regular file (not a symlink or a
    hard link — it could point to a data file), up to MAX_FILE_SIZE, in `<project>/.claude/`. The filter still checks
    its content."""
    if not s:
        return False
    full_path = s if os.path.isabs(s) else os.path.join(cwd, s)
    file = p["file"]
    try:
        if os.path.islink(full_path) or os.path.islink(file) or os.path.realpath(full_path) != os.path.realpath(file):
            return False
        if os.path.realpath(os.path.dirname(file)) != os.path.realpath(os.path.join(p.get("error_root", p["root"]), ".claude")):
            return False
        if not os.path.exists(file):
            return True  # Write of a new file in place of a deleted one
        st = os.stat(file)
        return os.path.isfile(file) and st.st_nlink == 1 and st.st_size <= MAX_FILE_SIZE
    except OSError:
        return False


def error_denial(cfg: dict, tool: str, tool_input: dict, cwd: str) -> str | None:
    """Invalid project file → deny everything except Read (filtered) and Write of the file itself — Edit would show part of
    the file without the output filter."""
    p = cfg.get("project")
    if not p or not p.get("error"):
        return None
    if tool in ("Read", "Write") and is_exempt(p, str(tool_input.get("file_path") or ""), cwd):
        return None
    return (
        f"piigate: the project filter file is invalid — {p['error']}. Until it is fixed the filter denies everything in "
        f"this project (deny by default); only Read and Write (the whole file anew) of {p['file']} are allowed."
    )


def require_valid(cfg: dict) -> None:
    p = cfg.get("project")
    if p and p.get("error"):
        raise FilterError(f"the project filter file is invalid — {p['error']}")
