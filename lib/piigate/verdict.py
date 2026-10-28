"""Content verdict: does a file with an extension from `sources.extensions` really contain personal data.

The gate asks for it for files outside the sensitive directories: CLEAN → allow, PERSONAL → deny (categories and counts,
no values), UNKNOWN → deny (safe default: file too large, format without extraction, mail, error).
Rules only (`rules.detect`, no Presidio and no model) — they fit the gate's time limit (~0.5 s/MB). The verdict is
cached by the sha256 of the content and the rules version in the filter's data directory (protected from the model).
"""

import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path

from . import FilterError, config, project, rules

CLEAN, PERSONAL, UNKNOWN = "clean", "personal", "unknown"
PHI = PERSONAL  # old name, still used by search.py
TEXT_EXTS = {".sql", ".dump", ".csv", ".tsv"}
EXTRACTED_EXTS = {".pdf", ".docx", ".odt", ".xlsx", ".xlsm", ".ods"}
# DATE and DRUG are skipped — in schemas and UPDATEs they are ordinary values (migration dates, product names)
PHI_TYPES = {
    "PERSON",
    "EMAIL",
    "PHONE",
    "PESEL",
    "NIP",
    "ACCOUNT",
    "CARD",
    "ADDRESS",
    "DOCUMENT",
    "IP",
    "PRESCRIPTION",
    "NUMBER",
}
# numbers in a URL path (GitHub image ids) and numbers glued to a letter (hashes) are not personal data
NUMERIC = {"PHONE", "PESEL", "NIP", "ACCOUNT", "CARD", "DOCUMENT", "IP", "PRESCRIPTION", "NUMBER"}
URL_RE = re.compile(r"https?://[^\s'\"<>()?#]+")
GLOBAL_UNICAST_V6 = ipaddress.ip_network("2000::/3")
# addresses in domains reserved for examples (RFC 2606/6761) — demo data, not personal
EXAMPLE_EMAIL_RE = re.compile(
    r"(?i)@(?:[\w-]+\.)*(?:example\.(?:com|org|net)|[\w-]+\.(?:example|invalid|localhost))$"
)
DEFAULTS = {"enabled": True, "limit_mb": 10, "max_files": 50}
MAX_ENTRIES = 5000
_RULE_FILES = [Path(rules.__file__), Path(rules.__file__).with_name("first_names.txt"), Path(__file__)]


@dataclass(frozen=True)
class Verdict:
    result: str
    description: str = ""  # PERSONAL: "PERSON 3, EMAIL 2"; UNKNOWN: the reason


def settings(cfg: dict) -> dict:
    return {**DEFAULTS, **(cfg["sources"].get("content_check") or {})}


def rules_version() -> str:
    """A change of the rules, the name list or this module invalidates cached verdicts."""
    h = hashlib.sha256()
    for p in _RULE_FILES:
        h.update(p.read_bytes())
    return h.hexdigest()[:16]


def _ip_non_personal(address: str) -> bool:
    """Loopback, private networks, 0.0.0.0, broadcast — configuration, not a trace of a person; a version number (1.2.3.400)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return True
    if ip.version == 6 and ip not in GLOBAL_UNICAST_V6:  # ::1:8765 (loopback with a port), ::ffff:…, fd00::
        return True
    return not ip.is_global


def check_text(t: str, cfg: dict) -> dict[str, int]:
    """Rule hits per type (no values); with project filters: its patterns and sensitive columns."""
    plain = {s.casefold() for s in cfg["text"].get("plain_words", [])}
    counter: dict[str, int] = {}
    addresses = [(m.start(), m.end()) for m in URL_RE.finditer(t)]
    own = project.labels(cfg)
    for f in rules.detect(t, dates="none", drugs=False) + project.fragments(t, cfg):
        if f.type_ in own:  # project pattern — none of the general rules' exceptions
            counter[f.type_] = counter.get(f.type_, 0) + 1
            continue
        if f.type_ not in PHI_TYPES or t[f.start : f.end].casefold() in plain:
            continue
        if f.type_ == "EMAIL" and EXAMPLE_EMAIL_RE.search(t[f.start : f.end]):
            continue
        if f.type_ == "IP" and _ip_non_personal(t[f.start : f.end]):
            continue
        if f.type_ in NUMERIC and (
            any(s <= f.start and f.end <= k for s, k in addresses)
            or t[f.start - 1 : f.start].isalpha()
            or t[f.end : f.end + 1].isalpha()
        ):
            continue
        counter[f.type_] = counter.get(f.type_, 0) + 1
    if n := project.columns_in_text(t, cfg):
        counter["SENSITIVE_COLUMN"] = n
    return counter


def describe_counter(counter: dict[str, int]) -> str:
    return ", ".join(f"{k} {v}" for k, v in sorted(counter.items(), key=lambda x: -x[1]))


def _text(path: Path, ext: str, data: bytes) -> str:
    from . import files, table  # lazy import: the gate does not pay for spreadsheet modules it does not need

    if ext == ".pdf":
        return files.pdf_text(path)
    if ext == ".docx":
        return files.docx_text(data)
    if ext == ".odt":
        return files.odt_text(data)
    if ext in (".xlsx", ".xlsm", ".ods"):
        tables = table.from_xlsx(data, path.name) if ext != ".ods" else table.from_ods(data)
        return "\n".join("\t".join(row) for t in tables for row in [t.headers, *t.rows])
    if b"\0" in data[:8192]:
        raise FilterError("binary file — content cannot be checked")
    return table._decode(data)


class VerdictCache:
    """Verdicts by sha256 (JSON in the filter's data directory); atomic writes, a corrupt file = empty cache."""

    def __init__(self):
        self.file = config.data_dir() / "verdicts.json"
        self.version = rules_version()
        try:
            data = json.loads(self.file.read_text(encoding="utf-8"))
            self.entries = data["entries"] if data.get("version") == self.version else {}
        except (OSError, ValueError, KeyError, TypeError):
            self.entries = {}

    def get(self, sha: str) -> Verdict | None:
        w = self.entries.get(sha)
        return Verdict(w["w"], w.get("o", "")) if isinstance(w, dict) and w.get("w") in (CLEAN, PERSONAL) else None

    def save(self, sha: str, verdict: Verdict) -> None:
        self.entries[sha] = {"w": verdict.result, "o": verdict.description, "t": int(time.time())}
        if len(self.entries) > MAX_ENTRIES:
            for k in sorted(self.entries, key=lambda k: self.entries[k].get("t", 0))[: len(self.entries) - MAX_ENTRIES]:
                del self.entries[k]
        try:
            self.file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.file.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps({"version": self.version, "entries": self.entries}), encoding="utf-8")
            os.replace(tmp, self.file)
        except OSError:
            pass  # without the cache the verdict still applies — it is computed again next time


class Judge:
    """Verdicts for one gate decision (the cache is loaded once)."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.opts = settings(cfg)
        self._cache: VerdictCache | None = None

    @property
    def cache(self) -> VerdictCache:
        if self._cache is None:
            self._cache = VerdictCache()
        return self._cache

    def file(self, path: str) -> Verdict:
        if not self.opts["enabled"]:
            return Verdict(UNKNOWN, "content checks disabled in the configuration")
        p = Path(path)
        ext = p.suffix.casefold()
        if ext not in TEXT_EXTS | EXTRACTED_EXTS:
            return Verdict(UNKNOWN, f"format {ext} has no content check (mail, .xls/.doc/.rtf)")
        try:
            if not p.is_file():
                return Verdict(UNKNOWN, "the file does not exist (or is a directory) — content cannot be checked")
            if p.stat().st_size > self.opts["limit_mb"] * 1024 * 1024:
                return Verdict(UNKNOWN, f"file over {self.opts['limit_mb']} MB — too large to check in the gate")
            data = p.read_bytes()
        except OSError as e:
            return Verdict(UNKNOWN, f"cannot read the file ({type(e).__name__})")
        sha = hashlib.sha256(data).hexdigest()
        if proj := self.cfg.get("project"):  # different project filters = a different verdict
            sha += ":" + proj.get("digest", "")
        if cached := self.cache.get(sha):
            return cached
        try:
            counter = check_text(_text(p, ext, data), self.cfg)
        except FilterError as e:
            return Verdict(UNKNOWN, str(e))
        except Exception as e:  # noqa: BLE001 — corrupt ZIP/XML etc.: type only (the message may quote content)
            return Verdict(UNKNOWN, f"cannot extract text ({type(e).__name__})")
        verdict = Verdict(PERSONAL, describe_counter(counter)) if counter else Verdict(CLEAN)
        self.cache.save(sha, verdict)
        return verdict
