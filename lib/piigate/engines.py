"""Clients of the NER engine (Presidio Analyzer) and of Ollama (optional second layer).

The engine runs in one of two modes (config `engine.mode`):
- `local` (default): Presidio + spaCy in memory of the piigate MCP server; hooks and the CLI reach it through a Unix
  socket (engine_socket.py, standard library only);
- `container`: the Presidio REST API in a container on a loopback address (`engine.container_url`, see docker/).

Any error (engine missing, timeout, bad response) → FilterError: the caller denies and never returns the original.
Loopback addresses / a private socket only — the data never leaves the machine.
"""

import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from . import FilterError, engine_socket, rules
from .rules import Fragment

PRESIDIO_TYPES = {
    "PERSON": ("PERSON", 2),
    "LOCATION": ("ADDRESS", 2),
    "ORGANIZATION": ("ORG", 1),
    "NRP": ("PERSON", 1),
    "DATE_TIME": ("DATE", 1),
    "EMAIL_ADDRESS": ("EMAIL", 3),
    "PHONE_NUMBER": ("PHONE", 2),
    "IBAN_CODE": ("ACCOUNT", 3),
    "CREDIT_CARD": ("CARD", 3),
    "IP_ADDRESS": ("IP", 2),
    "PL_PESEL": ("PESEL", 3),
}
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
ENGLISH_WORDS = {"the", "and", "of", "to", "is", "with", "for", "please", "regards", "dear", "your", "this", "that"}
# language detection vocabulary (decides whether to also run the English Presidio model)
POLISH_WORDS = {"i", "w", "z", "na", "się", "nie", "jest", "do", "że", "oraz", "dla", "pozdrawiam", "proszę"}


def _loopback_only(url: str) -> None:
    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in LOOPBACK and not host.endswith(".localhost"):
        raise FilterError(f"service address outside loopback ({host}) — denied, the data must not leave the machine")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None  # 307 from an on-demand proxy (service starting) is handled here: retry the same request


_OPENER = urllib.request.build_opener(_NoRedirect)
RETRY_STATUSES = {307, 308, 502, 503, 504}


def _post(url: str, data: dict, timeout_s: float) -> object:
    """POST JSON; a container started on demand (e.g. behind a reverse proxy) answers 307/50x until it is up —
    retried until the deadline."""
    task_text = json.dumps(data).encode("utf-8")
    deadline = time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FilterError(f"{url}: the service did not answer within {timeout_s:.0f} s")
        task = urllib.request.Request(
            url, data=task_text, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with _OPENER.open(task, timeout=remaining) as resp:
                content = resp.read()
                if "json" not in (resp.headers.get("Content-Type") or ""):
                    raise FilterError(f"{url}: the response is not JSON (service still starting?)")
                return json.loads(content)
        except FilterError:
            raise
        except urllib.error.HTTPError as e:
            if e.code in RETRY_STATUSES:
                time.sleep(min(2.0, max(0.0, deadline - time.monotonic())))
                continue
            if e.code == 404:  # a reverse proxy without a route = the container does not exist
                raise FilterError(
                    f"{url}: HTTP 404 — the service is not running (is the Presidio container running? "
                    "see README, Container engine)"
                ) from None
            raise FilterError(f"{url}: HTTP {e.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise FilterError(f"{url}: {type(e).__name__}: {e}") from None


def _chunks(text: str, size: int = 8000):
    """Text chunks split at line boundaries (offset, content)."""
    pos = 0
    while pos < len(text):
        end = min(len(text), pos + size)
        if end < len(text):
            nl = text.rfind("\n", pos, end)
            if nl > pos:
                end = nl + 1
        yield pos, text[pos:end]
        pos = end


def languages(text: str, cfg: dict) -> list[str]:
    """Polish always, English too when the text looks English (`text.auto_english`) — limited to `engine.languages`."""
    configured = list(engine_cfg(cfg)["languages"])
    result = ["pl"]
    if cfg["text"].get("auto_english", True):
        words = [s.casefold() for s in text.split()[:3000]]
        en = sum(s in ENGLISH_WORDS for s in words)
        pl = sum(s in POLISH_WORDS for s in words)
        if en >= 5 and en > pl * 0.5:
            result.append("en")
    return [lang for lang in result if lang in configured] or configured[:1]


ENGINE_DEFAULTS = {
    "mode": "local",
    "languages": ["pl", "en"],
    "container_url": "http://127.0.0.1:8719",
    "threshold": 0.3,
    "timeout_s": 150,
}
LOCAL_NOT_RUNNING = (
    "local engine not running (it lives in the piigate MCP server; start a Claude Code session with the plugin, "
    "or set engine.mode=container)"
)


def engine_cfg(cfg: dict) -> dict:
    e = {**ENGINE_DEFAULTS, **(cfg.get("engine") or {})}
    if e["mode"] not in ("local", "container"):
        raise FilterError(f"engine.mode must be local or container, not {e['mode']!r}")
    if not e["languages"]:
        raise FilterError("engine.languages is empty")
    return e


def engine_description(cfg: dict) -> str:
    """For status reports: which engine and where."""
    e = {**ENGINE_DEFAULTS, **(cfg.get("engine") or {})}
    if e["mode"] == "container":
        return f"container {e['container_url']}"
    try:
        where = str(engine_socket.socket_path())
    except engine_socket.EngineUnavailable as err:
        where = str(err)
    return f"local (in the piigate MCP server, socket {where})"


def _analyze_local(chunk: str, lang: str, threshold: float, timeout_s: float) -> object:
    try:
        return engine_socket.request(
            {"op": "analyze", "text": chunk, "language": lang, "score_threshold": threshold}, timeout_s
        )
    except engine_socket.EngineNotRunning:
        raise FilterError(LOCAL_NOT_RUNNING) from None
    except engine_socket.EngineUnavailable as e:
        raise FilterError(str(e)) from None


def presidio(text: str, cfg: dict) -> list[Fragment]:
    e = engine_cfg(cfg)
    if e["mode"] == "container":
        url = str(e["container_url"]).rstrip("/")
        _loopback_only(url)

        def analyze(chunk, lang, threshold, timeout_s):
            return _post(f"{url}/analyze", {"text": chunk, "language": lang, "score_threshold": threshold}, timeout_s)
    else:
        analyze = _analyze_local
    threshold = float(e["threshold"])
    deadline = time.monotonic() + float(e["timeout_s"])
    # plain words (tool names, abbreviations) — NER takes them for persons/companies ("Ollamy" → PERSON, "PHI" → ORG);
    # only Presidio hits of type PERSON/ORG/ADDRESS, the rules (PESEL, phone, e-mail…) work unchanged
    plain = {s.casefold() for s in cfg["text"].get("plain_words", [])}
    result: list[Fragment] = []
    for lang in languages(text, cfg):
        for offset, chunk in _chunks(text):
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                raise FilterError("Presidio: analysis timed out")
            resp = analyze(chunk, lang, threshold, remaining)
            if not isinstance(resp, list) or not all(isinstance(r, dict) for r in resp):
                raise FilterError("Presidio: unexpected response")
            for r in resp:
                type_, weight = PRESIDIO_TYPES.get(r.get("entity_type"), ("NUMBER", 1))
                try:
                    start, end = offset + int(r["start"]), offset + int(r["end"])
                except (KeyError, TypeError, ValueError):
                    raise FilterError("Presidio: unexpected response") from None
                value = text[start:end].strip(" \t\r\n,;:()[]\"'.")
                if type_ in ("PERSON", "ORG", "ADDRESS") and value.casefold() in plain:
                    continue
                if type_ == "PERSON" and rules.is_common_noun(value):
                    continue  # "przyszła z Babcią" — a capitalized common noun, not a person
                if type_ == "PHONE" and re.search(r"[/A-Za-z]", value):
                    type_ = "NUMBER"  # FV/2026/10/123 is a document number, not a phone — still masked
                result.append(Fragment(start, end, type_, weight))
    return result


def presidio_health(cfg: dict, timeout_s: float = 5) -> str:
    """"running …" when the engine answers (both modes), otherwise "not responding: …" / "not running: …"."""
    try:
        e = engine_cfg(cfg)
    except FilterError as err:
        return f"not running: {err}"
    if e["mode"] == "local":
        try:
            answer = engine_socket.request({"op": "health"}, timeout_s)
        except engine_socket.EngineNotRunning:
            return f"not running: {LOCAL_NOT_RUNNING}"
        except engine_socket.EngineUnavailable as err:
            return f"not responding: {err}"
        status = answer.get("status") if isinstance(answer, dict) else answer
        return f"running (local engine: {status})"
    url = str(e["container_url"]).rstrip("/")
    try:
        with urllib.request.urlopen(f"{url}/health", timeout=timeout_s) as resp:
            return f"running ({resp.read(200).decode('utf-8', 'replace').strip()})"
    except Exception as e:  # noqa: BLE001 — diagnostics only
        return f"not responding: {type(e).__name__}: {e}"


OLLAMA_PROMPT = """You are a personal data filter. The text below may be in Polish or English. Some of its data \
has already been replaced with pseudonyms of the form UPPERCASE_number (e.g. PERSON_3, ADDRESS_1) — do NOT report \
those. Find the REMAINING data that identifies a person or their health: first names, surnames, nicknames, \
addresses, towns of residence, phone numbers, e-mail addresses, document numbers, PESEL numbers, birth dates, \
prescription numbers, patient card numbers, drug names tied to a person.
Answer with JSON only: {"items": [{"text": "<exact fragment copied from the text>", "type": "PERSON|ADDRESS|PHONE|EMAIL|DOCUMENT|PESEL|DATE|PRESCRIPTION|NUMBER|DRUG"}]}.
If nothing is left: {"items": []}.

TEXT:
"""


def ollama(text: str, cfg: dict) -> list[tuple[str, str]]:
    o = cfg["ollama"]
    url = o["url"].rstrip("/")
    _loopback_only(url)
    model = o["model"]
    if "cloud" in model.casefold():
        raise FilterError(f"Ollama: model {model} runs in the cloud — not allowed (local models only)")
    deadline = time.monotonic() + float(o.get("timeout_s", 240))
    result: list[tuple[str, str]] = []
    for _, chunk in _chunks(text, 3000):
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            raise FilterError("Ollama: analysis timed out")
        resp = _post(
            f"{url}/api/generate",
            {
                "model": model,
                "prompt": OLLAMA_PROMPT + chunk,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0, "num_ctx": 8192},
            },
            remaining,
        )
        try:
            data = json.loads(resp["response"]).get("items", [])
        except (KeyError, TypeError, ValueError, AttributeError):
            raise FilterError("Ollama: the response is not valid JSON") from None
        for d in data if isinstance(data, list) else []:
            if isinstance(d, dict) and isinstance(d.get("text"), str):
                result.append((d["text"].strip(), str(d.get("type") or "NUMBER").upper()))
    return result


def ollama_health(cfg: dict, timeout_s: float = 5) -> str:
    url = cfg["ollama"]["url"].rstrip("/")
    try:
        with urllib.request.urlopen(f"{url}/api/tags", timeout=timeout_s) as resp:
            models = [m["name"] for m in json.loads(resp.read()).get("models", [])]
        model = cfg["ollama"]["model"]
        return f"running; model {model}: {'present' if model in models else 'MISSING (ollama pull ' + model + ')'}"
    except Exception as e:  # noqa: BLE001 — diagnostics only
        return f"not responding: {type(e).__name__}: {e}"
