"""Free text (mail bodies, PDFs, documents): Polish rules + Presidio (+ optionally Ollama) → stable pseudonyms."""

import re

from . import FilterError, project, rules, engines
from .pseudonym_map import PSEUDONYM_RE, PseudonymMap
from .rules import Fragment

FILENAME_RE = re.compile(
    r"[\w\-. ()]{1,120}\.(?:pdf|xlsx|xlsm|xls|ods|csv|tsv|docx|doc|odt|rtf|eml|msg|txt|jpe?g|png|tiff?|zip)\b",
    re.IGNORECASE,
)


def _merge(fragments: list[Fragment], text: str) -> list[Fragment]:
    """Merges overlapping (and adjacent same-type) fragments into one — the type with the highest weight wins."""
    result: list[Fragment] = []
    for f in sorted(fragments, key=lambda f: (f.start, -f.end)):
        if f.end <= f.start:
            continue
        if result:
            o = result[-1]
            gap = text[o.end : f.start]
            glue = r"[ \t]*" if f.type_ == "PERSON" else r"[\s.,/-]*"  # two persons separated by a comma are two persons
            if f.start < o.end or (o.type_ == f.type_ and len(gap) <= 2 and re.fullmatch(glue, gap)):
                type_ = o.type_ if o.weight >= f.weight else f.type_
                result[-1] = Fragment(o.start, max(o.end, f.end), type_, max(o.weight, f.weight))
                continue
        result.append(f)
    return result


def _trim(f: Fragment, text: str) -> Fragment | None:
    s, k = f.start, f.end
    while s < k and text[s] in " \t\r\n,;:()[]\"'":
        s += 1
    while k > s and text[k - 1] in " \t\r\n,;:()[]\"'.":
        k -= 1
    if f.type_ == "PERSON" and f.weight < 4:
        # NER can be greedy ("Przykładowska prosi") — a person is trimmed to capitalized words at both ends;
        # weight 4 = a string pointed out explicitly (local model in `piigate analyze`), e.g. a lowercase nickname — no trimming
        words = list(re.finditer(r"\S+", text[s:k]))
        while words and not words[-1].group()[0].isupper():
            words.pop()
        while words and not words[0].group()[0].isupper():
            words.pop(0)
        if not words:
            return None
        s, k = s + words[0].start(), s + words[-1].end()
    return Fragment(s, k, f.type_, f.weight) if k - s >= 2 else None


def _skip_pseudonyms(fragments: list[Fragment], text: str) -> list[Fragment]:
    """Do not pseudonymize pseudonyms again (text filtered a second time, Ollama layer)."""
    taken = [(m.start(), m.end()) for m in PSEUDONYM_RE.finditer(text)]
    return [f for f in fragments if not any(s <= f.start and f.end <= k for s, k in taken)]


def filter_text(
    text: str,
    cfg: dict,
    *,
    source: str = "files",
    rules_only: bool = False,
    pseudonym_map: PseudonymMap | None = None,
    extra: list[Fragment] | None = None,
    stems: dict[str, str] | None = None,
) -> tuple[str, dict[str, int]]:
    """Returns (text with pseudonyms, replacement count per label). Service failure → FilterError.

    `stems` — a dictionary shared by several parts of one whole (mail headers and body): the same person gets
    the same pseudonym, and a bare surname in the subject is recognized thanks to the full name in the body."""
    if not text.strip():
        return text, {}
    t = cfg["text"]
    labels = t["labels"]
    pseudonym_map = pseudonym_map or PseudonymMap()

    project.require_valid(cfg)
    fragments = rules.detect(text, dates=t.get("dates", "all"), drugs=t.get("drugs", True)) + (extra or [])
    fragments += project.fragments(text, cfg)
    for m in FILENAME_RE.finditer(text):  # Recepty_Kowalska.xlsx in a mail body / JSON from MCP
        fragments += [
            Fragment(m.start() + s, m.start() + k, "PERSON", 2)
            for s, k in rules.suspicious_name_words(m.group().replace("_", " "))
        ]
    if not rules_only:
        fragments += engines.presidio(text, cfg)
    if not t.get("organizations", True):
        fragments = [f for f in fragments if f.type_ != "ORG"]
    if t.get("dates") == "none":
        fragments = [f for f in fragments if f.type_ != "DATE"]
    fragments = [p for f in _skip_pseudonyms(fragments, text) if (p := _trim(f, text))]
    fragments = _merge(fragments, text)

    # pseudonym numbers; persons: word stems to find inflected forms and single name parts in the rest of the text
    # (Kowalskiej, "Pani Janina") — they get the same pseudonym as the full name
    assigned: list[tuple[Fragment, str]] = []
    stems = stems if stems is not None else {}
    # persons from the longest name: "Przykładowska" in the subject gets the pseudonym of "Zenobia Przykładowska" from the body
    for f in sorted(fragments, key=lambda f: (f.type_ != "PERSON", -(f.end - f.start), f.start)):
        label = labels.get(f.type_, f.type_)
        value = text[f.start : f.end]
        if f.type_ == "PERSON":
            own = [r.casefold() for r in rules.stems(value)]
            known = {stems[r] for r in own if r in stems}
            if own and len(known) == 1 and all(r in stems for r in own):
                p = known.pop()
                pseudonym_map.pseudonym(f.type_, label, value, number=int(p.rsplit("_", 1)[1]))
            else:
                p = pseudonym_map.pseudonym(f.type_, label, value)
            for r in own:
                stems.setdefault(r, p)
        else:
            p = pseudonym_map.pseudonym(f.type_, label, value)
        assigned.append((f, p))
    if stems:
        taken = [(f.start, f.end) for f, _ in assigned]
        regex = re.compile(
            r"(?<!\w)(" + "|".join(re.escape(r) for r in sorted(stems, key=len, reverse=True)) + r")\w*",
            re.IGNORECASE,
        )
        for m in regex.finditer(text):
            if any(s < m.end() and m.start() < k for s, k in taken):
                continue
            p = stems[m.group(1).casefold()]
            label, number = p.rsplit("_", 1)
            pseudonym_map.pseudonym("PERSON", label, m.group(), number=int(number))
            assigned.append((Fragment(m.start(), m.end(), "PERSON"), p))

    result = text
    counter: dict[str, int] = {}
    for f, p in sorted(assigned, key=lambda x: x[0].start, reverse=True):
        result = result[: f.start] + p + result[f.end :]
        label = p.rsplit("_", 1)[0]
        counter[label] = counter.get(label, 0) + 1

    if not rules_only and cfg["ollama"].get("enabled") and source in cfg["ollama"].get("sources", []):
        result = _ollama_layer(result, cfg, pseudonym_map, counter)
    return result, counter


def _ollama_layer(text: str, cfg: dict, pseudonym_map: PseudonymMap, counter: dict[str, int]) -> str:
    labels = cfg["text"]["labels"]
    for fragment, type_ in engines.ollama(text, cfg):
        if len(fragment) < 3 or PSEUDONYM_RE.fullmatch(fragment) or fragment not in text:
            continue  # the model hallucinates fragments not in the text — skip
        type_ = type_ if type_ in labels else "NUMBER"
        p = pseudonym_map.pseudonym(type_, labels[type_], fragment)
        n = text.count(fragment)
        text = text.replace(fragment, p)
        label = p.rsplit("_", 1)[0]
        counter[label] = counter.get(label, 0) + n
    return text


def tokens(texts) -> set[str]:
    """Words (≥ 3 letters) from values — e.g. spreadsheet cells; in file/sheet/column names they are treated as data."""
    result: set[str] = set()
    for t in texts:
        result |= {w.casefold() for w in re.findall(r"[^\W\d_]{3,}", t)}
    return result


def forbidden_words(text: str, forbidden: set[str]) -> list[Fragment]:
    if not forbidden:
        return []
    return [
        Fragment(m.start(), m.end(), "PERSON", 2)
        for m in re.finditer(r"[^\W\d_]{3,}", text)
        if m.group().casefold() in forbidden
    ]


def filter_name(name: str, cfg: dict, pseudonym_map: PseudonymMap | None = None, forbidden: set[str] | None = None) -> str:
    """File/sheet name (short, no sentence context): rules + every suspicious word → pseudonym."""
    norm_text = name.replace("_", " ")
    added = [Fragment(s, k, "PERSON", 2) for s, k in rules.suspicious_name_words(norm_text, forbidden or set())]
    added += [Fragment(m.start(), m.end(), "NUMBER", 3) for m in re.finditer(r"\d{9,}", norm_text)]
    return filter_text(norm_text, cfg, rules_only=True, pseudonym_map=pseudonym_map, extra=added)[0]


def summary(counter: dict[str, int]) -> str:
    if not counter:
        return "[piigate: nothing found to pseudonymize — the filter does not catch 100%]"
    parts = ", ".join(f"{k}×{v}" for k, v in sorted(counter.items()))
    return f"[piigate: pseudonyms {parts}; originals only in the local map]"


__all__ = ["FilterError", "filter_text", "filter_name", "summary", "tokens", "forbidden_words"]
