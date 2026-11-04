"""Polish detection rules (offline): patterns, checksums, inflected first names, surnames.

Result: a list of Fragment(start, end, type, weight). Types are internal (PERSON, ADDRESS…); pseudonym labels
come from the configuration. The rules always run — also when Presidio is down (we deny anyway then, but table
headers and file names are still filtered by the rules alone).
"""

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from . import sql

UPPER = "A-ZĄĆĘŁŃÓŚŹŻ"
LOWER = "a-ząćęłńóśźż"
WORD_CAPITALIZED = rf"[{UPPER}][{LOWER}]+(?:-[{UPPER}][{LOWER}]+)?"  # Kowalska, Nowak-Kowalska
WORD_UPPERCASE = rf"[{UPPER}]{{2,}}(?:-[{UPPER}]{{2,}})?"  # KOWALSKA
NAME = rf"(?:{WORD_CAPITALIZED}|{WORD_UPPERCASE})"


@dataclass
class Fragment:
    start: int
    end: int
    type_: str
    weight: int = 2


PESEL_CENTURIES = {0: 1900, 20: 2000, 40: 2100, 60: 2200, 80: 1800}  # month offset → century


def pesel_valid(digits: str) -> bool:
    """The check digit and a real birth date (YYMMDD, the century in the month: +80 1800s, +0 1900s, +20 2000s,
    +40 2100s, +60 2200s) — by the check digit alone 1 in 10 arbitrary 11-digit numbers (run IDs) would pass."""
    if len(digits) != 11 or not digits.isdigit():
        return False
    weights = (1, 3, 7, 9, 1, 3, 7, 9, 1, 3)
    if (10 - sum(int(c) * w for c, w in zip(digits, weights)) % 10) % 10 != int(digits[10]):
        return False
    coded = int(digits[2:4])
    month = coded % 20
    if not 1 <= month <= 12:
        return False
    year, day = PESEL_CENTURIES[coded - month] + int(digits[:2]), int(digits[4:6])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    days = (31, 29 if leap else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)[month - 1]
    return 1 <= day <= days


def nip_valid(digits: str) -> bool:
    if len(digits) != 10 or not digits.isdigit():
        return False
    weights = (6, 5, 7, 2, 3, 4, 5, 6, 7)
    return sum(int(c) * w for c, w in zip(digits, weights)) % 11 == int(digits[9])


def luhn_valid(digits: str) -> bool:
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, c in enumerate(reversed(digits)):
        d = int(c) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def iban_valid(text: str) -> bool:
    s = re.sub(r"\s", "", text).upper()
    if s.isdigit() and len(s) == 26:
        s = "PL" + s
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rotated = s[4:] + s[:4]
    return int("".join(str(int(ch, 36)) for ch in rotated)) % 97 == 1


# --- inflected first names -----------------------------------------------------------------------------


def _inflections(first_name: str) -> set[str]:
    forms = {first_name}
    if first_name.endswith("ia"):  # Zenobia, Julia, Maria
        r = first_name[:-1]
        forms |= {r + "i", r + "ę", r + "ą", r + "o", r + "ii"}
    elif first_name.endswith("a"):  # Anna, Janina, Barbara
        r = first_name[:-1]
        forms |= {r + "y", r + "ie", r + "ę", r + "ą", r + "o", r + "i"}
        if r.endswith(("k", "g")):  # Agnieszka → Agnieszki, Agnieszce
            forms |= {r + "i", r[:-1] + ("c" if r.endswith("k") else "dz") + "e"}
    else:  # Jan, Piotr, Paweł, Józef
        r = first_name
        if r.endswith("eł"):
            r = r[:-2] + "ł"  # Paweł → Pawła
        if r.endswith("ek"):
            r = r[:-2] + "k"  # Marek → Marka
        forms |= {r + "a", r + "owi", r + "em", r + "ie", r + "u"}
    return forms


@lru_cache(maxsize=1)
def first_names() -> frozenset[str]:
    file = Path(__file__).with_name("first_names.txt")
    name_forms: set[str] = set()
    for row in file.read_text(encoding="utf-8").splitlines():
        if row.startswith("#"):
            continue
        for first_name in row.split():
            name_forms |= {f.casefold() for f in _inflections(first_name)}
    return frozenset(name_forms)


# Typical Polish surname suffixes (inflected) and words that look like them (place names, adjectives)
SURNAME_SUFFIXES = re.compile(
    rf"\b[{UPPER}][{LOWER}]{{2,}}(?:ski|ska|skiego|skiej|skim|ską|scy|cki|cka|ckiego|ckiej|ckim|cką|dzki|dzka|dzkiego|"
    rf"dzkiej|wicz|wicza|wiczowi|wiczem|czyk|czyka|czak|czaka|iak|iaka|uk|uka)\b"
)
NOT_SURNAMES = {
    "polska",
    "polski",
    "polskiej",
    "polskie",
    "polskiego",
    "polskim",
    "polską",
    "gdańska",
    "warszawska",
    "krakowska",
    "poznańska",
    "wrocławska",
    "śląska",
    "śląskiej",
    "mazowiecka",
    "mazowieckiej",
    "małopolska",
    "wielkopolska",
    "pomorska",
    "lubelska",
    "łódzka",
    "łódzkiej",
    "miejska",
    "miejskiej",
    "wiejska",
    "szkolna",
    "apteka",
    "apteki",
    "angielski",
    "niemiecki",
    "europejska",
    "europejskiej",
    "publiczny",
    "medyczny",
    "brutto",
    "netto",
}
_LABEL = r"(?i:imię|imie|nazwisko|pesel|adres|telefon|tel|e-?mail|kontakt|podpis|data|nip|regon|krs|nr|numer)\b"
# form of address or title before a person's name (any case); the name itself must be capitalized, otherwise
# "Pacjentka zgłosiła się" or "dr hab." would yield a person in the gate verdict
_PERSON_NAME = rf"({NAME}(?:\s+(?!{_LABEL}){NAME})?)"
NAME_PHRASES = re.compile(
    r"(?i:\b(?:Pan|Pani|Pana|Panią|Panu|Panem|Państwo|p\.|dr\.?(?:\s+hab\.?)?|lek\.(?:\s*med\.)?|mgr|prof\.?|inż\.?|"
    r"ks\.|pacjent|pacjenta|pacjentka|pacjentki|pacjentowi|pacjentce|ur\.|imię i nazwisko|nazwisko|imię|osoba))"
    rf"\s*[:.]?\s+{_PERSON_NAME}"
)
# field labels (signature, author, contact…) — only with a colon: "autor Nodemailera", "podpis DKIM" are not persons
FIELD_PHRASES = re.compile(
    r"(?i:\b(?:podpis|autor|autorka|kontakt|opiekun|opiekunka|kierownik|kierowniczka|dyrektor|dyrektorka|prezes|"
    r"specjalista|specjalistka|prowadząc[aye]|lekarz|lekarka|lekarz prowadzący))"
    rf"\s*:\s*{_PERSON_NAME}"
)
# institution names (Szpital Wolski, Uniwersytet Warszawski, Kierownik Poradni) — the -ski suffix is not a surname
# here; stem + up to 4 inflection letters, so that "Sądowski" is not a court
INSTITUTIONS = re.compile(
    r"(?:szpital|klinik|poradni|przychodni|ośrod|ośrodk|centrum|centr|instytut|fundacj|stowarzyszeni|związ|urząd|"
    r"urzęd|uniwersytet|politechnik|akademi|szkoł|szkol|uczelni|wydział|departament|ministerstw|apte[kc]|sąd|"
    r"prokuratur|zakład|oddział|gabinet|hospicj|laboratori|spółk|spółdzielni|parafi|starostw|gmin|powiat)\w{0,4}"
)
# form field labels — never glued to a person's name ("Imię: Bożydar Nazwisko: Testowy")
FIELD_LABELS = {
    "imię", "imie", "nazwisko", "pesel", "adres", "telefon", "tel", "email", "e-mail", "kontakt", "podpis", "data",
    "urodzenia", "nip", "regon", "krs", "pacjent", "pacjentka", "lekarz", "opiekun", "dowód", "nr", "numer",
}


def _institution(word: str) -> bool:
    return bool(INSTITUTIONS.fullmatch(word.casefold()))


# common nouns that NER (Presidio) takes for persons when capitalized ("przyszła z Babcią");
# only for Presidio PERSON hits made solely of such words — the rules (first names, suffixes) are not affected
COMMON_PERSON_NOUNS = [
    "Mama", "Tata", "Babcia", "Dziadek", "Ciocia", "Wujek", "Siostra", "Córka", "Synowa", "Żona", "Narzeczona",
    "Senior", "Seniorka", "Rodzic", "Opiekun", "Opiekunka", "Lekarz", "Lekarka", "Pielęgniarka", "Pielęgniarz",
    "Pacjent", "Pacjentka", "Klient", "Klientka", "Dyrektor", "Dyrektorka", "Kierownik", "Kierowniczka", "Prezes",
    "Doktor", "Profesor", "Terapeuta", "Terapeutka", "Wolontariusz", "Wolontariuszka", "Koordynator",
    "Koordynatorka", "Nauczyciel", "Nauczycielka", "Student", "Studentka", "Mieszkanka", "Sąsiad", "Sąsiadka",
    "Kolega", "Koleżanka", "Rehabilitant", "Rehabilitantka", "Farmaceuta", "Farmaceutka", "Ratownik", "Położna",
]


@lru_cache(maxsize=1)
def _common_nouns() -> frozenset[str]:
    return frozenset(f.casefold() for s in COMMON_PERSON_NOUNS for f in _inflections(s))


def is_common_noun(value: str) -> bool:
    """Whether a person name consists only of common nouns (Babcią, Mama Senior) — then it is not a person."""
    words = re.findall(r"[^\W\d_]+", value)
    return bool(words) and all(s.casefold() in _common_nouns() for s in words)

# --- patterns ---------------------------------------------------------------------------------------

MONTHS = (
    r"stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|września|października|listopada|grudnia|"
    r"styczeń|luty|marzec|kwiecień|maj|czerwiec|lipiec|sierpień|wrzesień|październik|listopad|grudzień"
)
STREET_PREFIXES = r"(?:ul\.|ulica|ulicy|al\.|aleja|alei|aleje|os\.|osiedle|pl\.|plac|placu|skwer|rondo|ul)"

PATTERNS: list[tuple[str, re.Pattern, int]] = [
    ("EMAIL", re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"), 3),
    ("ACCOUNT", re.compile(r"\b(?:PL\s?)?\d{2}(?:[ ]?\d{4}){6}\b"), 3),
    ("PRESCRIPTION", re.compile(r"\b\d{22}\b|\b\d{44}\b"), 3),
    (
        "PRESCRIPTION",
        re.compile(
            r"(?i)(?:recept\w*|nr\s+rec\.?|kod\s+(?:dostępu|recepty|realizacji)|klucz\s+recepty|Rp\.)"
            r"[^\d\n]{0,30}((?:\d[\d -]{2,40}\d))"
        ),
        3,
    ),
    (
        "NUMBER",
        re.compile(
            r"(?i)(?:id\s+pacjenta|nr\s+pacjenta|numer\s+pacjenta|karta\s+pacjenta|nr\s+karty|historii\s+choroby|"
            r"nr\s+ubezpieczenia|numer\s+ubezpieczenia|nr\s+kartoteki|kartoteka)\s*(?:nr|numer|id)?\s*[:.]?\s*"
            r"([A-Z0-9][A-Z0-9/.-]{3,})"
        ),
        3,
    ),
    ("DOCUMENT", re.compile(r"\b[A-Z]{3}\s?\d{6}\b|\b[A-Z]{2}\s?\d{7}\b"), 2),
    # driving license: number after the document name (form ABC12345, number 00123/13/1234) — ends with a digit
    ("DOCUMENT", re.compile(r"(?i:\bpraw[oa]\s+jazdy(?:\s+(?:nr|numer)\.?)?)\s*[:.]?\s*([A-Z0-9][A-Z0-9/-]{4,15}\d)\b"), 3),
    ("IP", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), 2),
    (
        "ADDRESS",
        re.compile(
            rf"(?i:\b{STREET_PREFIXES})\s*[{UPPER}0-9][\w.-]*(?:\s+[{UPPER}][\w.-]*){{0,3}}\s+\d+[a-zA-Z]?"
            rf"(?:\s*/\s*\d+[a-zA-Z]?|\s+(?:m\.|lok\.)\s*\d+)?"
        ),
        3,
    ),
    ("ADDRESS", re.compile(rf"\b\d{{2}}-\d{{3}}\b(?:\s+{NAME}(?:[ -]{NAME})?)?"), 3),
    ("DATE", re.compile(r"\b\d{1,2}[./-]\d{1,2}[./-](?:19|20)\d{2}\b|\b(?:19|20)\d{2}[./-]\d{1,2}[./-]\d{1,2}\b"), 2),
    ("DATE", re.compile(rf"(?i)\b\d{{1,2}}\s+(?:{MONTHS})\s+(?:19|20)\d{{2}}\b"), 2),
    # phones: separators in the usual places or +48; 9 digits without separators only after the word "tel."
    (
        "PHONE",
        re.compile(
            r"(?<![\w+-])(?:(?:\+|00)48[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{3}|\d{3}[ \t-]\d{3}[ \t-]\d{3}"
            r"|\(?\d{2}\)?[ \t-]\d{3}[ \t-]\d{2}[ \t-]\d{2})(?![\w]|-\d)"
        ),
        2,
    ),
    ("PHONE", re.compile(r"(?i)\b(?:tel|telefon\w*|kom|komórk\w*|nr\s+tel)\.?\s*[:.]?\s*(\+?\d{9,11})\b"), 2),
    # foreign and landline numbers with a country prefix (+49 30 1234567, +48 12 345 67 89) — 7–16 digits after "+"
    ("PHONE", re.compile(r"(?<![\w+])\+\d{1,3}(?:[\s-]?\d){6,13}(?![\d])"), 2),
]
DRUG_RE = re.compile(
    rf"\b([{UPPER}][{LOWER}A-Z]+(?:[ -][{LOWER}A-Z]+)?)\s+\d+(?:[.,]\d+)?\s?(?:mg|g|mcg|µg|μg|ml|j\.m\.|jm|IU|%)(?![\w])"
)
DRUG_CONTEXT_RE = re.compile(rf"(?i:\b(?:lek|leku|preparat|preparatu|Rp\.)\s*[:.]?\s*)({NAME})")
NIP_RE = re.compile(r"\b\d{3}-?\d{3}-?\d{2}-?\d{2}\b|\b\d{3}-?\d{2}-?\d{2}-?\d{3}\b")
NIP_CONTEXT_RE = re.compile(r"(?i)\bNIP\s*[:.]?\s*((?:PL)?\s?[\d -]{10,13}\d)")
REGON_RE = re.compile(r"(?i)\bREGON\s*[:.]?\s*(\d{9}(?:\d{5})?)\b")
KRS_RE = re.compile(r"(?i)\bKRS\s*[:.]?\s*(?:nr\.?\s*)?(\d{10})\b")
# IPv6: candidate with ≥ 2 colons and a digit, then validation (time 12:45:30, MAC, `std::x` are rejected)
IPV6_RE = re.compile(r"(?<![\w:.])(?=[0-9A-Fa-f:]*\d)(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
# PESEL: eleven contiguous digits, or the printed layouts 6+5 and 2-2-2-5 (a space or a hyphen) with a valid
# checksum; other digit groups are not one number (`bak-20261023-046` holds eleven digits split by a hyphen). With a
# "PESEL" label the usual separators are tolerated anywhere.
PESEL_RE = re.compile(r"(?<!\d)\d{11}(?!\d)")
PESEL_LAYOUT_RE = re.compile(r"(?<![\w.-])(?:\d{6}[ -]\d{5}|\d{2}[ -]\d{2}[ -]\d{2}[ -]\d{5})(?![\w-]|\.\w|-\d)")
PESEL_LABELLED_RE = re.compile(r"(?i)\bpesel\b[^\d\n]{0,15}(\d(?:[ -]?\d){10})(?!\d)")
# payment card: 13-19 contiguous digits, or the printed layouts 4-4-4-4, 4-6-5 / 4-6-4 (Amex, Diners) and 4-8-4 with a
# hyphen, a space or two spaces between the groups (they may differ); numbers that merely sit next to each other (HTTP
# codes `200 302 200 200 200`) are not one card
_CARD_SEP = r"(?: {1,2}|-)"
CARD_RE = re.compile(
    r"(?<!\d)\d{13,19}(?!\d)"
    rf"|(?<!\w)(?<!\w-)(?:\d{{4}}(?:{_CARD_SEP}\d{{4}}){{3}}|\d{{4}}{_CARD_SEP}\d{{6}}{_CARD_SEP}\d{{4,5}}"
    rf"|\d{{4}}{_CARD_SEP}\d{{8}}{_CARD_SEP}\d{{4}})(?!\w|-\w)"
)
WORD_RE = re.compile(rf"{NAME}")
# capital letters glued to a name and not starting another capitalized word (MariaDB, JanSQL — unlike JanKowalski)
ACRONYM_TAIL = re.compile(rf"[{UPPER}]+(?![{LOWER}])")


_TLD_RE = re.compile(r"[^\W\d_]{2,}|xn--[A-Za-z0-9-]+")


# a version written as a domain: `1.2.3`, `v7.13.1`, `1.2.3-next.4`, `1.2.3.beta`, `1.0.0-rc.1` — the whole domain, so
# that `1.2.pl` is not one
_VERSION_DOMAIN_RE = re.compile(
    r"v?\d+(?:\.\d+)+(?:[-.](?:alpha|beta|rc|next|dev|pre|canary|snapshot|final)(?:[.-]?\d+)*)?", re.IGNORECASE
)


def email_valid(address: str) -> bool:
    """Whether what follows the last `@` can be a domain: the last label (TLD) is made of letters, and the whole of it
    is not a version (`pkg@1.2.3`, `module/v7@v7.13.1`, `pkg@1.2.3-next.4`, `pkg@1.2.3.beta`); `jan@1.2.pl` is an
    address."""
    domain = address.rsplit("@", 1)[-1].strip(".")
    labels = domain.split(".")
    if len(labels) < 2 or not _TLD_RE.fullmatch(labels[-1]):
        return False
    return not _VERSION_DOMAIN_RE.fullmatch(domain)


# ISO 8601 / RFC 3339 timestamps (2026-11-02T20:11:01Z, 2026-11-02 20:11:01+01:00): a technical value (release time,
# log line), not a birth date. A date with the time 00:00 is how databases export a plain date — that stays a date.
TIMESTAMP_RE = re.compile(
    r"(?<![\w.-])(?:19|20)\d{2}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:[.,]\d+)?)?|\s\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"
    r"(?:Z|[+-]\d{2}(?::?\d{2})?)?(?![\w:])"
)


BIRTH_MARKER_RE = re.compile(r"ur\.|urodz|dob|birth")  # in the 30 characters before a date: a birth date


def timestamp_spans(text: str) -> list[tuple[int, int]]:
    """Spans of timestamps with a real time of day (see TIMESTAMP_RE), except those right after a birth marker
    (`ur. 1985-03-14 08:15:00` is a birth date written with a time)."""
    return [
        (m.start(), m.end())
        for m in TIMESTAMP_RE.finditer(text)
        if re.search(r"[1-9]", re.sub(r"[Z+-]\d{2}(?::?\d{2})?$|^.{10}", "", m.group()))
        and not BIRTH_MARKER_RE.search(text[max(0, m.start() - 30) : m.start()].casefold())
    ]


# a dotted number (`v0.5.1`, `1.80.0`, `1.2.3-next.4`): NER sometimes tags a piece of it ("v0", "80.") and the pseudonym
# would cut the token (`ORG_5.5.1`, `1.DATE_7.0`)
VERSION_TOKEN_RE = re.compile(r"(?<![\w.])v?\d+(?:\.\d+)+(?:[-+][\w.]+)?(?![\w])")
_DATE_LIKE_RE = re.compile(r"(\d{1,2})\.(\d{1,2})\.(?:\d{2}|\d{4})")


def fit_to_tokens(text: str, start: int, end: int) -> tuple[int, int] | None:
    """A NER hit that begins or ends inside a dotted number: a number that can be a date (5.5.90) — the whole token
    (fail closed); anything else (a version) — None, the hit is dropped. A hit that does not cut a token: unchanged."""
    for m in VERSION_TOKEN_RE.finditer(text, max(0, start - 128), min(len(text), end + 128)):
        if m.end() <= start or end <= m.start() or (start <= m.start() and m.end() <= end):
            continue
        d = _DATE_LIKE_RE.fullmatch(m.group())
        if d and int(d.group(1)) <= 31 and int(d.group(2)) <= 12:
            return min(start, m.start()), max(end, m.end())
        return None
    return start, end


def _group(m: re.Match) -> tuple[int, int]:
    return (m.start(1), m.end(1)) if m.re.groups and m.group(1) else (m.start(), m.end())


# four or more HTTP status codes in one line, with one kind of separator, are a list of numbers (`200 302 404 500`),
# not a phone — groups that are not all status codes (`600 700 800 900`) stay phones; a line break never joins them (a column of phones), nor does a phone label
_HTTP_CODE = r"(?:10[0-3]|20[0-8]|226|30[0-8]|4[0-2]\d|431|451|50\d|51[01])"
NUMBER_LIST_RE = re.compile(rf"(?<![\w+.-]){_HTTP_CODE}([ \t-]){_HTTP_CODE}(?:\1{_HTTP_CODE}){{2,}}(?!\w)")
BARE_PHONE_RE = re.compile(r"\d{3}[ \t-]\d{3}[ \t-]\d{3}")
PHONE_LABEL_RE = re.compile(r"(?i)\b(?:tel|telefon\w*|kom|komórk\w*)\.?\s*[:.]?\s*$")


def detect(text: str, *, dates: str = "all", drugs: bool = True) -> list[Fragment]:
    result: list[Fragment] = []
    lists = [m.span() for m in NUMBER_LIST_RE.finditer(text) if not PHONE_LABEL_RE.search(text, max(0, m.start() - 24), m.start())]
    for type_, regex, weight in PATTERNS:
        if type_ == "DATE" and dates == "none":
            continue
        for m in regex.finditer(text):
            s, k = _group(m)
            if type_ == "DATE" and dates == "birth":
                before = text[max(0, s - 30) : s].casefold()
                if not BIRTH_MARKER_RE.search(before):
                    continue
            if type_ == "EMAIL" and not email_valid(m.group()):
                continue
            if type_ == "PHONE" and BARE_PHONE_RE.fullmatch(m.group()) and any(a <= s and k <= b for a, b in lists):
                continue
            result.append(Fragment(s, k, type_, weight))

    for m in PESEL_RE.finditer(text):  # PESEL, cards — by checksum
        if pesel_valid(m.group()):
            result.append(Fragment(m.start(), m.end(), "PESEL", 3))
        else:  # 11 digits without a valid checksum — still a personal number
            result.append(Fragment(m.start(), m.end(), "NUMBER", 2))
    for m in PESEL_LAYOUT_RE.finditer(text):
        if pesel_valid(re.sub(r"\D", "", m.group())):
            result.append(Fragment(m.start(), m.end(), "PESEL", 3))
    for m in PESEL_LABELLED_RE.finditer(text):
        if not PESEL_RE.fullmatch(m.group(1)) and pesel_valid(re.sub(r"\D", "", m.group(1))):
            result.append(Fragment(m.start(1), m.end(1), "PESEL", 3))
    for m in CARD_RE.finditer(text):
        if luhn_valid(re.sub(r"\D", "", m.group())):
            result.append(Fragment(m.start(), m.end(), "CARD", 3))
    for m in NIP_RE.finditer(text):
        if nip_valid(re.sub(r"\D", "", m.group())):
            result.append(Fragment(m.start(), m.end(), "NIP", 3))
    for regex in (NIP_CONTEXT_RE, REGON_RE, KRS_RE):
        for m in regex.finditer(text):
            result.append(Fragment(m.start(1), m.end(1), "NIP", 3))
    for m in IPV6_RE.finditer(text):
        try:
            ipaddress.IPv6Address(m.group())
        except ValueError:
            continue
        result.append(Fragment(m.start(), m.end(), "IP", 2))

    if drugs:
        for regex in (DRUG_RE, DRUG_CONTEXT_RE):
            for m in regex.finditer(text):
                result.append(Fragment(m.start(1), m.end(1), "DRUG", 2))

    result += find_persons(text)
    return sql.drop_identifiers(text, result)  # table and column names of a SQL script are not people or places


def find_persons(text: str) -> list[Fragment]:
    """First name from the list (+ the adjacent capitalized word), surnames by suffix and after forms of address."""
    result: list[Fragment] = []
    known = first_names()
    words = list(WORD_RE.finditer(text))
    for i, m in enumerate(words):
        if m.group().casefold() not in known:
            continue
        if ACRONYM_TAIL.match(text, m.end()):  # MariaDB, MariaDB10 — a product name, not "Maria" + "DB"
            continue
        s, k = m.start(), m.end()
        # capitalized neighbour right next to it (Jan Kowalski, KOWALSKA JANINA) — both words are the person;
        # a field label ("Imię: Bożydar Nazwisko: …") and an institution name are not part of the person
        if i + 1 < len(words) and re.fullmatch(r"[ \t]+", text[k : words[i + 1].start()] or "x"):
            next_word = words[i + 1].group()
            if next_word.casefold() not in FIELD_LABELS and not _institution(next_word):
                k = words[i + 1].end()
        if i > 0 and re.fullmatch(r"[ \t]+", text[words[i - 1].end() : s] or "x"):
            prev_word = words[i - 1].group()
            # surname before the first name (KOWALSKA JANINA, Kowalska Janina) — not "Dzwoniła Zenobia" at sentence start
            if (
                prev_word.isupper() or SURNAME_SUFFIXES.fullmatch(prev_word) or prev_word.casefold() in known
            ) and prev_word.casefold() not in NOT_SURNAMES | FIELD_LABELS:
                s = words[i - 1].start()
        result.append(Fragment(s, k, "PERSON", 2))
    for m in SURNAME_SUFFIXES.finditer(text):
        if m.group().casefold() in NOT_SURNAMES or _after_institution(text, m.start()):
            continue
        result.append(Fragment(m.start(), m.end(), "PERSON", 2))
    for m in (*NAME_PHRASES.finditer(text), *FIELD_PHRASES.finditer(text)):
        name = m.group(1).split()
        if _institution(name[0]):  # Kierownik Poradni, Dyrektor Szpitala (institutions)
            continue
        if len(name) > 1 and _institution(name[1]):  # Pani Doktor Poradni → only the first word
            result.append(Fragment(m.start(1), m.start(1) + len(name[0]), "PERSON", 2))
        else:
            result.append(Fragment(m.start(1), m.end(1), "PERSON", 2))
    return result


def _after_institution(text: str, start: int) -> bool:
    """Word with a surname suffix inside an institution name: up to 2 capitalized words earlier there is "Szpital",
    "Uniwersytet"… (Szpital Wolski, Uniwersytet Medyczny Warszawski)."""
    before = re.findall(rf"[{UPPER}{LOWER}]+", text[max(0, start - 60) : start])[-2:]
    return any(_institution(s) for s in before)


# Well-known technology names that NER takes for people, places or companies (issue #3). Only names that are not
# plausible Polish first names or surnames; a user adds more in `text.plain_words`.
TECH_NAMES = frozenset(
    s.casefold()
    for s in (
        "Nuxt Vite Vitest Cypress Webpack Rollup Esbuild Babel ESLint Prettier Tailwind Bootstrap Symfony Doctrine "
        "Twig Composer Packagist Docker Traefik Sablier Playwright Puppeteer Mocha Jest Vue Vuex Pinia Svelte Astro "
        "Gulp Grunt Nginx Apache Redis Memcached Kubernetes Terraform Ansible Grafana Prometheus Webpackbar "
        "Axios Lodash Express Laravel Django Flask Selenium Storybook Sass Less Stylelint Husky Lerna Turborepo "
        "Fedora Debian Ubuntu Alpine Pandoc Hunspell Shellcheck Ripgrep Lighthouse Wireshark"
    ).split()
)
_TOKEN_CHAR = re.compile(r"[\w@./-]")
_LOWER_IDENTIFIER = re.compile(r"[a-z0-9]+(?:[-_./][a-z0-9]+)*")
_CAMEL_CASE = re.compile(r"[A-Za-z][a-z0-9]*(?:[A-Z][a-z0-9]*)+")


def technical_term(text: str, start: int, end: int, type_: str) -> bool:
    """Whether a NER hit (PERSON / ORG / ADDRESS) is a technology or package name, not data (issue #3): a known
    name (`TECH_NAMES`), a lowercase identifier with a separator (`cypress-axe`, `ps_customersignin`, `vendor/package`,
    `@scope`; never a bare word — it may be a surname)
    or — for ORG / ADDRESS — a CamelCase product name (CommonJS). A part that is a first name (`jan-kowalski`) or a
    surname by suffix keeps the hit: user names built of a person's name stay masked."""
    value = text[start:end].strip(" \t\r\n,;:()[]\"'.")
    if not value or re.search(r"\s", value):  # several words — a name or a sentence, not an identifier
        return False
    s, k = start, end
    while s > 0 and _TOKEN_CHAR.match(text[s - 1]):
        s -= 1
    while k < len(text) and _TOKEN_CHAR.match(text[k]):
        k += 1
    token = text[s:k].strip(".-/@ \t\r\n,;:()[]\"'")
    if not token:
        return False
    parts = [p for p in re.split(r"[-_./@]+", token.casefold()) if p]
    if any(p in first_names() or SURNAME_SUFFIXES.fullmatch(p.capitalize()) for p in parts):
        return False
    if value.casefold() in TECH_NAMES or token.casefold() in TECH_NAMES:
        return True
    # a bare lowercase word without a separator may be a surname ("nowak") — only kebab/snake/vendor/@scope qualify
    scoped = text[s:k].lstrip(" \t\r\n,;:()[]\"'.-/").startswith("@")
    if _LOWER_IDENTIFIER.fullmatch(token) and (scoped or re.search(r"[-_/]", token)):
        return True
    return type_ in ("ORG", "ADDRESS") and bool(_CAMEL_CASE.fullmatch(token))


def stems(fragment: str) -> list[str]:
    """Stems of a person name's words, to find inflected forms in the rest of the text (Kowalska → Kowalsk…)."""
    result = []
    for word in re.findall(rf"[{UPPER}][{UPPER}{LOWER}]{{3,}}", fragment):  # proper names — capitalized
        if word.casefold() in {"pani", "pana", "panią", "pacjent", "pacjentka"}:
            continue
        result.append(word[:-2] if len(word) >= 7 else word[:-1] if len(word) >= 5 else word)
    return result


DOCUMENT_WORDS = {
    "faktura",
    "faktury",
    "fv",
    "vat",
    "korekta",
    "recepta",
    "recepty",
    "recept",
    "zestawienie",
    "raport",
    "lista",
    "wykaz",
    "skan",
    "scan",
    "umowa",
    "aneks",
    "zamówienie",
    "zamowienie",
    "oferta",
    "pismo",
    "dokument",
    "załącznik",
    "zalacznik",
    "rozliczenie",
    "refundacja",
    "apteka",
    "apteki",
    "nfz",
    "kopia",
    "export",
    "eksport",
    "dane",
    "plik",
    "wyniki",
    "wynik",
    "mail",
    "wiadomość",
    "wiadomosc",
    "odpowiedź",
    "re",
    "fwd",
    "zapytanie",
    "pacjenci",
    "pacjentów",
    "pacjentow",
    "sprzedaż",
    "sprzedaz",
    "zakup",
    "zakupy",
    "magazyn",
    "stan",
    "stany",
    "arkusz",
    "sheet",
    "tabela",
    "pdf",
    "xlsx",
    "xls",
    "csv",
    "eml",
    "docx",
    "odt",
    "ods",
    "txt",
    "zip",
    "styczeń",
    "luty",
    "marzec",
    "kwiecień",
    "maj",
    "czerwiec",
    "lipiec",
    "sierpień",
    "wrzesień",
    "październik",
    "pazdziernik",
    "listopad",
    "grudzień",
    "grudzien",
    "kwiecien",
    "styczen",
    "sierpien",
    "wrzesien",
}


def suspicious_name_words(name: str, forbidden: set[str] | frozenset[str] = frozenset()) -> list[tuple[int, int]]:
    """File/sheet name: every capitalized word outside the document vocabulary, a first name, a surname by suffix
    or a word that occurs in cell values → pseudonymized (file names are short — we prefer too much)."""
    result = []
    for m in re.finditer(rf"[{UPPER}{LOWER}A-Za-z]{{3,}}", name):
        w = m.group()
        cf = w.casefold()
        if cf in DOCUMENT_WORDS and cf not in forbidden:
            continue
        if (
            w[0].isupper() or cf in first_names() or cf in forbidden or SURNAME_SUFFIXES.fullmatch(w.capitalize())
        ) and cf not in NOT_SURNAMES:
            result.append((m.start(), m.end()))
    return result
