"""Sensors: cheap masking of certain identifiers (checksums) in EVERY Bash/Read/Grep output.

Second line of defence for data that bypassed the gate (a file copied elsewhere, `python -c`).
No network, milliseconds; does not detect names or addresses — only the full text filter does that (`piigate text`,
the MCP tools).
"""

import re

from . import project, rules

DIGITS_RE = re.compile(r"(?<![\d])\d[\d -]{9,30}\d(?![\d])")
ACCOUNT_RE = re.compile(r"\b(?:PL\s?)?\d{2}(?:[ ]?\d{4}){6}\b")


def mask(text: str, cfg: dict) -> tuple[str, int]:
    c = cfg.get("sensors", {})
    counter = 0

    def account(m: re.Match) -> str:
        nonlocal counter
        if rules.iban_valid(m.group()):
            counter += 1
            return "[ACCOUNT hidden by piigate]"
        return m.group()

    def digits(m: re.Match) -> str:
        nonlocal counter
        s = re.sub(r"\D", "", m.group())
        if c.get("pesel", True) and len(s) == 11 and rules.pesel_valid(s) and re.fullmatch(r"\d{11}", m.group()):
            counter += 1
            return "[PESEL hidden by piigate]"
        if c.get("card", True) and rules.luhn_valid(s) and len(s) >= 15 and not s.startswith("0"):
            counter += 1
            return "[CARD hidden by piigate]"
        return m.group()

    disjoint, end = [], -1  # project patterns — masked like PESEL; on overlap the first one wins
    for f in sorted(project.fragments(text, cfg), key=lambda f: (f.start, -f.end)):
        if f.start >= end:
            disjoint.append(f)
            end = f.end
    for f in reversed(disjoint):
        text = text[: f.start] + f"[{f.type_} hidden by piigate]" + text[f.end :]
        counter += 1
    if c.get("account", True):
        text = ACCOUNT_RE.sub(account, text)
    text = DIGITS_RE.sub(digits, text)
    return text, counter
