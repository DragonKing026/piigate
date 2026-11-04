"""Sensors: cheap masking of certain identifiers (checksums) in EVERY Bash/Read/Grep output.

Second line of defence for data that bypassed the gate (a file copied elsewhere, `python -c`).
No network, milliseconds; does not detect names or addresses — only the full text filter does that (`piigate text`,
the MCP tools).
"""

import re

from . import project, rules

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

    def pesel(m: re.Match) -> str:
        nonlocal counter
        if c.get("pesel", True) and rules.pesel_valid(m.group()):
            counter += 1
            return "[PESEL hidden by piigate]"
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
    text = rules.PESEL_RE.sub(pesel, text)
    if c.get("card", True):
        for start, end in reversed(rules.card_spans(text, lambda digits, _: len(digits) >= 15 and not digits.startswith("0"))):
            text = text[:start] + "[CARD hidden by piigate]" + text[end:]
            counter += 1
    return text, counter
