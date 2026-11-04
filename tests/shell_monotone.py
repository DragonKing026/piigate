"""Monotonicity (issue 340, round 8): every word of the line is judged as the old gate judged it, so when the OLD gate
denies and the AST gate allows, the case must belong to a short explicit list of STRUCTURAL classes — places where the old
gate misread the structure of the line (not a word) and the AST gate reads it right. Anything else is a test failure.

`classify(command)` returns the class name or None. The list below is what the user is shown."""

from __future__ import annotations

import re
from collections import Counter

CLASSES = {
    "subshell-cd": "`( cd .. )`, `(f)`: a command in a subshell does not change the directory of what follows (the old gate keeps the "
    "directory it never left as 'maybe changed' and denies)",
    "quoted-operator-word": "`rm D/.gitignore '&&' rmdir D`, `cat '>' f`: a quoted word that reads like an operator is a word, not an "
    "operator (the old gate split the command there). Where it matters the AST gate keeps the old decision (`_no_content`)",
    "heredoc-body-to-file": "`cat > f <<EOF … EOF`: the body written to a file is text, not code run now (the old gate read it as part of the "
    "command)",
    "dollar-in-write-target": "`cat > \"$S/x\"`, `tee $f`: a variable of KNOWN value in the target is that path (the old gate denied "
    "any script written to a name with a `$`, by an accident of `_unvettable_script`)",
}

_PATTERNS = {
    "subshell-cd": re.compile(r"\(\s*(?:cd|pushd)\b|\(\s*\w+\s*\)\s*(?:;|&&|\n)"),
    "quoted-operator-word": re.compile(r"""['"]\s*(?:&&|\|\||;|\||&|>>?|<)\s*['"]|\\&\\&|\\>|\\\|"""),
    "heredoc-body-to-file": re.compile(r"(?:\bcat\b[^\n|;]*>[^\n]*<<|\bcat\b[^\n|;]*<<[^\n]*>|\btee\b[^\n]*<<)"),
    "dollar-in-write-target": re.compile(r"(?:>>?\s*[\"']?\$\{?\w|\btee\b[^\n|;]*\$\{?\w)"),
}


def classify(command: str) -> str | None:
    for name, pattern in _PATTERNS.items():
        if pattern.search(command):
            return name
    return None


def tally(records: list[dict], dialects=("bash", "zsh")) -> tuple[Counter, list[dict]]:
    """Counts the OLD-DENY-NEW-ALLOW records per class (a record counts once); returns (counter, unlisted records)."""
    counts: Counter = Counter()
    unlisted = []
    for r in records:
        if any(r[d]["category"] == "OLD-DENY-NEW-ALLOW" for d in dialects):
            k = classify(r["command"])
            if k is None:
                unlisted.append(r)
            else:
                counts[k] += 1
    return counts, unlisted
