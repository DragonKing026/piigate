"""Monotonicity (issue 340, round 8): every word of the line is judged as the old gate judged it, so when the OLD gate
denies and the AST gate allows, the case must belong to a short explicit list of STRUCTURAL classes — places where the old
gate misread the structure of the line (not a word) and the AST gate reads it right. Anything else is a test failure.

The class of a case is its CAUSE, found by ablation (not by how the command looks): the AST gate is run again with one
feature switched off (`shell.ABLATE`) and the feature that brings the denial back is the class. `classify(row, dialect)`
returns it or None. The list below is what the user is shown."""

from __future__ import annotations

from collections import Counter

CLASSES = {
    "subshell-cd": "`( cd .. )`, `(f)`: a command in a subshell does not change the directory of what follows (the old gate keeps the "
    "directory it never left as 'maybe changed' and denies)",
    "pipeline-cd": "`echo | cd ..; cat S*/p*`: a pipeline stage runs in a forked shell (bash without `lastpipe`), so its `cd` does not "
    "change the directory of what follows (the old gate took the `cd` as run here and denied)",
    "known-value-resolution": "`cat > \"$S/x\"`, `tee $f`, `cd $d`: a variable of KNOWN value is that value (the old gate treated every "
    "`$` in a write target or a path as unknown)",
}


def classify(row: dict, dialect: str) -> str | None:
    """The class of an OLD-DENY-NEW-ALLOW row: the feature of the AST gate that, switched off (`shell.ABLATE`), brings the
    old decision back (`shadow.classify_cause`, recorded by the measurement). None: no listed feature explains it."""
    cause = row[dialect].get("cause")
    return cause if cause in CLASSES else None


def tally(records: list[dict], dialects=("bash", "zsh")) -> tuple[Counter, list[dict]]:
    """Counts the OLD-DENY-NEW-ALLOW records per class (a record counts once); returns (counter, unlisted records)."""
    counts: Counter = Counter()
    unlisted = []
    for r in records:
        if any(r[d]["category"] == "OLD-DENY-NEW-ALLOW" for d in dialects):
            ks = {classify(r, d) for d in dialects if r[d]["category"] == "OLD-DENY-NEW-ALLOW"}
            if None in ks:
                unlisted.append(r)
            else:
                counts.update(ks)
    return counts, unlisted
