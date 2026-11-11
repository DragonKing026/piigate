"""Shadow mode for the Bash gate (issue 340): the syntax-tree gate (`shell_gate.AstGate`) judges every Bash command NEXT TO the
old gate, and only NUMBERS are kept — never the command, a path, a name, an argument or the text of a reason.

The old gate decides, always: its result is final. The shadow runs in a forked child, after the decision is made; the hook
does not wait for it. An exception, a timeout or a hang of `shfmt` in the child changes nothing (the hook has already
answered), and the child kills itself after `BUDGET_S` seconds. It is OFF until the user sets `"shell_shadow": true` in
~/.config/piigate/config.json (`piigate shadow-on` does it; `piigate shadow-off` undoes it).

File: `shell-shadow.json` in the filter's data directory (where the map and the key are; the gate treats it as a filter file:
the model can neither read nor write it). Mode 0600, written under a lock, replaced atomically, ~10 KB at most.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import resource
import signal
import sys
import tempfile
import time
from pathlib import Path

from . import config

FILE = "shell-shadow.json"
BUDGET_S = 1.0  # the shadow's whole life: after this the child kills itself (a hung shfmt included)
SHFMT_TIMEOUT_S = 0.5  # shfmt inside the shadow (the gate itself keeps its own limit)
KEEP_DAYS = 60

CATEGORIES = (
    "same-allow", "same-deny", "old-deny-new-allow", "old-allow-new-deny", "parse-error", "shadow-error", "shadow-timeout",
)
# the cause of an old-deny-new-allow: the feature of the syntax-tree gate that, switched off, makes it deny again
FEATURES = ("subshell-cd", "pipeline-cd", "known-value-resolution", "absolute-cd")
CAUSES = (*FEATURES, "other")
REASON_LABELS = (
    "sensitive-dir", "filter-files", "unfiltered-tool", "data-file", "ssh-query", "mcp-piigate", "marker-dir", "human-only",
    "cannot-parse", "code-the-tree-cannot-read", "zsh-syntax", "other",
)
# the kind of a parse-error (`shell.PARSE_KINDS`; `syntax-error:<dialect>`, `unsupported-…:<shfmt node type>` or `:other`)
_PARSE_LABELS: tuple | None = None


def parse_labels() -> tuple:
    """The allowed labels, built on first use: this module must not import the syntax-tree front-end at load time (the hook
    imports this module for every Bash command; the front-end is imported only in the forked child)."""
    global _PARSE_LABELS
    if _PARSE_LABELS is None:
        from . import shell

        _PARSE_LABELS = tuple(
            dict.fromkeys(
                [
                    *shell.PARSE_KINDS,
                    *(f"syntax-error:{d}" for d in shell.DIALECTS),
                    *(f"unsupported-word-part:{t}" for t in (*shell.WORD_PART_TYPES, "other")),
                    *(f"unsupported-command-type:{t}" for t in (*shell.COMMAND_TYPES, "other")),
                    "syntax-error:other",
                ]
            )
        )
    return _PARSE_LABELS


MS_BUCKETS = ("<=5", "<=10", "<=25", "<=50", "<=100", "<=250", "<=500", ">500")


def enabled(cfg: dict) -> bool:
    return bool(cfg.get("shell_shadow", False))


def _label(reason: str | None) -> str:
    """A reason as one of a few fixed labels (by the fixed words of the gate's messages) — never the text itself."""
    if not reason:
        return "other"
    table = (
        ("is for a human only", "human-only"),
        ("cannot be parsed", "cannot-parse"),
        ("zsh", "zsh-syntax"),
        ("the gate cannot judge", "code-the-tree-cannot-read"),
        ("output does not go through the filter", "unfiltered-tool"),
        ("sensitive data directory", "sensitive-dir"),
        ("database query", "ssh-query"),
        ("pseudonym map", "filter-files"),
        ("filter file", "filter-files"),
        ("disabled in Bash", "mcp-piigate"),
        ("holds only the piigate marker", "marker-dir"),
        ("personal data", "data-file"),
    )
    return next((label for needle, label in table if needle in reason), "other")


def _bucket(ms: float) -> str:
    for limit, name in zip((5, 10, 25, 50, 100, 250, 500), MS_BUCKETS, strict=False):
        if ms <= limit:
            return name
    return MS_BUCKETS[-1]


def path() -> str:
    return str(config.data_dir() / FILE)


def _empty_day() -> dict:
    return {**dict.fromkeys(CATEGORIES, 0), "causes": {}, "reasons": {}, "parse_kinds": {}, "ms": {}}


def _counts(value, allowed) -> dict:
    """A dict of non-negative integers under keys from a fixed list; anything else is dropped."""
    if not isinstance(value, dict):
        return {}
    return {k: v for k, v in value.items() if k in allowed and type(v) is int and v >= 0}


def clean(loaded) -> dict:
    """The file as the schema allows it: unknown keys, wrong types and malformed days are dropped (a corrupt or alien
    file starts again from what is valid — never an exception)."""
    days: dict = {}
    if isinstance(loaded, dict) and isinstance(loaded.get("days"), dict):
        for name, d in loaded["days"].items():
            if not (isinstance(name, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", name) and isinstance(d, dict)):
                continue
            day = _empty_day()
            day.update(_counts(d, CATEGORIES))
            day["causes"] = _counts(d.get("causes"), CAUSES)
            day["ms"] = _counts(d.get("ms"), MS_BUCKETS)
            day["parse_kinds"] = _counts(d.get("parse_kinds"), parse_labels())
            reasons = d.get("reasons")
            if isinstance(reasons, dict):
                day["reasons"] = {
                    k: _counts(reasons.get(k), REASON_LABELS) for k in ("old-deny-new-allow", "old-allow-new-deny") if k in reasons
                }
            days[name] = day
    return {"version": 1, "days": days}


_TMP: str | None = None  # the temporary file between mkstemp and os.replace: the alarm handler removes it
_HOLDING = False  # this process holds the lock: the alarm handler must not come back into `_update`
LOCK_WAIT_S = 0.3


def _lock(folder: str):
    """The lock file, held (non-blocking, a short wait at most) or None. Never follows a symlink; mode 0600."""
    fd = os.open(os.path.join(folder, FILE + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    deadline = time.monotonic() + LOCK_WAIT_S
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except OSError:
            if time.monotonic() >= deadline:
                os.close(fd)
                return None
            time.sleep(0.01)


def _update(change) -> bool:
    """Applies `change(data)` to the counters under an exclusive lock; False when the lock is busy (nothing is written —
    the shadow only counts, a lost count is acceptable, a wait is not)."""
    global _HOLDING, _TMP
    folder = str(config.data_dir())
    os.makedirs(folder, mode=0o700, exist_ok=True)
    fd = _lock(folder)
    if fd is None:
        return False
    _HOLDING = True
    tmp = None
    try:
        try:
            with open(os.path.join(folder, FILE), encoding="utf-8") as f:
                loaded = json.load(f)
        except (OSError, ValueError, RecursionError):
            loaded = None
        data = clean(loaded)
        change(data)
        days = data["days"]
        for old in sorted(days)[:-KEEP_DAYS]:
            del days[old]
        out, tmp = tempfile.mkstemp(prefix=FILE + ".", dir=folder)  # 0600, an unpredictable name in the same directory
        _TMP = tmp
        with os.fdopen(out, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True)
        os.replace(tmp, os.path.join(folder, FILE))
        tmp = _TMP = None
        return True
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        _HOLDING, _TMP = False, None
        os.close(fd)


def _bump(day: dict, category: str, ms: float | None = None, cause: str | None = None, old: str | None = None, new: str | None = None, kind: str | None = None) -> None:
    day[category] = day.get(category, 0) + 1
    if ms is not None:
        b = day.setdefault("ms", {})
        b[_bucket(ms)] = b.get(_bucket(ms), 0) + 1
    if cause:
        c = day.setdefault("causes", {})
        c[cause] = c.get(cause, 0) + 1
    if kind and category == "parse-error":
        k = day.setdefault("parse_kinds", {})
        k[kind] = k.get(kind, 0) + 1
    label = old if category == "old-deny-new-allow" else new if category == "old-allow-new-deny" else None
    if label:
        r = day.setdefault("reasons", {}).setdefault(category, {})
        r[label] = r.get(label, 0) + 1


def record(
    category: str, ms: float | None = None, cause: str | None = None, old: str | None = None, new: str | None = None,
    kind: str | None = None,
) -> bool:
    today = time.strftime("%Y-%m-%d")
    return _update(lambda data: _bump(data["days"].setdefault(today, _empty_day()), category, ms, cause, old, new, kind))


def classify_cause(cfg: dict, cwd: str, command: str, files: bool, dialect: str | None = None) -> str:
    """Why the syntax-tree gate allows what the old gate denies: switch one of its features off at a time and see which one
    brings the denial back. A command that no feature explains is `other`."""
    from . import shell, shell_gate

    for feature in FEATURES:
        shell.ABLATE = {feature}
        try:
            if shell_gate.AstGate(cfg, cwd, dialect).bash(command, files) is not None:
                return feature
        finally:
            shell.ABLATE = set()
    return "other"


def judge(cfg: dict, cwd: str, command: str, files: bool, old_reason: str | None) -> tuple[str, float, str | None, str | None, str | None, str | None]:
    """(category, ms, cause, old label, new label, parse kind) of one command — the work of the child."""
    from . import shell, shell_gate

    shell.SHFMT_TIMEOUT = SHFMT_TIMEOUT_S
    start = time.perf_counter()
    gate = shell_gate.AstGate(cfg, cwd)
    new_reason = gate.bash(command, files)
    ms = (time.perf_counter() - start) * 1000
    if gate.internal_error:
        return "shadow-error", ms, None, None, None, None
    if gate.parse_error:
        kind = gate.parse_kind if gate.parse_kind in parse_labels() else "other"  # a fixed label, whatever the gate holds
        return "parse-error", ms, None, None, None, kind
    if old_reason is None and new_reason is None:
        return "same-allow", ms, None, None, None, None
    if old_reason is not None and new_reason is not None:
        return "same-deny", ms, None, None, None, None
    if old_reason is not None:
        return "old-deny-new-allow", ms, classify_cause(cfg, cwd, command, files), _label(old_reason), None, None
    return "old-allow-new-deny", ms, None, None, _label(new_reason), None


def _drop_tmp() -> None:
    """The alarm came between mkstemp and os.replace: do not leave the temporary file behind."""
    if _TMP:
        try:
            os.unlink(_TMP)
        except OSError:
            pass


def _harden() -> None:
    """The child holds the command in memory (it may hold personal data): no core dump, not ptrace-able; and a CPU limit that
    does not depend on Python (the kernel kills it) next to the wall-clock alarm."""
    for call in (
        lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)),
        lambda: resource.setrlimit(resource.RLIMIT_CPU, (2, 3)),
        lambda: __import__("ctypes").CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0),  # PR_SET_DUMPABLE = 0
    ):
        try:
            call()
        except Exception:  # noqa: BLE001, S110 — best effort
            pass


def _child(cfg: dict, cwd: str, command: str, files: bool, old_reason: str | None) -> None:
    def die(signum, frame):  # the last word: whatever the child was doing, it ends now
        _drop_tmp()
        os._exit(0)

    def too_slow(signum, frame):  # the budget is over (a hung shfmt, a pathological line)
        signal.signal(signal.SIGALRM, die)
        signal.setitimer(signal.ITIMER_REAL, 0.5)  # recording must fit in this
        _drop_tmp()
        if not _HOLDING:  # inside `_update` the lock is ours already: do not come back into it
            try:
                record("shadow-timeout")
            except BaseException:  # noqa: BLE001, S110
                pass
        os._exit(0)

    _harden()
    signal.signal(signal.SIGALRM, too_slow)
    signal.setitimer(signal.ITIMER_REAL, BUDGET_S)
    try:
        category, ms, cause, old, new, kind = judge(cfg, cwd, command, files, old_reason)
        record(category, ms, cause, old, new, kind)
    except Exception:  # noqa: BLE001 — the shadow must never matter; it only counts that it failed
        try:
            record("shadow-error")
        except Exception:  # noqa: BLE001, S110
            pass


def observe(cfg: dict, cwd: str, command: str, old_reason: str | None, files: bool = True, wait: bool = False) -> int | None:
    """Starts the shadow for one command and returns at once (the old gate has decided; nothing here can change that).
    Returns the child's pid (None when off or when it cannot start). `wait=True` is for tests."""
    try:
        if not enabled(cfg) or not hasattr(os, "fork"):
            return None
        sys.stdout.flush()
        sys.stderr.flush()
        pid = os.fork()
    except Exception:  # noqa: BLE001
        return None
    if pid:
        if wait:
            deadline = time.monotonic() + BUDGET_S + 2
            while time.monotonic() < deadline:
                done, _ = os.waitpid(pid, os.WNOHANG)
                if done:
                    break
                time.sleep(0.005)
        return pid
    try:  # the child: no stdin, no output, then the work, then out without running anything else
        null = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        _child(cfg, cwd, command, files, old_reason)
    finally:
        os._exit(0)


# ---------------------------------------------------------------------------------------------------------- reading


def read() -> dict:
    try:
        return clean(json.loads(Path(path()).read_text(encoding="utf-8")))
    except (OSError, ValueError, RecursionError):
        return clean(None)


def _sorted(counts: dict) -> dict | str:
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))) or "—"


def report() -> str:
    """The numbers, as text: totals and the last days — nothing else exists in the file."""
    data = read()
    days = data["days"]
    if not days:
        return "shadow: no counts yet (it is off unless `shell_shadow` is true — `piigate shadow-on`)"
    total = dict.fromkeys(CATEGORIES, 0)
    causes: dict[str, int] = {}
    ms: dict[str, int] = {}
    reasons: dict[str, dict[str, int]] = {"old-deny-new-allow": {}, "old-allow-new-deny": {}}
    kinds: dict[str, int] = {}
    for d in days.values():
        for c in CATEGORIES:
            total[c] += int(d.get(c, 0))
        for k, v in (d.get("causes") or {}).items():
            causes[k] = causes.get(k, 0) + int(v)
        for cat, labels in (d.get("reasons") or {}).items():
            for k, v in labels.items():
                reasons[cat][k] = reasons[cat].get(k, 0) + int(v)
        for k, v in (d.get("parse_kinds") or {}).items():
            kinds[k] = kinds.get(k, 0) + int(v)
        for k, v in (d.get("ms") or {}).items():
            ms[k] = ms.get(k, 0) + int(v)
    lines = [f"shadow: {len(days)} day(s), {min(days)} … {max(days)}"]
    lines += [f"  {c:20} {total[c]}" for c in CATEGORIES]
    lines.append(f"  causes of old-deny-new-allow: {causes or '—'}")
    lines.append(f"  reasons of the old gate in old-deny-new-allow: {_sorted(reasons['old-deny-new-allow'])}")
    lines.append(f"  reasons of the new gate in old-allow-new-deny: {_sorted(reasons['old-allow-new-deny'])}")
    lines.append(f"  kinds of parse-error: {_sorted(kinds)}")
    lines.append(f"  time (ms) histogram: {dict(sorted(ms.items()))}")
    return "\n".join(lines)


def reset() -> None:
    folder = str(config.data_dir())
    try:
        names = os.listdir(folder)
    except OSError:
        return
    for name in names:
        if name == FILE or name.startswith(FILE + ".") and name != FILE + ".lock":
            try:
                os.unlink(os.path.join(folder, name))
            except OSError:
                pass
