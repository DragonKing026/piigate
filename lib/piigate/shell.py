"""Shell command parser for the Bash gate (PROTOTYPE — not wired into gate.py).

`parse(command, cwd=...)` returns every simple command of a Bash command line — also those nested in `$( )`, backticks,
`<( )`, `( )`, `{ }`, loops, `if`, `case`, functions and the script of `bash -c '…'` / `eval '…'` — with the words split
the way the shell splits them (quoting kept), redirections and heredocs separated from the arguments, and the set of
directories each command may run in. The grammar comes from `shfmt --to-json` (mvdan/sh, `-ln bash`): the command goes
to its standard input, nothing is evaluated or expanded. Anything the parser cannot be sure about raises `ParseError`
(no binary, a syntax error, a timeout, a node type this module does not know) — the gate is expected to deny then.

Facts a regex tokenizer has to guess are structural here: which text is a quoted word and which a glob, where a
heredoc body is, that `2>/dev/null` is a redirection and not an operand, that `cd` in a subshell or a pipeline stage does
not leak, that `a || cd x` may skip the cd.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field

SHFMT_TIMEOUT = 5.0  # seconds; a pathological input must not hang the hook
MAX_DEPTH = 4  # nesting of `bash -c '…'` / `eval` scripts that is parsed
MAX_BYTES = 256 * 1024  # larger commands are refused (fail closed) instead of being parsed

SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "mksh", "ash", "fish"}
# interpreters that read a program from stdin when called without a script (or with `-`)
INTERPRETERS = {"python", "python3", "node", "nodejs", "perl", "ruby", "php", "lua", "deno", "bun"}
CODE_FLAGS = {"-c", "-m", "-e", "-E", "-p", "-r", "--eval", "--command", "--print", "--exec"}
WRAPPERS = {"env", "sudo", "doas", "nice", "nohup", "exec", "command", "builtin", "time", "setsid", "stdbuf", "timeout"}
WRAPPER_VALUE_OPTIONS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U"},
    "doas": {"-u", "-C"},
    "nice": {"-n"},
    "env": {"-u", "-C", "-S"},
    "stdbuf": {"-i", "-o", "-e"},
    "timeout": {"-s", "-k"},
}


class ParseError(Exception):
    """The command could not be parsed with certainty — the caller must treat it as unknown (deny)."""


class ShfmtMissing(ParseError):
    """No `shfmt` binary found (not on PATH, not in ~/.local/bin)."""


@dataclass(frozen=True)
class Word:
    text: str  # the shell's view of the literal parts; an expansion is kept as a placeholder (`$x`, `${x}`, `$(…)`)
    quoting: str  # none | single | double | mixed
    expands: bool  # the value is not known statically: $var, ${}, $(), ``, $(( )), <( ), glob, ~, brace, extglob
    kinds: frozenset[str] = frozenset()  # param cmd arith proc glob tilde brace extglob

    @property
    def static(self) -> bool:
        return not self.expands


@dataclass(frozen=True)
class Heredoc:
    body: str  # without the delimiter line; `<<-` has leading tabs removed; expansions are placeholders when unquoted
    delimiter: str
    quoted: bool  # `<<'EOF'`, `<<"EOF"`, `<<\EOF`: the shell expands nothing in the body


@dataclass(frozen=True)
class Redirect:
    op: str  # > >> < <> >& <& &> &>> >| <<  <<-  <<<
    target: Word | None  # file / descriptor / here-string; None for a heredoc
    heredoc: Heredoc | None = None
    fd: str | None = None  # `2` in `2>file`, `{fd}` in `{fd}>file`
    inherited: bool = False  # the redirection belongs to an enclosing `{ …; } > f`, `while …; done < f`, function


@dataclass(frozen=True)
class Assign:
    name: str
    value: Word | None  # None for `a=(…)` arrays and a bare `name`
    array: tuple[Word, ...] = ()
    append: bool = False


@dataclass
class Call:
    argv: list[Word]  # empty for `x=1`, `> file`
    redirects: list[Redirect]
    cwds: frozenset[str]  # directories the command may run in (lexical, no symlink resolution)
    in_subshell: bool  # runs in a forked shell: ( ), $( ), <( ), a pipeline stage, `&` — its cd/assignments do not leak
    substitutions: list[Call] = field(default_factory=list)  # DIRECT $( ) / ` ` / <( ) / >( ) inside this command
    pipe_to_shell: bool = False  # its output (or heredoc) is piped into an interpreter that executes it
    assigns: list[Assign] = field(default_factory=list)  # `FOO=1 cmd`
    cwd_known: bool = (
        True  # False: a non-literal `cd`/`pushd` came before — cwds holds the session directory as a guess
    )
    origin: str = "top"  # top | $( | ` | <( | >( | -c | eval | function
    stdin_interpreter: str = (
        ""  # shell/python/node… reading its program from stdin (`bash`, `python3 -`, `source /dev/stdin`)
    )
    piped_in: bool = False  # stdin comes from a pipe
    opaque_code: bool = False  # `bash -c "$x"` / `eval $x`: code the parser cannot see
    background: bool = False

    @property
    def name(self) -> str:
        """Basename of the command word when it is static (`/usr/bin/cat` → cat), else ''."""
        return os.path.basename(self.argv[0].text) if self.argv and self.argv[0].static else ""


# ------------------------------------------------------------------------------------------------ running shfmt


def _shfmt_binary() -> str:
    found = shutil.which("shfmt")
    if found:
        return found
    for candidate in (os.path.expanduser("~/.local/bin/shfmt"), "/usr/local/bin/shfmt", "/usr/bin/shfmt"):
        if os.access(candidate, os.X_OK):
            return candidate
    raise ShfmtMissing("shfmt not found")


def ast(command: str) -> dict:
    """The raw shfmt JSON syntax tree of the command (stdin only, no files, working directory `/`)."""
    if len(command.encode("utf-8", "replace")) > MAX_BYTES:
        raise ParseError("command too long")
    try:
        done = subprocess.run(
            [_shfmt_binary(), "-ln", "bash", "--to-json"],
            input=command.encode("utf-8", "surrogateescape"),
            capture_output=True,
            timeout=SHFMT_TIMEOUT,
            check=False,
            cwd="/",
            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
        )
    except subprocess.TimeoutExpired as e:
        raise ParseError("shfmt timed out") from e
    except OSError as e:
        raise ParseError(f"cannot run shfmt: {e.strerror}") from e
    if done.returncode != 0:
        message = done.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ParseError("syntax error: " + (message[0][:200] if message else f"shfmt exit {done.returncode}"))
    try:
        tree = json.loads(done.stdout)
    except ValueError as e:
        raise ParseError("shfmt returned invalid JSON") from e
    if not isinstance(tree, dict) or tree.get("Type") != "File":
        raise ParseError("unexpected shfmt output")
    return tree


# ------------------------------------------------------------------------------------------------ words


def _unescape(raw: str) -> str:
    return re.sub(r"\\(.)", r"\1", raw, flags=re.DOTALL)


def _unescape_dq(raw: str) -> str:
    return re.sub(r'\\([$`"\\])', r"\1", raw)


_ANSI = re.compile(r"\\(x[0-9a-fA-F]{1,2}|u[0-9a-fA-F]{1,4}|U[0-9a-fA-F]{1,8}|[0-7]{1,3}|c.|.)", re.DOTALL)
_ANSI_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v"}


def _ansi_c(raw: str) -> str:
    def one(m: re.Match) -> str:
        s = m.group(1)
        if s[0] in "xuU" and len(s) > 1:
            return chr(int(s[1:], 16)) if int(s[1:], 16) < 0x110000 else ""
        if s[0].isdigit():
            return chr(int(s, 8) % 256)
        return _ANSI_SIMPLE.get(s, s[-1])

    return _ANSI.sub(one, raw)


def _has_glob(raw: str) -> bool:
    i, n = 0, len(raw)
    while i < n:
        c = raw[i]
        if c == "\\":
            i += 2
            continue
        if c in "*?":
            return True
        if c == "[" and "]" in raw[i + 1 :]:
            return True
        i += 1
    return False


def _has_brace(raw: str) -> bool:
    """`{a,b}` or `{1..3}` outside escapes: a comma or `..` at the top level of a balanced brace pair."""
    i, n = 0, len(raw)
    while i < n:
        if raw[i] == "\\":
            i += 2
            continue
        if raw[i] == "{":
            depth, j, top = 1, i + 1, ""
            while j < n and depth:
                if raw[j] == "\\":
                    j += 2
                    continue
                if raw[j] == "{":
                    depth += 1
                elif raw[j] == "}":
                    depth -= 1
                elif depth == 1:
                    top += raw[j]
                j += 1
            if not depth and ("," in top or ".." in top):
                return True
        i += 1
    return False


def _param_text(p: dict) -> str:
    name = (p.get("Param") or {}).get("Value", "")
    return "$" + name if p.get("Short") else "${" + name + "}"


def _find_subst(node):
    """CmdSubst / ProcSubst nodes anywhere under the node (not inside another one): [(type, node)]."""
    found = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if n.get("Type") in ("CmdSubst", "ProcSubst"):
                found.append(n)
            else:
                stack.extend(n.values())
        elif isinstance(n, list):
            stack.extend(n)
    found.reverse()
    return found


def _word(node: dict) -> Word:
    texts: list[str] = []
    kinds: set[str] = set()
    quoting: set[str] = set()
    for i, p in enumerate(node.get("Parts", [])):
        t = p["Type"]
        if t == "Lit":
            raw = p["Value"]
            quoting.add("none")
            texts.append(_unescape(raw))
            if _has_glob(raw):
                kinds.add("glob")
            if _has_brace(raw):
                kinds.add("brace")
            if i == 0 and raw.startswith("~"):
                kinds.add("tilde")
        elif t == "SglQuoted":
            quoting.add("single")
            texts.append(_ansi_c(p["Value"]) if p.get("Dollar") else p["Value"])
        elif t == "DblQuoted":
            quoting.add("double")
            for q in p.get("Parts", []):
                if q["Type"] == "Lit":
                    texts.append(_unescape_dq(q["Value"]))
                else:
                    texts.append(_expansion_text(q, kinds))
        else:
            texts.append(_expansion_text(p, kinds))
    if not quoting:
        label = "none"
    elif len(quoting) == 1:
        label = next(iter(quoting))
    else:
        label = "mixed"
    return Word("".join(texts), label, bool(kinds), frozenset(kinds))


def _expansion_text(p: dict, kinds: set[str]) -> str:
    t = p["Type"]
    if t == "ParamExp":
        kinds.add("param")
        return _param_text(p)
    if t == "CmdSubst":
        kinds.add("cmd")
        return "$(…)"
    if t == "ArithmExp":
        kinds.add("arith")
        return "$((…))"
    if t == "ProcSubst":
        kinds.add("proc")
        return p.get("Op", "<(") + "…)"
    if t == "ExtGlob":
        kinds.add("extglob")
        return (p.get("Op") or "") + (p.get("Pattern") or {}).get("Value", "") + ")"
    raise ParseError(f"unsupported word part {t}")


def _heredoc(redir: dict) -> Heredoc:
    delim_node = redir["Word"]
    quoted = any(p["Type"] != "Lit" or "\\" in p["Value"] for p in delim_node["Parts"])
    delimiter = _word(delim_node).text
    pieces: list[str] = []
    kinds: set[str] = set()
    for p in (redir.get("Hdoc") or {}).get("Parts", []):
        if p["Type"] == "Lit":
            pieces.append(p["Value"] if quoted else re.sub(r"\\([$`\\])", r"\1", p["Value"]))
        else:
            pieces.append(_expansion_text(p, kinds))
    body = "".join(pieces)
    if redir["Op"] == "<<-":
        body = re.sub(r"(?m)^\t+", "", body)
    return Heredoc(body, delimiter, quoted)


def _redirect(r: dict, inherited: bool = False) -> Redirect:
    op = r["Op"]
    fd = (r.get("N") or {}).get("Value")
    if op in ("<<", "<<-"):
        return Redirect(op, None, _heredoc(r), fd, inherited)
    return Redirect(op, _word(r["Word"]), None, fd, inherited)


# ------------------------------------------------------------------------------------------------ walking


@dataclass(frozen=True)
class _State:
    sure: frozenset[str]  # where the next command runs when everything before it (joined by &&) succeeded
    seen: frozenset[str]  # every directory a command so far may have run in
    known: bool = True


def _resolve(target: str, base: str, tilde: bool = True) -> str:
    target = os.path.expanduser(target) if tilde else target
    return os.path.normpath(target if os.path.isabs(target) else os.path.join(base, target))


def _effective(argv: list[Word]) -> list[Word]:
    """The command with the wrappers (`sudo -u x`, `env A=1`, `nice -n 5`, `exec`, `time`…) stripped."""
    words = list(argv)
    while words and words[0].static and os.path.basename(words[0].text) in WRAPPERS:
        wrapper = os.path.basename(words[0].text)
        words = words[1:]
        value_options = WRAPPER_VALUE_OPTIONS.get(wrapper, set())
        while (
            words
            and words[0].static
            and (words[0].text.startswith("-") or (wrapper == "env" and re.fullmatch(r"\w+=.*", words[0].text)))
        ):
            took_value = words[0].text in value_options
            words = words[1:]
            if took_value and words:
                words = words[1:]
        if wrapper == "timeout" and words:  # the duration
            words = words[1:]
    return words


def _script_words(argv: list[Word]) -> tuple[str, list[Word]] | None:
    """('bash', [script word]) for `bash -c SCRIPT`, ('eval', args) for eval; None otherwise."""
    words = _effective(argv)
    if not words or not words[0].static:
        return None
    name = os.path.basename(words[0].text)
    if name == "eval":
        return "eval", words[1:]
    if name not in SHELLS:
        return None
    i = 1
    while i < len(words):
        w = words[i].text if words[i].static else ""
        if w in ("-o", "+o", "-O", "+O"):
            i += 2
            continue
        if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", w):
            return name, words[i + 1 : i + 2]
        if not w.startswith(("-", "+")):
            return None  # a script file
        i += 1
    return None


def _stdin_interpreter(argv: list[Word]) -> str:
    """Name of the interpreter when this command reads its program from stdin, else ''."""
    words = _effective(argv)
    if not words or not words[0].static:
        return ""
    name = os.path.basename(words[0].text)
    args = [w.text if w.static else "\0dynamic" for w in words[1:]]
    if name in ("source", "."):
        return name if args[:1] in (["/dev/stdin"], ["/dev/fd/0"], ["-"]) else ""
    base = re.sub(r"[\d.]+$", "", name)  # python3.12 → python
    if name in SHELLS:
        if any(re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", a) for a in args):
            return ""
        positional = [a for a in args if not a.startswith(("-", "+"))]
        return name if not positional or "-s" in args else ""
    if base in INTERPRETERS or name in INTERPRETERS:
        if any(a in CODE_FLAGS or (a.startswith("-") and a[1:2] in "cmeEpr" and len(a) == 2) for a in args):
            return ""
        positional = [a for a in args if a == "-" or not a.startswith("-")]
        return name if not positional or positional[0] == "-" else ""
    return ""


class _Walker:
    def __init__(self, session_cwd: str, depth: int = 0):
        self.session = os.path.normpath(session_cwd)
        self.calls: list[Call] = []
        self.dry = 0
        self.depth = depth

    # -- emitting
    def emit(self, call: Call) -> Call:
        if not self.dry:
            self.calls.append(call)
        return call

    # -- substitutions found in some JSON (words, redirects, heredocs…)
    def substs(self, node, st: _State, parent: Call | None) -> None:
        for s in _find_subst(node):
            origin = "`" if s.get("Backquotes") else {"CmdSubst": "$(", "ProcSubst": s.get("Op", "<(")}[s["Type"]]
            before = len(self.calls)
            self.stmts(s.get("Stmts") or [], _State(st.sure, st.seen, st.known), True, (), origin)
            if parent is not None:
                parent.substitutions.extend(_toplevel(self.calls[before:]))

    # -- statements
    def stmts(self, items: list[dict], st: _State, sub: bool, inh: tuple[Redirect, ...], origin: str) -> _State:
        for i, s in enumerate(items):
            if i:  # after `;` / newline the previous command may have failed (the last is followed by the caller's operator)
                st = _State(st.seen, st.seen, st.known)
            st = self.stmt(s, st, sub, inh, origin)
        return st

    def stmt(self, s: dict, st: _State, sub: bool, inh: tuple[Redirect, ...], origin: str) -> _State:
        own = tuple(_redirect(r) for r in s.get("Redirs") or [])
        redirs = (*own, *inh)
        background = bool(s.get("Background") or s.get("Coprocess"))
        if background:
            self.cmd(s.get("Cmd"), st, True, redirs, origin, s, own)
            return st
        return self.cmd(s.get("Cmd"), st, sub, redirs, origin, s, own)

    def cmd(self, c, st, sub, redirs, origin, stmt, own) -> _State:
        t = c["Type"] if c else None
        inherited = tuple(Redirect(r.op, r.target, r.heredoc, r.fd, True) for r in redirs)
        if t is None:  # `> file`, `<<EOF` with no command
            call = self.emit(Call([], list(redirs), st.sure, sub, origin=origin, cwd_known=st.known))
            call.background = bool(stmt.get("Background"))
            self.substs(stmt.get("Redirs") or [], st, call)
            return st
        if t == "CallExpr":
            return self.call(c, st, sub, redirs, origin, stmt)
        if t == "BinaryCmd":
            return self.binary(c, st, sub, inherited, origin)
        if t == "Subshell":
            self.stmts(c.get("Stmts") or [], st, True, inherited, origin)
            self.substs(stmt.get("Redirs") or [], st, None)
            return st
        if t == "Block":
            out = self.stmts(c.get("Stmts") or [], st, sub, inherited, origin)
            self.substs(stmt.get("Redirs") or [], st, None)
            return out
        if t == "IfClause":
            return self.if_clause(c, st, sub, inherited, origin)
        if t == "WhileClause":
            return self.loop(
                lambda s0: self.stmts(
                    c.get("Do") or [],
                    self.stmts(c.get("Cond") or [], s0, sub, inherited, origin),
                    sub,
                    inherited,
                    origin,
                ),
                st,
            )
        if t == "ForClause":
            self.substs(c.get("Loop"), st, None)
            return self.loop(lambda s0: self.stmts(c.get("Do") or [], s0, sub, inherited, origin), st)
        if t == "CaseClause":
            self.substs(c.get("Word"), st, None)
            outs = [st]
            for item in c.get("Items") or []:
                self.substs(item.get("Patterns"), st, None)
                outs.append(self.stmts(item.get("Stmts") or [], st, sub, inherited, origin))
            return _join(outs)
        if t == "FuncDecl":
            wide = frozenset({*st.seen, self.session})
            self.stmt(c["Body"], _State(wide, wide, False), sub, inherited, "function")
            return st
        if t == "TimeClause" or t == "CoprocClause":
            if c.get("Stmt"):
                inner = self.stmt(c["Stmt"], st, sub or t == "CoprocClause", inherited, origin)
                return st if t == "CoprocClause" else inner
            return st
        if t in ("DeclClause", "TestClause", "ArithmCmd", "LetClause"):
            return self.builtin_like(c, t, st, sub, redirs, origin, stmt)
        raise ParseError(f"unsupported command type {t}")

    def if_clause(self, c, st, sub, inh, origin) -> _State:
        cond = self.stmts(c.get("Cond") or [], st, sub, inh, origin) if c.get("Cond") else st
        then = self.stmts(c.get("Then") or [], cond, sub, inh, origin)
        other_in = _State(cond.seen, cond.seen, cond.known)  # the condition may have changed directory and failed
        if c.get("Else"):
            other = self.if_clause(c["Else"], other_in, sub, inh, origin)
        else:
            other = other_in
        return _join([then, other])

    def loop(self, body, st: _State) -> _State:
        self.dry += 1
        try:
            first = body(st)
        finally:
            self.dry -= 1
        wide = _State(st.sure | first.sure, first.seen, first.known)  # the next round starts where the body ended
        again = body(wide)
        return _State(st.sure | again.sure, again.seen, again.known)

    def binary(self, c, st, sub, redirs, origin) -> _State:
        op = c["Op"]
        if op in ("|", "|&"):
            return self.pipeline(c, st, sub, redirs, origin)
        x = self.stmt(c["X"], st, sub, redirs, origin)
        if op == "&&":
            return self.stmt(c["Y"], _State(x.sure, x.seen, x.known), sub, redirs, origin)
        # `||`: the right side runs where the left one failed - anywhere the left side went
        y = self.stmt(c["Y"], _State(x.seen, x.seen, x.known), sub, redirs, origin)
        return _State(x.sure | y.sure, y.seen, x.known and y.known)

    def pipeline(self, c, st, sub, redirs, origin) -> _State:
        stages: list[dict] = []

        def flatten(n):
            cmd = n.get("Cmd")
            if cmd and cmd["Type"] == "BinaryCmd" and cmd["Op"] in ("|", "|&") and not n.get("Redirs"):
                flatten(cmd["X"])
                flatten(cmd["Y"])
            else:
                stages.append(n)

        flatten({"Cmd": c})
        spans: list[tuple[int, int]] = []
        for i, stage in enumerate(stages):
            before = len(self.calls)
            self.stmt(stage, st, True, redirs, origin)
            spans.append((before, len(self.calls)))
            if i and not self.dry:
                for call in _toplevel(self.calls[before:]):
                    call.piped_in = True
        if not self.dry:
            for i, (a, b) in enumerate(spans):
                if any(call.stdin_interpreter and call.piped_in for call in _toplevel(self.calls[a:b])):
                    for j in range(i):
                        for call in _toplevel(self.calls[spans[j][0] : spans[j][1]]):
                            call.pipe_to_shell = True
        return st

    # -- simple command
    def call(self, c, st, sub, redirs, origin, stmt) -> _State:
        argv = [_word(w) for w in c.get("Args") or []]
        assigns = [self.assign(a) for a in c.get("Assigns") or []]
        call = self.emit(Call(argv, list(redirs), st.sure, sub, assigns=assigns, origin=origin, cwd_known=st.known))
        call.background = bool(stmt.get("Background"))
        call.stdin_interpreter = _stdin_interpreter(argv)
        for part in (c.get("Assigns"), c.get("Args"), stmt.get("Redirs")):
            self.substs(part, st, call)
        self.nested_script(call, st)
        return self.after_call(call, st)

    def assign(self, a: dict) -> Assign:
        array = tuple(_word(e["Value"]) for e in (a.get("Array") or {}).get("Elems", []) if e.get("Value"))
        value = _word(a["Value"]) if a.get("Value") else None
        return Assign((a.get("Name") or {}).get("Value", ""), value, array, bool(a.get("Append")))

    def builtin_like(self, c, t, st, sub, redirs, origin, stmt) -> _State:
        words: list[Word] = []
        if t == "DeclClause":
            words.append(Word((c.get("Variant") or {}).get("Value", "declare"), "none", False))
            for a in c.get("Args") or []:
                if a.get("Name") and (a.get("Value") or a.get("Array")):
                    v = _word(a["Value"]) if a.get("Value") else Word("(…)", "none", False)
                    words.append(Word(a["Name"]["Value"] + "=" + v.text, v.quoting, v.expands, v.kinds))
                elif a.get("Name"):
                    words.append(Word(a["Name"]["Value"], "none", False))
                elif a.get("Value"):
                    words.append(_word(a["Value"]))
        else:
            words.append(Word({"TestClause": "[[", "ArithmCmd": "((", "LetClause": "let"}[t], "none", False))
            for n in _find_words(c):
                words.append(_word(n))
        call = self.emit(Call(words, list(redirs), st.sure, sub, origin=origin, cwd_known=st.known))
        call.background = bool(stmt.get("Background"))
        self.substs(c, st, call)
        self.substs(stmt.get("Redirs"), st, call)
        return st

    def nested_script(self, call: Call, st: _State) -> None:
        found = _script_words(call.argv)
        if not found:
            return
        kind, words = found
        origin = "eval" if kind == "eval" else "-c"
        if not words or any(not w.static for w in words):
            call.opaque_code = bool(words) or kind != "eval"
            return
        if self.depth >= MAX_DEPTH:
            raise ParseError("scripts nested too deeply")
        text = " ".join(w.text for w in words)
        inner = _Walker(self.session, self.depth + 1)
        inner.dry = self.dry
        inner.stmts(ast(text).get("Stmts") or [], _State(st.sure, st.seen, st.known), True, (), origin)
        call.substitutions.extend(_toplevel(inner.calls))
        if not self.dry:
            self.calls.extend(inner.calls)

    def after_call(self, call: Call, st: _State) -> _State:
        if not call.argv:
            return st
        words = list(call.argv)
        while words and words[0].static and words[0].text in ("builtin", "command"):
            words = words[1:]
        if not words or not words[0].static:
            return st
        name = words[0].text
        if name == "popd":
            return _State(st.seen, st.seen, st.known)
        if name not in ("cd", "pushd"):
            return st
        args = []
        for w in words[1:]:
            if w.static and w.text in ("-L", "-P", "-e", "-@", "--") and not args:
                continue
            args.append(w)
        if len(args) > 1:
            return self.unknown_dir(st)
        tilde = True
        if not args:
            target = "~" if name == "cd" else None
        elif args[0].kinds <= {"tilde"} and args[0].text != "-" and not re.match(r"[+-]\d+$", args[0].text):
            target = args[0].text
            tilde = "tilde" in args[0].kinds
        else:
            target = None
        if target is None:
            return self.unknown_dir(st)
        moved = frozenset(_resolve(target, d, tilde) for d in st.sure)
        return _State(moved, st.seen | moved, st.known)

    def unknown_dir(self, st: _State) -> _State:
        wide = frozenset({*st.seen, self.session})
        return _State(wide, wide, False)


def _toplevel(calls: list[Call]) -> list[Call]:
    """The calls of the list that are not a substitution / nested script of another call in it."""
    nested = {id(c) for call in calls for c in call.substitutions}
    return [c for c in calls if id(c) not in nested]


def _join(states: list[_State]) -> _State:
    sure: frozenset[str] = frozenset()
    seen: frozenset[str] = frozenset()
    known = True
    for s in states:
        sure |= s.sure
        seen |= s.seen
        known = known and s.known
    return _State(sure, seen, known)


def _find_words(node) -> list[dict]:
    """Word-like nodes (with Parts) of a test / arithmetic / let command, in source order."""
    found = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if n.get("Type") in ("CmdSubst", "ProcSubst"):
                continue
            if "Parts" in n and n.get("Type") in (None, "Word"):
                found.append(n)
            else:
                stack.extend(reversed(list(n.values())))
        elif isinstance(n, list):
            stack.extend(reversed(n))
    return found


def parse(command: str, *, cwd: str) -> list[Call]:
    """Every simple command in the line (also nested ones), in source order, parents before their substitutions.

    Raises ParseError when the line cannot be parsed with certainty. Nothing else escapes: a tree shape this module did
    not expect, or nesting deeper than the Python stack, is a ParseError too (the caller denies on it)."""
    walker = _Walker(cwd)
    start = frozenset({walker.session})
    try:
        walker.stmts(ast(command).get("Stmts") or [], _State(start, start), False, (), "top")
    except ParseError:
        raise
    except (RecursionError, KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
        raise ParseError(f"cannot walk the syntax tree ({type(e).__name__})") from e
    return walker.calls
