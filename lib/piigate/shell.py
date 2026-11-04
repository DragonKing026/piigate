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
import hashlib
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

DIALECTS = ("bash", "zsh")  # the grammar shfmt is asked for (`-ln`); the agent's Bash tool may run either shell
DEFAULT_DIALECT = "bash"
SHFMT_TIMEOUT = 5.0  # seconds; a pathological input must not hang the hook
MAX_DEPTH = 4  # nesting of `bash -c '…'` / `eval` scripts that is parsed
MAX_BYTES = 256 * 1024  # larger commands are refused (fail closed) instead of being parsed
MAX_CALL_DEPTH = 4  # functions calling functions
MAX_LOOP_NESTING = 6  # loops inside loops: each level walks its body twice, so the time is 2**depth

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
    """No `shfmt` binary with a pinned checksum (not bundled with the plugin, not in ~/.local/bin)."""


@dataclass(frozen=True)
class Word:
    text: str  # the shell's view of the literal parts; an expansion is kept as a placeholder (`$x`, `${x}`, `$(…)`)
    quoting: str  # none | single | double | mixed
    expands: bool  # the value is not known statically: $var, ${}, $(), ``, $(( )), <( ), glob, ~, brace, extglob
    kinds: frozenset[str] = frozenset()  # param cmd arith proc glob tilde brace extglob
    quote: str = ""  # `'` or `"` when the word is ONE quoted fragment (alone or after `--option=`): never globbed or brace-expanded

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
    piped_stderr: bool = False  # ... from `|&`: the previous stage's stderr comes with it
    loop_var: str = ""  # the variable of a `for` / `select` pseudo-call
    pipes_out: bool = False  # its stage feeds a later stage of the pipeline (every command of a `{ a; b; } | c` stage does)
    opaque_code: bool = False  # `bash -c "$x"` / `eval $x`: code the parser cannot see
    background: bool = False

    @property
    def name(self) -> str:
        """Basename of the command word when it is static (`/usr/bin/cat` → cat), else ''."""
        return os.path.basename(self.argv[0].text) if self.argv and self.argv[0].static else ""


# ------------------------------------------------------------------------------------------------ running shfmt


# The parser is part of the gate: a program that answers `{"Type":"File"}` to everything would make the gate allow it
# all. So the binary that runs must be exactly one this module knows — by the SHA-256 of its bytes, checked for every
# run (the bytes that are checked are the bytes that run: on Linux they go through a memfd).
# Source of the sums: the `digest` field of the assets of the GitHub release mvdan/sh v3.14.1
# (`gh api repos/mvdan/sh/releases/tags/v3.14.1`), the release's own checksum for each uploaded file. Nothing downloaded.
SHFMT_VERSION = "3.14.1"
SHFMT_PINS = {
    ("linux", "amd64"): "76e77641faa025814b77f153b29796b8e6fa2fca03e0c76a691608b86c7ea7bf",
    ("linux", "arm64"): "5f2db09dae91fca848f7adbdd014632e921a383863a2ad7e0450ad3aba0c6489",
    ("darwin", "amd64"): "d33eee0da0f92835b3562e9767a05cee7e4eaeef47daa03bfd09da17b4b590a6",
    ("darwin", "arm64"): "b7c872db63553ccffc7253aba3ed7d4885a27d83f1ba567b1138c6315a5847e5",
}
PLUGIN_ROOT = Path(__file__).resolve().parents[2]


def _platform() -> tuple[str, str]:
    system = {"linux": "linux", "darwin": "darwin"}.get(sys.platform, sys.platform)
    machine = platform.machine().lower()
    return system, {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)


def _shfmt_candidates() -> list[str]:
    """Where the pinned binary may be: the plugin's own file, until it is bundled also the user's install. PATH is never
    searched (the agent can put a program there)."""
    system, arch = _platform()
    return [str(PLUGIN_ROOT / "bin" / f"shfmt-{system}-{arch}"), os.path.expanduser("~/.local/bin/shfmt")]


def _shfmt_binary() -> tuple[str, bytes]:
    """(path, bytes) of the first candidate whose SHA-256 is the pin of this platform; ShfmtMissing otherwise."""
    pin = SHFMT_PINS.get(_platform())
    if pin is None:
        raise ShfmtMissing(f"no pinned shfmt for {_platform()}")
    wrong = []
    for candidate in _shfmt_candidates():
        try:
            data = Path(candidate).read_bytes()
        except OSError:
            continue
        if hashlib.sha256(data).hexdigest() == pin:
            return candidate, data
        wrong.append(candidate)
    raise ShfmtMissing("shfmt with the pinned checksum not found" + (" (a file with another checksum exists)" if wrong else ""))


def _sealed_memfd(data: bytes) -> int:
    """A memfd that holds exactly `data` and can no longer be written, grown or shrunk (nor can the seals change)."""
    import fcntl

    fd = os.memfd_create("shfmt", os.MFD_ALLOW_SEALING)
    try:
        os.write(fd, data)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
    except OSError:
        os.close(fd)
        raise
    return fd


def _run_shfmt(command: bytes, dialect: str) -> subprocess.CompletedProcess:
    """Runs the checked bytes. On Linux they are copied into a sealed memfd and THAT is executed: nothing on disk can
    change what runs after the check. If that is impossible (no memfd, not executable there, no sealing) the answer is
    ParseError — there is no fallback to running the file: it could have changed since it was hashed. Without memfd_create
    (macOS) the file is run after the check: a window between the hash and the exec in which someone who can write the
    file (the same user — the agent) swaps it; then the swapped program answers for the gate. Nothing closes that on
    macOS without a signed/immutable binary in the plugin."""
    path, data = _shfmt_binary()
    args = ["-ln", dialect, "--to-json"]
    env = {"PATH": "/usr/bin:/bin"}
    if hasattr(os, "memfd_create"):
        try:
            fd = _sealed_memfd(data)
        except (OSError, AttributeError) as e:
            raise ParseError(f"cannot seal the verified shfmt in memory: {e}") from e
        try:
            return subprocess.run(
                [f"/proc/self/fd/{fd}", *args], input=command, capture_output=True, timeout=SHFMT_TIMEOUT,
                check=False, cwd="/", env=env, pass_fds=(fd,),
            )
        finally:
            os.close(fd)
    return subprocess.run(
        [path, *args], input=command, capture_output=True, timeout=SHFMT_TIMEOUT, check=False, cwd="/", env=env
    )


def ast(command: str, dialect: str = DEFAULT_DIALECT) -> dict:
    """The raw shfmt JSON syntax tree of the command (stdin only, no files, working directory `/`)."""
    if dialect not in DIALECTS:
        raise ParseError(f"unknown dialect {dialect!r}")
    if len(command.encode("utf-8", "replace")) > MAX_BYTES:
        raise ParseError("command too long")
    try:
        done = _run_shfmt(command.encode("utf-8", "surrogateescape"), dialect)
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
    if not tree.get("Stmts") and any(line.strip() and not line.lstrip().startswith("#") for line in command.splitlines()):
        raise ParseError("shfmt found no command in a line that is not a comment")  # a parser that says "nothing" is lying
    return tree


# ------------------------------------------------------------------------------------------------ words
#
# shfmt writes the JSON of a Go struct with `omitempty`: a field that holds the zero value is NOT in the output. That
# is how the tree says "empty": `''` is {"Type": "SglQuoted"} without "Value", `""` is a DblQuoted without "Parts", an
# empty heredoc has no "Hdoc", `a=` has an Assign without "Value". Each access below is one of two kinds:
#   - a TEXT field (Lit/SglQuoted Value, DblQuoted/Hdoc Parts, Assign Value) — absent means the empty string / list
#     (`_text`, `.get(..., "")`);
#   - a STRUCTURE field (Type of a node, Op and Word of a redirection, X/Y/Op of BinaryCmd, Body of a function, Name of
#     an assignment) — absent means a tree this module does not understand: `_need` raises ParseError (fail closed).


def _need(node: dict, key: str):
    """A structure field: it is always present in a tree this module understands."""
    try:
        return node[key]
    except (KeyError, TypeError) as e:
        raise ParseError(f"unexpected syntax tree: no {key!r}") from e  # never the node: it holds the command


def _text(node: dict, key: str = "Value") -> str:
    """A text field: absent = empty (`omitempty`)."""
    return node.get(key) or ""


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


def _lits(node) -> list[str]:
    """Every literal text under a node, in order (a subscript, an arithmetic expression) — substitutions are walked apart."""
    if isinstance(node, dict):
        if node.get("Type") in ("CmdSubst", "ProcSubst"):
            return ["$(…)"]
        out = [node["Value"]] if node.get("Type") == "Lit" and node.get("Value") else []
        for k, v in node.items():
            if k not in ("Pos", "End", "Position"):
                out += _lits(v)
        return out
    if isinstance(node, list):
        return [x for v in node for x in _lits(v)]
    return []


def _param_text(p: dict, kinds: set[str]) -> str:
    """`$x`, `${x}`; with an operand (`${x:-Sensitive/a.csv}`, `${x/a/b}`) the operand stays in the text — it is what the
    shell substitutes, and a path in it must stay visible to the gate. An unquoted operand with a glob is globbed."""
    name = _text(p.get("Param") or {})
    kinds.add("$" + name)  # the variable this expansion reads: `kinds` carries "$name" (the adapter resolves it)
    if p.get("Short"):
        return "$" + name
    inner = name
    if p.get("NestedParam"):  # zsh `${${(e)x}}`, `${(e)${y}}`: the nested expansion is the name
        inner = _expansion_text(p["NestedParam"], kinds)
    exp, repl = p.get("Exp") or {}, p.get("Repl") or {}
    for prefix, operand in ((_text(exp, "Op"), exp.get("Word")), ("/", repl.get("Orig")), ("/", repl.get("With"))):
        if operand is not None:
            w = _word(operand)
            kinds |= w.kinds - {"param"}
            inner += prefix + w.text
    if p.get("Index") is not None:  # `${a[@]}`, `${a[$i]}`: the subscript is part of what the word names
        inner += "[" + "".join(_lits(p["Index"])) + "]"
    return "${" + inner + "}"


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
    for i, p in enumerate(node.get("Parts") or []):
        t = _need(p, "Type")
        if t == "Lit":
            raw = _text(p)
            quoting.add("none")
            texts.append(_unescape(raw))
            if re.search(r"(?<!\\)\(", raw):  # an unescaped `(` inside a word (`\(` is a literal paren: `find \( -name x \)`)
                # zsh only: a glob qualifier `*(.)` / `*(e:code:)` / `*(+func)` is kept by shfmt as plain text, it has no
                # node (it can run code: `(e:…:)`, `(e/…/)`, `(+func)`, `(#qe…)` — never read from the text)
                kinds.add("zsh")  # no node for what the qualifier does: the gate decides by the context, not by its text
            if _has_glob(raw):
                kinds.add("glob")
            if _has_brace(raw):
                kinds.add("brace")
            if i == 0 and raw.startswith("~"):
                kinds.add("tilde")
        elif t == "SglQuoted":
            quoting.add("single")
            texts.append(_ansi_c(_text(p)) if p.get("Dollar") else _text(p))
        elif t == "DblQuoted":
            quoting.add("double")
            for q in p.get("Parts") or []:
                if _need(q, "Type") == "Lit":
                    texts.append(_unescape_dq(_text(q)))
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
    parts = node.get("Parts") or []
    quote = ""
    if parts and (len(parts) == 1 or (len(parts) == 2 and parts[0]["Type"] == "Lit" and re.fullmatch(r"--[\w-]+=", _text(parts[0])))):
        last = parts[-1]
        if last["Type"] == "DblQuoted":
            quote = '"'
        elif last["Type"] == "SglQuoted" and not last.get("Dollar"):
            quote = "'"
    return Word("".join(texts), label, bool(kinds), frozenset(kinds), quote)


def _expansion_text(p: dict, kinds: set[str]) -> str:
    t = _need(p, "Type")
    if t == "ParamExp":
        kinds.add("param")
        if p.keys() & {"Flags", "GlobSubst", "Modifiers", "NestedParam"}:  # zsh `${(e)x}`, `${~x}`, `${x:a}`, `${${…}}`
            kinds.add("zsh")
            if set(_text(p.get("Flags") or {})) & set("e%"):
                kinds.add("zsh-code")  # `(e)` evaluates `$(…)` and `$x` in the value (works without any setopt); `(%)` prompt escapes
        exp = p.get("Exp") or {}
        if exp.get("Op") == "@" and exp.get("Word") and _word(exp["Word"]).text == "P":
            kinds.update({"cmd", "exec"})  # bash `${x@P}`: prompt expansion runs `$(…)` found in the value
        return _param_text(p, kinds)
    if t == "CmdSubst":
        kinds.add("cmd")
        return "$(…)"
    if t == "ArithmExp":
        kinds.add("arith")
        if _find_subst(p):
            kinds.add("cmd")
        return "$((" + "".join(_lits(p)) + "))"  # the operands stay in the word (a subscript there may name a file)
    if t == "ProcSubst":
        kinds.add("proc")
        return p.get("Op", "<(") + "…)"
    if t == "ExtGlob":
        kinds.add("extglob")
        kinds.add("zsh")  # zsh reads `(…)` after a pattern as a glob qualifier; the tree has no node for what is inside
        return _text(p, "Op") + _text(p.get("Pattern") or {}) + ")"
    raise ParseError(f"unsupported word part {t}")


def _heredoc(redir: dict) -> Heredoc:
    delim_node = _need(redir, "Word")
    quoted = any(_need(p, "Type") != "Lit" or "\\" in _text(p) for p in _need(delim_node, "Parts"))
    delimiter = _word(delim_node).text
    pieces: list[str] = []
    kinds: set[str] = set()
    for p in (redir.get("Hdoc") or {}).get("Parts") or []:  # no "Hdoc" / "Parts": an empty body
        if _need(p, "Type") == "Lit":
            pieces.append(_text(p) if quoted else re.sub(r"\\([$`\\])", r"\1", _text(p)))
        else:
            pieces.append(_expansion_text(p, kinds))
    body = "".join(pieces)
    if _need(redir, "Op") == "<<-":
        body = re.sub(r"(?m)^\t+", "", body)
    return Heredoc(body, delimiter, quoted)


def _redirect(r: dict, inherited: bool = False) -> Redirect:
    op = _need(r, "Op")
    fd = _text(r.get("N") or {}) or None
    if op in ("<<", "<<-"):
        return Redirect(op, None, _heredoc(r), fd, inherited)
    return Redirect(op, _word(_need(r, "Word")), None, fd, inherited)


# ------------------------------------------------------------------------------------------------ walking


@dataclass(frozen=True)
class _State:
    sure: frozenset[str]  # where the next command runs when everything before it (joined by &&) succeeded
    seen: frozenset[str]  # every directory a command so far may have run in
    known: bool = True  # the directory of the next `&&` successor is exactly `sure`
    any_known: bool = True  # ... on every path (a `cd` that may have failed leaves the earlier directories possible)


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
    def __init__(self, session_cwd: str, depth: int = 0, dialect: str = DEFAULT_DIALECT):
        self.dialect = dialect
        self.loops = 0  # loops open around the statement being walked
        self.functions: dict[str, dict] = {}  # name -> body of the functions declared so far: analysed again at each call
        self.stack: list[str] = []  # functions being walked (a recursive call is refused)
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
            origin = "`" if s.get("Backquotes") else {"CmdSubst": "$(", "ProcSubst": s.get("Op", "<(")}[_need(s, "Type")]
            before = len(self.calls)
            self.stmts(s.get("Stmts") or [], st, True, (), origin)
            if parent is not None:
                parent.substitutions.extend(_toplevel(self.calls[before:]))

    # -- statements
    def stmts(self, items: list[dict], st: _State, sub: bool, inh: tuple[Redirect, ...], origin: str) -> _State:
        for i, s in enumerate(items):
            if i:  # after `;` / newline the previous command may have failed (the last is followed by the caller's operator)
                st = _State(st.seen, st.seen, st.any_known, st.any_known)
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
        t = _need(c, "Type") if c else None
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
            # the words of `for f in WORDS` / `select f in WORDS` are arguments like any other: a path there is judged
            words = [Word("select" if c.get("Select") else "for", "none", False), *(_word(n) for n in _find_words(c.get("Loop")))]
            call = self.emit(Call(words, list(redirs), st.sure, sub, origin=origin, cwd_known=st.known))
            call.loop_var = _text((c.get("Loop") or {}).get("Name") or {})
            self.substs(c.get("Loop"), st, call)
            return self.loop(lambda s0: self.stmts(c.get("Do") or [], s0, sub, inherited, origin), st)
        if t == "CaseClause":
            words = [Word("case", "none", False), *(_word(n) for n in _find_words(c.get("Word")))]
            for item in c.get("Items") or []:
                words += [_word(n) for n in _find_words(item.get("Patterns"))]
            call = self.emit(Call(words, list(redirs), st.sure, sub, origin=origin, cwd_known=st.known))
            self.substs(c.get("Word"), st, call)
            outs = [st]
            for item in c.get("Items") or []:
                self.substs(item.get("Patterns"), st, call)
                outs.append(self.stmts(item.get("Stmts") or [], st, sub, inherited, origin))
            return _join(outs)
        if t == "FuncDecl":
            name = _text(c.get("Name") or {})
            body = _need(c, "Body")
            self.functions[name] = body
            # the words of the body are emitted where it is declared (nothing disappears even if it is never called); the
            # effect on the directory and the pipeline is analysed where it is CALLED (`call`)
            self.stmt(body, st, sub, inherited, "function")
            return st
        if t == "CoprocClause":
            # a coprocess runs beside the rest of the line and its output comes back through `$COPROC`: nobody follows it
            call = self.emit(Call([Word("coproc", "none", False)], list(redirs), st.sure, sub, origin=origin, cwd_known=st.known))
            call.opaque_code = True
            if c.get("Stmt"):
                self.stmt(c["Stmt"], st, True, inherited, origin)
            return st
        if t == "TimeClause":
            if c.get("Stmt"):
                return self.stmt(c["Stmt"], st, sub, inherited, origin)
            return st
        if t in ("DeclClause", "TestClause", "ArithmCmd", "LetClause"):
            return self.builtin_like(c, t, st, sub, redirs, origin, stmt)
        raise ParseError(f"unsupported command type {t}")

    def if_clause(self, c, st, sub, inh, origin) -> _State:
        cond = self.stmts(c.get("Cond") or [], st, sub, inh, origin) if c.get("Cond") else st
        then = self.stmts(c.get("Then") or [], cond, sub, inh, origin)
        other_in = _State(cond.seen, cond.seen, cond.any_known, cond.any_known)  # the condition may have changed directory and failed
        if c.get("Else"):
            other = self.if_clause(c["Else"], other_in, sub, inh, origin)
        else:
            other = other_in
        return _join([then, other])

    def loop(self, body, st: _State) -> _State:
        if self.loops >= MAX_LOOP_NESTING:
            raise ParseError("loops nested too deeply")
        self.loops += 1
        try:
            self.dry += 1
            try:
                first = body(st)
            finally:
                self.dry -= 1
            wide = _State(st.sure | first.sure, first.seen, first.known, first.any_known)  # the next round starts where it ended
            again = body(wide)
        finally:
            self.loops -= 1
        return _State(st.sure | again.sure, again.seen, st.known and again.known, st.any_known and again.any_known)

    def binary(self, c, st, sub, redirs, origin) -> _State:
        op = _need(c, "Op")
        if op in ("|", "|&"):
            return self.pipeline(c, st, sub, redirs, origin)
        x = self.stmt(_need(c, "X"), st, sub, redirs, origin)
        if op == "&&":
            return self.stmt(_need(c, "Y"), x, sub, redirs, origin)
        # `||`: the right side runs where the left one failed - anywhere the left side went
        y = self.stmt(_need(c, "Y"), _State(x.seen, x.seen, x.any_known, x.any_known), sub, redirs, origin)
        return _State(x.sure | y.sure, y.seen, x.known and y.known, x.any_known and y.any_known)

    def pipeline(self, c, st, sub, redirs, origin) -> _State:
        stages: list[dict] = []
        ops: list[str] = []  # ops[i - 1] joins stage i - 1 and stage i

        def flatten(n):
            cmd = n.get("Cmd")
            if cmd and cmd.get("Type") == "BinaryCmd" and _need(cmd, "Op") in ("|", "|&") and not n.get("Redirs"):
                flatten(_need(cmd, "X"))
                ops.append(cmd["Op"])
                flatten(_need(cmd, "Y"))
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
                    call.piped_stderr = ops[i - 1] == "|&"
        if not self.dry:
            for a, b in spans[:-1]:  # every command of a stage feeds the next stage, not only the last one
                for call in _toplevel(self.calls[a:b]):
                    call.pipes_out = True
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
        after = self.nested_script(call, st)  # `eval cd ..` runs in this shell: its directory carries on
        self.chdir_wrapper(call, st)
        name = argv[0].text if argv and argv[0].static else ""
        if name in self.functions:
            return self.call_function(name, call, after or st, sub, redirs, origin)
        return self.after_call(call, after or st)

    def call_function(self, name: str, call: Call, st: _State, sub, redirs, origin) -> _State:
        """The body of a function, walked again where it is called: with the directory of the call, its commands in the
        pipeline of the call, its `cd` carried on (a function runs in the calling shell)."""
        if name in self.stack:
            raise ParseError("recursive function")
        if len(self.stack) >= MAX_CALL_DEPTH:
            raise ParseError("functions called too deeply")
        inherited = tuple(Redirect(r.op, r.target, r.heredoc, r.fd, True) for r in redirs)
        self.stack.append(name)
        try:
            return self.stmt(self.functions[name], st, sub, inherited, "function")
        finally:
            self.stack.pop()

    def assign(self, a: dict) -> Assign:
        array: list[Word] = []
        if a.get("Index") is not None:  # `a[k]=v`: the subscript is a word of the assignment
            array.append(Word("".join(_lits(a["Index"])), "none", False))
        for e in (a.get("Array") or {}).get("Elems") or []:  # `a=(x y)`, `a=([k]=v)`: every index and every value
            if e.get("Index") is not None:
                array.append(Word("[" + "".join(_lits(e["Index"])) + "]", "none", False))
            if e.get("Value"):
                array.append(_word(e["Value"]))
        value = _word(a["Value"]) if a.get("Value") else None  # `a=` has no "Value": the empty string
        return Assign(_text(_need(a, "Name")), value, tuple(array), bool(a.get("Append")))

    def builtin_like(self, c, t, st, sub, redirs, origin, stmt) -> _State:
        words: list[Word] = []
        decl_assigns: list[Assign] = []
        if t == "DeclClause":
            words.append(Word(_text(c.get("Variant") or {}) or "declare", "none", False))
            for a in c.get("Args") or []:
                if a.get("Name") and (a.get("Value") or a.get("Array") or a.get("Index") is not None):
                    asg = self.assign(a)  # `declare -a a=(P)`, `declare -A a=([k]=P)`: the elements are words of the command
                    decl_assigns.append(asg)
                    v = asg.value or Word("", "none", False)
                    words.append(Word(asg.name + "=" + v.text, v.quoting, v.expands, v.kinds))
                    words += list(asg.array)
                elif a.get("Name"):
                    words.append(Word(_text(a["Name"]), "none", False))
                elif a.get("Value"):
                    words.append(_word(a["Value"]))
        else:
            words.append(Word({"TestClause": "[[", "ArithmCmd": "((", "LetClause": "let"}[t], "none", False))
            for n in _find_words(c):
                words.append(_word(n))
        call = self.emit(Call(words, list(redirs), st.sure, sub, assigns=decl_assigns, origin=origin, cwd_known=st.known))
        call.background = bool(stmt.get("Background"))
        self.substs(c, st, call)
        self.substs(stmt.get("Redirs"), st, call)
        return st

    def chdir_wrapper(self, call: Call, st: _State) -> None:
        """`env -C dir cmd`, `sudo -D dir cmd`: the command runs elsewhere — in any directory seen so far."""
        words = list(call.argv)
        while words and words[0].static and os.path.basename(words[0].text) in WRAPPERS:
            wrapper = os.path.basename(words[0].text)
            for w in words[1:]:
                if not w.static or not w.text.startswith("-"):
                    break
                if (wrapper in ("env", "sudo", "doas") and re.fullmatch(r"-[A-Za-z]*[CD]|--chdir(?:=.*)?|-[CD].+", w.text)) or (
                    wrapper == "env" and w.text.startswith("--chdir")
                ):
                    call.cwds = frozenset({*st.seen, self.session})
                    call.cwd_known = False
                    return
            words = words[1:]

    def nested_script(self, call: Call, st: _State) -> _State | None:
        """The scripts the command runs: `bash -c S`, `eval S` — and the same behind a launcher in its arguments
        (`find -exec sh -c S ';'`, `xargs sh -c S`, `env -i bash -c S`): every shell word of the argv followed by -c."""
        out: _State | None = None
        i = 0
        done: set[int] = set()  # a script reached from two starting words (`sudo bash -c S`) runs once
        while i < len(call.argv):
            found = _script_words(call.argv[i:])
            if found and not (found[1] and id(found[1][0]) in done):
                done.update(id(w) for w in found[1][:1])
                state = self.run_script(call, st, *found)
                if found[0] == "eval" and i == 0:
                    out = state  # a top-level eval runs in THIS shell: its directory carries on
                elif state is not None and i:
                    pass  # behind a launcher: a child process
            i += 1
        return out

    def run_script(self, call: Call, st: _State, kind: str, words: list[Word]) -> _State | None:
        origin = "eval" if kind == "eval" else "-c"
        if not words or any(not w.static for w in words):
            call.opaque_code = call.opaque_code or bool(words) or kind != "eval"
            return self.unknown_dir(st) if kind == "eval" and words else None
        if self.depth >= MAX_DEPTH:
            raise ParseError("scripts nested too deeply")
        text = " ".join(w.text for w in words)
        inner = _Walker(self.session, self.depth + 1, self.dialect)
        inner.dry = self.dry
        out = inner.stmts(ast(text, self.dialect).get("Stmts") or [], st, True, (), origin)
        call.substitutions.extend(_toplevel(inner.calls))
        if not self.dry:
            self.calls.extend(inner.calls)
        return out if kind == "eval" else None  # `bash -c` is a child process: nothing carries back

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
            return _State(st.seen, st.seen, st.any_known, st.any_known)
        if name in ("alias", "source", "."):
            return self.unknown_dir(st)  # an alias may be `cd`; a sourced file may change directory
        if name == "chdir":
            name = "cd"
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
        elif (
            args[0].kinds <= {"tilde"}
            and args[0].text != "-"
            and not re.match(r"[+-]\d+$", args[0].text)
            and not ("~" in args[0].text and args[0].text != "~" and not args[0].text.startswith("~/"))  # `~-`, `~user`, `~d`
        ):
            target = args[0].text
            tilde = "tilde" in args[0].kinds
        else:
            target = None
        if target is None:
            return self.unknown_dir(st)
        moved = frozenset(_resolve(target, d, tilde) for d in st.sure)
        absolute = os.path.isabs(os.path.expanduser(target) if tilde else target)
        # `cd` may fail: the directories before it stay possible (`seen`), and `known` is only restored for what follows
        # `&&` — after `;` it is `any_known` that counts, and a `cd /abs` does not repair that
        return _State(moved, st.seen | moved, st.known or absolute, st.any_known)

    def unknown_dir(self, st: _State) -> _State:
        wide = frozenset({*st.seen, self.session})
        return _State(wide, wide, False, False)


def _toplevel(calls: list[Call]) -> list[Call]:
    """The calls of the list that are not a substitution / nested script of another call in it."""
    nested = {id(c) for call in calls for c in call.substitutions}
    return [c for c in calls if id(c) not in nested]


def _join(states: list[_State]) -> _State:
    sure: frozenset[str] = frozenset()
    seen: frozenset[str] = frozenset()
    known = any_known = True
    for s in states:
        sure |= s.sure
        seen |= s.seen
        known = known and s.known
        any_known = any_known and s.any_known
    return _State(sure, seen, known, any_known)


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


class CallList(list):
    """The calls of a line, plus `assigned_in_expansions`: variables that a `${x:=…}` / `${x=…}` may assign."""

    assigned_in_expansions: frozenset[str] = frozenset()


def _expansion_assignments(node) -> set[str]:
    """Names assigned by `${x:=…}` / `${x=…}` anywhere in the tree (also in a nested substitution or script word)."""
    found: set[str] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            if n.get("Type") == "ParamExp" and (n.get("Exp") or {}).get("Op") in ("=", ":="):
                found.add(_text(n.get("Param") or {}))
            stack.extend(n.values())
        elif isinstance(n, list):
            stack.extend(n)
    return found


def parse(command: str, *, cwd: str, dialect: str = DEFAULT_DIALECT) -> list[Call]:
    """Every simple command in the line (also nested ones), in source order, parents before their substitutions.

    Raises ParseError when the line cannot be parsed with certainty. Nothing else escapes: a tree shape this module did
    not expect, or nesting deeper than the Python stack, is a ParseError too (the caller denies on it).
    `dialect` is the grammar shfmt reads (`bash` | `zsh`); scripts nested in `-c` / `eval` are read in the same one."""
    walker = _Walker(cwd, dialect=dialect)
    start = frozenset({walker.session})
    result = CallList()
    try:
        tree = ast(command, dialect)
        walker.stmts(tree.get("Stmts") or [], _State(start, start), False, (), "top")
        result.assigned_in_expansions = frozenset(_expansion_assignments(tree))
    except ParseError:
        raise
    except (RecursionError, KeyError, TypeError, ValueError, IndexError, AttributeError) as e:
        raise ParseError(f"cannot walk the syntax tree ({type(e).__name__})") from e
    result.extend(walker.calls)
    return result
