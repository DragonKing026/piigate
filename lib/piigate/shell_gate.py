"""AstGate: the Bash gate with a front-end built on the shfmt syntax tree (SHADOW — issue 340, not used by any hook).

`AstGate(Gate)` replaces only what turns the command line into facts: the flat token list, the stages, the directories
each stage runs in, the substitutions, the heredoc bodies, the places that run a named program. All of it comes from
one `shell.parse` per command. The classification stays the one of `Gate` (option tables GIT_SPECS / FILTER_SPECS,
`_scan`, `_allowed`, `_stage_class`, `_stage_kinds`, `_operand_locations`, the directory-name markers, the verdicts).

NOTHING under lib/piigate or hooks imports this module (tests/test_shell_gate.py checks it). A command the parser cannot
read is DENIED here; `parse_error` then holds the message so that a measurement can count it as its own category.

The flat token list: every simple command of the tree (also those in `$( )`, `<( )`, `-c` scripts, shell heredocs) is one
stage; stages are joined by `|` (the command receives a pipe), `&` (after a background command) or `;`; redirections are
`[fd] op target` after the arguments; an assignment is `NAME=value` before them. A word that is one quoted fragment is
a `QuotedToken`. Nested commands follow the command that contains them, after the whole pipeline.
"""

from __future__ import annotations

import os
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from . import gate, shell
from .gate import DIRECT_LAUNCHERS, LAUNCHERS, SHELLS, QuotedToken

UNKNOWN_DIR = "/.piigate-directory-the-gate-cannot-determine"  # a stand-in directory: where the stage ran is not known
OPERATOR_WORD = re.compile(r"[;&|()<>\n]+|\d*[<>]+[&|]?\d*-?")  # a WORD that the flat list would show as an operator
SUBST_PLACEHOLDER = re.compile(r"\$\(…\)|[<>=]\(…\)")  # what a command / process substitution looks like inside a word
# commands whose arguments are only text or names for the shell itself — a relative path there reads nothing
TEXT_ONLY = {
    "echo", "printf", "true", "false", ":", "test", "[", "[[", "((", "let", "export", "declare", "typeset", "local", "readonly",
    "unset", "set", "shift", "wait", "sleep", "pwd", "for", "select", "case", "exit", "return", "read", "cd", "pushd", "popd",
}
SAFE_VALUE = re.compile(r"[\w./@%+:,-]*")  # a static value that may replace `$x` in a word: no space, glob, quote, tilde
DECLARATIONS = {"declare", "typeset", "local", "readonly", "export"}
# builtins that assign to the variables named in their arguments (or may): every identifier among the arguments gets a
# value nobody can read from the line
ASSIGNING = {"read", "mapfile", "readarray", "getopts", "unset", "coproc"}
SUBSTITUTION_ORIGINS = ("$(", "`", "<(", ">(")
NESTED_UNKNOWN = SUBSTITUTION_ORIGINS + ("-c", "eval")  # a call there has arguments the old gate reports as None


@dataclass
class _Body:
    text: str
    quoted: bool
    script: bool  # read by a shell / launcher: code
    stripped: bool  # written to a file / a commit message: dropped from the text view


@dataclass
class _Parsed:
    raw: str
    calls: list[shell.Call]
    tokens: list[str]
    stage_calls: list[shell.Call | None]  # one per stage group of `tokens`
    bodies: list[_Body] = field(default_factory=list)
    view: str = ""
    rest: frozenset = frozenset()  # the words of the command itself (without the text bodies of its heredocs)


class _Dyn(str):
    """A word whose value the line does not hold: `unresolved` names the variables read with no known value, `subst`
    says it holds a command / process substitution."""

    unresolved: tuple = ()
    subst: bool = False
    dyn = True


class _DynQuoted(QuotedToken):
    unresolved: tuple = ()
    subst: bool = False
    dyn = True


class AstGate(gate.Gate):
    dialect = "bash"

    def __init__(self, cfg: dict, cwd: str, dialect: str | None = None):
        super().__init__(cfg, cwd)
        if dialect:
            self.dialect = dialect
        self.parse_error = ""
        self.internal_error = ""
        self._cache: dict[str, _Parsed] = {}
        self._index: dict[int, int] = {}
        self._sites: dict = {}
        self._unknown: set = set()
        self._env: dict = {}
        self._current: _Parsed | None = None

    # ------------------------------------------------------------------------------------------------ building

    # -- the value of variables: known only when the ONE assignment of the line is a fully static word
    def _variables(self, calls: list[shell.Call], assigned_in_expansions) -> None:
        sites: dict[str, list[tuple[int, str, str]]] = defaultdict(list)
        unknown: set[str] = set(assigned_in_expansions)
        for i, c in enumerate(calls):
            persistent = not c.argv or c.name in DECLARATIONS  # `x=1` alone / `declare x=1`; `x=1 cmd` is only for cmd
            for a in c.assigns:
                static = (
                    persistent and a.value is not None and not a.array and not a.append and a.value.static
                    and SAFE_VALUE.fullmatch(a.value.text) is not None
                )
                sites[a.name].append((i, "static" if static else "dynamic", a.value.text if static else ""))
            if c.loop_var:  # the variable of `for` / `select` takes each of the items, which are judged as words themselves
                items = c.argv[1:]
                ok = all(w.static or (w.kinds - {"glob", "brace"} == set()) for w in items)
                sites[c.loop_var].append((i, "set" if ok else "dynamic", ""))
            words = [w.text for w in c.argv[1:] if w.static]
            if c.name in ASSIGNING:
                unknown |= {t for t in words if re.fullmatch(r"[A-Za-z_]\w*", t)}
            elif c.name == "printf" and "-v" in words:
                unknown |= set(words[words.index("-v") + 1 : words.index("-v") + 2])
            elif c.name in DECLARATIONS and any(t.startswith("-") and "n" in t for t in words):
                unknown |= {t.split("=")[0] for t in words if not t.startswith("-")}  # a nameref: `declare -n r=x`
        self._sites, self._unknown = sites, unknown
        self._env = {"HOME": os.path.expanduser("~"), "PWD": self.cwd, "TMPDIR": os.environ.get("TMPDIR") or "/tmp"}

    def _value(self, name: str, use: int, origin: str) -> tuple[str, str]:
        """("static", text) | ("set", "") | ("unknown", "")."""
        if name in self._unknown:
            return "unknown", ""
        found = self._sites.get(name)
        if found:
            if len(found) != 1:
                return "unknown", ""
            i, kind, value = found[0]
            if kind == "static" and (i < use or origin == "function"):
                return "static", value
            return ("set", "") if kind == "set" else ("unknown", "")
        if name in self._env:  # the environment, said explicitly: where the session is, and the user's home
            return "static", self._env[name]
        return "unknown", ""

    def _word_token(self, w: shell.Word, use: int = 0, origin: str = "top") -> str:
        if OPERATOR_WORD.fullmatch(w.text):
            # `cat '>' f`, `find -exec x {} \;`: a word that reads like an operator must not become one in the flat list
            # (the classification compares strings: `>` would make `f` a write target)
            return QuotedToken("\\" + w.text, w.quote or "'")
        names = [k[1:] for k in w.kinds if k.startswith("$")]
        values = {n: self._value(n, use, origin) for n in names}

        def substitute(m: re.Match) -> str:  # all names at once: `$b$c` must not become `$bive-data` after `$c` is replaced
            name = m.group(1) or m.group(2)
            kind, value = values.get(name, ("unknown", ""))
            return value if kind == "static" else m.group(0)

        text = re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", substitute, w.text)
        unresolved = []
        for n in names:
            kind = values[n][0]
            exact = text in (f"${n}", "${" + n + "}")
            still = re.search(r"\$\{?" + re.escape(n) + r"(?![A-Za-z0-9_])", text) is not None
            if kind == "set" and exact:
                continue
            if kind != "static" or still:
                unresolved.append(n)
        subst = bool({"cmd", "proc"} & w.kinds)
        if unresolved or subst:
            tok = _DynQuoted(text, w.quote) if w.quote else _Dyn(text)
            tok.unresolved, tok.subst = tuple(unresolved), subst
            return tok
        return QuotedToken(text, w.quote) if w.quote else text

    def _call_tokens(self, c: shell.Call) -> list[str]:
        use = self._index.get(id(c), 0)
        toks: list[str] = []
        for a in c.assigns:
            value = a.value.text if a.value else ("(" + " ".join(x.text for x in a.array) + ")" if a.array else "")
            toks.append(a.name + ("+=" if a.append else "=") + value)
        for w in c.argv:
            if "zsh" in w.kinds and w.text.startswith("(") and w.text.endswith(")") and w.quoting == "none":
                toks += w.text[1:-1].split()  # zsh `foreach f (a b c)`: a parenthesised word list — each one is a word
            else:
                toks.append(self._word_token(w, use, c.origin))
        for r in c.redirects:
            if r.fd:
                toks.append(r.fd)
            if r.heredoc is not None:
                toks += ["<<", r.heredoc.delimiter]
            else:
                toks.append(r.op)
                if r.target is not None:
                    toks.append(self._word_token(r.target, use, c.origin))
        return toks

    @staticmethod
    def _descend(c: shell.Call):
        for s in c.substitutions:
            yield s
            yield from AstGate._descend(s)

    def _script_heredoc(self, c: shell.Call) -> bool:
        if not c.argv:
            return True
        words = shell._effective(c.argv)  # `sudo -u x bash <<EOF`
        first = c.argv[0]
        names = {os.path.basename(w.text) for w in (first, *words[:1]) if w.static}
        return bool(names & LAUNCHERS) or bool(c.stdin_interpreter and c.stdin_interpreter in SHELLS)

    @staticmethod
    def _body_words(text: str) -> list[str]:
        return gate.Gate._tokens(text) or text.split()

    def _file_writer(self, c: shell.Call) -> list[str] | None:
        """Names a heredoc is written to (`cat > f <<EOF`, `tee f <<EOF`) or [] for a commit message (`git commit -F -`);
        None when the heredoc is stdin data of something else."""
        name = c.name
        if name == "cat":
            dest = [r.target.text for r in c.redirects if r.op in (">", ">>") and r.target is not None]
            return dest or None
        if name == "tee":
            dest = [w.text for w in c.argv[1:] if not w.text.startswith("-")]
            return dest or None
        if name == "git":
            args = [w.text for w in c.argv[1:]]
            if {"commit", "tag"} & set(args[:2]):
                for i, a in enumerate(args):
                    if (a.startswith("-") and not a.startswith("--") and "F" in a[1:] and args[i + 1 : i + 2] == ["-"]) or (
                        a == "--file" and args[i + 1 : i + 2] == ["-"]
                    ) or a == "--file=-":
                        return []
        return None

    def _build(self, command: str) -> _Parsed:
        calls = shell.parse(command, cwd=self.cwd, dialect=self.dialect)
        self._index = {id(c): i for i, c in enumerate(calls)}
        self._variables(calls, getattr(calls, "assigned_in_expansions", ()))
        # bodies of heredocs read by a shell or launcher are code: parsed like the command itself
        bodies: list[_Body] = []
        text_bodies: list[str] = []  # stdin text of a non-shell: not shell code, so it has no tree
        seen_text: set[int] = set()
        for c in list(calls):
            for r in c.redirects:
                if r.heredoc is None:
                    continue
                h = r.heredoc  # also one inherited from `{ …; } <<EOF`, `( … ) <<EOF`, a loop, a function: its commands read it
                if self._script_heredoc(c):
                    if c.stdin_interpreter in SHELLS or (c.argv and c.name in SHELLS):
                        for d in sorted(c.cwds) or [self.cwd]:
                            extra = shell.parse(h.body, cwd=d, dialect=self.dialect)
                            c.substitutions.extend(shell._toplevel(extra))
                            calls.extend(extra)
                        bodies.append(_Body(h.body, h.quoted, True, False))
                    else:  # a launcher (xargs, find, env…) or no command: its words are what the body holds
                        bodies.append(_Body(h.body, h.quoted, True, False))
                        if id(h) not in seen_text:
                            text_bodies.append(h.body)
                else:
                    stripped = self._file_writer(c) is not None
                    bodies.append(_Body(h.body, h.quoted, False, stripped))
                    if not stripped and id(h) not in seen_text:
                        text_bodies.append(h.body)
                seen_text.add(id(h))
        top = shell._toplevel(calls)
        groups: list[tuple[list[str], shell.Call | None, str]] = []
        pending: list[shell.Call] = []

        def flush() -> None:
            for n in pending:
                groups.append((self._call_tokens(n), n, ";"))
            pending.clear()

        before: shell.Call | None = None
        for c in top:
            # a pipeline stage may hold several commands (`{ a; b; } | c`, `while …; done | c`, `( … ) | c`): all of them
            # are connected to the next stage, and the commands of one stage to each other
            piped = c.piped_in or (before is not None and before.pipes_out)
            if not piped:
                flush()
            groups.append((self._call_tokens(c), c, ("|&" if c.piped_stderr else "|") if piped else ";"))
            pending.extend(self._descend(c))
            before = c
        flush()
        tokens: list[str] = []
        stage_calls: list[shell.Call | None] = []
        previous: shell.Call | None = None
        for toks, c, sep in groups:
            if not toks:
                continue
            if tokens:
                tokens.append("&" if previous is not None and previous.background and sep not in ("|", "|&") else sep)
            tokens += toks
            stage_calls.append(c)
            previous = c
        if previous is not None and previous.background:
            tokens.append("&")
        # text view for the checks that look for a word in the whole line (heredoc bodies written to a file left out); a
        # file written by a heredoc AND named again in the command is used later: its body counts as text then
        all_text = " ".join(tokens)
        dests = {os.path.basename(d) for c in calls for d in (self._file_writer(c) or [])}
        reused = any(all_text.count(d) > 1 for d in dests if d)
        rest = frozenset(map(str, tokens))
        keep = []
        for b in bodies:
            if b.stripped and reused:
                b = _Body(b.text, b.quoted, b.script, False)
                text_bodies.append(b.text)
            keep.append(b)
        bodies = keep
        # A text body is data, not shell: it is cut into words by the same tokenizer as before (quotes, punctuation) —
        # the only place where the old tokenizer is still used. Its words are judged as stages (a path in a script the
        # model feeds to python is a path), with no command attached.
        for body in text_bodies:
            words = self._body_words(body)
            if words:
                if tokens:
                    tokens.append(";")
                tokens += words
                stage_calls += [None] * len(self._stages_loose(words))
        view = all_text
        for b in bodies:
            if not b.stripped:
                view += "\n" + b.text
        if any("\x00" in str(t) for t in tokens):
            raise shell.ParseError("a NUL byte in a word")
        return _Parsed(command, calls, tokens, stage_calls, bodies, view, rest)

    def _store(self, command: str) -> _Parsed:
        p = self._build(command)
        self._cache[command] = p
        self._cache[p.view] = p
        return p

    def _lookup(self, command: str) -> _Parsed | None:
        p = self._cache.get(command)
        if p is None:
            try:
                p = self._store(command)
            except shell.ParseError:
                return None
        return p

    @staticmethod
    def _words(c: shell.Call) -> list[shell.Word]:
        return [*c.argv, *(a.value for a in c.assigns if a.value), *(x for a in c.assigns for x in a.array),
                *(r.target for r in c.redirects if r.target is not None)]

    @staticmethod
    def _may_change_options(calls: list[shell.Call]) -> bool:
        """The line can switch shell options (zsh glob qualifiers run code only with BARE_GLOB_QUAL, `(#q…)` with
        EXTENDED_GLOB; Claude Code's shell has both off): `setopt`, `unsetopt`, `emulate`, `set -o`/`+o`, `options[…]=`, a
        shell started with `-o`/`-c`, `eval`, `source`."""
        for c in calls:
            words = [w.text for w in c.argv[1:]]
            if c.name in ("setopt", "unsetopt", "emulate", "eval", "source", ".", "coproc"):
                return True
            if c.name == "set" and any(re.match(r"[-+][A-Za-z]*[oX]", t) for t in words):
                return True
            if c.name in SHELLS and any(re.match(r"[-+][A-Za-z]*[oc]", t) for t in words):
                return True
            if c.name in ("typeset", "declare", "local", "readonly", "export") and any(t.startswith("options") for t in words):
                return True
            if any(a.name in ("options", "setopt", "unsetopt") for a in c.assigns):
                return True
        return False

    def _unjudgeable(self, calls: list[shell.Call]) -> str:
        """Why the command cannot be judged at all (empty when it can): code or a command name the tree does not hold.
        Every construct this module does not understand ends here — a new syntax means a denial, never a pass."""
        options = self._may_change_options(calls)
        for c in calls:
            for w in self._words(c):
                if "zsh-code" in w.kinds:
                    return "a zsh parameter flag that runs code (`${(e)x}`, `${(%)x}`)"
                if "exec" in w.kinds:
                    return "an expansion that runs code (`${x@P}`)"
                if options and "zsh" in w.kinds:
                    return "a zsh glob qualifier or parameter flag in a command that may change the shell options"
            if c.opaque_code:
                return "code the parser cannot see (`eval $x`, `bash -c \"$x\"`, `coproc`)"
            if c.argv and {"cmd", "proc"} & c.argv[0].kinds:
                return "a command name that is the output of a substitution"
        return ""

    # ------------------------------------------------------------------------------------------------ entry

    def bash(self, command: str, files: bool = True) -> str | None:
        self.parse_error = self.internal_error = ""
        self._current = None
        if "\x00" in command:
            return super().bash(command, files)
        try:
            try:
                self._current = self._store(command)
            except shell.ParseError as e:
                self.parse_error = str(e)
                return f"piigate: command denied — it cannot be parsed with certainty ({e}). {gate.HINT}"
            if why := self._unjudgeable(self._current.calls):
                return f"piigate: command denied — {why}; the gate cannot judge what it runs. {gate.HINT}"
            return super().bash(command, files)
        except Exception as e:  # whatever the adapter did not foresee: deny, and say so
            self.internal_error = f"{type(e).__name__}: {e}"[:200]
            return f"piigate: command denied — the shadow gate failed ({type(e).__name__}). {gate.HINT}"

    # ------------------------------------------------------------------------------------------------ front-end

    def _strip_file_heredocs(self, command: str) -> str:
        cur = self._current
        return cur.view if cur is not None and cur.raw == command else command

    def _tokens(self, command: str) -> list[str] | None:
        p = self._lookup(command)
        return None if p is None else p.tokens

    def _substitutions(self, text: str) -> list[str]:
        return []  # every command inside `$( )`, backticks, `<( )` is a stage of its own in the token list

    def _without_single_quoted(self, command: str) -> str:
        p = self._lookup(command)
        if p is None:
            return gate.Gate._without_single_quoted(command)
        out = ["''" if getattr(t, "single", False) else t for t in p.tokens]
        if any(c.origin in SUBSTITUTION_ORIGINS for c in p.calls) or any(
            {"cmd", "proc"} & w.kinds for c in p.calls for w in c.argv
        ):
            out.append("$(…)")
        return " ".join(out)

    def _heredoc_text(self, command: str) -> tuple[str, set[str], set[str], str]:
        p = self._lookup(command)
        if p is None:
            return command, set(), set(), ""
        texts = [b for b in p.bodies if not b.script and not b.stripped]
        if not texts:
            return p.view, set(), set(), ""
        body = "\n".join(b.text for b in texts)
        rest = set(p.rest)
        inner = set(self._body_words(body))
        expanded = {w for b in texts if not b.quoted for w in self._body_words(b.text)}
        return p.view, inner - rest, inner - rest - expanded, body

    def _stage_dirs(self, command: str, tokens: list[str]) -> list[list[str]]:
        p = self._cache.get(command) or self._lookup(command)
        if p is None or tokens is not p.tokens:
            return super()._stage_dirs(command, tokens)
        stages = self._stages_loose(tokens)
        everywhere = sorted({d for c in p.calls for d in c.cwds} | {self.cwd})
        if any(not c.cwd_known for c in p.calls):
            everywhere.append(UNKNOWN_DIR)
        if len(stages) != len(p.stage_calls):  # a word that looks like an operator shifted the stages: check everywhere
            return [list(everywhere) for _ in stages]
        result = []
        for c in p.stage_calls:
            dirs = sorted(c.cwds) if c is not None else everywhere
            result.append([*dirs, UNKNOWN_DIR] if c is not None and not c.cwd_known else dirs)
        return result

    def _stage_kinds(self, stage, c, text, literal, verbatim, body):
        if self.cwd == UNKNOWN_DIR:  # the stage may have run in a directory the tree cannot name (a `cd` to a glob, to
            return self._unknown_dir_kinds(stage)  # `-`, from a function, from `eval`/`alias`): relative paths mean nothing
        found = super()._stage_kinds(stage, c, text, literal, verbatim, body)
        return found + self._dynamic_operand_kinds(stage)

    def _operands(self, stage: list[str]) -> list[tuple[int, str]]:
        """The words of the stage that are not its command, an option, a write target, text or a search pattern. Called
        with the dynamic words already replaced by a plain `X`, so that the gate's own helpers see an ordinary word."""
        skip = self._write_targets(stage) | self._commit_message(stage) | self._searcher_args(stage)[0]
        if stage and stage[0] in ("echo", "printf"):
            skip |= set(range(1, len(stage)))
        assignment = stage and stage[0] == "env"  # `NAME=value` words that `_strip_prefixes` put in front of a command
        return [
            (i, t)
            for i, t in enumerate(stage)
            if i and i not in skip and t and not t.startswith("-") and not gate.REDIRECT_ALONE.fullmatch(t)
            and not (assignment and re.match(r"[A-Za-z_]\w*\+?=", t))
        ]

    def _unknown_dir_kinds(self, stage: list[str]) -> list[tuple[str, str]]:
        cmd = Path(stage[0]).name if stage else ""
        if not stage or cmd in TEXT_ONLY or self._stage_class(stage) in ("names", "remote"):
            return []
        probe = [("X" if self._dyn(t) else str(t)) for t in stage]
        relative = [t for _, t in self._operands(probe) if not t.startswith(("/", "~"))]
        searching = cmd in gate.SEARCHERS and self._searcher_args(stage)[2]
        if relative or searching:
            return [("sensitive", "a relative path after a `cd`/function/eval whose directory the gate cannot determine")]
        return []

    @staticmethod
    def _dyn(t) -> bool:
        return bool(getattr(t, "dyn", False)) and not getattr(t, "single", False)

    def _dynamic_operand_kinds(self, stage: list[str]) -> list[tuple[str, str]]:
        """An operand whose value the line does not hold (a variable with no single static assignment, a command or
        process substitution) is a path nobody can read from the command. For a reader: refused. For a lister: its
        names count as names of a sensitive directory (they must not flow into a reader). A write target: refused."""
        if not stage:
            return []
        deny = [("sensitive", "an operand whose value the command does not hold (a variable or substitution) — the path is unknown")]
        probe = [("X" if self._dyn(t) else str(t)) for t in stage]
        if self._dyn(stage[0]):
            return deny  # the command itself is named by a variable of unknown value
        if any(self._dyn(stage[i]) for i in self._write_targets(probe) if i < len(stage)):
            return deny  # `tee $(echo P)`, `> "$out"`: where it writes is unknown (it may be a file that runs later)
        cmd = Path(stage[0]).name
        if cmd in TEXT_ONLY:
            return []
        operands = [(i, t) for i, t in self._operands(probe) if self._dyn(stage[i])]
        if not operands:
            return []
        kind = self._stage_class(probe)
        if kind == "names":
            self._names_seen.add(tuple(stage))  # a listing of an unknown place: its names must stay on the screen
            return []
        if kind == "remote" and cmd == "gh":
            return []
        return deny

    def _script_stages(self, tokens):
        stages, writes, unsafe = super()._script_stages(tokens)
        cur = next((p for p in self._cache.values() if p.tokens is tokens), None)
        if cur is not None and any(c.origin in ("<(", ">(") for c in cur.calls):
            unsafe = True  # text reaches a process substitution
        return stages, writes, unsafe

    def _invocations(self, command: str, names: set[str], depth: int = 0) -> list[list[str] | None]:
        """Where the command RUNS one of `names` (see Gate._invocations): the argv from the name on, or None where the
        arguments are unknown — a substitution, `-c`, eval, xargs, find -exec, a variable holding the name."""
        p = self._lookup(command)
        if p is None:
            return [None]

        def is_name(t: str) -> bool:
            return Path(t).name in names

        mentioned = any(
            n in w.text for c in p.calls for w in (*c.argv, *(a.value for a in c.assigns if a.value), *(x for a in c.assigns for x in a.array), *(r.target for r in c.redirects if r.target)) for n in names
        )
        if not mentioned:
            return []
        dynamic = any(w.expands for c in p.calls for w in c.argv)
        found: list[list[str] | None] = []
        for c in p.calls:
            if dynamic and any(
                any(is_name(x) for w in ([a.value] if a.value else []) + list(a.array) for x in w.text.split())
                for a in c.assigns
            ):
                found.append(None)
            if not c.argv:
                continue
            first = c.argv[0]
            nested = c.origin in NESTED_UNKNOWN
            cmd = Path(first.text).name  # `$HOME/bin/tool`: the literal base name is what the old gate matched too
            if cmd in names:
                found.append(None if nested else [w.text for w in c.argv])
                continue
            if not first.static or cmd not in LAUNCHERS:
                continue
            rest = c.argv[1:]
            if cmd in SHELLS or cmd == "eval":
                if any(is_name(w.text) for w in rest):
                    found.append(None)
                continue
            j = next((i for i, w in enumerate(rest) if is_name(w.text)), None)
            if j is not None:
                found.append([w.text for w in rest[j:]] if cmd in DIRECT_LAUNCHERS and not nested else None)
        return found
