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
from dataclasses import dataclass, field
from pathlib import Path

from . import gate, shell
from .gate import DIRECT_LAUNCHERS, LAUNCHERS, SHELLS, QuotedToken

OPERATOR_WORD = re.compile(r"[;&|()<>\n]+|\d*[<>]+[&|]?\d*-?")  # a WORD that the flat list would show as an operator
# commands whose arguments are only text or names for the shell itself — a relative path there reads nothing
TEXT_ONLY = {
    "echo", "printf", "true", "false", ":", "test", "[", "[[", "((", "let", "export", "declare", "typeset", "local", "readonly",
    "unset", "set", "shift", "wait", "sleep", "pwd", "for", "select", "case", "exit", "return", "read", "cd", "pushd", "popd",
}
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
    composed: str = ""  # the line as its WORDS compose it (quotes and variables resolved): `piigate rev''erse` -> `piigate reverse`
    dynamic_body: str = ""  # why an unquoted heredoc given to an interpreter holds a value nobody can read
    rest: frozenset = frozenset()  # the words of the command itself (without the text bodies of its heredocs)


class _TooMany(str):
    """A word with more possible values than are judged one by one: the stage is refused, never judged as the text."""


class _Set(QuotedToken):
    """A word that is one of several known values (the variable of a `for` over static words): `alts` are the others. It is
    a QuotedToken only in the sense of being a plain word (the gate globs it itself)."""

    quoted = False
    alts: tuple = ()

    def __new__(cls, value: str, quote: str = ""):
        return super().__new__(cls, value, quote)


class AstGate(gate.Gate):
    dialect = "bash"

    @staticmethod
    def dialects_for_shell(path: str | None = None) -> list[str]:
        """The grammar(s) to judge a line in: by `$SHELL` — zsh is zsh; bash, sh, dash, ash are bash; any other shell (or
        none) is unknown, and the line is then judged in BOTH grammars: it is refused if either refuses."""
        name = os.path.basename(path if path is not None else os.environ.get("SHELL", ""))
        if name == "zsh":
            return ["zsh"]
        if name in ("bash", "sh", "dash", "ash"):
            return ["bash"]
        return ["bash", "zsh"]

    def __init__(self, cfg: dict, cwd: str, dialect: str | None = None):
        super().__init__(cfg, cwd)
        self._dialects = [dialect] if dialect else self.dialects_for_shell()
        self.dialect = self._dialects[0]
        self.parse_error = ""
        self.parse_kind = ""  # a fixed label of the parse error (`shell.PARSE_KINDS`), for the shadow's count
        self.internal_error = ""
        self._cache: dict[str, _Parsed] = {}
        self._index: dict[int, int] = {}
        self._model: shell.VarModel | None = None
        self._named_dirs: dict[str, str] = {}
        self._current: _Parsed | None = None

    # ------------------------------------------------------------------------------------------------ building

    # -- words: the value is computed from the PIECES the tree gives (`shell.subst_word`), never by reading the text
    def _pwd(self, c: shell.Call | None) -> list[str] | None:
        """`$PWD` / `~+` at this command: every directory it may run in (a `cd` that may have failed leaves two), else None.
        Each of them is a possible value, and each is judged — so a symlink reached through `cd ln` is judged as the
        directory it really is (the gate resolves real paths)."""
        if c is None:
            return [self.cwd]
        return sorted(c.cwds) if c.cwd_known else None

    def _word_tokens(self, w: shell.Word, c: shell.Call | None, use: int, origin: str) -> list[str]:
        """The words of the flat list for one word of the tree. Only what is CERTAIN is replaced (a variable with one static
        assignment, a `for` over static words, a function argument, $PWD, $HOME, $TMPDIR, $SHELL, `~+`, a `hash -d` name);
        whatever is not certain stays exactly as written, `$x` and `${x:-…}` and `$(…)` with all their text."""
        if OPERATOR_WORD.fullmatch(w.text):
            # `cat '>' f`, `find -exec x {} \;`: a word that reads like an operator must not become one in the flat list
            # (the classification compares strings: `>` would make `f` a write target)
            return [QuotedToken("\\" + w.text, w.quote or "'")]
        pwd = self._pwd(c)
        model = self._model
        positional = c.positional if c is not None else None

        def lookup(name: str):
            return model.value(name, use, origin, positional, pwd) if model is not None else ("unknown", None)

        variants, unresolved, noglob = shell.subst_word(w, lookup, self.dialect)
        text0 = variants[0][0] if len(variants) == 1 and len(variants[0]) == 1 else None
        if text0 is not None and text0.startswith("/proc/") and "tilde" not in w.kinds:
            # `/proc/self/cwd/..`, `/proc/$$/cwd/..`, `/proc/self/root/…`: the directory of the shell itself, said in another way
            m = re.match(r"/proc/(?:self|thread-self|\$\$|\$\{\$\})/(cwd|root)(?:/(.*))?$", text0)
            if m and (m.group(1) == "root" or pwd is not None):
                bases = pwd if m.group(1) == "cwd" else [""]
                variants = [[(b + "/" + (m.group(2) or "")) if m.group(2) is not None else (b or "/")] for b in bases]
                text0 = variants[0][0] if len(variants) == 1 else None
        if text0 is not None and "tilde" in w.kinds:
            if w.text.startswith("~+") and pwd is not None:  # `~+/x` is $PWD/x, for each directory it may be
                variants = [[b + text0[2:]] for b in pwd]
                text0 = None
            else:
                m = re.match(r"~([A-Za-z_]\w*)", text0)
                if m and m.group(1) in self._named_dirs:  # zsh `hash -d name=path`, then `~name/x`
                    variants = [[self._named_dirs[m.group(1)] + text0[m.end() :]]]
        words = variants[0] if len(variants) == 1 or all(len(v) == 1 for v in variants) else [w.text]
        if {"cmd", "proc"} & w.kinds and w.quoting == "none" and len(words) == 1:
            # an unquoted `$(echo cat P)` / `` `echo cat P` `` / `<(…)`: the shell runs it, and the old tokenizer cut its text
            # at the blanks and at `$ ( )`, so each piece was judged as a word of its own (a path `P` among them) — exactly
            # as here: the text of a substitution is judged the way the old gate judges it
            words = [str(t) for t in gate.Gate._tokens(words[0]) or words[0].split()]
        out: list[str] = []
        for text in words:
            tok = QuotedToken(text, w.quote) if w.quote else (QuotedToken(text, '"') if noglob and len(words) == 1 else text)
            if "(too many)" in unresolved:
                tok = _TooMany(text)
            if len(variants) > 1 and len(words) == 1 and all(len(v) == 1 for v in variants):
                tok = _Set(text, w.quote)
                tok.alts = tuple(v[0] for v in variants[1:])  # a SET: the first is the token, every value is judged
            out.append(tok)
        return out

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
                toks += self._word_tokens(w, c, use, c.origin)
        for r in c.redirects:
            if r.fd:
                toks.append(r.fd)
            if r.heredoc is not None:
                toks += ["<<", r.heredoc.delimiter]
            else:
                toks.append(r.op)
                if r.target is not None:
                    toks += self._word_tokens(r.target, c, use, c.origin)
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

    def _said(self, w: shell.Word, c: shell.Call) -> str:
        """The word as the shell will use it, as one string (a variable of known value replaced, anything else as written)."""
        return " ".join(str(t) for t in self._word_tokens(w, c, self._index.get(id(c), 0), c.origin))

    @staticmethod
    def _printed_text(c: shell.Call) -> str | None:
        """What `echo` / `printf` print, when their arguments are words of the line (no command inside)."""
        if not all(w.static or {"param"} >= w.kinds - {k for k in w.kinds if k.startswith("$")} for w in c.argv):
            return None
        args = [w.text for w in c.argv[1:] if not (w.text.startswith("-") and re.fullmatch(r"-[neE]+", w.text))]
        if c.name == "printf" and args:
            rest = iter(args[1:])
            return re.sub(r"%[sb]", lambda m: next(rest, ""), shell._ansi_c(args[0]))
        return " ".join(args)

    def _expanded_body(self, h: shell.Heredoc, c: shell.Call) -> str:
        """The text of an unquoted heredoc as the shell makes it: `$x` / `${x}` of a variable with a KNOWN value replaced;
        anything else stays as written (the old gate saw it so)."""
        if h.quoted or not h.names:
            return h.body
        model = self._model
        use = self._index.get(id(c), 0)

        def sub(m: re.Match) -> str:
            name = m.group(1) or m.group(2)
            kind, value = model.value(name, use, c.origin, c.positional, self._pwd(c)) if model else ("unknown", None)
            return value if kind == "static" else m.group(0)

        return re.sub(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)", sub, h.body)

    @staticmethod
    def _body_words(text: str) -> list[str]:
        return gate.Gate._tokens(text) or text.split()

    def _file_writer(self, c: shell.Call) -> list[str] | None:
        """Names a heredoc is written to (`cat > f <<EOF`, `tee f <<EOF`) or [] for a commit message (`git commit -F -`);
        None when the heredoc is stdin data of something else."""
        name = c.name
        use = self._index.get(id(c), 0)

        def said(w: shell.Word) -> str:  # the name as the shell will use it (`$f` of a known value is that value)
            return " ".join(str(t) for t in self._word_tokens(w, c, use, c.origin))

        if name == "cat":
            dest = [said(r.target) for r in c.redirects if r.op in (">", ">>") and r.target is not None]
            return dest or None
        if name == "tee":
            dest = [said(w) for w in c.argv[1:] if not w.text.startswith("-")]
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
        self._model = getattr(calls, "model", None) or shell.build_model(calls, getattr(calls, "assigned_in_expansions", ()), self.cwd)
        # bodies of heredocs read by a shell or launcher are code: parsed like the command itself
        bodies: list[_Body] = []
        text_bodies: list[str] = []
        dynamic_body = ""
        seen_text: set[int] = set()
        self._named_dirs = {}
        for c in list(calls):
            if c.name == "hash" and any(w.text == "-d" for w in c.argv[1:] if w.static):  # zsh `hash -d name=path`
                for w in c.argv[1:]:
                    if w.static and "=" in w.text and not w.text.startswith("-"):
                        name, _, path = w.text.partition("=")
                        self._named_dirs[name] = path
            if c.name in ("echo", "printf") and any(r.op in (">", ">>") for r in c.redirects):
                # `echo 'cd x; cat ../S*/p*' > f.sh; bash f.sh`: a file written in the line and RUN in the line is code
                dests = {self._said(r.target, c) for r in c.redirects if r.op in (">", ">>") and r.target is not None}
                for r in calls:
                    argv = [self._said(w, r) for w in r.argv]
                    runs = bool(argv) and (
                        (os.path.basename(argv[0]) in SHELLS | shell.INTERPRETERS | {"source", "."} and any(a in dests for a in argv[1:]))
                        or argv[0] in dests
                        or (argv[0].startswith("./") and argv[0][2:] in {d[2:] if d.startswith("./") else d for d in dests})
                    )
                    if runs:
                        text = self._printed_text(c)
                        if text is not None:
                            if os.path.basename(argv[0]) in shell.INTERPRETERS:
                                text_bodies.append(text)
                            else:
                                extra = shell.parse(text, cwd=self.cwd, dialect=self.dialect)
                                c.substitutions.extend(shell._toplevel(extra))
                                calls.extend(extra)
                        break
            if c.pipe_to_shell and c.name in ("echo", "printf") and all(w.static for w in c.argv):
                # `echo 'cat ../S*/p*' | bash`: what a command prints into a shell is that shell's program
                text = self._printed_text(c)
                receivers = [r for r in calls if r.piped_in and r.stdin_interpreter]
                if any(r.stdin_interpreter in SHELLS for r in receivers):
                    extra = shell.parse(text, cwd=self.cwd, dialect=self.dialect)
                    c.substitutions.extend(shell._toplevel(extra))
                    calls.extend(extra)
                elif receivers:
                    text_bodies.append(text)
            if c.name == "gh" and [w.text for w in c.argv[1:3] if w.static] == ["alias", "set"]:
                for w in c.argv[3:]:  # `gh alias set x '!cmd …'`: an alias that starts with `!` is shell code
                    if w.static and w.text.startswith("!"):
                        extra = shell.parse(w.text[1:], cwd=self.cwd, dialect=self.dialect)
                        c.substitutions.extend(shell._toplevel(extra))
                        calls.extend(extra)
            for r in c.redirects:
                if r.op == "<<<" and r.target is not None and r.target.static and (c.stdin_interpreter or c.name in SHELLS):
                    # a here-string given to a shell or an interpreter is its program, like a heredoc body
                    if c.stdin_interpreter in SHELLS or c.name in SHELLS:
                        extra = shell.parse(r.target.text, cwd=self.cwd, dialect=self.dialect)
                        c.substitutions.extend(shell._toplevel(extra))
                        calls.extend(extra)
                    else:
                        text_bodies.append(r.target.text)
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
                            text_bodies.append(self._expanded_body(h, c))
                else:
                    stripped = self._file_writer(c) is not None
                    bodies.append(_Body(h.body, h.quoted, False, stripped))
                    if not stripped and id(h) not in seen_text:
                        text_bodies.append(self._expanded_body(h, c))
                seen_text.add(id(h))
        top = shell._toplevel(calls)
        groups: list[tuple[list[str], shell.Call | None, str]] = []
        pending: list[shell.Call] = []

        def flush() -> None:
            for n in pending:
                groups.append((self._call_tokens(n), n, ";"))
            pending.clear()

        before: shell.Call | None = None
        for c in calls:  # text printed by a function may be the PATH it hands back (`pwd() { echo ../Sensitive-data; }`)
            if c.origin == "function" and c.name in ("echo", "printf"):
                words = [str(t) for w in c.argv[1:] for t in self._word_tokens(w, c, self._index.get(id(c), 0), c.origin)]
                if words:
                    text_bodies.append(" ".join(words))
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
        # MONOTONICITY: every word on the right of an assignment (`x=…`, `a=(…)`, `a+=(…)`, `a[k]=…`, `declare x=…`, an element
        # with a backtick or `$(…)`) is judged as the old gate judged it — as a word of the line — whether or not the model
        # can follow where the value goes next. (The old tokenizer saw `a=(../S*/p*)` as the words `a=`, `(`, `../S*/p*`, `)`.)
        for c in calls:
            for a in c.assigns:
                for w in [x for x in (a.value, *a.elements, *a.array) if x is not None]:
                    text_bodies.append(w.text)
        for body in text_bodies:
            words = self._body_words(body)
            if words:
                if tokens:
                    tokens.append(";")
                tokens += words
                stage_calls += [None] * len(self._stages_loose(words))
        if any(b.stripped for b in bodies):
            view = all_text  # a body written to a file is cut out: the text is the words of the command plus the other bodies
            for b in bodies:
                if not b.stripped:
                    view += "\n" + b.text
        else:
            view = command  # nothing to cut: the checks that read the line as text (recipes, `$` in a tool call) get it as written
        if any("\x00" in str(t) for t in tokens):
            raise shell.ParseError("a NUL byte in a word", "nul-byte")
        composed = all_text + "".join("\n" + b.text for b in bodies if not b.stripped)
        return _Parsed(command, calls, tokens, stage_calls, bodies, view, composed, dynamic_body, rest)

    def _store(self, command: str) -> _Parsed:
        p = self._build(command)
        self._cache[command] = p
        self._cache[p.view] = p
        self._cache[p.composed] = p
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

    def _unjudgeable(self, calls: list[shell.Call]) -> str:
        """Why the command cannot be judged at all (empty when it can): code or a command name the tree does not hold.
        Every construct this module does not understand ends here — a new syntax means a denial, never a pass."""
        names = {c.name for c in calls}
        glob_rules_changed = "shopt" in names or any(a.name.lower() == "globignore" for c in calls for a in c.assigns)
        fpath = any(a.name.lower() == "fpath" for c in calls for a in c.assigns) or any(
            "fpath" in w.text.lower() for c in calls for w in c.argv
        )
        if "autoload" in names and fpath:
            return "zsh `autoload` together with `fpath`: the body of the function comes from a file the line does not hold"
        for c in calls:
            for w in self._words(c):
                if "zsh-code" in w.kinds:
                    return "a zsh glob qualifier or parameter flag that may run code (`(e…)`, `(+…)`, `(#q…)`, `${(e)x}`)"
                if "exec" in w.kinds:
                    return "an expansion that runs code (`${x@P}`)"
                if glob_rules_changed and "glob" in w.kinds and re.search(r"(?:^|/)\.[^/]*[*?\[]", w.text):
                    return "a glob with a leading dot where `shopt` / GLOBIGNORE may change what it matches (`.*` reaching `..`)"
            if c.name == "coproc":
                return "`coproc`: a process that runs beside the line and answers through $COPROC"
            if c.name == "print" and any(re.match(r"-[A-Za-z]*P", w.text) for w in c.argv[1:] if w.static):
                return "`print -P`: prompt expansion runs `$(…)` found in its arguments"
        return ""

    # ------------------------------------------------------------------------------------------------ entry

    def bash(self, command: str, files: bool = True) -> str | None:
        """Judged in the grammar of `$SHELL`; when the shell is unknown, in both — refused if either refuses."""
        reason = None
        errors: list[tuple[str, str]] = []
        for dialect in self._dialects:
            self.dialect = dialect
            self._cache = {}
            reason = self._bash_in(command, files)
            if reason:
                return reason
            errors.append((self.parse_error, self.parse_kind))
        self.parse_error, self.parse_kind = next((e for e in errors if e[0]), ("", ""))
        return None

    def _bash_in(self, command: str, files: bool = True) -> str | None:
        self.parse_error = self.parse_kind = self.internal_error = ""
        self._current = None
        if "\x00" in command:
            return super().bash(command, files)
        try:
            try:
                self._current = self._store(command)
            except shell.ParseError as e:
                self.parse_error = str(e)
                self.parse_kind = e.kind
                return f"piigate: command denied — it cannot be parsed with certainty ({e}). {gate.HINT}"
            for b in self._current.bodies:  # a body written to a file may be run by another call: its text is checked for the
                if b.stripped and re.search(r"PIIGATE_\w+|XDG_DOCUMENTS_DIR", b.text) or any(  # filter's own files whether or not
                    m in b.text for m in self.protected_markers if b.stripped  # the same line runs it
                ):
                    return (
                        "piigate: the command touches a filter file (PIIGATE_* / XDG_DOCUMENTS_DIR / the map, key or "
                        "engine paths) in a script it writes — the pseudonym map, key and filter configuration are "
                        "off-limits to the model."
                    )
            if why := self._unjudgeable(self._current.calls):
                return f"piigate: command denied — {why}; the gate cannot judge what it runs. {gate.HINT}"
            composed = self._current.composed
            if composed != command and re.search(r"\b(?:analyze|anonymize)\b", composed) and any(
                c is None or c[1:2] in (["analyze"], ["anonymize"]) for c in self._invocations(command, {"piigate"})
            ):
                return gate.MCP_PIIGATE  # `piigate ana''lyze x`: the words say it, the raw text does not
            return super().bash(command, files)
        except Exception as e:  # whatever the adapter did not foresee: deny, and say so
            self.internal_error = f"{type(e).__name__}: {e}"[:200]
            return f"piigate: command denied — the shadow gate failed ({type(e).__name__}). {gate.HINT}"

    # ------------------------------------------------------------------------------------------------ front-end

    def _strip_file_heredocs(self, command: str) -> str:
        cur = self._current
        return cur.view if cur is not None and cur.raw == command else command

    def _human_only(self, command: str, tokens: list[str] | None) -> str | None:
        """`piigate reverse` / `project approve` — checked on the line as written AND on the line as its words compose it
        (`piigate rev''erse`, `q=rev; piigate ${q}erse`, `eval "piigate rev""erse"`)."""
        reason = super()._human_only(command, tokens)
        if reason:
            return reason
        p = self._cache.get(command)
        if p is not None and p.composed != command:
            return super()._human_only(p.composed, tokens)
        return None

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
        if len(stages) != len(p.stage_calls):  # a word that looks like an operator shifted the stages: check everywhere
            return [list(everywhere) for _ in stages]
        result = []
        for c in p.stage_calls:
            result.append(sorted(c.cwds) if c is not None else everywhere)
        return result

    def _stage_kinds(self, stage, c, text, literal, verbatim, body):
        # a word that is one of several known values (a `for` over static words): the stage is judged for each value
        if any(isinstance(t, _TooMany) for t in stage):
            return [("sensitive", "a variable with too many possible values to judge each one")]
        positions = [i for i, t in enumerate(stage) if getattr(t, "alts", ())]
        variants = [list(stage)]
        for i in positions:
            variants = [v[:i] + [alt] + v[i + 1 :] for v in variants for alt in (stage[i], *stage[i].alts)]
            if len(variants) > 64:
                return [("sensitive", "a variable with too many possible values to judge")]
        found: list[tuple[str, str]] = []
        for v in variants:
            found += super()._stage_kinds(v, c, text, literal, verbatim, body)
        return found + self._indirect_reads(stage)

    # programs that read a file named inside an argument: `curl -d @file`, `-F name=@file`, `--data-urlencode name@file`,
    # `-T file`, `gh api -F key=@file`, `--input file`; zsh `${mapfile[file]}` (zmodload zsh/mapfile) reads a file too
    UPLOADERS = {"curl", "wget", "http", "https", "xh", "gh"}
    UPLOAD_OPTIONS = {"-T", "--upload-file", "--input", "--body-file", "-K", "--config"}

    def _indirect_reads(self, stage: list[str]) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        cmd = Path(stage[0]).name if stage else ""
        for i, t in enumerate(stage):
            t = str(t)
            m = re.search(r"\$\{mapfile\[([^\]]+)\]", t)
            paths = [m.group(1)] if m else []
            if cmd in self.UPLOADERS and i:
                if m := re.search(r"(?:^|[=,])@(.+)$|^[^=@]+@(.+)$", t):
                    paths.append(m.group(1) or m.group(2))
                if i and str(stage[i - 1]) in self.UPLOAD_OPTIONS and not t.startswith("-"):
                    paths.append(t)
            for path in paths:
                if r := self._token_kind(path, False):
                    found.append(r)
        return found

    def _no_content(self, tokens: list[str]) -> bool:
        """`rm D/.gitignore '&&' rmdir D`: a word that reads like an operator is still a word, but it is not the one-command
        `cp/mv/rm` the no-output rule is for — it keeps the old decision (the quoted `&&` used to split the command)."""
        if any(str(t).startswith("\\") and OPERATOR_WORD.fullmatch(str(t)[1:]) for t in tokens):
            return False
        return super()._no_content(tokens)

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
            n in t
            for c in p.calls
            for t in [
                *(str(x) for w in c.argv for x in self._word_tokens(w, c, self._index.get(id(c), 0), c.origin)),
                *(a.value.text for a in c.assigns if a.value),
                *(x.text for a in c.assigns for x in a.array),
                *(r.target.text for r in c.redirects if r.target),
            ]
            for n in names
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
            use = self._index.get(id(c), 0)
            texts = [str(t) for w in c.argv for t in self._word_tokens(w, c, use, c.origin)]  # what the shell runs
            if not texts:
                continue
            nested = c.origin in NESTED_UNKNOWN
            cmd = Path(texts[0]).name  # `$HOME/bin/tool`: the literal base name is what the old gate matched too
            if cmd in names:
                found.append(None if nested else texts)
                continue
            if cmd not in LAUNCHERS:
                continue
            rest = texts[1:]
            if cmd in SHELLS or cmd == "eval":
                if any(is_name(t) for t in rest):
                    found.append(None)
                continue
            j = next((i for i, t in enumerate(rest) if is_name(t)), None)
            if j is not None:
                found.append(rest[j:] if cmd in DIRECT_LAUNCHERS and not nested else None)
        return found
