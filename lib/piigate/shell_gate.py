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

UNKNOWN_DIR = "/.piigate-directory-the-gate-cannot-determine"  # a stand-in directory: where the stage ran is not known
OPERATOR_WORD = re.compile(r"[;&|()<>\n]+|\d*[<>]+[&|]?\d*-?")  # a WORD that the flat list would show as an operator
SUBST_PLACEHOLDER = re.compile(r"\$\(…\)|[<>=]\(…\)")  # what a command / process substitution looks like inside a word
# commands whose arguments are only text or names for the shell itself — a relative path there reads nothing
TEXT_ONLY = {
    "echo", "printf", "true", "false", ":", "test", "[", "[[", "((", "let", "export", "declare", "typeset", "local", "readonly",
    "unset", "set", "shift", "wait", "sleep", "pwd", "for", "select", "case", "exit", "return", "read", "cd", "pushd", "popd",
}
FILE_VALUED = {  # options whose value is a FILE the program reads (or runs): an unknown value is an unknown file
    "-f", "--file", "--pre", "--hostname-bin", "--ignore-file", "--exclude-from", "--files-from", "--files0-from", "--input",
    "--body-file", "--template", "--notes-file",
}
GH_FILE_VALUED = {"-F", "--body-file", "--input", "--notes-file", "--template", "--file", "-t"}
GH_FILE_COMMANDS = {("gist", "create"), ("gist", "edit"), ("release", "upload"), ("release", "create"), ("release", "edit")}
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


class _Dyn(str):
    """A word whose value the line does not hold: `unresolved` names the variables read with no known value, `subst`
    says it holds a command / process substitution."""

    unresolved: tuple = ()
    subst: bool = False
    dyn = True


class _Set(QuotedToken):
    """A word that is one of several known values (the variable of a `for` over static words): `alts` are the others. It is
    a QuotedToken only in the sense of being a plain word (the gate globs it itself)."""

    quoted = False
    alts: tuple = ()

    def __new__(cls, value: str, quote: str = ""):
        return super().__new__(cls, value, quote)


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
        self._model: shell.VarModel | None = None
        self._body_dynamic = False
        self._current: _Parsed | None = None

    # ------------------------------------------------------------------------------------------------ building

    # -- words: the value is computed from the PIECES the tree gives (`shell.subst_word`), never by reading the text
    def _pwd(self, c: shell.Call | None) -> str | None:
        """`$PWD` / `~+` at this command: its directory when that is exactly one known directory."""
        if c is None:
            return self.cwd
        return next(iter(c.cwds)) if c.cwd_known and len(c.cwds) == 1 else None

    # `$(command)` whose output the gate knows without running it. Deliberately short and explicit:
    #  - `pwd`: the directory of the command (an exactly known one);
    #  - `git rev-parse --show-toplevel`: the root of the repository of that directory, computed from the files;
    #  - `dirname P` / `basename P` of a static path;
    #  - date, whoami, hostname, uname, id, nproc, arch with static arguments free of `/`, `*`, `?`, `[`: their output has no
    #    path separator or glob, so it can only stand for a piece of a name — it is replaced by the plain letter X.
    # Anything else (mktemp, ls, find, cat …) is unknown. The value is a path the line does not control only in the second
    # case, and there it is a real directory that is then judged like any path in the line.
    SAFE_OUTPUT = {"date", "whoami", "hostname", "uname", "id", "nproc", "arch"}

    def _command_value(self, argv: tuple, pwd: str | None) -> str | None:
        name, args = argv[0], argv[1:]
        if name == "pwd" and all(a in ("-L", "-P") for a in args):
            return pwd
        if name == "git" and args == ("rev-parse", "--show-toplevel") and pwd is not None:
            from . import config

            return config.git_root(pwd)
        if name in ("dirname", "basename") and len(args) == 1 and not args[0].startswith("-"):
            return os.path.dirname(args[0]) or "." if name == "dirname" else os.path.basename(args[0].rstrip("/"))
        if name in self.SAFE_OUTPUT and not any(re.search(r"[/*?\[]", a) for a in args):
            return "X"
        return None

    def _word_tokens(self, w: shell.Word, c: shell.Call | None, use: int, origin: str) -> list[str]:
        if OPERATOR_WORD.fullmatch(w.text):
            # `cat '>' f`, `find -exec x {} \;`: a word that reads like an operator must not become one in the flat list
            # (the classification compares strings: `>` would make `f` a write target)
            return [QuotedToken("\\" + w.text, w.quote or "'")]
        pwd = self._pwd(c)
        model = self._model
        positional = c.positional if c is not None else None

        declared = c is not None and c.declared and positional is None

        def lookup(name: str):
            if declared and (name.isdigit() and name != "0" or name in ("@", "*", "#")):
                return "declared", None
            return model.value(name, use, origin, positional, pwd) if model is not None else ("unknown", None)

        def cmd_value(argv: tuple) -> str | None:
            return self._command_value(argv, pwd)

        variants, unresolved = shell.subst_word(w, lookup, self.dialect, cmd_value)
        if w.segs and w.text.startswith("~+") and "tilde" in w.kinds:  # `~+/x` is $PWD/x, `~-` is $OLDPWD
            if pwd is not None and len(variants) == 1 and len(variants[0]) == 1:
                variants = [[pwd + variants[0][0][2:]]]
            else:
                unresolved.append("PWD")
        elif w.text.startswith("~-") and "tilde" in w.kinds:
            unresolved.append("OLDPWD")
        subst = "proc" in w.kinds or "(substitution)" in unresolved
        if len(variants) == 1:
            words = variants[0]
        elif all(len(v) == 1 for v in variants):
            words = variants[0]  # a SET: the first is the token, every value is judged (`alts`)
        else:
            words, unresolved = [w.text], unresolved + ["(set)"]
        out: list[str] = []
        for text in words:
            if unresolved or subst:
                tok = _DynQuoted(text, w.quote) if w.quote else _Dyn(text)
                tok.unresolved, tok.subst = tuple(unresolved), subst
            else:
                tok = QuotedToken(text, w.quote) if w.quote else text
                if len(variants) > 1 and len(words) == 1:
                    tok = _Set(text, w.quote)
                    tok.alts = tuple(v[0] for v in variants[1:])
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

    def _expanded_body(self, h: shell.Heredoc, c: shell.Call) -> str:
        """The text of an unquoted heredoc as the shell makes it: `${x}` of a variable with a known value replaced. A body
        that still holds a variable or a command substitution afterwards sets `_body_dynamic`."""
        self._body_dynamic = False
        if h.quoted or not (h.names or h.subst):
            return h.body
        model = self._model
        use = self._index.get(id(c), 0)

        def sub(m: re.Match) -> str:
            kind, value = model.value(m.group(1), use, c.origin, c.positional, self._pwd(c)) if model else ("unknown", None)
            if kind != "static":
                self._body_dynamic = True
                return m.group(0)
            return value

        text = re.sub(r"\$\{([A-Za-z_]\w*)\}", sub, h.body)
        if h.subst or re.search(r"\$\{[^}]*\}", text):
            self._body_dynamic = True
        return text

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
        self._model = getattr(calls, "model", None) or shell.build_model(calls, getattr(calls, "assigned_in_expansions", ()), self.cwd)
        # bodies of heredocs read by a shell or launcher are code: parsed like the command itself
        bodies: list[_Body] = []
        text_bodies: list[str] = []
        dynamic_body = ""
        writer_dynamic = False  # stdin text of a non-shell: not shell code, so it has no tree
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
                            text_bodies.append(self._expanded_body(h, c))
                else:
                    stripped = self._file_writer(c) is not None
                    bodies.append(_Body(h.body, h.quoted, False, stripped))
                    if stripped:
                        self._expanded_body(h, c)
                        writer_dynamic = writer_dynamic or self._body_dynamic  # text built at run time, written to a file
                    if not stripped and id(h) not in seen_text:
                        body_text = self._expanded_body(h, c)
                        text_bodies.append(body_text)
                        if self._body_dynamic and (c.stdin_interpreter or c.name in shell.INTERPRETERS):
                            dynamic_body = "an unquoted heredoc given to an interpreter holds a variable or substitution with no known value"
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
        if writer_dynamic and reused:  # the old gate's rule, kept: a script made of run-time text, then run in the same line
            dynamic_body = "a script written from text built at run time (a variable or substitution of unknown value) and run in the same command"
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
        if any(b.stripped for b in bodies):
            view = all_text  # a body written to a file is cut out: the text is the words of the command plus the other bodies
            for b in bodies:
                if not b.stripped:
                    view += "\n" + b.text
        else:
            view = command  # nothing to cut: the checks that read the line as text (recipes, `$` in a tool call) get it as written
        if any("\x00" in str(t) for t in tokens):
            raise shell.ParseError("a NUL byte in a word")
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
            for b in self._current.bodies:  # a body written to a file may be run by another call: its text is checked for the
                if b.stripped and re.search(r"PIIGATE_\w+|XDG_DOCUMENTS_DIR", b.text) or any(  # filter's own files whether or not
                    m in b.text for m in self.protected_markers if b.stripped  # the same line runs it
                ):
                    return (
                        "piigate: the command touches a filter file (PIIGATE_* / XDG_DOCUMENTS_DIR / the map, key or "
                        "engine paths) in a script it writes — the pseudonym map, key and filter configuration are "
                        "off-limits to the model."
                    )
            if why := self._unjudgeable(self._current.calls) or self._current.dynamic_body:
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
        # a word that is one of several known values (a `for` over static words): the stage is judged for each value
        positions = [i for i, t in enumerate(stage) if getattr(t, "alts", ())]
        variants = [list(stage)]
        for i in positions:
            variants = [v[:i] + [alt] + v[i + 1 :] for v in variants for alt in (stage[i], *stage[i].alts)]
            if len(variants) > 64:
                return [("sensitive", "a variable with too many possible values to judge")]
        found: list[tuple[str, str]] = []
        for v in variants:
            found += super()._stage_kinds(v, c, text, literal, verbatim, body)
        return found + self._dynamic_operand_kinds(stage)

    def _stage_class(self, stage: list[str]) -> str:
        """`rg --files` only prints the names of files: like `ls`/`find` (the gate's own table does not know it)."""
        cmd = Path(stage[0]).name if stage else ""
        if cmd == "rg" and stage[0] == cmd and "--files" in stage[1:] and not any(
            str(t).startswith(("--pre", "--hostname-bin")) for t in stage[1:]
        ):
            return "names"
        return super()._stage_class(stage)

    def _operands(self, stage: list[str]) -> list[tuple[int, str]]:
        """The words of the stage that are not its command, an option, a write target, text or a search pattern. Called
        with the dynamic words already replaced by a plain `X`, so that the gate's own helpers see an ordinary word."""
        listing = bool(stage) and stage[0] == "rg" and "--files" in stage[1:]  # `rg --files DIR`: no pattern, DIR is a path
        skip = self._write_targets(stage) | self._commit_message(stage) | (set() if listing else self._searcher_args(stage)[0])
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

    def _file_valued(self, stage: list[str], i: int, cmd: str) -> bool:
        """The dynamic word `stage[i]` is the value of an option that names a file, or `--opt=value` of one, or `@file`."""
        t = str(stage[i])
        options = GH_FILE_VALUED if cmd == "gh" else FILE_VALUED
        previous = str(stage[i - 1]) if i else ""
        m = re.match(r"(--?[\w-]+)=", t)
        return (
            previous in options
            or bool(m and m.group(1) in options)
            or (cmd == "gh" and (t.startswith("@") or "=@" in t or previous in ("-f", "--field", "--raw-field")))
        )

    def _dynamic_operand_kinds(self, stage: list[str]) -> list[tuple[str, str]]:
        """An operand whose value the line does not hold (a variable with no single static assignment, a command or
        process substitution) is a path nobody can read from the command. For a reader: refused. For a lister: its
        names count as names of a sensitive directory (they must not flow into a reader). A write target or a file
        option (`--file=`, `--pre`, `--body-file`, `@file`): refused."""
        if not stage:
            return []
        deny = [("sensitive", "an operand whose value the command does not hold (a variable or substitution) — the path is unknown")]
        probe = [("X" if self._dyn(t) else str(t)) for t in stage]
        if self._dyn(stage[0]):
            return deny  # the command itself is named by a variable of unknown value
        writes = self._write_targets(probe)
        if any(self._dyn(stage[i]) for i in writes if i < len(stage)):
            return deny  # `tee $(echo P)`, `> "$out"`: where it writes is unknown (it may be a file that runs later)
        cmd = Path(stage[0]).name
        dyn = [i for i, t in enumerate(stage) if i and self._dyn(t)]
        if not dyn:
            return []
        if any(self._file_valued(stage, i, cmd) for i in dyn):
            return deny
        if cmd in ("echo", "printf"):  # text — unless a glob turns it into the list of names that match
            if any(re.search(r"[*?\[]", str(stage[i])) and not getattr(stage[i], "single", False) and i not in writes for i in dyn):
                self._names_seen.add(tuple(stage))
            return []
        if cmd in TEXT_ONLY:
            return []
        operands = [(i, t) for i, t in self._operands(probe) if self._dyn(stage[i])]
        if not operands:
            return []
        kind = self._stage_class(probe)
        if kind == "names":
            self._names_seen.add(tuple(stage))  # a listing of an unknown place: its names must stay on the screen
            return []
        if cmd == "gh" and kind == "remote":
            words = [str(t) for t in stage[1:] if not str(t).startswith("-")]
            if tuple(words[:2]) in GH_FILE_COMMANDS:
                return deny  # `gh gist create "$f"`, `gh release upload tag "$f"`: the operands are files that get uploaded
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
