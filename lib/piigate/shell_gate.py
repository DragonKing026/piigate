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
    tainted: frozenset = frozenset()  # variables assigned from a command substitution
    rest: frozenset = frozenset()  # the words of the command itself (without the text bodies of its heredocs)


class AstGate(gate.Gate):
    dialect = "bash"

    def __init__(self, cfg: dict, cwd: str, dialect: str | None = None):
        super().__init__(cfg, cwd)
        if dialect:
            self.dialect = dialect
        self.parse_error = ""
        self.internal_error = ""
        self._cache: dict[str, _Parsed] = {}
        self._current: _Parsed | None = None

    # ------------------------------------------------------------------------------------------------ building

    def _word_token(self, w: shell.Word) -> str:
        if OPERATOR_WORD.fullmatch(w.text):
            # `cat '>' f`, `find -exec x {} \;`: a word that reads like an operator must not become one in the flat list
            # (the classification compares strings: `>` would make `f` a write target)
            return QuotedToken("\\" + w.text, w.quote or "'")
        return QuotedToken(w.text, w.quote) if w.quote else w.text

    def _call_tokens(self, c: shell.Call) -> list[str]:
        toks: list[str] = []
        for a in c.assigns:
            value = a.value.text if a.value else ("(" + " ".join(x.text for x in a.array) + ")" if a.array else "")
            toks.append(a.name + ("+=" if a.append else "=") + value)
        toks += [self._word_token(w) for w in c.argv]
        for r in c.redirects:
            if r.fd:
                toks.append(r.fd)
            if r.heredoc is not None:
                toks += ["<<", r.heredoc.delimiter]
            else:
                toks.append(r.op)
                if r.target is not None:
                    toks.append(self._word_token(r.target))
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
        tainted = frozenset(
            a.name
            for c in calls
            for a in c.assigns
            if any({"cmd", "proc"} & w.kinds for w in ([a.value] if a.value else []) + list(a.array))
        )
        return _Parsed(command, calls, tokens, stage_calls, bodies, view, tainted, rest)

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

    def _unjudgeable(self, calls: list[shell.Call]) -> str:
        """Why the command cannot be judged at all (empty when it can): code or a command name the tree does not hold."""
        # zsh syntax that has no node in the tree: a glob qualifier / parameter flag. Code in it (`(e:cmd:)`, `(+func)`,
        # `${(e)x}`) is refused; any other qualifier only when the command can switch qualifiers on (`setopt`, `emulate`)
        options = any(c.name in ("setopt", "unsetopt", "emulate") for c in calls)
        for c in calls:
            for w in self._words(c):
                if "zsh-code" in w.kinds:
                    return "zsh syntax that runs code (a glob qualifier `(e:…:)` / `(+func)`, a flag `${(e)x}`)"
                if "exec" in w.kinds:
                    return "an expansion that runs code (`${x@P}`)"
                if options and "zsh" in w.kinds:
                    return "a zsh glob qualifier or parameter flag in a command that may change the shell options"
            if c.opaque_code:
                return "code the parser cannot see (`eval $x`, `bash -c \"$x\"`)"
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
        """The words of the stage that are not its command, an option, a write target, text or a search pattern."""
        # a message / pattern that holds a substitution is still a message / pattern: probe with the placeholders removed
        probe = [SUBST_PLACEHOLDER.sub("X", str(t)) for t in stage]
        skip = self._write_targets(stage) | self._commit_message(probe) | self._searcher_args(probe)[0]
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
        relative = [t for _, t in self._operands(stage) if not t.startswith(("/", "~"))]
        searching = cmd in gate.SEARCHERS and self._searcher_args(stage)[2]
        if relative or searching:
            return [("sensitive", "a relative path after a `cd`/function/eval whose directory the gate cannot determine")]
        return []

    def _dynamic_operand_kinds(self, stage: list[str]) -> list[tuple[str, str]]:
        """A file operand built by a command substitution (`cat $(echo P)`, `f=$(echo P); cat "$f"`, `${f:-$(echo P)}`)
        is a path nobody can read from the command: refused for a reader. Text (echo, a commit message) is not."""
        cmd = Path(stage[0]).name if stage else ""
        if not stage or cmd in TEXT_ONLY:
            return []
        tainted = self._current.tainted if self._current is not None else frozenset()
        pattern = re.compile(r"\$\{?(?:" + "|".join(map(re.escape, tainted)) + r")\b") if tainted else None
        for _, t in self._operands(stage):
            if SUBST_PLACEHOLDER.search(t) or (pattern and pattern.search(t)):
                return [("sensitive", "an operand that a command substitution builds (the path it names is not in the command)")]
        return []

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
