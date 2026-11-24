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
from .gate import DIRECT_LAUNCHERS, LAUNCHERS, SHELLS, QuotedToken, Reason

OPERATOR_WORD = re.compile(r"[;&|()<>\n]+|\d*[<>]+[&|]?\d*-?")  # a WORD that the flat list would show as an operator
# commands whose arguments are only text or names for the shell itself — a relative path there reads nothing
TEXT_ONLY = {
    "echo", "printf", "true", "false", ":", "test", "[", "[[", "((", "let", "export", "declare", "typeset", "local", "readonly",
    "unset", "set", "shift", "wait", "sleep", "pwd", "for", "select", "case", "exit", "return", "read", "cd", "pushd", "popd",
}
SUBSTITUTION_ORIGINS = ("$(", "`", "<(", ">(")
# programs that read the files they are given as operands (a path built by a command substitution is an unknown path, #22) and
# the options whose NEXT word is a value, not a file
READERS = {
    "cat", "tac", "head", "tail", "less", "more", "most", "nl", "wc", "sort", "uniq", "cut", "paste", "join", "comm", "diff",
    "cmp", "grep", "egrep", "fgrep", "zgrep", "rg", "rga", "ag", "ack", "sed", "awk", "gawk", "mawk", "jq", "yq", "gojq", "xxd",
    "od", "hexdump", "strings", "base64", "md5sum", "sha1sum", "sha256sum", "sha512sum", "b2sum", "cksum", "bat", "batcat",
    "column", "fold", "rev", "expand", "unexpand", "shuf", "pr", "fmt", "split", "csplit", "cp", "mv", "rsync", "scp", "install",
    "tar", "zip", "unzip", "7z", "find", "fd", "fdfind", "source", ".",
}
PROGRAM_FIRST = {"grep", "egrep", "fgrep", "zgrep", "rg", "rga", "ag", "ack", "sed", "awk", "gawk", "mawk", "jq", "yq", "gojq"}
VALUE_OPTIONS = {
    "head": {"-n", "-c"}, "tail": {"-n", "-c", "-s"}, "cut": {"-d", "-f", "-c", "-b"}, "sort": {"-k", "-t", "-S", "-T", "-o"},
    "join": {"-t", "-j", "-1", "-2", "-o"}, "paste": {"-d"}, "fold": {"-w"}, "nl": {"-b", "-n", "-w", "-s", "-v", "-i"},
    "awk": {"-F", "-v"}, "gawk": {"-F", "-v"}, "mawk": {"-F", "-v"}, "split": {"-l", "-b", "-n", "-a"}, "wc": set(),
    "grep": {"-e", "-m", "-A", "-B", "-C"}, "egrep": {"-e", "-m", "-A", "-B", "-C"}, "fgrep": {"-e", "-m", "-A", "-B", "-C"},
    "rg": {"-e", "-m", "-A", "-B", "-C", "-g", "-t", "-T", "-j", "--glob", "--type", "--type-not", "--max-count"},
    "sed": {"-e"}, "jq": {"--arg", "--argjson", "--slurpfile", "--rawfile"},
}
XARGS_VALUE_OPTIONS = {"-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a", "--max-args", "--max-procs", "--delimiter", "--arg-file"}
# the only commands a compound list may use to touch a sensitive source without reading it (they create, remove or change modes)
CREATE_COMMANDS = {"mkdir", "rm", "rmdir", "touch", "chmod", "chown", "chgrp"}
# ... and the options they may have there (#32): (short flags, short options with a value, long flags, long options with a value).
# Anything else — `-v`, `-c`, `--changes`, `-i`, `-I`, `--reference`, an abbreviated long option — can print the names it touches
# (names in a sensitive directory can be personal data) or read another file, so it makes the stage a read.
_OWNER_FLAGS = ("Rfh", "", ("--recursive", "--quiet", "--silent", "--no-dereference"), ())
CREATE_FLAGS = {
    "mkdir": ("p", "m", ("--parents",), ("--mode",)),
    "rm": ("rRfd", "", ("--recursive", "--force", "--dir"), ()),
    "rmdir": ("p", "", ("--parents", "--ignore-fail-on-non-empty"), ()),
    "touch": ("amch", "dt", ("--no-create", "--no-dereference"), ("--date",)),
    "chmod": _OWNER_FLAGS,
    "chown": _OWNER_FLAGS,
    "chgrp": _OWNER_FLAGS,
}
# programs known to treat what they read from stdin (or from `<(…)`) as DATA, never as code — the only receivers of text that a
# stage builds with an expansion (#41); everything else is a possible interpreter. A program that takes a program or a command in
# an option has an explicit list of the options it may have there (FILTER_OPTIONS): every other option, an abbreviated long
# option included (getopt_long takes `--co` for `--compress-program`), and every word that is not literal and not the value of
# an option makes it no filter. A program of the list without an entry here has no option that runs anything (grep, cat, wc…).
STDIN_DATA = shell.DATA_ONLY | {
    "sort", "tee", "less", "more", "tac", "pr", "fmt", "expand", "unexpand", "diff", "cmp", "comm", "jq", "gojq", "sed",
    "awk", "gawk", "mawk", "piigate", "pbcopy", "wl-copy", "xclip", "xsel",
}
# name -> (short flags, short options with a value, long flags, long options with the number of words they take)
_JQ_OPTIONS = ("rcsnCMSaejR", "", frozenset({
    "--raw-output", "--compact-output", "--slurp", "--null-input", "--color-output", "--monochrome-output", "--sort-keys",
    "--ascii-output", "--exit-status", "--join-output", "--raw-input", "--tab", "--seq", "--stream", "--raw-output0",
}), {"--arg": 2, "--argjson": 2, "--indent": 1})
FILTER_OPTIONS = {
    "sed": ("nErsuz", "e", frozenset({"--quiet", "--silent", "--regexp-extended", "--separate", "--unbuffered", "--null-data"}),
            {"--expression": 1}),
    "sort": ("bdfghiMnrRuVzcCms", "ktS", frozenset({
        "--ignore-leading-blanks", "--dictionary-order", "--ignore-case", "--general-numeric-sort", "--human-numeric-sort",
        "--ignore-nonprinting", "--month-sort", "--numeric-sort", "--random-sort", "--reverse", "--stable", "--unique",
        "--version-sort", "--zero-terminated", "--check", "--merge",
    }), {"--key": 1, "--field-separator": 1, "--buffer-size": 1}),
    "jq": _JQ_OPTIONS,
    "gojq": _JQ_OPTIONS,
    "awk": ("", "Fv", frozenset(), {}),
    "gawk": ("", "Fv", frozenset(), {}),
    "mawk": ("", "Fv", frozenset(), {}),
    "less": ("NSRrFXiIqQsnwJ", "", frozenset(), {}),
    "more": ("", "", frozenset(), {}),
}
# where a program of STDIN_DATA may live when it is named by a path (`/usr/bin/sort`); any other path (`./cat`, `/tmp/x/sort`) is
# a file the model may have written, not the filter (#43)
SYSTEM_BINDIRS = ("/usr/bin", "/bin", "/usr/local/bin")
# `< file` read by one of these is not text the line builds, even when the NAME of the file is built (#43): an interpreter or a shell run
# on a script FILE of its own that exists (`python3 script.py < "$f"`) and a local client of a database that has only the options of
# DB_OPTIONS. A client that gets the same text from a heredoc or a here-string with an expansion stays refused: `psql` and `mysql` run
# what they read (`\!` is a shell command), so only the text of a file that nobody built is data. Review: no `deno` / `bun` (a
# subcommand is no script), nothing in a container (`docker exec … psql`: which program reads it cannot be told from the words), no
# `sqlite3` (a dot-command in an argument runs a shell). The file name is still judged as the path it is (#22).
FILE_INTERPRETERS = {"python", "python3", "node", "nodejs", "perl", "ruby", "php", "lua"}
# client -> (flags, options with a value, long options with a value): any other option may run a file or a command (`psql -f`/`-c`,
# `mysql -e`/`--init-command`/`--defaults-file`)
DB_OPTIONS = {
    "psql": (frozenset({"-q", "-A", "-t", "-X", "-w", "-W", "-1", "--quiet", "--no-psqlrc"}), frozenset({"-h", "-p", "-U", "-d"}),
             frozenset({"--host", "--port", "--username", "--dbname"})),
    "mysql": (frozenset({"-s", "-B", "-N", "-q", "-p", "--batch", "--silent", "--skip-column-names", "--no-defaults"}),
              frozenset({"-h", "-P", "-u", "-D"}), frozenset({"--host", "--port", "--user", "--database"})),
}
DB_OPTIONS["mariadb"] = DB_OPTIONS["mysql"]
PYTHON_PLAIN_FLAGS = {"-u", "-B", "-O", "-OO", "-q", "-I", "-s", "-S", "-E"}  # python options that do not run or load code
# a prefix assignment that is harmless to a program that reads its input as data (`LC_ALL=C sort`); any other (`LESSOPEN=… less`,
# `PATH=. sort`, `GIT_EDITOR=sh git commit -e`, `LD_PRELOAD=… cat`) lets the environment decide what the program runs: no exception
# of the data receivers and the data filters holds for such a call (#43)
HARMLESS_ASSIGNMENTS = {"LC_ALL", "LANG", "TZ"}
# names that, assigned or exported ANYWHERE in the line, change what a data receiver (git, gh, kubectl, openssl) starts
RECEIVER_ENVIRONMENT = re.compile(
    r"(?:GIT|GH|KUBE|OPENSSL|LD|MYSQL|NODE)_\w*|PG\w*|PYTHON\w*|PERL5\w*|RUBY\w*|LESS\w*|AWK\w*|HOME|XDG_CONFIG_HOME|PSQLRC|"
    r"EDITOR|VISUAL|PAGER|BROWSER|PATH|BASH_ENV|ENV|KUBECONFIG"
)
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
    functions: frozenset = frozenset()  # the names of the functions the line declares
    cd_overflow: bool = False  # a `cd PATTERN` of the line named too many directories to follow (the old gate refuses such a line)


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
        self._code_label = "stdin-receiver"  # the rule of the last `_expanded_into_code` (a fixed label, see `_stdin_refusal`)
        self._cache: dict[str, _Parsed] = {}
        self._index: dict[int, int] = {}
        self._model: shell.VarModel | None = None
        self._named_dirs: dict[str, str] = {}
        self._current: _Parsed | None = None
        self._stage_log: list[tuple[list[str], set[int], list, bool]] = []  # per stage judged by the last `_touches` (see `_creates_only`)

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
        shell.CD_OVERFLOW = False
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
        return _Parsed(
            command, calls, tokens, stage_calls, bodies, view, composed, dynamic_body, rest, getattr(calls, "functions", frozenset()),
            shell.CD_OVERFLOW,
        )

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

    def _unjudgeable(self, calls: list[shell.Call]) -> tuple[str, str] | None:
        """(why, label) the command cannot be judged at all (None when it can): code or a command name the tree does not hold.
        Every construct this module does not understand ends here — a new syntax means a denial, never a pass."""
        names = {c.name for c in calls}
        glob_rules_changed = "shopt" in names or any(a.name.lower() == "globignore" for c in calls for a in c.assigns)
        fpath = any(a.name.lower() == "fpath" for c in calls for a in c.assigns) or any(
            "fpath" in w.text.lower() for c in calls for w in c.argv
        )
        if "autoload" in names and fpath:
            return "zsh `autoload` together with `fpath`: the body of the function comes from a file the line does not hold", "autoload-fpath"
        pwd_rebound = self._pwd_rebound(calls)
        for c in calls:
            for w in self._words(c):
                if "pwdsub" in w.kinds and pwd_rebound:
                    return "`$(pwd)` in a line that redefines `pwd` or `PWD` (a function, an alias, an assignment)", "substituted-operand"
                if "zsh-code" in w.kinds:
                    return "a zsh glob qualifier or parameter flag that may run code (`(e…)`, `(+…)`, `(#q…)`, `${(e)x}`)", "zsh-code"
                if "exec" in w.kinds:
                    return "an expansion that runs code (`${x@P}`)", "expansion-runs-code"
                if glob_rules_changed and "glob" in w.kinds and re.search(r"(?:^|/)\.[^/]*[*?\[]", w.text):
                    return (
                        "a glob with a leading dot where `shopt` / GLOBIGNORE may change what it matches (`.*` reaching `..`)",
                        "dot-glob-shopt",
                    )
            if c.name == "coproc":
                return "`coproc`: a process that runs beside the line and answers through $COPROC", "coproc"
            if c.name == "print" and any(re.match(r"-[A-Za-z]*P", w.text) for w in c.argv[1:] if w.static):
                return "`print -P`: prompt expansion runs `$(…)` found in its arguments", "print-prompt"
        return None

    def _pending_write(self, t: str) -> tuple[str, str] | None:
        """The old rule, except that a PATTERN (`*.csv`) is no data file that does not exist yet: the tree gate puts the value of a
        loop variable back into the body, so `for f in *.csv; do wc -l "$f"; done` names the pattern in two stages. A pattern is
        expanded and every match judged by its content; a file the line writes (`-o out.csv`, `> out.csv`) is still refused."""
        for k in dict.fromkeys((t, t.split("=", 1)[-1])):
            p = gate._path(k, self.cwd)
            if not p.casefold().endswith(self.extensions):
                continue
            pattern = bool(re.search(r"[*?\[]", k))
            if p in self._written or (not pattern and not os.path.exists(p) and len(self._appears.get(p, ())) >= 2):
                return self._note(
                    "extension", p, "a data file that an earlier stage of this command writes — its content cannot be checked before it runs"
                )
        return None

    def _pwd_rebound(self, calls: list) -> bool:
        """Does the line redefine what `$(pwd)` prints — a function or an alias or a builtin switch named for it, or any way of
        assigning `PWD`? The model reads `$(pwd)` as `$PWD`; that is only true while nothing changes either."""
        if self._current is not None and "pwd" in self._current.functions:
            return True
        model = self._model
        if model is not None and ("PWD" in model.sites or "PWD" in model.unknown):
            return True
        for c in calls:
            if c.name in ("alias", "enable", "disable", "hash", "unhash", "unalias") or any(a.name == "PWD" for a in c.assigns):
                return True
            if any(w.static and re.fullmatch(r"PWD(=.*)?", w.text) for w in c.argv[1:]):
                return True
        return False

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
                return Reason(f"piigate: command denied — it cannot be parsed with certainty ({e}). {gate.HINT}", "cannot-parse")
            for b in self._current.bodies:  # a body written to a file may be run by another call: its text is checked for the
                if b.stripped and re.search(r"PIIGATE_\w+|XDG_DOCUMENTS_DIR", b.text) or any(  # filter's own files whether or not
                    m in b.text for m in self.protected_markers if b.stripped  # the same line runs it
                ):
                    return Reason(
                        "piigate: the command touches a filter file (PIIGATE_* / XDG_DOCUMENTS_DIR / the map, key or "
                        "engine paths) in a script it writes — the pseudonym map, key and filter configuration are "
                        "off-limits to the model.",
                        "filter-files",
                    )
            if unjudgeable := self._unjudgeable(self._current.calls):
                why, label = unjudgeable
                return Reason(f"piigate: command denied — {why}; the gate cannot judge what it runs. {gate.HINT}", label)
            composed = self._current.composed
            if composed != command and re.search(r"\b(?:analyze|anonymize)\b", composed) and any(
                c is None or c[1:2] in (["analyze"], ["anonymize"]) for c in self._invocations(command, {"piigate"})
            ):
                return gate.MCP_PIIGATE  # `piigate ana''lyze x`: the words say it, the raw text does not
            if reason := super().bash(command, files):
                return reason
            if self._current.cd_overflow:  # fail closed, as the old gate: a sensitive directory may hide among the unfollowed ones
                return Reason(
                    f"piigate: command denied — a `cd` with a pattern names more than {gate.CD_MATCHES} directories; the gate cannot "
                    f"check them all. {gate.HINT}",
                    "cd-too-many",
                )
            if reason := self._substituted_operand(self._current):
                return reason
            if self.sensitive or self.project_sensitive or self.sensitive_name:
                c = self._expanded_into_code(self._current)
                if c is not None:
                    return Reason(
                        f"piigate: command denied — `{c.name or 'a command'}` reads text that a stage of the line builds with an "
                        f"expansion (a substitution or a variable) and is not a known data filter, so it may run it as code; the "
                        f"gate cannot read that code, and a sensitive source is configured. {gate.HINT}",
                        self._code_label,
                    )
            return None
        except Exception as e:  # whatever the adapter did not foresee: deny, and say so
            self.internal_error = f"{type(e).__name__}: {e}"[:200]
            return Reason(f"piigate: command denied — the shadow gate failed ({type(e).__name__}). {gate.HINT}", "internal-error")

    # ------------------------------------------------------------------------------------------------ operands from a command

    @staticmethod
    def _expands_command(w: shell.Word | None) -> bool:
        return w is not None and bool({"cmd", "proc"} & w.kinds)

    @staticmethod
    def _reader_operands(name: str, args: list[shell.Word]) -> list[shell.Word]:
        """The words after the command that may be files: no options, no value of an option, no pattern / program word."""
        found: list[shell.Word] = []
        values = VALUE_OPTIONS.get(name, set())
        program_given = any(w.static and w.text in ("-e", "-f", "--regexp", "--file", "--expression") for w in args)
        need_program = name in PROGRAM_FIRST and not program_given
        paths_only = name in ("find",)  # `find P… -name "$(…)"`: only the words before the expression are paths
        skip = False
        for w in args:
            if skip:
                skip = False
                continue
            if w.static and w.text.startswith("-") and len(w.text) > 1:
                if paths_only:
                    break
                skip = w.text in values
                continue
            if paths_only and w.static and w.text.startswith(("(", "!")):
                break
            if need_program:
                need_program = False
                continue
            found.append(w)
        return found

    def _substituted_operand(self, p: _Parsed | None) -> str | None:
        """A word with `$(…)` / backticks / `<(…)` that is a file operand of a command that reads files, or the list of names
        given to `xargs <reader>` from a pipe fed by such a word, names a path nobody can see: with a sensitive source it is
        refused, like any path the gate cannot resolve (#22). A substitution anywhere else (`X=$(date); echo "$X"`, a commit
        message, `echo "$(git rev-parse HEAD)"`) is not an operand of a reader."""
        if p is None or not (self.sensitive or self.project_sensitive or self.sensitive_name):
            return None
        for i, c in enumerate(p.calls):
            words = shell._effective(c.argv)
            name = os.path.basename(words[0].text) if words and words[0].static else ""
            via_xargs = False
            if name == "xargs":
                args, k = words[1:], 0
                while k < len(args) and args[k].static and args[k].text.startswith("-") and len(args[k].text) > 1:
                    k += 1 + (args[k].text in XARGS_VALUE_OPTIONS)
                inner = shell._effective(args[k:])
                name = os.path.basename(inner[0].text) if inner and inner[0].static else ""
                words, via_xargs = inner, True
            stdin_words = [r.target for r in c.redirects if r.op in ("<", "<<<") and r.target is not None]
            hit = None
            if name in READERS:
                hit = next((w for w in self._reader_operands(name, words[1:]) if self._expands_command(w)), None)
            if hit is None and via_xargs and name in READERS:
                feeders = [w for j in range(i) if p.calls[j].pipes_out for w in (*p.calls[j].argv, *(r.target for r in p.calls[j].redirects if r.target))]
                hit = next((w for w in (*feeders, *stdin_words) if self._expands_command(w)), None)
            if hit is None and (name in READERS or not name or self._stdin_file_receiver(c, p, False)) and not via_xargs:
                hit = next((w for w in stdin_words if self._expands_command(w) and w.text and not w.text.startswith("<<<")), None)
            if hit is not None:
                return Reason(
                    f"piigate: command denied — `{name or 'a command'}` reads files and one of them is named by a command "
                    f"substitution ({hit.text}): the gate cannot see the path it will get, and a sensitive source is configured. "
                    f"{gate.HINT}",
                    "substituted-operand",
                )
        return None

    @staticmethod
    def _xargs_command(words: list[shell.Word]) -> list[shell.Word]:
        """The command `xargs` runs (its words after the options)."""
        args, k = words[1:], 0
        while k < len(args) and args[k].static and args[k].text.startswith("-") and len(args[k].text) > 1:
            k += 1 + (args[k].text in XARGS_VALUE_OPTIONS)
        return shell._effective(args[k:])

    def _expanded_into_code(self, p: _Parsed | None) -> shell.Call | None:
        """A stage that RECEIVES text a stage with an expansion makes — through a pipe, `<<<`, a heredoc, `<`, or a file argument
        `<(…)`, or the `>(…)` that a stage writes to — and is not a known data filter (STDIN_DATA) is code nobody can read: `echo "$(echo piigate) reverse" | sh`,
        `| python3`, `| busybox sh`, `| env -S sh`, `| make -f -`, `| awk '{system($0)}'`, `sh <<< "…"`, `python3 <(printf …)` (#41).
        The rule is fail closed: no list of programs that run their input is complete, so what is not known to be a filter is a
        sink. Feeders are the earlier stages of the SAME pipeline. Text without an expansion is read by the tree
        (`echo 'ls' | sh`) and judged as before. Returns the call that reads it, or None."""
        if p is None:
            return None
        live = {"param", "cmd", "proc", "arith", "brace"}  # `echo p{ii,}gate`: the words are made by the shell, not read from the line

        def expands(w: shell.Word | None) -> bool:
            return w is not None and bool(live & w.kinds)

        def dynamic_heredoc(r) -> bool:
            return r.heredoc is not None and bool(r.heredoc.subst or r.heredoc.names)

        def feeds(f: shell.Call) -> bool:
            return any(expands(w) for w in (*f.argv, *(r.target for r in f.redirects if r.target is not None))) or any(
                dynamic_heredoc(r) for r in f.redirects
            )

        stages: dict[int, list[tuple[int, shell.Call]]] = {}
        for c in p.calls:
            for pid, stage in c.pipes:
                stages.setdefault(pid, []).append((stage, c))
        rebound = any(c.name == "alias" or any(a.name in shell.CODE_ARRAYS for a in c.assigns) for c in p.calls)

        def literal(f: shell.Call) -> bool:
            """A stage that is the plain `echo` / `printf` / `cat` of a LITERAL text: every word static (no variable, no glob, no
            brace, no substitution), a `cat` without a file, a heredoc or a here-string without an expansion, nothing read from a file."""
            if rebound or f.name not in ("echo", "printf", "cat") or f.name in p.functions or not all(w.static for w in f.argv):
                return False
            if f.name == "cat" and any(w.text == "-" or not w.text.startswith("-") for w in f.argv[1:]):
                return False
            return all(
                r.op not in ("<", "<>") and not dynamic_heredoc(r) and (r.target is None or r.target.static) for r in f.redirects
            )

        def transformed(c: shell.Call) -> bool:
            """A shell or an interpreter that reads its program from a pipe whose earlier stage is anything but a plain `echo` /
            `printf` / `cat` of a literal (`base64 -d | sh`, `rev | sh`, `sed … | sh`, `awk … | sh`, `curl … | sh`): the text it gets is
            not the text of the line, so nobody can read the code (#41, #43). `echo 'ls' | sh` is read by the tree."""
            return bool(c.stdin_interpreter) and any(
                not literal(f) for pid, stage in c.pipes if stage for s, f in stages[pid] if s < stage
            )
        parent = {id(sub): c for c in p.calls for sub in c.substitutions}
        fed_calls: set[int] = set()
        for c in p.calls:
            own = [r for r in c.redirects if r.op in ("<<<", "<", "<<")]
            from_file = self._stdin_file_receiver(c, p, rebound)  # `< "$f"`: the name is built, the text is not (#43)
            built = (
                any((expands(r.target) and not (from_file and r.op == "<")) or dynamic_heredoc(r) for r in own)
                or any("proc" in w.kinds and not w.text.startswith(">(") for w in c.argv)
                or any(feeds(f) for pid, stage in c.pipes if stage for s, f in stages[pid] if s < stage)
            )
            text_to_shell = transformed(c)
            fed = built or text_to_shell
            if c.origin == ">(" and (up := parent.get(id(c))) is not None:  # `tee >(sh)`, `printf "$x" > >(sh)`: its stdin is the output of `up`
                fed = fed or id(up) in fed_calls or any(
                    expands(w) for w in (*up.argv, *(r.target for r in up.redirects if r.target is not None)) if not w.text.startswith(">(")
                )
            if fed:
                fed_calls.add(id(c))
                if (refusal := self._stdin_refusal(c, p, rebound)) is not None:
                    self._code_label = refusal if built or not text_to_shell else "text-to-shell"
                    return c
        return None

    def _stdin_file_receiver(self, c: shell.Call, p: _Parsed, rebound: bool) -> bool:
        """Does `c` read `< file` as data it did not build: an interpreter or a shell that runs a script FILE of its own (the first
        operand: a literal, an existing regular file in each directory the call may run in, never under /dev, /proc, /sys, no
        option but a plain flag of python), or a local database client with the options of DB_OPTIONS only? A function, an alias, a
        name nobody can read, a name by a path outside the system directories, a wrapper that is not `command` / `nice` / `time` is not."""
        words = shell._effective(c.argv)
        if (
            rebound or not words or not words[0].static or self._prefix_assignment(c) or not self._known_location(words[0].text)
            or self._receiver_environment_changed(p) or self._line_writes(p)
        ):
            return False
        if len(words) != len(c.argv) and not {
            os.path.basename(w.text) for w in c.argv[: len(c.argv) - len(words)] if w.static
        } <= {"command", "builtin", "noglob", "nocorrect", "time", "nice"}:
            return False
        name = os.path.basename(words[0].text)
        if name in p.functions:
            return False
        args = words[1:]
        if name in DB_OPTIONS:
            return self._plain_db_client(DB_OPTIONS[name], args)
        base = re.sub(r"[\d.]+$", "", name)
        if base in FILE_INTERPRETERS or name in SHELLS:
            k = 0
            while base == "python" and k < len(args) and args[k].static and args[k].text in PYTHON_PLAIN_FLAGS:
                k += 1
            script = args[k] if k < len(args) else None
            dirs = sorted(c.cwds) if c.cwd_known else []
            return script is not None and script.static and bool(dirs) and all(self._script_file(script.text, d) for d in dirs)
        return False

    @staticmethod
    def _script_file(text: str, cwd: str) -> bool:
        """`text` names an existing regular file (not a device, not a pipe, not a link into /dev or /proc), by the name as written
        (`//dev/stdin`, `/./dev/stdin`, `/tmp/../dev/fd/0` read as /dev/stdin) and by the real path."""
        if not text or text.startswith(("-", "+")):
            return False
        path = os.path.normpath(os.path.join(cwd, text))
        path = "/" + path.lstrip("/")  # POSIX keeps a leading `//`
        try:
            real = os.path.realpath(path)
            return not any(x == q or x.startswith(q + "/") for x in (path, real) for q in ("/dev", "/proc", "/sys")) and os.path.isfile(real)
        except OSError:
            return False

    @staticmethod
    def _literal_or_value(args: list[shell.Word], value_options: frozenset[str] | set[str]) -> bool:
        """ONE rule for the exceptions that take options (the database clients, `git commit -F -`; #43, review): every word is a
        literal. The only word that is not may be the VALUE of an option of `value_options` — an option that takes a value and
        runs nothing — given as a separate token right after it (`-d "$db"`, `-m "$msg"`). `"-c$q"`, `"--init-command=$q"`,
        `"$opt"`, `"$(printf -- -engine)"` and an operand with an expansion, quoted or not, are words nobody can read, and one of
        them may be an option that runs code: they end the exception. A word is never skipped because its text is unknown."""
        takes_value = False
        for w in args:
            if takes_value:  # this token IS the value, whatever it looks like (`-d -d "$x"`: the second `-d` is a value, `"$x"` is not)
                takes_value = False
            elif w.static:
                takes_value = w.text in value_options
            else:
                return False
        return True

    @staticmethod
    def _plain_db_client(spec, args: list[shell.Word]) -> bool:
        """A local database client with the options of `spec` only, every word literal but the value of an option that takes one."""
        flags, short_values, long_values = spec
        if not AstGate._literal_or_value(args, short_values | long_values):
            return False
        k = 0
        while k < len(args):
            w = args[k]
            k += 1
            if not w.static:
                return False  # (a value is skipped below, with its option: nothing else may be here)
            t = w.text
            if t == "--" or t == "-" or not t.startswith("-"):
                continue
            name, eq, _ = t.partition("=")
            if t.startswith("--"):
                if name in long_values:
                    k += 0 if eq else 1
                elif t not in flags:
                    return False
            elif t in short_values:
                k += 1
            elif t not in flags and not (t[:2] in short_values and len(t) > 2):  # `-hhost`
                return False
        return True

    def _reads_stdin_as_data(self, c: shell.Call, p: _Parsed, rebound: bool) -> bool:
        """Is `c` a program known to treat what it reads as data and never as code — a program of STDIN_DATA with options that
        keep it so (FILTER_OPTIONS; for `sed` a script of `_sed_script_ok`, for `awk` a program of `_awk_program_ok`;
        `piigate text` / `table`), possibly behind `xargs` (judged by what it runs; `xargs` alone runs `echo`)? A function, an
        alias, a name nobody can read, a wrapper that is not `command` / `nice` / `time` is not."""
        return self._stdin_refusal(c, p, rebound) is None

    def _stdin_refusal(self, c: shell.Call, p: _Parsed, rebound: bool) -> str | None:
        """None when `c` reads its input as data (`_reads_stdin_as_data`); otherwise the fixed label of the rule that refuses it
        (the shadow mode counts it): the decision is the same as the bool's, the label only says which rule it was."""
        words = shell._effective(c.argv)
        if rebound:
            return "rebound-names"
        if not words or not words[0].static:
            return "unknown-receiver"
        if self._prefix_assignment(c):
            return "env-assign"
        if self._receiver_environment_changed(p):
            return "receiver-env"
        if len(words) != len(c.argv) and not {
            os.path.basename(w.text) for w in c.argv[: len(c.argv) - len(words)] if w.static
        } <= {"command", "builtin", "noglob", "nocorrect", "time", "nice"}:
            return "wrapper"
        if not self._known_location(words[0].text):
            return "unknown-location"
        via_xargs = False
        if os.path.basename(words[0].text) == "xargs":
            via_xargs = True
            words = self._xargs_command(words)
            if not words:
                return None
            if not words[0].static or not self._known_location(words[0].text):
                return "xargs-program"
            if os.path.basename(words[0].text) in FILTER_OPTIONS:
                # the input of xargs ends up in the arguments of a filter that takes a program or options — appended
                # (`printf '%s\n' -e "e $x" | xargs sed p f`) or put in by `-I{}` / `-i` / `--replace` (`xargs -I{} awk {}`): code (#43)
                return "xargs-program"
        name = os.path.basename(words[0].text)
        if name in p.functions:
            return "function"
        if not via_xargs and self._data_receiver(name, words[1:], p):  # (through xargs its input is APPENDED to the arguments: options)
            return None
        if name not in STDIN_DATA:
            return "stdin-interpreter" if c.stdin_interpreter else "stdin-receiver"
        args = words[1:]
        if name == "piigate":
            return None if args and args[0].static and args[0].text in ("text", "table") else "piigate-subcommand"
        spec = FILTER_OPTIONS.get(name)
        if spec is None:
            return None
        scanned = self._scan_options(args, spec)
        if scanned is None:
            return "filter-options"
        operands, values = scanned
        if name in ("less", "more") and any(o.startswith("+") for o in operands):
            return "pager-command"  # `less +!cmd`: an operand that starts with `+` is a command of the pager
        if name == "sed":
            programs = [v for o, v in values if o in ("e", "--expression")] or [operands[0] if operands else None]
            return None if all(t is not None and self._sed_script_ok(t) for t in programs) else "filter-program"
        if name in ("awk", "gawk", "mawk"):
            return None if operands and self._awk_program_ok(operands[0]) else "filter-program"
        return None

    @staticmethod
    def _stdin_flag(texts: list[str | None], short: str, longs: tuple[str, ...]) -> bool:
        """Is `-` given as the file of one of the options (`-F -`, `-F-`, `-aF -`, `--file -`, `--file=-`)?"""
        for i, t in enumerate(texts):
            if t is None:
                continue
            nxt = texts[i + 1] if i + 1 < len(texts) else None
            if t == short + "-" or any(t == o + "=-" for o in longs):
                return True
            if nxt == "-" and (t in longs or re.fullmatch(r"-[A-Za-z]*" + short[1:], t)):
                return True
        return False

    _WRITERS = {"tee", "cp", "mv", "dd", "install", "ln", "truncate", "rsync", "shuf", "sort", "split", "csplit"}

    @classmethod
    def _line_writes(cls, p: _Parsed) -> bool:
        """Does the line WRITE a file anywhere: a redirection `>` / `>>` / `>|` / `&>` / `<>` (not to /dev), `tee`, `cp`, `mv`, `dd`,
        `install`, `ln`, `sed -i`, `curl -o` / `-O`, `wget -O`…? Then a script that the line names may be the one it writes: no `<`
        exception (#43, review)."""
        for c in p.calls:
            if any(
                r.op in (">", ">>", ">|", "&>", "&>>", "<>")
                and not (r.target is not None and r.target.static and r.target.text.startswith("/dev/"))
                for r in c.redirects
            ):
                return True
            texts = [w.text for w in c.argv[1:]]
            if c.name in cls._WRITERS:
                return True
            if c.name == "sed" and any(re.fullmatch(r"-[A-Za-z]*i[A-Za-z]*", t) or t.startswith("--in-place") for t in texts):
                return True
            if c.name in ("curl", "wget", "http", "https", "xh", "aria2c") and any(
                t.startswith(("-o", "-O", "--output", "--remote-name")) for t in texts
            ):
                return True
        return False

    @staticmethod
    def _prefix_assignment(c: shell.Call) -> bool:
        """The call has an assignment in front of it that is not a harmless one: `NAME=value cmd`."""
        return any(a.name not in HARMLESS_ASSIGNMENTS for a in c.assigns)

    @staticmethod
    def _receiver_environment_changed(p: _Parsed) -> bool:
        """Does the line assign or export a variable that decides what a program that reads stdin or a script starts (GIT_EDITOR,
        EDITOR, PATH, HOME, PYTHONPATH, PSQLRC, NODE_OPTIONS, LESSOPEN…; RECEIVER_ENVIRONMENT)? Used for every data exception (#43)."""
        for c in p.calls:
            if any(RECEIVER_ENVIRONMENT.fullmatch(a.name) for a in c.assigns):
                return True
            if c.name in ("export", "declare", "typeset", "readonly", "local", "env", "set", "setenv"):
                for w in c.argv[1:]:
                    m = re.match(r"([A-Za-z_]\w*)=", w.text)
                    if m and RECEIVER_ENVIRONMENT.fullmatch(m.group(1)):
                        return True
        return False

    @staticmethod
    def _stdin_flag(texts: list[str | None], short: str, longs: tuple[str, ...]) -> bool:
        """Is `-` given as the file of one of the options (`-F -`, `-F-`, `--file -`, `--file=-`)? A cluster (`-aF -`) is no match: it is
        a cluster that may hold `-e` (review)."""
        for i, t in enumerate(texts):
            if t is None:
                continue
            nxt = texts[i + 1] if i + 1 < len(texts) else None
            if t == short + "-" or any(t == o + "=-" for o in longs):
                return True
            if nxt == "-" and (t == short or t in longs):
                return True
        return False

    @staticmethod
    def _has_option(texts: list[str | None], shorts: str, longs: tuple[str, ...]) -> bool:
        """An option of the list, by its short letters (also inside a cluster: `-eF`) or its long name or any abbreviation of it
        (getopt_long takes `--ed` for `--edit`)."""
        for t in texts:
            if t is None or not t.startswith("-") or t == "-":
                continue
            if t.startswith("--"):
                name = t.partition("=")[0]
                if len(name) > 2 and any(o.startswith(name) for o in longs):
                    return True
            elif any(ch in shorts for ch in t[1:]):
                return True
        return False

    def _data_receiver(self, name: str, args: list[shell.Word], p: _Parsed) -> bool:
        """The ONE program (besides the filters of STDIN_DATA, `base64` among them, whose result a shell later in the pipe still
        makes code) that reads stdin as DATA only when it is told to (#43): `git commit -F -` / `git tag -F -`, the message. No `-e` /
        `--edit` (an editor runs the text: `GIT_EDITOR=sh`, also in a cluster `-eF`), no `--template`, `-c` / `-C`, nothing before the
        subcommand (`-c`, `-C`, `--exec-path`, `--git-dir`, `--work-tree`), no assignment in front of the call or of RECEIVER_ENVIRONMENT
        in the line, EVERY word literal, the value of `-m` included (a literal `-m` can be the value of the one before it, and the next built word is then a free option: `-m -m "$(printf -- --edit)"`; git refuses `-m` with `-F` anyway). The hooks of the repository are code
        written earlier and run later: the known limit of the README, not judged here. Removed in review: `kubectl`, `gh`, `openssl`
        (a word that is quoted but built, `"$(printf -- --kubeconfig=k)"`, can be an option that runs code), `python3 -m json.tool`
        (`-m` imports `./json`), `docker` / `podman login` (the credential helper is chosen by `PATH` / `DOCKER_CONFIG`)."""
        if name != "git" or self._receiver_environment_changed(p) or not self._literal_or_value(args, frozenset()):
            return False
        texts = [w.text if w.static else None for w in args]
        return (
            texts[:1] in (["commit"], ["tag"])
            and self._stdin_flag(texts[1:], "-F", ("--file",))
            and not self._has_option(texts[1:], "etcCpi", ("--edit", "--reedit-message", "--reuse-message", "--patch", "--interactive", "--include", "--template", "--exec-path", "--git-dir", "--work-tree"))
        )

    @staticmethod
    def _known_location(text: str) -> bool:
        """A bare name (the shell finds it on PATH) or a path in a system directory; `./cat` or `/tmp/x/sort` is a file of the model's (#43)."""
        return "/" not in text or os.path.dirname(text) in SYSTEM_BINDIRS

    @staticmethod
    def _scan_options(args: list[shell.Word], spec) -> tuple[list[str], list[tuple[str, str | None]]] | None:
        """The operands (literal texts) and the option values (option, text or None when not literal) of `args`, or None when an
        option is not on the list of `spec`, or a word that is neither literal nor the value of an option is there (it may be an
        option: getopt takes them after the operands too)."""
        shorts, short_values, longs, long_values = spec
        operands: list[str] = []
        values: list[tuple[str, str | None]] = []
        done = False
        k = 0

        def take(option: str, n: int) -> bool:
            nonlocal k
            for _ in range(n):
                if k >= len(args):
                    return False
                values.append((option, args[k].text if args[k].static else None))
                k += 1
            return True

        while k < len(args):
            w = args[k]
            k += 1
            if not w.static:
                return None
            t = w.text
            if done or t == "-" or not t.startswith("-"):
                operands.append(t)
            elif t == "--":
                done = True
            elif t.startswith("--"):
                name, eq, rest = t.partition("=")
                if name in long_values:
                    if eq:
                        values.append((name, rest))
                    if not take(name, long_values[name] - bool(eq)):
                        return None
                elif t not in longs:
                    return None
            else:
                for j, ch in enumerate(t[1:], 1):
                    if ch in short_values:
                        if t[j + 1 :]:
                            values.append((ch, t[j + 1 :]))
                        elif not take(ch, 1):
                            return None
                        break
                    if ch not in shorts:
                        return None
        return operands, values

    _AWK_FORBIDDEN_WORDS = re.compile(r"system|getline|ENVIRON|close|fflush|\bexec\b|PROCINFO|SYMTAB|FUNCTAB")

    @staticmethod
    def _awk_program_ok(program: str) -> bool:
        """An awk program that cannot run a command or write a file, judged on the RAW text — no lexer: the lexers of awk (a
        regular expression with `[[:alpha:]/"]`, `[]/]`, a division that reads like a regex) are not ours to copy, and a scan that
        disagrees with gawk about where a string or a regex ends hides code (#43, review). The rules, each fail closed:
          * nothing of `system`, `getline`, `ENVIRON`, `close`, `fflush`, `exec`, `PROCINFO`… anywhere (a string too);
          * no `@` (`@load`, `@include`, an indirect call) anywhere;
          * `print` / `printf` is the only way to write a file (`>`, `>>`) or to start a command (`|`, `|&`): when the text has
            `print` (`printf` holds it), a `>` or a `|` ANYWHERE in it — in a string or a regex too — makes it code;
          * without `print`, `>` is a comparison (`NR>1`, `$3>5`) and `|` is `||` or part of a regular expression (`/a|b/`): data.
        So `{print $2}`, `NR>1`, `$1 == "x"`, `/a|b/` pass; `{print > "f"}`, `{print | "cmd"}`, `$1 > 5 {print}` (a comparison next
        to a `print`, not told apart from a redirection) and `/[[:alpha:]/"]/ {print | "sh"}` do not."""
        if AstGate._AWK_FORBIDDEN_WORDS.search(program) or "@" in program:
            return False
        return not ("print" in program and (">" in program or "|" in program))

    @staticmethod
    def _sed_script_ok(text: str) -> bool:
        """A sed script of the small grammar: commands `p` `d` `=` `q` `Q` `s` `y`, each with an optional address (a number,
        `$`, `/re/` with `I` / `M`, or two of them with a comma, then `!`); `s` flags `g` `p` `I` `i` `M` `m` and digits. No
        `e`, `w`, `W`, `r`, `R`, `x~y`, `+N`, `~N`, `\\cREc`, blocks, labels or comments — whatever the tokenizer does not
        know is not a data filter."""
        n = len(text)
        i = 0

        def part(i: int, d: str) -> int:
            """The index after the next unescaped `d` (a backslash takes the next character), or -1."""
            while i < n:
                if text[i] == "\\":
                    i += 2
                elif text[i] == d:
                    return i + 1
                else:
                    i += 1
            return -1

        def address(i: int) -> int:
            if i < n and text[i] == "$":
                return i + 1
            if i < n and text[i].isdigit():
                while i < n and text[i].isdigit():
                    i += 1
                return i
            if i < n and text[i] == "/":
                i = part(i + 1, "/")
                while 0 < i < n and text[i] in "IM":
                    i += 1
                return i
            return -1

        while True:
            while i < n and text[i] in " \t\n;":
                i += 1
            if i >= n:
                return True
            j = address(i)
            if j >= 0:
                i = j
                if i < n and text[i] == ",":
                    i = address(i + 1)
                    if i < 0:
                        return False
                while i < n and text[i] in " \t":
                    i += 1
                if i < n and text[i] == "!":
                    i += 1
                    while i < n and text[i] in " \t":
                        i += 1
            if i >= n:
                return False
            c = text[i]
            i += 1
            if c in "pd=":
                pass
            elif c in "qQ":
                while i < n and text[i].isdigit():
                    i += 1
            elif c in "sy":
                if i >= n or text[i].isalnum() or text[i] in " \t\n\\;":
                    return False
                d = text[i]
                i = part(i + 1, d)
                if i < 0:
                    return False
                i = part(i, d)
                if i < 0:
                    return False
                while c == "s" and i < n and text[i] in "gpIiMm0123456789":
                    i += 1
            else:
                return False
            while i < n and text[i] in " \t":
                i += 1
            if i < n and text[i] not in ";\n":
                return False

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

    def _human_only_dynamic(self, command: str, tokens: list[str] | None, standalone: bool) -> bool:
        """Can `piigate` be run with a subcommand the words do not show? By the rule of shell.py (WHAT CAN RUN A WORD): a word
        whose value nobody knows (`$c`, `$(…)`, a glob) is data only for a command of `shell.DATA_ONLY` (`echo`, `cat`…); in the
        argv of any other command — a launcher (`xargs $c`, `taskset 1 $c`, `find -exec $c`), an interpreter (`python3 -c "$code"`),
        a function, an alias, an unknown name — it may be the program that runs. So is a command whose name is unknown
        (`$c reverse`) and code the parser cannot read (`eval $x`, `bash -c "$x"`). A `$(…)` elsewhere in the line, or the word
        `reverse` / `approve` in an argument of another program (a URL, a grep pattern, `sorted(…, reverse=True)`), is not one
        (#26). A line the tree cannot tell about is judged by its text, as before."""
        p = self._cache.get(command)
        if p is None or tokens is None or "human-only-precise" in shell.ABLATE:
            return super()._human_only_dynamic(command, tokens, standalone)
        if self._expanded_into_code(p) is not None:
            return True  # text with an expansion given to a shell or an interpreter: code nobody can read (#41)
        rebound = any(c.name == "alias" or any(a.name in shell.CODE_ARRAYS for a in c.assigns) for c in p.calls)
        for c in p.calls:
            if c.opaque_code:
                return True
            words = shell._effective(c.argv)
            if words and not words[0].static:
                return True
            name = os.path.basename(words[0].text) if words else ""
            known = name in shell.DATA_ONLY and not rebound and name not in p.functions
            if not known and any(w.expands for w in c.argv):
                return True
        return False

    def _tokens(self, command: str) -> list[str] | None:
        if "tree-tokens" in shell.ABLATE:
            return gate.Gate._tokens(command)
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

    def _runs_text(self, tokens: list[str] | None) -> bool:
        """Can the line run text as shell code? The old test looks for `eval` as a word ANYWHERE; here an `eval` that the tree
        shows as an ARGUMENT of a plain program (`playwright-cli eval "document.querySelectorAll('.x')"`, the parser counts
        them in `Call.eval_as_argument`) is not the builtin: it runs nothing, and the quoted text after it is data, not a glob
        qualifier (#34). Every `eval` word the old tokenizer sees must be accounted for that way — else the line is judged as
        before."""
        cur = self._current
        if tokens is not None and cur is not None and cur.raw == self._raw and "eval-argument" not in shell.ABLATE:
            evals = [t for t in tokens if Path(str(t)).name == "eval"]
            if evals and len(evals) == sum(c.eval_as_argument for c in cur.calls):
                tokens = [t for t in tokens if Path(str(t)).name != "eval"]
        return super()._runs_text(tokens)

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

    def _touches(self, command: str, tokens: list[str]) -> tuple[str | None, str]:
        self._stage_log = []
        return super()._touches(command, tokens)

    def _stage_kinds(self, stage, c, text, literal, verbatim, body):
        found = self._stage_kinds_of(stage, c, text, literal, verbatim, body)
        self._stage_log.append((list(stage), set(c), list(found), tuple(stage) in self._names_seen))
        return found

    def _stage_kinds_of(self, stage, c, text, literal, verbatim, body):
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

    @staticmethod
    def _prints_or_reads(stage: list[str]) -> bool:
        """The stage has an option that is not on the list of its command (CREATE_FLAGS): `-v` / `--verbose`, `chmod -c`,
        `--changes`, `rm -i` / `-I` print the names they touch; `touch -r`, `--reference` read the metadata of another file;
        an option nobody listed is unknown. A word that starts with `$` (unresolved) may be an option too. `chmod -x f` / `+x` is
        a mode, not an option."""
        cmd = Path(stage[0]).name if stage else ""
        spec = CREATE_FLAGS.get(cmd)
        if spec is None:
            return True
        shorts, short_values, longs, long_values = spec
        words = [str(t) for t in stage[1:]]
        i = 0
        while i < len(words):
            t = words[i]
            i += 1
            if t == "--":
                return False  # the rest are operands
            if t.startswith(("$", "`")):
                return True
            if not t.startswith("-") or t == "-":
                continue
            if cmd == "chmod" and re.fullmatch(r"[-+][rwxXstugo]+(?:,.*)?", t):
                continue  # a mode (`-w`, `-x`), not an option
            if t.startswith("--"):
                name, eq, _ = t.partition("=")
                if name in long_values:
                    i += 0 if eq else 1  # `--mode 755`
                elif t not in longs:
                    return True
                continue
            for j, ch in enumerate(t[1:], 1):
                if ch in short_values:
                    i += 0 if t[j + 1 :] else 1  # `-m755` carries its value, `-m 755` takes the next word
                    break
                if ch not in shorts:
                    return True
        return False

    def _creates_only(self, tokens: list[str]) -> bool:
        """A compound line (`cd .. && mkdir Sensitive-data/x`, `mkdir -p S/n && echo a > S/n/n.txt`) whose every stage either
        touches no sensitive source at all (a `cd` included) or only CREATES in it — `mkdir` & co. (the no-output commands of
        the configuration) and the target of a `>` / `>>` — brings no content back; one stage that reads (`cat`, `ls` of the
        directory, `<` from it, a name it mentions as an operand) makes the line a read (#32). Stages come from the last `_touches`,
        each judged in the directories it runs in."""
        log = self._stage_log
        cur = self._current
        if cur is None or tokens is not cur.tokens or len(log) < 2 or self._unvettable_script(tokens):
            return False
        if any(t in ("|", "|&", "&", "(", ")", "<<", "<<<") for t in map(str, tokens)):
            return False  # a pipe, a background job, a group or text fed to a command: not a plain list of commands
        needles = {Path(k).name.casefold() for k in (*self.sensitive, *self.project_sensitive, *self.markers) if k}
        if self.sensitive_name:
            needles.add(self.sensitive_name.casefold())
        for stage, writes, found, listed in log:
            cmd = stage[0] if stage else ""
            if cmd in ("cd", "pushd", "popd") and Path(cmd).name == cmd:
                continue  # prints nothing: where it goes is the next stage's business (its directory comes from the tree)
            if not found and not listed and not any(
                n in str(t).casefold() for i, t in enumerate(stage) if i not in writes for n in needles
            ):
                continue  # touches no sensitive source; a write target is not a read
            if cmd in CREATE_COMMANDS and not self._prints_or_reads(stage) and super()._no_content(stage):
                continue  # `mkdir -p S/n`, `rm S/x`: no output
            return False
        return True

    def _no_content(self, tokens: list[str]) -> bool:
        """`rm D/.gitignore '&&' rmdir D`: a word that reads like an operator is still a word, but it is not the one-command
        `cp/mv/rm` the no-output rule is for — it keeps the old decision (the quoted `&&` used to split the command)."""
        if any(str(t).startswith("\\") and OPERATOR_WORD.fullmatch(str(t)[1:]) for t in tokens):
            return False
        return super()._no_content(tokens) or ("creates-only" not in shell.ABLATE and self._creates_only(tokens))

    def _unvettable_script(self, tokens: list[str]) -> bool:
        """The old rule (`echo "$x" > s.sh; bash s.sh`) plus the same text written by a LATER stage of its pipeline: `echo "$x" |
        tee s.sh; bash s.sh`, `… | cat > s.sh; bash s.sh` (#43). The stage that writes holds no expansion itself — the text comes
        from the stage before it. Text without an expansion is read by the tree and judged as before."""
        if super()._unvettable_script(tokens):
            return True
        cur = self._current
        if cur is None or tokens is not cur.tokens:
            return False
        stages, writes, _ = self._script_stages(tokens)
        if not writes or all(self._safe_stage(core) for core in stages[min(k for k, _, _ in writes) + 1 :]):
            return False
        for c in cur.calls:
            if c.name not in ("tee", "cat"):
                continue
            dests = [w for w in c.argv[1:] if not w.text.startswith("-")] if c.name == "tee" else [
                r.target for r in c.redirects if r.op in (">", ">>") and r.target is not None
            ]
            if not any(
                not d.text.startswith("/dev/") and "proc" not in d.kinds
                and (re.search(r"\.(?:sh|bash|zsh|ksh|fish|py|pl|rb|js|php|mk)$", d.text) or "." not in os.path.basename(d.text))
                for d in dests
            ):
                continue
            for pid, stage in c.pipes:
                for s, f in self._pipeline_stages(cur, pid):
                    if s < stage and f.name in ("echo", "printf", "cat") and self._builds_text(f):
                        return True
            if self._builds_text(c):  # the writer holds the text itself: `tee s.sh <<< "$x"`, `cat > s.sh <<EOF … $x … EOF`
                return True
        return False

    @staticmethod
    def _pipeline_stages(p: _Parsed, pid: int) -> list[tuple[int, shell.Call]]:
        return [(stage, c) for c in p.calls for i, stage in c.pipes if i == pid]

    @staticmethod
    def _builds_text(f: shell.Call) -> bool:
        """`echo` / `printf` / `cat` whose text the line builds: an expansion or a brace in an argument, a `%` format of `printf`, a
        heredoc or a here-string with an expansion."""
        if any(w.kinds & {"param", "cmd", "proc", "arith", "brace"} for w in f.argv[1:]):
            return True
        if any(
            (r.heredoc is not None and (r.heredoc.subst or r.heredoc.names))
            or (r.op == "<<<" and r.target is not None and r.target.kinds & {"param", "cmd", "proc", "arith", "brace"})
            for r in f.redirects
        ):
            return True
        return f.name == "printf" and any("%" in w.text for w in f.argv[1:2])

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
