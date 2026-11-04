"""Tests of the shadow gate on the syntax tree (lib/piigate/shell_gate.py, issue 340). Run: python3 -I tests/test_shell_gate.py

The data are synthetic: a throw-away directory with a dummy sensitive directory. They need `shfmt` (skipped without it).
"""

import ast
import os
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(TESTS_DIR))

TMP = Path(tempfile.mkdtemp(prefix="piigate-shellgate-"))
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "config")
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "data")

from piigate import config, gate, shell, shell_gate  # noqa: E402

try:
    shell._shfmt_binary()
    AVAILABLE = True
except shell.ParseError:
    AVAILABLE = False


class TestNoProductionImport(unittest.TestCase):
    """The shadow modules are measured, not used: no code that runs in a hook or the server may import them."""

    SHADOW = {"shell", "shell_gate"}

    def imported(self, path: Path) -> set[str]:
        found: set[str] = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                found |= {a.name.split(".")[-1] for a in node.names}
                found |= {a.name.split(".")[1] for a in node.names if "." in a.name}
            elif isinstance(node, ast.ImportFrom):
                found |= {a.name for a in node.names}
                if node.module:
                    found |= set(node.module.split("."))
        return found

    def test_production_code_does_not_import_the_shadow_modules(self):
        files = [p for p in (ROOT / "lib").rglob("*.py") if p.name not in ("shell.py", "shell_gate.py")]
        files += [ROOT / "server.py", *sorted((ROOT / "hooks").glob("*.py"))]
        self.assertGreater(len(files), 10)
        for path in files:
            with self.subTest(file=str(path.relative_to(ROOT))):
                self.assertFalse(self.imported(path) & self.SHADOW)

    def test_hooks_and_launchers_do_not_mention_them(self):
        for path in [*(ROOT / "hooks").glob("*"), ROOT / "bin" / "piigate"]:
            if path.is_file():
                self.assertNotIn("shell_gate", path.read_text(encoding="utf-8", errors="replace"), path)

    def test_gate_py_is_untouched_by_the_adapter(self):
        self.assertNotIn("shell_gate", (ROOT / "lib" / "piigate" / "gate.py").read_text(encoding="utf-8"))


@unittest.skipUnless(AVAILABLE, "shfmt not installed")
class Base(unittest.TestCase):
    def setUp(self):
        self.root = TMP / self.id().split(".")[-1]
        self.work = self.root / "work"
        self.work.mkdir(parents=True)
        (self.root / "Sensitive-data").mkdir()
        (self.root / "Sensitive-data" / "people.csv").write_text("dummy\n", encoding="utf-8")
        (self.work / "x.csv").write_text("a,b\n", encoding="utf-8")
        cfg = config.load(str(self.work))
        cfg["sources"]["directories"] = [str(self.root / "Sensitive-data")]
        cfg["sources"]["only_phi_projects"] = False
        cfg["in_project"] = {"sensitive": [], "anonymized": []}
        self.cfg = cfg

    def ast(self, dialect="bash") -> shell_gate.AstGate:
        return shell_gate.AstGate(self.cfg, str(self.work), dialect)

    def old(self) -> gate.Gate:
        return gate.Gate(self.cfg, str(self.work))


class TestDecisions(Base):
    def test_plain_decisions_agree_with_the_old_gate(self):
        for command in (
            "ls",
            "cat ../Sensitive-data/people.csv",
            "cat ../S*/p*.csv",
            "echo ok | cat",
            "cd .. && ls Sensitive-data",
            "cat x.csv; cat ../Sensitive-data/people.csv",
            "python3 - <<'EOF'\nprint(open('../Sensitive-data/people.csv').read())\nEOF",
            "cat <<'EOF' | bash\ncat ../Sensitive-data/people.csv\nEOF",
            "echo \"$(cat ../Sensitive-data/people.csv)\"",
        ):
            with self.subTest(command):
                self.assertEqual(self.old().bash(command) is None, self.ast().bash(command) is None)

    def test_empty_single_quotes_glued_to_a_glob(self):
        """`''Sens*/*.json` (an empty word glued to a glob) crashed the prototype with KeyError: 'Value'."""
        g = self.ast()
        self.assertIsNone(g.bash("jq -n ''x*.json"))
        self.assertEqual(g.parse_error, "")
        self.assertIsNotNone(self.ast().bash("jq -n ''../Sens*/*.csv"))

    def test_parse_error_is_a_denial_with_its_own_flag(self):
        g = self.ast()
        self.assertIsNotNone(g.bash('echo "unterminated'))
        self.assertTrue(g.parse_error)
        self.assertEqual(self.ast().parse_error, "")

    def test_dialect_decides_what_parses(self):
        command = "foreach f (a b)\necho $f\nend"  # zsh only
        g = self.ast("bash")
        self.assertIsNotNone(g.bash(command))
        self.assertTrue(g.parse_error)
        g = self.ast("zsh")
        self.assertIsNone(g.bash(command))
        self.assertEqual(g.parse_error, "")
        self.assertIsNotNone(self.ast("zsh").bash("cat =(cat ../Sensitive-data/people.csv)"))

    def test_zsh_flag_that_runs_code_is_denied_in_every_nesting(self):
        for command in (
            "x='$(cat ../S*/p*.csv)'; echo ${(e)x}",
            "x='$(cat ../S*/p*.csv)'; echo ${${(e)x}}",
            "x='$(cat ../S*/p*.csv)'; echo ${(e)${x}}",
            "x='$(cat ../S*/p*.csv)'; echo ${y:-${(e)x}}",
        ):
            g = self.ast("zsh")
            self.assertIsNotNone(g.bash(command), command)
            self.assertFalse(g.parse_error, command)

    def test_zsh_qualifier_with_code_letters_is_denied_whatever_the_line_says(self):
        """No context: an `e`, a `+` or a `#q` inside the parentheses of a word with a qualifier, with any separator
        (`/ , ! + [ ] { }`), is refused. `*(.)`, `*.csv(N)`, `+(a|b)` pass."""
        for command in (
            "echo *(e:'cat ../S*/p*.csv >&2':)",
            "echo *(e,'cat ../S*/p*.csv >&2',)",
            "echo *(e!'cat ../S*/p*.csv >&2'!)",
            "echo *(e/'cat ../S*/p*.csv >&2'/)",
            "echo *.csv(.e:'x':)",
            "echo *(+f)",
            "echo *(#qe:f:)",
            "setopt bareglobqual; echo *(e:'x':)",
            "echo *(e:'cat ../Sensitive-data/people.csv >&2':)",
        ):
            for dialect in shell.DIALECTS:
                g = self.ast(dialect)
                self.assertIsNotNone(g.bash(command), (command, dialect))
        for command in ("ls *(.)", "echo *.csv(N)", "echo +(a|b)", "echo *(om[1,3])", "echo *(/)"):
            self.assertIsNone(self.ast("zsh").bash(command), command)

    def test_text_heredoc_body_is_judged(self):
        self.assertIsNotNone(self.ast().bash("python3 - <<'EOF'\nprint(open('../Sensitive-data/people.csv').read())\nEOF"))
        self.assertIsNone(self.ast().bash("python3 - <<'EOF'\nprint(1)\nEOF"))

    def test_file_heredoc_body_is_not_judged_unless_the_file_is_used(self):
        self.assertIsNone(self.ast().bash("cat > note.md <<'EOF'\nsee ../Sensitive-data/people.csv\nEOF"))
        self.assertIsNotNone(self.ast().bash("cat > s.sh <<'EOF'\ncat ../Sensitive-data/people.csv\nEOF\nbash s.sh"))

    def test_the_tokens_come_from_the_tree(self):
        g = self.ast()
        g.bash("echo $(cat x.csv) | grep a 2>/dev/null")
        tokens = g._current.tokens
        self.assertEqual(tokens[:2], ["echo", "$(…)"])
        self.assertIn("|", tokens)
        self.assertEqual(tokens[tokens.index("2") : tokens.index("2") + 3], ["2", ">", "/dev/null"])
        g.bash("cat '' \"a b\" --opt='c'")
        words = [t for t in g._current.tokens if getattr(t, "quoted", False)]
        self.assertEqual([getattr(t, "quote", "") for t in words], ["'", '"', "'"])
        g.bash("ssh h 'x' |& piigate table")
        self.assertIn("|&", g._current.tokens)


class TestRules(Base):
    """The rules of round 2: what the tree knows must reach the classification."""

    def deny(self, command: str, dialect: str = "bash") -> None:
        g = self.ast(dialect)
        self.assertIsNotNone(g.bash(command), command)

    def test_words_of_loops_and_heredocs_of_groups(self):
        self.deny("for f in ../S*/p*.csv; do cat $f; done")
        self.deny("select f in ../Sensitive-data/people.csv; do cat $f; break; done")
        for group in ("{ bash; }", "( bash )", "{ python3 -; }"):
            self.deny(group + " <<'EOF'\ncat ../Sensitive-data/people.csv\nEOF" if "bash" in group else group + " <<'EOF'\nprint(open('../Sensitive-data/people.csv').read())\nEOF")
        self.deny("f() { bash; } <<'EOF'\ncat ../Sensitive-data/people.csv\nEOF\nf")
        self.deny("{ cat; } <<'EOF' | bash\ncat ../Sensitive-data/people.csv\nEOF")

    def test_every_command_of_a_pipeline_stage_is_connected(self):
        for command in (
            "{ find ../Sensitive-data -type f; :; } | xargs cat",
            "( find ../Sensitive-data -type f; : ) | xargs cat",
            "find ../Sensitive-data -type f | while read f; do cat \"$f\"; done",
            "{ echo 'cat ../Sensitive-data/people.csv'; :; } | sh",
        ):
            self.deny(command)
        g = self.ast()
        g.bash("{ a; b; } | c")
        self.assertEqual(g._current.tokens, ["a", "|", "b", "|", "c"])

    def test_substitutions_that_build_a_path_or_code(self):
        for command in (
            "eval \"$(echo 'cat ../S*/p*.csv')\"",
            "bash -c \"$(echo 'cat ../S*/p*.csv')\"",
            "`echo cat ../S*/p*.csv`",
            "cat \"$(echo ../S*/p*.csv)\"",
            "cat $(echo ../S*/p*.csv)",
            "f=$(echo ../S*/p*.csv); cat \"$f\"",
            "cat ${f:-$(echo ../S*/p*.csv)}",
            "x='cat ../S*/p*.csv'; eval $x",
            "x='$(cat ../S*/p*.csv >&2)'; echo \"${x@P}\"",
        ):
            with self.subTest(command):
                self.deny(command)
        for command in ("echo $(date)", "x=$(date +%F); echo $x", 'git commit -m "msg $(date)"', "eval 'ls'"):
            with self.subTest(command):
                self.assertIsNone(self.ast().bash(command))

    def test_operator_words_stay_words(self):
        for word in (">", ">>", ">|", "&>", "\\>", ";", "|", "("):
            command = f"cat '{word}' ../Sensitive-data/people.csv" if "\\" not in word else f"cat {word} ../Sensitive-data/people.csv"
            with self.subTest(command):
                self.deny(command)
        g = self.ast()
        g.bash("cat '>' x.csv > out.csv")
        self.assertEqual([str(t) for t in g._current.tokens], ["cat", "\\>", "x.csv", ">", "out.csv"])

    def test_variables_have_a_value_only_when_one_static_assignment_gives_it(self):
        for command in (
            "d=../Sensitive-data; cat $d/people.csv",
            "a=..; b=Sensit; c=ive-data; cat $a/$b$c/people.csv",
            "c=cat; $c ../Sensitive-data/people.csv",
            "readonly r=../Sensitive-data/people.csv; cat $r",
            "export e=../Sensitive-data/people.csv; cat $e",
            "declare -a a=(../Sensitive-data/people.csv); cat \"${a[@]}\"",
            "declare -A a=([k]=../Sensitive-data/people.csv); cat \"${a[k]}\"",
            "for d in ../Sensitive-data/people.csv; do cat $d; done",
        ):
            with self.subTest(command):
                self.deny(command)
        for command in (  # no known value: a refusal for a reader
            "read d <<< x; cat $d", "printf -v d %s x; cat $d", "echo ${d:=x}; cat $d", "set -- x; cat $1", "x=a; y=$x; cat $y",
            "x=a; x=b; cat $x", "cat $x; x=a", "declare -n r=d; cat $r", "cat $SOME_PATH", "cat \"$1\"",
        ):
            with self.subTest(command):
                self.deny(command)
        for command in (  # known: the one static assignment, the environment named on purpose, a loop over static words
            "d=notes; cat $d.md", "cat $HOME/notes.md", "cat $PWD/notes.md", "for f in *.md; do cat $f; done", "cat '$x'",
        ):
            with self.subTest(command):
                self.assertIsNone(self.ast().bash(command))

    def test_unknown_write_target_and_lister(self):
        self.deny("tee $(echo ../S*/p*.csv) </dev/null")
        self.deny('echo x > "$OUT"')
        self.assertIsNone(self.ast().bash("echo x > out.txt"))
        self.deny("ls $D | xargs cat")  # the names of a place nobody knows flow into a reader
        self.assertIsNone(self.ast().bash("ls $D | head -3"))

    def test_zsh_foreach_word_list(self):
        self.deny("foreach f (../S*/p*.csv)\ncat $f\nend", "zsh")
        self.assertIsNone(self.ast("zsh").bash("foreach f (a b)\necho $f\nend"))

    def test_nul_in_a_word_and_unexpected_errors_deny(self):
        g = self.ast()
        self.assertIsNotNone(g.bash("cat $'\\0'"))
        self.assertTrue(g.parse_error)
        from unittest import mock

        g = self.ast()
        with mock.patch.object(shell_gate.AstGate, "_unjudgeable", side_effect=RuntimeError("boom")):
            self.assertIsNotNone(g.bash("ls"))
        self.assertIn("RuntimeError", g.internal_error)

    def test_fake_shfmt_means_deny_not_allow(self):
        from unittest import mock

        with mock.patch.object(shell, "_shfmt_candidates", return_value=["/nonexistent/shfmt"]):
            g = self.ast()
            self.assertIsNotNone(g.bash("cat ../Sensitive-data/people.csv"))
            self.assertTrue(g.parse_error)


class TestRound4(Base):
    def deny(self, command: str, dialect: str = "zsh") -> None:
        g = self.ast(dialect)
        self.assertIsNotNone(g.bash(command), command)

    def allow(self, command: str, dialect: str = "zsh") -> None:
        g = self.ast(dialect)
        self.assertIsNone(g.bash(command), (command, g.bash(command)))

    def test_pwd_and_tilde_plus_follow_the_directory(self):
        self.deny("cd ../Sensitive-data; cat $PWD/people.csv")
        self.deny("cd ../Sensitive-data; cat ~+/people.csv")
        self.deny("cd ../Sens*; cat $PWD/people.csv")  # an unknown directory: PWD is unknown
        self.allow("cat $PWD/notes.md")

    def test_eval_and_variables_reach_the_functions_of_the_line(self):
        for command in (
            "f() { cd ../S*; }; eval f; cat people.csv",
            "f() { cd ../S*; }; eval 'f'; cat people.csv",
            "f() { cd ../S*; }; ff=f; $ff; cat people.csv",
            "f() { cd ../S*; }; eval $x; cat people.csv",
        ):
            self.deny(command)
        self.allow("f() { cd /tmp; }; eval f; cat hosts.txt")

    def test_a_negated_or_until_condition_leaves_the_directory_unknown(self):
        for command in (
            "! cd ../S*; cat people.csv",
            "if ! cd ../S*; then :; fi; cat people.csv",
            "until cd ../S*; do :; done; cat people.csv",
            "! cd /nonexistent && cat ../Sensitive-data/people.csv",
        ):
            self.deny(command)

    def test_the_words_compose_the_line_for_the_human_only_commands(self):
        for command in (
            "piigate rev''erse x", 'piigate "rev"erse x', "piigate rever\\se x", "piigate $'rev\\x65rse' x",
            "q=rev; piigate ${q}erse x", "piigate project app''rove", "piigate ana''lyze x", 'eval "piigate rev""erse"',
        ):
            with self.subTest(command):
                self.deny(command, "bash")
                self.deny(command, "zsh")

    def test_gh_files_and_text(self):
        for command in (
            'gh issue create --body-file "$(echo ../S*/p*.csv)" --title t', 'gh issue create -F "$f" --title t',
            'gh api x --input "$f"', 'gh api -F data=@"$f" x', 'gh gist create "$f"', 'gh release upload v1 "$f"',
        ):
            with self.subTest(command):
                self.deny(command)
        self.allow('gh issue create --title "$(date)" --body hi')
        self.allow('gh issue comment 1 --body "$f"')

    def test_listers_with_unknown_values_feed_the_names_flow(self):
        for command in ('echo "$x"/* | xargs cat', "printf '%s\\n' \"$x\"/* | xargs cat", 'rg --files "$x" | xargs cat'):
            self.deny(command)
        self.allow('echo "$x"/* | head -3')
        self.allow('rg --files "$x" | head -3')

    def test_file_valued_options_with_unknown_values(self):
        for command in ('grep --file="$x" a', 'grep -f "$x" a', 'rg --pre "$x" foo .', 'rg --pre="$x" foo .',
                        'rg --hostname-bin "$x" foo', 'rg --ignore-file "$x" foo'):
            self.deny(command)

    def test_zsh_autoload_with_fpath_and_bash_glob_rules(self):
        self.deny("fpath=(.); autoload -Uz hook; hook")
        self.allow("autoload -Uz compinit")
        self.deny("shopt -u globskipdots; cat .*/S*/p*.csv", "bash")
        self.deny("GLOBIGNORE=; cat .*/S*/p*.csv", "bash")

    def test_unquoted_heredoc_to_an_interpreter_with_an_unknown_value(self):
        self.deny("x=..; python3 - <<EOF\nopen('$x/Sensitive-data/people.csv')\nEOF")  # a value known: the path is judged
        self.deny("python3 - <<EOF\nopen('$(echo ../S*/p*.csv)')\nEOF")
        self.deny("python3 - <<EOF\nopen('$UNKNOWN/x')\nEOF")
        self.allow("python3 - <<'EOF'\nprint('$UNKNOWN')\nEOF")  # quoted: nothing is expanded
        self.allow("cat <<EOF\n$UNKNOWN\nEOF")  # text for cat, not an interpreter

    def test_known_values_cost_nothing(self):
        for command in (
            'D="a b"; cat "$D"', "D=sub; cd \"$D\" && cat notes.md", 'for f in *.md; do cat "$f".bak; done',
            'T="ls -l"; $T', 't() { python3 x.py "$@"; }; t log', 't() { cat "$1"; }; t notes.md',
            "cat $PWD/notes.md", "x=$(pwd); cat $x/notes.md", 'cat "$(pwd)/notes.md"', "cat log-$(date +%F).txt",
            "echo $?; echo ${pipestatus[0]}", "ls *(om[1,3])",
        ):
            with self.subTest(command):
                self.allow(command)

    def test_known_values_are_judged(self):
        for command in (
            'D="../Sensitive-data"; cat "$D/people.csv"', "D=../Sensitive-data; cd \"$D\" && cat people.csv",
            "for d in ../Sensitive-data ../x; do cat $d/people.csv; done", 't() { cat "$1"; }; t ../Sensitive-data/people.csv',
            'x=$(pwd); cd ..; cat $x/../Sensitive-data/people.csv',
        ):
            with self.subTest(command):
                self.deny(command)

    def test_the_commands_with_a_known_output_are_explicit(self):
        g = self.ast()
        self.assertEqual(g._command_value(("pwd",), "/w"), "/w")
        self.assertIsNone(g._command_value(("mktemp",), "/w"))
        self.assertIsNone(g._command_value(("ls",), "/w"))
        self.assertEqual(g._command_value(("date", "+%F"), "/w"), "X")
        self.assertIsNone(g._command_value(("date", "+%d/%m"), "/w"))  # a `/` in the format: not a name any more
        self.assertEqual(g._command_value(("dirname", "a/b/c"), "/w"), "a/b")


class TestWordValuesAgainstARealShell(Base):
    """B1: the value of a word is computed from the pieces of the tree. For a corpus of static variables and every way to
    glue them to quotes, the words `AstGate` makes of `cat WORD` are what a real zsh / bash makes of `printf [%s] WORD`."""

    PREFIX = "x='../Sens'; y='a  b'; e=''; q='it'; s='*'; "
    WORDS = (
        '"$x"itive-data/p', '$x"itive-data"/p', "$x'itive-data'/p", "$x\\itive", "\"$x\"$'itive'", '"$x"_', "${x}y", "$x$x", "${x}${q}",
        '"$y"', '"$y"x', "$y", "x$y", "$e", '"$e"', "a$e", '"$e"a', '$e"$e"', "pre${q}post", '"${x}"', "'$x'", '"a$x b"', "$s", '"$s"',
    )

    def real(self, shell_name: str, word: str) -> str:
        import shutil
        import subprocess
        import tempfile

        exe = shutil.which(shell_name)
        if not exe:
            self.skipTest(f"{shell_name} not installed")
        with tempfile.TemporaryDirectory() as d:  # empty: a glob matches nothing
            argv = [exe, "-f", "-c"] if shell_name == "zsh" else [exe, "--noprofile", "--norc", "-c"]
            done = subprocess.run([*argv, self.PREFIX + "printf '[%s]' " + word], cwd=d, capture_output=True, text=True, timeout=10, check=False)
        return done.stdout

    def test_the_words_are_what_the_shell_makes(self):
        for dialect in shell.DIALECTS:
            for word in self.WORDS:
                real = self.real(dialect, word)
                g = self.ast(dialect)
                g.bash(self.PREFIX + "cat " + word)
                tokens = g._current.tokens if g._current else []
                words = tokens[tokens.index("cat") + 1 :] if "cat" in tokens else []
                if any(getattr(t, "dyn", False) for t in words):
                    continue  # not resolved (bash splits `x$y`): a refusal for a reader, never a wrong value
                made = "".join(f"[{t}]" for t in words) or "[]"  # printf with no argument prints one empty field
                # a glob character that survives is the gate's to expand (`$s` is `*` for bash: unresolved, kept as text)
                if ("*" in word or "$s" in word) and dialect == "bash":
                    continue
                with self.subTest(dialect=dialect, word=word):
                    self.assertEqual(made.replace("\\", ""), real)

    def test_the_gluing_cases_of_the_review(self):
        for word in ('"$x"itive-data/people.csv', '$x"itive-data"/people.csv', "$x'itive-data'/people.csv", "$x\\itive-data/people.csv",
                     "\"$x\"$'itive-data'/people.csv"):
            with self.subTest(word):
                for dialect in shell.DIALECTS:
                    self.assertIsNotNone(self.ast(dialect).bash("x=../Sens; cat " + word), (word, dialect))


class TestSealedBinary(Base):
    def test_no_fallback_to_the_file_when_the_seal_fails(self):
        from unittest import mock

        with mock.patch.object(shell, "_sealed_memfd", side_effect=OSError("no seals")):
            with self.assertRaises(shell.ParseError):
                shell.parse("cat x", cwd="/w")
            g = self.ast()
            self.assertIsNotNone(g.bash("ls"))
            self.assertTrue(g.parse_error)

    def test_the_memfd_is_sealed(self):
        import fcntl
        import os

        fd = shell._sealed_memfd(b"abc")
        try:
            seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            want = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
            self.assertEqual(seals & want, want)
            with self.assertRaises(OSError):
                os.write(fd, b"x")
        finally:
            os.close(fd)


class TestRealShellRunner(unittest.TestCase):
    """The only way the test tools start a real shell: no core dumps, limits, FUNCNEST, a session of its own."""

    def test_limits_are_applied(self):
        import shell_zsh_cases as zc

        done = zc.run_limited(["/usr/bin/bash", "--noprofile", "--norc", "-c", "ulimit -c; ulimit -t; ulimit -f; echo $FUNCNEST"],
                              "/", {"PATH": "/usr/bin:/bin"})
        self.assertEqual(done["out"].split(), ["0", "5", "1024", "64"])
        self.assertEqual((done["rc"], done["signal"], done["timeout"]), (0, 0, False))

    def test_a_signal_is_reported_and_a_hang_is_killed(self):
        import shell_zsh_cases as zc

        done = zc.run_limited(["/usr/bin/bash", "--noprofile", "--norc", "-c", "kill -TERM $$"], "/", {"PATH": "/usr/bin:/bin"})
        self.assertEqual(done["signal"], 15)
        done = zc.run_limited(["/usr/bin/bash", "--noprofile", "--norc", "-c", "sleep 30"], "/", {"PATH": "/usr/bin:/bin"}, timeout=0.5)
        self.assertTrue(done["timeout"])

    def test_hostile_lines_are_not_run(self):
        import shell_adversarial

        run = [c.name for c in shell_adversarial.CASES if not c.norun and shell_adversarial.HOSTILE.search(c.command)]
        self.assertEqual(run, [])  # a recursion, a fork bomb, a huge expansion, an endless loop, deep nesting: norun with a reason
        norun = {c.name: c.norun for c in shell_adversarial.CASES if c.norun}
        self.assertIn("function-recursion", norun)
        for case in shell_adversarial.CASES:  # a network program is never run for real
            if shell_adversarial.NETWORK_PROGRAMS.search(case.command):
                self.assertTrue(case.norun, case.name)
        self.assertTrue(all(norun.values()))
        for case in shell_adversarial.CASES:
            if case.norun:
                continue
            self.assertNotIn("FUNCNEST", case.command)


class TestAdversarialCorpus(Base):
    """Every line of tests/shell_adversarial.py that a real shell reads is denied — except the listed limitations."""

    def test_no_unexplained_hole(self):
        import shutil

        import shell_adversarial

        if not shutil.which("zsh"):
            self.skipTest("zsh not installed: the corpus is measured against real shells")
        rows = shell_adversarial.measure()
        killed = {r["name"]: r["signals"] for r in rows if r["signals"]}
        self.assertEqual(killed, {}, "a real shell died of a signal: the measurement of these cases is void")
        for dialect in shell.DIALECTS:
            self.assertEqual([r["name"] for r in shell_adversarial.unexplained(rows, dialect)], [], dialect)
        for r in rows:
            if r["expect"]:
                for dialect in shell.DIALECTS:
                    self.assertEqual(r[dialect]["decision"], r["expect"], (r["name"], dialect))
            for dialect in shell.DIALECTS:
                self.assertEqual(r[dialect]["internal_error"], "", r["name"])


class TestDirectoryModel(Base):
    """What can change the directory of a later command: all of it must widen the set, never narrow it."""

    def last_cwds(self, command: str) -> frozenset[str]:
        return shell.parse(command, cwd="/w")[-1].cwds

    def test_cd_chain_narrows(self):
        self.assertEqual(self.last_cwds("cd a && cat x"), {"/w/a"})
        self.assertEqual(self.last_cwds("cd a && (cd ..) && cat x"), {"/w/a"})  # a subshell does not leak

    WIDEN = (
        "cd a && cd ~- && cat x",
        "cd a && eval $x && cat x",
        "cd a && alias c=cd && c .. && cat x",
        "f() { cd ../S*; }; f && cat x",
        "cd a && source ./s.sh && cat x",
        "cd a && cd - && cat x",
        "cd ../S* && cat x",
        "cd ../{a,b} && cat x",
        "cd ~+/.. && cat x",
        "pushd ../S* && cat x",
    )

    def test_everything_that_may_change_directory_says_it_does_not_know(self):
        for command in self.WIDEN:
            with self.subTest(command):
                last = [c for c in shell.parse(command, cwd="/w") if c.name == "cat"][-1]
                self.assertFalse(last.cwd_known)  # the directory is a guess: `cwds` must not be trusted

    def test_an_unknown_directory_and_a_relative_reader_operand_is_a_denial(self):
        for command in self.WIDEN:
            command = command.replace("cat x", "cat people.csv")
            with self.subTest(command):
                g = self.ast()
                self.assertIsNotNone(g.bash(command))
                self.assertEqual(g.parse_error, "")
        for command in ("cd \"$D\" && ls", "f() { cd /tmp; }; f; ls", "cd \"$D\"; cd /tmp && cat hosts.txt", "cd \"$D\" && git status"):
            with self.subTest(command):
                self.assertIsNone(self.ast().bash(command))  # names, an absolute directory, a git call: no relative read

    def test_functions_are_analysed_where_they_are_called(self):
        calls = shell.parse("f() { cd ..; }; cd a && f && cat x", cwd="/w")
        self.assertEqual(calls[-1].cwds, {"/w"})  # the `cd ..` of the body carried on
        self.assertTrue(calls[-1].cwd_known)
        calls = shell.parse("f() { cat x; }; cd a && f && f", cwd="/w")
        self.assertEqual([sorted(c.cwds) for c in calls if c.name == "cat"], [["/w"], ["/w/a"], ["/w/a"]])
        calls = shell.parse("f() { find d; :; }; f | xargs cat", cwd="/w")
        # (the body is also emitted where it is declared, outside the pipeline: the LAST find and `:` are the called ones)
        last = {c.name: c for c in calls if c.name in ("find", ":", "xargs")}
        self.assertEqual([(n, last[n].piped_in, last[n].pipes_out) for n in ("find", ":", "xargs")],
                         [("find", False, True), (":", False, True), ("xargs", True, False)])

    def test_recursion_and_depth_are_refused(self):
        with self.assertRaises(shell.ParseError):
            shell.parse("f() { f; }; f", cwd="/w")
        with self.assertRaises(shell.ParseError):
            shell.parse("a() { :; }; b() { a; }; c() { b; }; d() { c; }; e() { d; }; g() { e; }; g", cwd="/w")

    def test_a_failed_cd_is_not_repaired_by_a_later_absolute_cd(self):
        """`cd X` may fail: the commands after `;` may still run where they were. Only the `&&` chain after an absolute
        `cd` is known again."""
        for command in (
            "cd ../S*; cd /nonexistent; cat x",
            "f() { cd ../S*; }; f; cd /nonexistent; cat x",
            "cd a || true; cd /nonexistent; cat x",
        ):
            last = shell.parse(command, cwd="/w")[-1]
            self.assertIn("/w", last.cwds, command)
        self.assertFalse(shell.parse("cd ../S*; cd /nonexistent; cat x", cwd="/w")[-1].cwd_known)
        last = shell.parse("cd ../S* && cd /abs && cat x", cwd="/w")[-1]
        self.assertTrue(last.cwd_known)
        self.assertEqual(last.cwds, {"/abs"})
        for command in ("cd ../Sens*; cd /nonexistent; cat people.csv", "f() { cd ../Sens*; }; f; cd /nonexistent; cat people.csv"):
            self.assertIsNotNone(self.ast().bash(command), command)

    def test_a_static_eval_is_followed(self):
        for command in ("cd a && eval cd .. && cat x", "cd a && eval 'cd ..' && cat x", "cd a && chdir .. && cat x"):
            last = shell.parse(command, cwd="/w")[-1]
            self.assertTrue(last.cwd_known)
            self.assertEqual(last.cwds, {"/w"})

    def test_absolute_cd_makes_the_directory_known_again(self):
        last = shell.parse('cd "$D"; cd /tmp && cat x', cwd="/w")[-1]
        self.assertTrue(last.cwd_known)
        self.assertEqual(last.cwds, {"/tmp"})

    def test_env_chdir_runs_elsewhere(self):
        call = shell.parse("cd a && env -C .. cat x", cwd="/w")[-1]
        self.assertIn("/w", call.cwds)
        self.assertFalse(call.cwd_known)

    def test_shell_script_behind_a_launcher_is_parsed(self):
        calls = shell.parse("find . -exec sh -c 'cd ../..; cat Sens*/a.txt' ';'", cwd="/w")
        self.assertEqual([c.name for c in calls], ["find", "cd", "cat"])
        calls = shell.parse("sudo -u root bash -lc 'ls'", cwd="/w")
        self.assertEqual([c.name for c in calls], ["sudo", "ls"])  # reached from two words, run once

    def test_pipe_stderr_is_kept(self):
        a, b, c = shell.parse("a | b |& c", cwd="/w")
        self.assertEqual((a.piped_in, b.piped_in, c.piped_in), (False, True, True))
        self.assertEqual((b.piped_stderr, c.piped_stderr), (False, True))


if __name__ == "__main__":
    unittest.main()
