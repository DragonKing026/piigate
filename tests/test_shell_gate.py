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

    def test_zsh_syntax_without_a_node_is_denied(self):
        for command in (
            "echo *(e:'cat ../S*/p*.csv >&2':)",
            "echo *.csv(e:'cat ../S*/p*.csv >&2':)",
            "x='$(cat ../S*/p*.csv >&2)'; echo ${(e)x}",
            "echo *(+f)",
        ):
            for dialect in shell.DIALECTS:
                with self.subTest(command, dialect=dialect):
                    g = self.ast(dialect)
                    self.assertIsNotNone(g.bash(command))
                    if not g.parse_error:
                        self.assertIn("zsh", g.bash(command))

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

    def test_zsh_code_is_refused_other_qualifiers_only_with_setopt(self):
        for command in ("echo *(e:'cat ../S*/p*.csv >&2':)", "echo *(+f)", "x='$(cat ../S*/p*.csv)'; echo ${(e)x}"):
            for dialect in shell.DIALECTS:
                g = self.ast(dialect)
                self.assertIsNotNone(g.bash(command), (command, dialect))
        self.assertIsNone(self.ast("zsh").bash("ls *(.)"))
        self.assertIsNone(self.ast("zsh").bash("echo +(a|b)"))
        self.assertIsNotNone(self.ast("zsh").bash("setopt BARE_GLOB_QUAL; ls *(.)"))

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


class TestAdversarialCorpus(Base):
    """Every line of tests/shell_adversarial.py that a real shell reads is denied — except the listed limitations."""

    def test_no_unexplained_hole(self):
        import shutil

        import shell_adversarial

        if not shutil.which("zsh"):
            self.skipTest("zsh not installed: the corpus is measured against real shells")
        rows = shell_adversarial.measure()
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
        "f() { cd ..; }; cd a && f && cat x",
        "f() { cat x; }; cd a && f",
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
