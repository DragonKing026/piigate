"""Tests of the shell parser prototype (lib/piigate/shell.py). Run: python3 -I tests/test_shell.py

They check the STRUCTURE the parser returns (words, quoting, heredocs, redirections, directories), not a gate decision.
The commands are the ones from the gate's regression tests for issues #1, #4, #5, #7, #10, #13, #18, #19 and #21.
They need the `shfmt` binary (mvdan/sh) and skip themselves without it.
"""

import sys
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS_DIR.parent / "lib"))
sys.path.insert(0, str(TESTS_DIR))

from piigate import shell  # noqa: E402

try:
    shell._shfmt_binary()
    AVAILABLE = True
except shell.ParseError:
    AVAILABLE = False

CWD = "/w"


def parse(command: str, cwd: str = CWD) -> list[shell.Call]:
    return shell.parse(command, cwd=cwd)


def named(calls: list[shell.Call], name: str) -> list[shell.Call]:
    return [c for c in calls if c.name == name]


def texts(call: shell.Call) -> list[str]:
    return [w.text for w in call.argv]


def heredoc(call: shell.Call) -> shell.Heredoc:
    found = [r.heredoc for r in call.redirects if r.heredoc]
    assert len(found) == 1, call.redirects
    return found[0]


@unittest.skipUnless(AVAILABLE, "shfmt not installed")
class Base(unittest.TestCase):
    pass


class TestHeredocs(Base):
    def test_issue_1_glob_in_quoted_heredoc_is_body_not_word(self):
        """`name.*` in a quoted heredoc fed to a non-shell is text; the same pattern as an argument is a glob."""
        (call,) = parse("python3 - <<'EOF'\nprint('zgoda.*')\nEOF")
        self.assertEqual(texts(call), ["python3", "-"])
        self.assertTrue(all(w.static for w in call.argv))
        self.assertEqual(call.stdin_interpreter, "python3")
        self.assertEqual(heredoc(call), shell.Heredoc("print('zgoda.*')\n", "EOF", True))
        (cat,) = parse("cat people.* <<'EOF'\npeople.*\nEOF")
        self.assertIn("glob", cat.argv[1].kinds)
        self.assertEqual(cat.stdin_interpreter, "")
        self.assertEqual(heredoc(cat).body, "people.*\n")

    def test_issue_1_shell_reads_the_body(self):
        (call,) = parse("bash <<'EOF'\ncat people.*\nEOF")
        self.assertEqual(call.stdin_interpreter, "bash")
        self.assertEqual(heredoc(call).body, "cat people.*\n")
        calls = parse('python3 - <<EOF\nprint("`cat people.*`")\nEOF')  # unquoted: the shell runs the backticks
        py, cat = calls
        self.assertFalse(heredoc(py).quoted)
        self.assertEqual((cat.name, cat.origin, cat.in_subshell), ("cat", "`", True))
        self.assertEqual(py.substitutions, [cat])
        self.assertIn("glob", cat.argv[1].kinds)

    def test_issue_1_quoted_delimiter_forms(self):
        for command in ("python3 - <<'EOF'\nx\nEOF", 'python3 - <<"EOF"\nx\nEOF', "python3 - <<\\EOF\nx\nEOF"):
            with self.subTest(command):
                (call,) = parse(command)
                self.assertTrue(heredoc(call).quoted)
                self.assertEqual(heredoc(call).delimiter, "EOF")
        (call,) = parse("cat <<EOF\nx\nEOF")
        self.assertFalse(heredoc(call).quoted)

    def test_issue_4_dump_call_in_body(self):
        script = (
            "python3 - out <<'EOF'\nimport json, sys\nd = json.load(open('verdicts.json'))\n"
            "for k, v in d.items():\n    json.dump(v, open(f'{out}/{k}.json', 'w'), ensure_ascii=False, indent=1)\n"
            "    pickle.dump (v, f)\nEOF"
        )
        (call,) = parse(script)
        self.assertEqual(texts(call), ["python3", "-", "out"])
        self.assertEqual(call.stdin_interpreter, "python3")
        self.assertIn("json.dump(v", heredoc(call).body)
        self.assertIn("pickle.dump (v, f)", heredoc(call).body)

    def test_issue_4_body_run_by_a_shell(self):
        calls = parse("cat <<'EOF' | bash\ncat people.csv\nEOF")
        cat, bash = calls
        self.assertTrue(cat.pipe_to_shell)
        self.assertEqual(heredoc(cat).body, "cat people.csv\n")
        self.assertEqual((bash.stdin_interpreter, bash.piped_in), ("bash", True))
        self.assertFalse(bash.pipe_to_shell)

    def test_issue_5_variable_in_quoted_and_unquoted_heredoc(self):
        (quoted,) = parse("python3 - <<'EOF'\nargs = ['${CLAUDE_PLUGIN_ROOT}/hooks/x.py']\nEOF")
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", heredoc(quoted).body)
        self.assertTrue(heredoc(quoted).quoted)
        (unquoted,) = parse('python3 - <<EOF\nopen("${CLAUDE_PLUGIN_ROOT}/config.json")\nEOF')
        self.assertFalse(heredoc(unquoted).quoted)
        self.assertIn("${CLAUDE_PLUGIN_ROOT}", heredoc(unquoted).body)  # the shell would expand it
        (word_use,) = parse("cat ${CLAUDE_PLUGIN_ROOT}/config.json")
        self.assertEqual(word_use.argv[1].kinds, frozenset({"param"}))
        self.assertEqual(word_use.argv[1].text, "${CLAUDE_PLUGIN_ROOT}/config.json")

    def test_issue_5_gh_body_with_quotes_and_trailing_comma(self):
        (call,) = parse(
            "gh issue create -R o/r --title t -F - <<'EOF'\nThe hook doesn't match: "
            '"${CLAUDE_PLUGIN_ROOT}/hooks/straznik.py"], — it is another plugin\'s root\nEOF'
        )
        self.assertEqual(texts(call), ["gh", "issue", "create", "-R", "o/r", "--title", "t", "-F", "-"])
        self.assertEqual(call.stdin_interpreter, "")
        self.assertIn("doesn't match", heredoc(call).body)

    def test_issue_7_directory_name_in_heredoc_text(self):
        """The body of a heredoc fed to a non-shell is data; for a shell it is code; a word naming it is an operand."""
        (py,) = parse("python3 - notes.md <<'EOF'\ntext = 'files in Sensitive-data/x.json are personal'\nEOF")
        self.assertNotIn("Sensitive-data", " ".join(texts(py)))
        self.assertIn("Sensitive-data/x.json", heredoc(py).body)
        (gh,) = parse("gh issue create --title t --body-file - <<'EOF'\nsee Sensitive-data/x.json\nEOF")
        self.assertEqual(gh.stdin_interpreter, "")
        self.assertNotIn("Sensitive-data", " ".join(texts(gh)))
        (cat,) = parse("cat > notes.md <<'EOF'\nsee Sensitive-data/x.json\nEOF")
        self.assertEqual([r.op for r in cat.redirects], [">", "<<"])
        self.assertEqual(cat.redirects[0].target.text, "notes.md")
        self.assertEqual((cat.stdin_interpreter, cat.pipe_to_shell), ("", False))
        self.assertEqual(texts(cat), ["cat"])

    def test_issue_7_what_stays_visible(self):
        (cat,) = parse("cat Sensitive-data/x.json")
        self.assertEqual(texts(cat), ["cat", "Sensitive-data/x.json"])
        (c,) = parse("python3 -c \"open('Sensitive-data/x.json')\"")
        self.assertEqual(c.stdin_interpreter, "")
        self.assertEqual((c.argv[2].quoting, c.argv[2].text), ("double", "open('Sensitive-data/x.json')"))
        (bash,) = parse("bash <<'EOF'\ncat Sensitive-data/x.json\nEOF")
        self.assertEqual(bash.stdin_interpreter, "bash")
        self.assertIn("Sensitive-data/x.json", heredoc(bash).body)
        cat, sh = parse("cat <<'EOF' | bash\ncat Sensitive-data/x.json\nEOF")
        self.assertTrue(cat.pipe_to_shell)
        (echo,) = parse("echo Sensitive-data/x.json")
        self.assertEqual(texts(echo), ["echo", "Sensitive-data/x.json"])
        (gh,) = parse("gh issue create --title t --body 'the notes mention Sensitive-data/x.json'")
        self.assertEqual((gh.argv[-1].quoting, gh.argv[-1].expands), ("single", False))

    def test_dash_strips_tabs_and_here_string(self):
        (call,) = parse("cat <<-EOF\n\tone\n\t\ttwo\n\tEOF")
        self.assertEqual(heredoc(call).body, "one\ntwo\n")
        (call,) = parse('bash <<< "ls $HOME"')
        self.assertEqual(call.redirects[0].op, "<<<")
        self.assertEqual(call.redirects[0].target.text, "ls $HOME")
        self.assertEqual(call.stdin_interpreter, "bash")

    def test_two_heredocs_on_one_command_and_inside_substitution(self):
        (call,) = parse("cat <<A <<B\na\nA\nb\nB")
        self.assertEqual([r.heredoc.body for r in call.redirects], ["a\n", "b\n"])
        echo, cat = parse("echo $(cat <<E\nin\nE\n)")
        self.assertEqual(heredoc(cat).body, "in\n")
        self.assertEqual(echo.substitutions, [cat])


class TestWordsAndQuoting(Base):
    def test_issue_10_sed_awk_program_is_a_quoted_static_word(self):
        for command, index in (
            ("sed -n '/[Ww] trakcie/,/^$/p' compose.yml", 2),
            ("sed -E -n -e '/^[A-Z]* x/p' -e '/[0-9] y/d' compose.yml", 4),
            ("awk '/[Ww] trakcie/ {print $1}' compose.yml", 1),
            ("sed -i.bak 's/[a-z]* /x/' compose.yml", 2),
        ):
            with self.subTest(command):
                (call,) = parse(command)
                program = call.argv[index]
                self.assertEqual((program.quoting, program.expands), ("single", False))
                self.assertEqual(call.argv[-1].text, "compose.yml")
        printf, sed = parse("printf 'a\\nb\\n' | sed -n '/[Ww] trakcie/,/^$/p'")
        self.assertEqual((printf.piped_in, sed.piped_in), (False, True))
        self.assertTrue(printf.in_subshell and sed.in_subshell)

    def test_issue_10_unquoted_bracket_pattern_is_a_glob(self):
        (call,) = parse("ls /[Ww]x* [a-z].c")
        self.assertEqual([w.kinds for w in call.argv[1:]], [frozenset({"glob"}), frozenset({"glob"})])
        (call,) = parse("ls '*.c' \"*.c\" \\*.c a\\ b")
        self.assertTrue(all(w.static for w in call.argv))
        self.assertEqual([w.quoting for w in call.argv], ["none", "single", "double", "none", "none"])
        self.assertEqual(call.argv[3].text, "*.c")
        self.assertEqual(call.argv[4].text, "a b")

    def test_issue_13_jq_programs_in_single_and_double_quotes(self):
        (call,) = parse(
            "gh issue list -R owner/repo --state all --json number,title -q '.[]|\"#\\(.number) \\(.title)\"'"
        )
        self.assertEqual((call.argv[-1].quoting, call.argv[-1].expands), ("single", False))
        self.assertEqual(call.argv[-1].text, '.[]|"#\\(.number) \\(.title)"')
        (call,) = parse("gh issue comment 13 -R owner/repo --body \"denied: jq -r '.checks[]|.name'\"")
        self.assertEqual(call.name, "gh")
        self.assertEqual(call.argv[-1].quoting, "double")
        self.assertEqual(call.argv[-1].text, "denied: jq -r '.checks[]|.name'")
        self.assertEqual(len(parse("gh issue comment 13 --body \"denied: jq -r '.checks[]|.name'\"")), 1)

    def test_issue_13_substitution_in_double_quotes_is_a_call(self):
        echo, jq = parse("echo \"$(jq -r '.hooks.PreToolUse[0].hooks[0].command' compose.yml)\"")
        self.assertEqual(echo.argv[1].quoting, "double")
        self.assertEqual(echo.argv[1].kinds, frozenset({"cmd"}))
        self.assertEqual((jq.name, jq.origin, jq.in_subshell), ("jq", "$(", True))
        self.assertEqual(echo.substitutions, [jq])

    def test_issue_13_stderr_redirect_is_not_an_operand(self):
        gh, piigate = parse("gh issue list -R owner/repo --limit 1 --json title -q '.[].title' 2>&1 | piigate text")
        self.assertNotIn("2>&1", texts(gh))
        self.assertEqual([(r.op, r.fd, r.target.text) for r in gh.redirects], [(">&", "2", "1")])
        self.assertTrue(gh.pipe_to_shell is False and piigate.piped_in)

    def test_issue_19_jq_alternative_operator_is_program_text(self):
        (call,) = parse("jq --arg d '/x/*' -r '.a // $d' compose.yml")
        self.assertEqual((call.argv[2].text, call.argv[2].quoting, call.argv[2].expands), ("d", "none", False))
        self.assertEqual((call.argv[3].text, call.argv[3].quoting, call.argv[3].expands), ("/x/*", "single", False))
        self.assertEqual((call.argv[5].text, call.argv[5].expands), (".a // $d", False))
        (call,) = parse('gh issue list --json n --jq=\'.[] | "\\(.m // "-")"\'')
        word = call.argv[-1]
        self.assertEqual((word.quoting, word.expands), ("mixed", False))
        self.assertTrue(word.text.startswith("--jq=.[] | "))
        (call,) = parse("gh api repos/o/r/milestones --template '{{range .}}{{.title}}//{{end}}'")
        self.assertFalse(call.argv[-1].expands)
        (call,) = parse("jq '.a // 1' Sensitive-data/*")
        self.assertEqual((call.argv[1].expands, call.argv[2].kinds), (False, frozenset({"glob"})))

    def test_expansion_kinds(self):
        (call,) = parse("echo $x ${y:-z} $((1+2)) ~ ~/a {a,b}.txt {1..3} '{a,b}' a{} $'x\\ty' \"$@\"")
        kinds = [w.kinds for w in call.argv[1:]]
        self.assertEqual(
            kinds,
            [
                frozenset({"param"}),
                frozenset({"param"}),
                frozenset({"arith"}),
                frozenset({"tilde"}),
                frozenset({"tilde"}),
                frozenset({"brace"}),
                frozenset({"brace"}),
                frozenset(),
                frozenset(),
                frozenset(),
                frozenset({"param"}),
            ],
        )
        self.assertEqual(call.argv[10].text, "x\ty")  # ANSI-C quoting
        self.assertEqual(call.argv[11].quoting, "double")

    def test_line_continuation_and_comment(self):
        (call,) = parse("echo a\\\nb # comment")
        self.assertEqual(texts(call), ["echo", "ab"])


class TestStructure(Base):
    def test_issue_21_newline_separates_commands(self):
        for command in (
            "echo x\ncat Sensitive-data/a.txt",
            "echo x &&\ncat Sensitive-data/a.txt",
            "echo x \\\n&& cat Sensitive-data/a.txt",
            "echo x\n\ncat Sensitive-data/a.txt\n",
            "printf '%s' 'a\nb'\ncat Sensitive-data/a.txt",
        ):
            with self.subTest(command):
                echo, cat = parse(command)
                self.assertEqual(texts(cat), ["cat", "Sensitive-data/a.txt"])
                self.assertEqual(len(echo.argv) and echo.name in ("echo", "printf"), True)
        printf, _ = parse("printf '%s' 'a\nb'\ncat x")
        self.assertEqual(printf.argv[2].text, "a\nb")  # the newline inside quotes stays in the word

    def test_operators_and_pipelines(self):
        calls = parse("a && b || c; d | e |& f &\ng")
        self.assertEqual([c.name for c in calls], list("abcdefg"))
        self.assertEqual([c.in_subshell for c in calls], [False, False, False, True, True, True, False])
        self.assertTrue(calls[5].background is False and calls[3].background is False)  # the whole pipeline is `&`
        (call,) = parse("sleep 1 &")
        self.assertTrue(call.background)

    def test_compound_commands_and_functions(self):
        calls = parse("if cd a; then ls; elif pwd; then id; else w; fi; while read l; do echo $l; done < f")
        self.assertEqual([c.name for c in calls], ["cd", "ls", "pwd", "id", "w", "read", "echo"])
        self.assertTrue(all(r.inherited for c in calls[5:] for r in c.redirects))
        calls = parse("for i in $(ls d); do cat $i; done; case $x in a) pwd;; esac; f() { cat z; }; { cat; } < s.txt")
        self.assertEqual([c.name for c in calls], ["ls", "cat", "pwd", "cat", "cat"])
        self.assertEqual(calls[3].origin, "function")
        self.assertEqual([(r.op, r.target.text, r.inherited) for r in calls[4].redirects], [("<", "s.txt", True)])

    def test_assignments_and_substitutions(self):
        call = parse("FOO=1 BAR=$(id) cat f")[0]
        self.assertEqual([a.name for a in call.assigns], ["FOO", "BAR"])
        self.assertEqual(texts(call), ["cat", "f"])
        assign, id_ = parse("x=$(id)")
        self.assertEqual((assign.argv, id_.name), ([], "id"))
        self.assertEqual(assign.substitutions, [id_])
        decl, id_ = parse("export A=$(id) B=2")
        self.assertEqual(texts(decl), ["export", "A=$(…)", "B=2"])
        diff, ls = parse("diff <(ls a) b")
        self.assertEqual((ls.origin, diff.argv[1].kinds), ("<(", frozenset({"proc"})))
        tee_parent, tee = parse("cat > >(tee f)")
        self.assertEqual((tee.origin, tee_parent.redirects[0].target.kinds), (">(", frozenset({"proc"})))
        test, pwd = parse("[[ -f $(pwd) ]] && echo")[:2]
        self.assertEqual(test.name, "[[")
        self.assertEqual(test.substitutions[0].name, "pwd")

    def test_shell_scripts_in_arguments(self):
        bash, cd, cat = parse("bash -c 'cd q && cat f'")
        self.assertEqual((cd.origin, cat.origin), ("-c", "-c"))
        self.assertEqual(cat.cwds, frozenset({"/w/q"}))
        self.assertEqual(bash.substitutions, [cd, cat])
        sudo, ls = parse("sudo -u root bash -lc 'ls'")
        self.assertEqual(ls.origin, "-c")
        (call,) = parse('bash -c "$x"')
        self.assertTrue(call.opaque_code)
        evaluated = parse("eval 'cat people.csv'")
        self.assertEqual([c.name for c in evaluated], ["eval", "cat"])
        (script,) = parse("bash run.sh")
        self.assertEqual((script.stdin_interpreter, script.opaque_code), ("", False))

    def test_stdin_interpreters(self):
        cases = {
            "python3 -": "python3",
            "python3": "python3",
            "python3 - a b": "python3",
            "bash": "bash",
            "sh -s": "sh",
            "sudo bash": "bash",
            "env A=1 python3 -": "python3",
            "source /dev/stdin": "source",
            "python3 script.py": "",
            "python3 -c 'x'": "",
            "python3 -m json.tool": "",
            "bash -c x": "",
            "bash s.sh": "",
            "cat": "",
            "node -e 1": "",
            "node -": "node",
        }
        for command, expected in cases.items():
            with self.subTest(command):
                self.assertEqual(parse(command)[-1].stdin_interpreter, expected)


class TestDirectories(Base):
    """Issue #18: the directories a command may run in, compared with the sets the gate computes in _stage_dirs."""

    def last_dirs(self, command: str, cwd: str = CWD) -> frozenset[str]:
        return parse(command, cwd)[-1].cwds

    def test_literal_cd_before_and_narrows(self):
        for command in (
            "cd raporty/nocne && ls -d */ | head -2",
            "cd raporty/nocne && for d in */; do echo $d; done",
            "cd raporty && cd nocne && grep -r foo",
            "pushd raporty/nocne && tree",
            "cd -P raporty/nocne && find . -name '*.md'",
            "cd raporty/nocne 2>/dev/null && ls -R",
            "cd raporty/nocne 2>&1 && ls -R",
            "cd raporty/nocne &>/dev/null && ls -R",
        ):
            with self.subTest(command):
                self.assertEqual(self.last_dirs(command), frozenset({"/w/raporty/nocne"}))
                self.assertTrue(parse(command)[-1].cwd_known)
        self.assertEqual(self.last_dirs("cd /abs/x && ls", "/w"), frozenset({"/abs/x"}))
        self.assertEqual(self.last_dirs("cd .. && ls", "/w/a"), frozenset({"/w"}))
        home = str(Path("~").expanduser())
        self.assertEqual(self.last_dirs("cd && ls"), frozenset({home}))
        self.assertEqual(self.last_dirs("cd ~/x && ls"), frozenset({home + "/x"}))

    def test_cd_redirections_are_not_operands(self):
        cd = parse("cd raporty/nocne 2>/dev/null && ls -R")[0]
        self.assertEqual(texts(cd), ["cd", "raporty/nocne"])
        self.assertEqual([(r.op, r.fd) for r in cd.redirects], [(">", "2")])

    def test_stage_may_run_in_the_session_directory(self):
        both = frozenset({"/w", "/w/raporty/nocne"})
        for command in (
            "cd raporty/nocne; ls -R",
            "cd raporty/nocne || ls -R",
            "cd raporty/nocne && true; ls -R",
            "true || cd raporty/nocne && ls -R",
            "cd raporty/nocne && ls\nls -R",
            "cd raporty/nocne && popd && ls -R",
        ):
            with self.subTest(command):
                self.assertEqual(self.last_dirs(command), both)
        for command in (  # in a forked shell the cd does not leak (the gate's superset is wider here)
            "cd raporty/nocne | ls -R",
            "cd raporty/nocne & ls -R",
            "(cd raporty/nocne && true) && ls -R",
        ):
            with self.subTest(command):
                self.assertEqual(self.last_dirs(command), frozenset({"/w"}))

    def test_cd_to_two_places(self):
        self.assertEqual(self.last_dirs("cd raporty/nocne && cd ../.. && ls -R"), frozenset({"/w"}))
        self.assertEqual(self.last_dirs("cd raporty/nocne 2>&1 && cd ../.. && ls -R"), frozenset({"/w"}))
        self.assertEqual(
            self.last_dirs("cd raporty/nocne && cat ../../Sensitive-data/x.txt"), frozenset({"/w/raporty/nocne"})
        )

    def test_non_literal_cd_is_unknown(self):
        for command in (
            'cd "$D" && ls -R',
            "cd - && ls -R",
            "cd $(pwd) && ls",
            "cd a b && ls",
            "cd a* && ls",
            "pushd && ls",
        ):
            with self.subTest(command):
                last = parse(command)[-1]
                self.assertFalse(last.cwd_known)
                self.assertIn("/w", last.cwds)

    def test_brace_group_leaks_and_loop_bodies_repeat(self):
        self.assertEqual(self.last_dirs("{ cd a && ls; } && cat f"), frozenset({"/w/a"}))
        self.assertEqual(self.last_dirs("{ cd a; ls; } && cat f"), frozenset({"/w", "/w/a"}))
        dirs = [c.cwds for c in parse("for i in 1 2; do ls; cd d; done")]
        self.assertEqual(dirs[0], frozenset({"/w", "/w/d"}))  # the second round starts in d

    def test_substitution_and_function_directories(self):
        calls = parse("cd a && echo $(ls) && cat f")
        self.assertEqual({c.name: c.cwds for c in calls}["ls"], frozenset({"/w/a"}))
        calls = parse("f() { cat z; }; cd a && f")
        self.assertFalse(calls[0].cwd_known)  # called later, from anywhere
        self.assertIn("/w", calls[0].cwds)


class TestFailClosed(Base):
    def test_syntax_errors_raise(self):
        for command in ('echo "unterminated', "if x; then", "echo $(", "cat <<EOF\nno end", "fi", "a ||| b"):
            with self.subTest(command), self.assertRaises(shell.ParseError):
                parse(command)

    def test_unsupported_dialect_raises(self):
        # zsh-only syntax is not Bash: the parser must not guess
        for command in ("echo ${(f)x}", "echo ${(k)a}"):
            with self.subTest(command), self.assertRaises(shell.ParseError):
                parse(command)

    def test_missing_binary_and_timeout(self):
        saved = shell._shfmt_binary
        shell._shfmt_binary = lambda: (_ for _ in ()).throw(shell.ShfmtMissing("shfmt not found"))
        try:
            with self.assertRaises(shell.ShfmtMissing):
                parse("ls")
        finally:
            shell._shfmt_binary = saved
        timeout = shell.SHFMT_TIMEOUT
        shell.SHFMT_TIMEOUT = 1e-6
        try:
            with self.assertRaises(shell.ParseError):
                parse("ls")
        finally:
            shell.SHFMT_TIMEOUT = timeout
        with self.assertRaises(shell.ParseError):
            parse("echo " + "x" * (shell.MAX_BYTES + 1))

    def test_error_message_does_not_echo_the_command(self):
        with self.assertRaises(shell.ParseError) as caught:
            parse('echo "SECRET-VALUE-123')
        self.assertNotIn("SECRET-VALUE-123", str(caught.exception))

    def test_deep_nesting_is_a_parse_error_not_a_crash(self):
        """200 nested `$( )` overflow the Python stack: that must surface as ParseError (deny), not RecursionError."""
        with self.assertRaises(shell.ParseError):
            parse("echo " + "$(echo " * 200 + "x" + ")" * 200)

    def test_empty_and_comment_only(self):
        self.assertEqual(parse(""), [])
        self.assertEqual(parse("# nothing"), [])


class TestCorpus(Base):
    def test_every_command_of_the_gate_tests_parses(self):
        import shell_corpus

        cases = shell_corpus.extract()
        self.assertGreater(len(cases), 300)
        for case in cases:
            with self.subTest(command=case.command[:60], test=case.test):
                shell.parse(case.command, cwd=CWD)


if __name__ == "__main__":
    unittest.main()
