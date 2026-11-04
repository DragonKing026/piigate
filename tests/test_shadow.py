"""Tests of the shadow mode (lib/piigate/shadow.py). Run: python3 -I tests/test_shadow.py

The old gate decides; the shadow only counts — in a forked child, with a hard time budget, and WITHOUT any content of the
command. Everything here is synthetic."""

import json
import os
import statistics
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(TESTS_DIR))

TMP = Path(tempfile.mkdtemp(prefix="piigate-shadow-"))
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "config")
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "data")

import hook as hook_module  # noqa: E402
from piigate import config, gate, shadow, shell  # noqa: E402

try:
    shell._shfmt_binary()
    AVAILABLE = True
except shell.ParseError:
    AVAILABLE = False

SCHEMA_DAY_KEYS = set(shadow.CATEGORIES) | {"causes", "reasons", "ms"}


@unittest.skipUnless(AVAILABLE, "no pinned shfmt for this platform")
class TestShadow(unittest.TestCase):
    def setUp(self):
        import shutil

        shutil.rmtree(TMP / "data", ignore_errors=True)
        self.root = TMP / "world"
        shutil.rmtree(self.root, ignore_errors=True)
        (self.root / "work").mkdir(parents=True)
        (self.root / "Sensitive-data").mkdir()
        (self.root / "Sensitive-data" / "people.csv").write_text("dummy\n", encoding="utf-8")
        (self.root / "work" / "notes.md").write_text("x\n", encoding="utf-8")
        self.cfg = config.load(str(self.root / "work"))
        self.cfg["sources"]["directories"] = [str(self.root / "Sensitive-data")]
        self.cfg["sources"]["only_phi_projects"] = False
        self.cfg["in_project"] = {"sensitive": [], "anonymized": []}
        self.cfg["shell_shadow"] = True
        self.cwd = str(self.root / "work")
        patcher = mock.patch.dict(os.environ, {"SHELL": "/usr/bin/zsh"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def old(self, command: str):
        return gate.Gate(self.cfg, self.cwd).bash(command)

    def watch(self, command: str) -> None:
        shadow.observe(self.cfg, self.cwd, command, self.old(command), wait=True)

    def counts(self) -> dict:
        total: dict = {}
        for day in shadow.read()["days"].values():
            for k, v in day.items():
                if isinstance(v, int):
                    total[k] = total.get(k, 0) + v
        return total

    def test_off_by_default(self):
        self.assertFalse(config.load()["shell_shadow"])
        cfg = dict(self.cfg, shell_shadow=False)
        self.assertIsNone(shadow.observe(cfg, self.cwd, "ls", None, wait=True))
        self.assertFalse(Path(shadow.path()).exists())

    def test_categories_and_causes(self):
        for command in ("ls", "cat notes.md", "cat ../Sensitive-data/people.csv", 'echo "unterminated',
                        "(cd ../Sensitive-data); cat people.csv", "cat '>' notes.md"):
            self.watch(command)
        c = self.counts()
        self.assertGreaterEqual(c["same-allow"], 2)
        self.assertEqual(c["same-deny"], 1)
        self.assertEqual(c["parse-error"], 1)
        self.assertEqual(c["old-deny-new-allow"], 1)
        day = next(iter(shadow.read()["days"].values()))
        self.assertEqual(day["causes"], {"subshell-cd": 1})

    def test_the_file_holds_numbers_only(self):
        """A command with a (synthetic) PESEL and a surname: not one fragment of it in the file; the keys are fixed."""
        pesel, surname = "44051401458", "Zmyslowska"
        for command in (f"cat ../Sensitive-data/{surname}-{pesel}.csv", f"echo {surname} {pesel} > notes.md", f"grep {pesel} notes.md",
                        f"(cd ../Sensitive-data); cat {surname}.csv"):
            self.watch(command)
        raw = Path(shadow.path()).read_text(encoding="utf-8")
        for fragment in (pesel, surname, "Sensitive", "notes", self.root.name, "cat ", "echo"):
            self.assertNotIn(fragment, raw)
        data = json.loads(raw)
        self.assertEqual(set(data), {"version", "days"})
        for day in data["days"].values():
            self.assertLessEqual(set(day), SCHEMA_DAY_KEYS)
            self.assertLessEqual(set(day["causes"]), set(shadow.CAUSES))
            self.assertLessEqual(set(day["ms"]), set(shadow.MS_BUCKETS))
            for group in day["reasons"].values():
                self.assertLessEqual(set(group), set(shadow.REASON_LABELS))
            self.assertTrue(all(isinstance(v, int) for k, v in day.items() if k in shadow.CATEGORIES))
        self.assertEqual(Path(shadow.path()).stat().st_mode & 0o777, 0o600)
        self.assertEqual((Path(shadow.path() + ".lock")).stat().st_mode & 0o777, 0o600)
        self.assertLess(Path(shadow.path()).stat().st_size, 10_000)

    def test_the_decision_is_the_old_gates_whatever_the_shadow_does(self):
        data = {"hook_event_name": "PreToolUse", "cwd": self.cwd, "tool_name": "Bash",
                "tool_input": {"command": "cat ../Sensitive-data/people.csv"}}
        env = {"PIIGATE_CONFIG_DIR": str(TMP / "cfgshadow")}
        (TMP / "cfgshadow").mkdir(exist_ok=True)
        (TMP / "cfgshadow" / "config.json").write_text(json.dumps({"shell_shadow": True}), encoding="utf-8")
        with mock.patch.dict(os.environ, env):
            plain = hook_module.gate(data)
            self.assertIsNotNone(plain)
            with mock.patch.object(shadow, "judge", side_effect=RuntimeError("boom")):
                self.assertEqual(hook_module.gate(data), plain)
            with mock.patch.dict(sys.modules, {"piigate.shadow": None}):  # an import error
                self.assertEqual(hook_module.gate(data), plain)
            with mock.patch.object(shadow, "observe", side_effect=SystemExit(1)):
                self.assertEqual(hook_module.gate(data), plain)
            allowed = dict(data, tool_input={"command": "ls"})
            self.assertIsNone(hook_module.gate(allowed))
            with mock.patch.object(shadow, "observe", side_effect=KeyboardInterrupt()):
                self.assertIsNone(hook_module.gate(allowed))

    def test_a_failure_of_the_shadow_is_only_counted(self):
        with mock.patch.object(shadow, "judge", side_effect=RuntimeError("boom")):
            self.watch("ls")
        self.assertEqual(self.counts().get("shadow-error"), 1)

    def test_a_hung_shfmt_never_delays_the_hook_and_is_counted(self):
        def hang(*a, **k):
            time.sleep(60)

        with mock.patch.object(shell, "_run_shfmt", hang):
            start = time.monotonic()
            pid = shadow.observe(self.cfg, self.cwd, "ls", None)
            returned = time.monotonic() - start
            self.assertLess(returned, 0.25)  # the hook does not wait for the child
            deadline = time.monotonic() + shadow.BUDGET_S + 2
            while time.monotonic() < deadline:
                done, _ = os.waitpid(pid, os.WNOHANG) if pid else (1, 0)
                if done:
                    break
                time.sleep(0.01)
            else:
                os.kill(pid, 9)
                self.fail("the child outlived its budget")
        self.assertEqual(self.counts().get("shadow-timeout"), 1)

    def test_budget_measurement(self):
        returns, lives = [], []
        for _ in range(15):
            start = time.monotonic()
            pid = shadow.observe(self.cfg, self.cwd, "cat notes.md", None)
            returns.append((time.monotonic() - start) * 1000)
            while True:
                done, _ = os.waitpid(pid, os.WNOHANG)
                if done:
                    break
                time.sleep(0.002)
            lives.append((time.monotonic() - start) * 1000)
        print(
            f"\nshadow: hook waits median {statistics.median(returns):.1f} ms, p95 {sorted(returns)[int(len(returns) * .95) - 1]:.1f} ms; "
            f"the child lives median {statistics.median(lives):.1f} ms, p95 {sorted(lives)[int(len(lives) * .95) - 1]:.1f} ms "
            f"(budget {shadow.BUDGET_S} s, shfmt inside the shadow {shadow.SHFMT_TIMEOUT_S} s)"
        )
        self.assertLess(statistics.median(returns), 100)
        self.assertLess(max(lives), (shadow.BUDGET_S + 1) * 1000)

    def test_the_counts_are_protected_from_the_agent(self):
        g = gate.Gate(self.cfg, self.cwd)
        self.watch("ls")
        for command in (f"cat {shadow.path()}", f"cp {shadow.path()} /tmp/x", f"echo '{{}}' > {shadow.path()}", f"rm {shadow.path()}",
                        "python3 -c \"print(open('/home/u/.local/share/piigate/shell-shadow.json').read())\"",
                        "cat ~/.local/share/piigate/shell-shadow.json"):  # the default location, found by its marker (like the map)
            with self.subTest(command):
                self.assertIsNotNone(g.bash(command))

    def test_the_human_commands(self):
        g = gate.Gate(self.cfg, self.cwd)
        self.assertIsNone(g.bash("piigate shadow"))  # counts only: the agent may read them
        for command in ("piigate shadow-reset", "piigate shadow-on", "piigate shadow-off", "p=piigate; $p shadow-reset",
                        "bash -c 'piigate shadow-on'", "piigate shadow-off 2>&1 | cat"):
            with self.subTest(command):
                self.assertIsNotNone(g.bash(command))
        import subprocess

        done = subprocess.run([sys.executable, "-I", str(ROOT / "lib" / "cli.py"), "shadow-reset"], capture_output=True, text=True,
                              env={**os.environ, "CLAUDECODE": "1"}, check=False)
        self.assertEqual(done.returncode, 4)
        self.assertIn("denied", done.stderr)

    def test_old_days_are_dropped(self):
        shadow._update(lambda d: d["days"].update({f"2000-01-{i:02d}": shadow._empty_day() for i in range(1, 29)}))
        shadow._update(lambda d: d["days"].update({f"2001-{m:02d}-{i:02d}": shadow._empty_day() for m in range(1, 5) for i in range(1, 28)}))
        self.watch("ls")
        self.assertLessEqual(len(shadow.read()["days"]), shadow.KEEP_DAYS)

    def test_a_corrupt_file_starts_again(self):
        Path(shadow.path()).parent.mkdir(parents=True, exist_ok=True)
        Path(shadow.path()).write_text("{not json", encoding="utf-8")
        self.watch("ls")
        self.assertEqual(self.counts().get("same-allow"), 1)


if __name__ == "__main__":
    unittest.main()
