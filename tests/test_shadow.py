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

    def wait_child(self, pid, limit):
        """Seconds until the child is gone (killed and failed after `limit`)."""
        start = time.monotonic()
        while time.monotonic() - start < limit:
            done, _ = os.waitpid(pid, os.WNOHANG)
            if done:
                return time.monotonic() - start
            time.sleep(0.005)
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        self.fail(f"the child outlived {limit} s")

    def test_budget_measurement(self):
        """Informational numbers; the only assertions are hard limits with a wide margin (no flakiness under load)."""
        returns, lives = [], []
        for _ in range(15):
            start = time.monotonic()
            pid = shadow.observe(self.cfg, self.cwd, "cat notes.md", None)
            returns.append((time.monotonic() - start) * 1000)
            self.wait_child(pid, shadow.BUDGET_S + 5)
            lives.append((time.monotonic() - start) * 1000)
        print(
            f"\nshadow: hook waits median {statistics.median(returns):.1f} ms, max {max(returns):.1f} ms; "
            f"the child lives median {statistics.median(lives):.1f} ms, max {max(lives):.1f} ms "
            f"(budget {shadow.BUDGET_S} s, shfmt inside the shadow {shadow.SHFMT_TIMEOUT_S} s)"
        )
        self.assertLess(max(returns), 1000)  # the parent never waits for the child (a second is 1000x the usual)

    def hold_lock(self):
        """Another process holds the lock file."""
        import subprocess

        Path(shadow.path()).parent.mkdir(parents=True, exist_ok=True)
        code = ("import fcntl,os,sys,time\nfd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600)\n"
                "fcntl.flock(fd,fcntl.LOCK_EX)\nprint('held',flush=True)\ntime.sleep(60)\n")
        proc = subprocess.Popen([sys.executable, "-I", "-c", code, shadow.path() + ".lock"], stdout=subprocess.PIPE, text=True)
        self.addCleanup(proc.stdout.close)
        self.addCleanup(proc.wait)  # cleanups run last-in first-out: the kill comes before the wait
        self.addCleanup(proc.kill)
        self.assertEqual(proc.stdout.readline().strip(), "held")
        return proc

    def test_a_lock_held_elsewhere_never_stalls_the_children(self):
        self.hold_lock()
        for _ in range(5):  # one after another: none waits for the others
            start = time.monotonic()
            pid = shadow.observe(self.cfg, self.cwd, "ls", None)
            self.assertLess(time.monotonic() - start, 0.25)
            self.wait_child(pid, shadow.BUDGET_S + 1)
        self.assertEqual(shadow.read()["days"], {})  # nothing was written: a lost count is acceptable

    def test_the_alarm_inside_the_update_does_not_deadlock(self):
        """SIGALRM arrives while the child holds the lock: the handler must not take the lock again."""
        def slow(*a, **k):
            return shadow._update(lambda d: time.sleep(30))

        with mock.patch.object(shadow, "judge", slow):
            pid = shadow.observe(self.cfg, self.cwd, "ls", None)
            took = self.wait_child(pid, shadow.BUDGET_S + 1)
        self.assertGreaterEqual(took, shadow.BUDGET_S * 0.8)
        self.watch("ls")  # the lock went with the child: the next one writes
        self.assertEqual(self.counts().get("same-allow"), 1)

    def test_the_child_cannot_dump_core(self):
        out = TMP / "child-limits"
        out.unlink(missing_ok=True)

        def probe(*a, **k):
            import ctypes
            import resource

            dumpable = ctypes.CDLL(None).prctl(3, 0, 0, 0, 0)  # PR_GET_DUMPABLE
            out.write_text(json.dumps([list(resource.getrlimit(resource.RLIMIT_CORE)), dumpable,
                                       os.fstat(1).st_rdev == os.stat(os.devnull).st_rdev,
                                       os.fstat(2).st_rdev == os.stat(os.devnull).st_rdev, resource.getrlimit(resource.RLIMIT_CPU)[1]]))
            return "same-allow", 0.0, None, None, None

        with mock.patch.object(shadow, "judge", probe):
            self.watch("ls")
        core, dumpable, out_null, err_null, cpu = json.loads(out.read_text())
        self.assertEqual(core, [0, 0])
        self.assertEqual(dumpable, 0)
        self.assertTrue(out_null and err_null)  # stdout/stderr of the hook's pipe are closed for the child
        self.assertLessEqual(cpu, 3)

    def test_no_process_slot_means_no_shadow_and_no_delay(self):
        import subprocess

        code = ("import resource,sys,time\nsys.path.insert(0,sys.argv[1])\nfrom piigate import shadow\n"
                "resource.setrlimit(resource.RLIMIT_NPROC,(1,1))\nt=time.monotonic()\n"
                "print(shadow.observe({'shell_shadow':True},'/tmp','ls',None), time.monotonic()-t<0.25)\n")
        done = subprocess.run([sys.executable, "-I", "-c", code, str(ROOT / "lib")], capture_output=True, text=True,
                              env={"PIIGATE_DATA_DIR": str(TMP / "data"), "PIIGATE_CONFIG_DIR": str(TMP / "config")}, check=False,
                              timeout=30)
        self.assertEqual(done.stdout.strip(), "None True", done.stderr)

    def test_a_valid_json_with_the_wrong_types_starts_again(self):
        Path(shadow.path()).parent.mkdir(parents=True, exist_ok=True)
        for bad in ('{"days":{"2026-11-04":5}}', '{"days":[1]}', '[1,2]', '{"days":{"x":{"same-allow":"7"}}}',
                    '{"days":{"2026-11-04":{"same-allow":3,"secret":9,"causes":{"rm -rf":1,"other":2},"ms":"a","reasons":7}}}'):
            Path(shadow.path()).write_text(bad, encoding="utf-8")
            data = shadow.read()
            self.assertEqual(set(data), {"version", "days"})
            self.assertIn("shadow:", shadow.report())
            self.watch("ls")
            for day in shadow.read()["days"].values():
                self.assertLessEqual(set(day), SCHEMA_DAY_KEYS)
                self.assertLessEqual(set(day["causes"]), set(shadow.CAUSES))
            raw = Path(shadow.path()).read_text(encoding="utf-8")
            self.assertNotIn("secret", raw)
            self.assertNotIn("rm -rf", raw)
            Path(shadow.path()).unlink()

    def test_a_symlink_as_the_lock_is_not_followed(self):
        folder = Path(shadow.path()).parent
        folder.mkdir(parents=True, exist_ok=True)
        victim = TMP / "victim"
        victim.write_text("keep", encoding="utf-8")
        (folder / (shadow.FILE + ".lock")).symlink_to(victim)
        with self.assertRaises(OSError):
            shadow._update(lambda d: None)
        self.watch("ls")  # the child fails quietly
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep")
        self.assertFalse(Path(shadow.path()).exists())

    def test_the_directory_is_private_and_a_failed_write_leaves_nothing(self):
        shadow._update(lambda d: None)
        self.assertEqual(Path(shadow.path()).parent.stat().st_mode & 0o777, 0o700)
        with mock.patch.object(json, "dump", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                shadow._update(lambda d: None)
        self.assertEqual(sorted(p.name for p in Path(shadow.path()).parent.iterdir()), [shadow.FILE, shadow.FILE + ".lock"])

    def test_memfd_asks_for_exec_and_falls_back_on_einval(self):
        calls = []
        real = os.memfd_create

        def fake(name, flags=0):
            calls.append(flags)
            if flags & 0x10:
                raise OSError(22, "EINVAL")
            return real(name, flags)

        with mock.patch.object(os, "memfd_create", fake):
            os.close(shell._sealed_memfd(b"x"))
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[0] & 0x10 and not calls[1] & 0x10)

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
