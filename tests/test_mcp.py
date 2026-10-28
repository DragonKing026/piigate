#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11,<3.15"
# dependencies = ["mcp>=2.3,<3"]
# ///
"""Tests of the piigate MCP server — on SYNTHETIC data only (fixtures.py). Run: tests/uruchom.sh

The server is started as Claude Code starts it (stdio, `uv run --script`) and called with an MCP client. Checked: no
originals in results (text and structuredContent), denial of paths outside the sensitive directories, of filter files
and symlinks. The analysis model is replaced by a fake agent command. Most tests use the container engine (Presidio at
engine.container_url); TestLocalEngine starts the server in local mode with the test-only fake analyzer
(PIIGATE_FAKE_ENGINE=1) and talks to it through the socket the way the hooks do.
"""

import asyncio
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(TESTS_DIR))

TMP = Path(tempfile.mkdtemp(prefix="piigate-mcp-"))
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "dane-filtra")
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "konfiguracja")

import fixtures as dt
from piigate import config, engines
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SENSITIVE = TMP / "sensitive"
ANONYMIZED = TMP / "anonymized"
FILES = dt.write_all(SENSITIVE / "project")
VALUES = dt.values()
CONTAINER = {"mode": "container"}  # most tests: Presidio container at the default engine.container_url
PRESIDIO = engines.presidio_health({**config.load(), "engine": {**config.load()["engine"], **CONTAINER}}, timeout_s=150)
PRESIDIO = PRESIDIO.startswith("running")
PIIGATE_SERVER = ["uv", "run", "--quiet", "--script", str(ROOT / "server.py")]


def leaks(text: str) -> list[str]:
    return [w for w in VALUES if w in text]


def fake_agent(response: dict) -> Path:
    """Fake analysis agent: saves stdin (what the model would get) and prints JSON — the "model" leaks the data."""
    script = TMP / "fake-agent"
    script.write_text(
        f"#!/usr/bin/env bash\ncat > {TMP / 'fake-agent-input.txt'}\ncat <<'END'\n"
        f"{json.dumps(response, ensure_ascii=False)}\nEND\n",
        encoding="utf-8",
    )
    script.chmod(0o700)
    return script


def configure() -> None:
    p = dt.PATIENTS
    agent = fake_agent(
        {
            "sensitive_data": [{"category": "PESEL", "where": f"mail od {p[2]['surname']}", "count": 2}],
            "columns_to_mask": [],
            "fragments_to_mask": [{"text": p[1]["surname"], "type": "PERSON"}],
            "summary": f"Pani {p[0]['first_name']} {p[0]['surname']}, PESEL {p[0]['pesel']}, tel. {p[2]['phone']}.",
            "answer": f"Dotyczy {p[1]['first_name']} {p[1]['surname']} — 2 recepty.",
        }
    )
    folder = Path(os.environ["PIIGATE_CONFIG_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.json").write_text(
        json.dumps(
            {
                "engine": CONTAINER,
                "sources": {"directories": [str(SENSITIVE)]},
                "analysis": {"agent_command": [str(agent)]},
                "anonymization": {
                    "directory": str(ANONYMIZED),
                    "mail_mcp": ["python3", "-I", str(TESTS_DIR / "fake_mail_mcp.py")],
                },
            }
        ),
        encoding="utf-8",
    )


async def _session(server: list[str], calls: list[tuple[str, dict]], env: dict | None = None) -> list:
    # outside any repo and session dir — otherwise copies would go to <project>/Anonymized-data
    env_vars = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
    params = StdioServerParameters(
        command=server[0], args=server[1:], env={**env_vars, **(env or {})}, cwd=str(TMP)
    )
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        results = [await s.list_tools()]
        for name, arguments in calls:
            results.append(await s.call_tool(name, arguments))
        return results


def session(server: list[str], calls: list[tuple[str, dict]], env: dict | None = None) -> list:
    return asyncio.run(_session(server, calls, env))


def text(result) -> str:
    return "".join(c.text for c in result.content if getattr(c, "type", "") == "text")


def whole(result) -> str:
    return text(result) + json.dumps(result.structured_content or {}, ensure_ascii=False)


class TestPiigateServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configure()

    def test_tools(self):
        (file_list,) = session(PIIGATE_SERVER, [])
        names = {t.name for t in file_list.tools}
        self.assertEqual(names, {"piigate_analyze", "piigate_anonymize", "piigate_show", "piigate_list", "piigate_search"})

    @unittest.skipUnless(PRESIDIO, "the Presidio container is not reachable")
    def test_no_originals_in_result(self):
        _, file_list, show, show_number, anon, analysis, mail_query = session(
            PIIGATE_SERVER,
            [
                ("piigate_list", {"directory": str(SENSITIVE / "project")}),
                ("piigate_show", {"path": str(FILES["xlsx"])}),
                ("piigate_show", {"path": str(SENSITIVE / "project"), "number": 1}),
                ("piigate_anonymize", {"path": str(FILES["csv"]), "mask_columns": ["Lek"]}),
                ("piigate_analyze", {"path": str(FILES["eml"]), "question": "Kogo dotyczy?"}),
                ("piigate_analyze", {"mail_query": "Recepty", "question": "Czego chce nadawca?"}),
            ],
        )
        for name, w in [("list", file_list), ("show", show), ("show number", show_number), ("anonymize", anon),
                         ("analyze", analysis), ("mail_query", mail_query)]:
            with self.subTest(name):
                self.assertFalse(w.is_error, text(w))
                self.assertEqual(leaks(whole(w)), [])
        d = analysis.structured_content
        self.assertIn("## Summary", text(analysis))
        self.assertEqual(d["model"]["sensitive_data"][0]["count"], 2)
        self.assertIsInstance(d["time_s"], float)
        self.assertTrue(d["copies"]["files"])
        for p in Path(d["copies"]["directory"]).iterdir():  # copies on disk carry no originals either
            self.assertEqual(leaks(p.name + p.read_text(encoding="utf-8")), [], p.name)
        self.assertTrue(Path(anon.structured_content["directory"]).is_relative_to(ANONYMIZED))
        # the model got the original (through the agent's stdin), the caller did not
        self.assertIn(dt.PATIENTS[0]["pesel"], (TMP / "fake-agent-input.txt").read_text(encoding="utf-8"))

    def test_path_denials(self):
        regular_file = TMP / "zwykly.txt"
        regular_file.write_text("x")
        secret = TMP / "key"
        secret.write_text("tajne")
        symlink = SENSITIVE / "dowiazanie.csv"
        symlink.unlink(missing_ok=True)
        symlink.symlink_to(secret)
        pseudonym_map = Path(os.environ["PIIGATE_DATA_DIR"]) / "map.sqlite"
        cfg = Path(os.environ["PIIGATE_CONFIG_DIR"]) / "config.json"
        cases = [
            ("piigate_show", {"path": str(regular_file)}),
            ("piigate_show", {"path": "projekt/recepty.csv"}),
            ("piigate_show", {"path": str(symlink)}),
            ("piigate_show", {"path": str(cfg)}),
            ("piigate_show", {"path": str(pseudonym_map)}),
            ("piigate_list", {"directory": str(TMP)}),
            ("piigate_anonymize", {"path": str(FILES["csv"]), "output_dir": str(TMP / "gdziekolwiek")}),
            ("piigate_analyze", {"path": str(FILES["csv"]), "mail_query": "Recepty"}),
            ("piigate_analyze", {}),
            ("piigate_analyze", {"path": "/etc/passwd"}),
        ]
        results = session(PIIGATE_SERVER, cases)[1:]
        for (name, arguments), w in zip(cases, results):
            with self.subTest(name=name, arguments=arguments):
                self.assertTrue(w.is_error)
                self.assertIn("[piigate] denied", text(w))
                self.assertNotIn("tajne", whole(w))
        self.assertFalse((TMP / "gdziekolwiek").exists())

    @unittest.skipUnless(PRESIDIO, "the Presidio container is not reachable")
    def test_search(self):
        """Pattern = a surname from the data — the result (text and structuredContent) has neither the surname nor other
        values; a symlink to a file outside the directory and the filter's directory — no content."""
        secret = TMP / "klucz-210"
        secret.write_text("tajne 210")
        symlink = SENSITIVE / "dowiazanie-210.txt"
        symlink.unlink(missing_ok=True)
        symlink.symlink_to(secret)
        surname = dt.PATIENTS[1]["surname"]
        _, w, in_secret, in_protected = session(
            PIIGATE_SERVER,
            [
                ("piigate_search", {"pattern": surname, "path": str(SENSITIVE), "context": 1}),
                ("piigate_search", {"pattern": "tajne", "path": str(SENSITIVE)}),
                ("piigate_search", {"pattern": "x", "path": os.environ["PIIGATE_DATA_DIR"]}),
            ],
        )
        self.assertFalse(w.is_error, text(w))
        self.assertEqual(leaks(whole(w)), [])
        self.assertNotIn(surname, whole(w))
        self.assertTrue(w.structured_content["tables"])
        self.assertTrue(w.structured_content["text"])
        self.assertFalse(in_secret.is_error, text(in_secret))
        self.assertNotIn("tajne 210", whole(in_secret))
        self.assertTrue(in_protected.is_error)
        self.assertIn("[piigate] denied", text(in_protected))


HOOK_SIDE = """
import json, sys
sys.path.insert(0, sys.argv[1])
from piigate import FilterError, config, engines
cfg = config.load()
text = sys.argv[2]
try:
    found = [[text[f.start:f.end], f.type_] for f in engines.presidio(text, cfg)]
    print(json.dumps({"found": found, "health": engines.presidio_health(cfg)}))
except FilterError as e:
    print(json.dumps({"error": str(e), "health": engines.presidio_health(cfg)}))
"""


def hook_side(env: dict, text: str) -> dict:
    """engines.presidio as the hooks run it: plain python3 -I, standard library only."""
    r = subprocess.run(
        ["python3", "-I", "-c", HOOK_SIDE, str(ROOT / "lib"), text],
        capture_output=True, text=True, env={**os.environ, **env}, timeout=60, check=False,
    )
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


class TestLocalEngine(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="pgm-"))  # short: Unix socket paths are limited to ~107 bytes
        self.sock = self.dir / "engine.sock"
        config_dir = TMP / "config-local"
        config_dir.mkdir(exist_ok=True)
        (config_dir / "config.json").write_text(
            json.dumps({"engine": {"mode": "local"}, "sources": {"directories": [str(SENSITIVE)]}}), encoding="utf-8"
        )
        self.env = {"PIIGATE_SOCKET": str(self.sock), "PIIGATE_CONFIG_DIR": str(config_dir)}
        self.note = SENSITIVE / "local" / "note.txt"
        self.note.parent.mkdir(parents=True, exist_ok=True)
        p = dt.PATIENTS[0]
        self.note.write_text(f"Notatka: Xavor Qwertyński dzwonił, PESEL {p['pesel']}.\n", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_hooks_use_the_server_engine(self):
        sentence = "Wizyta: Xavor Qwertyński, gabinet 4."
        self.assertIn("local engine not running", hook_side(self.env, sentence)["error"])

        async def scenario():
            env_vars = {k: v for k, v in os.environ.items() if k != "CLAUDE_PROJECT_DIR"}
            params = StdioServerParameters(
                command=PIIGATE_SERVER[0], args=PIIGATE_SERVER[1:], cwd=str(TMP),
                env={**env_vars, **self.env, "PIIGATE_FAKE_ENGINE": "1"},
            )
            async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
                await s.initialize()
                self.assertTrue(self.sock.exists(), "the server did not bind the socket")
                self.assertEqual(stat.S_IMODE(self.sock.stat().st_mode), 0o600)
                hook = await asyncio.to_thread(hook_side, self.env, sentence)
                show = await s.call_tool("piigate_show", {"path": str(self.note)})
                return hook, show

        hook, show = asyncio.run(scenario())
        self.assertNotIn("error", hook, hook)
        self.assertIn(["Xavor Qwertyński", "PERSON"], hook["found"])
        self.assertTrue(hook["health"].startswith("running (local engine: loaded (fake engine"), hook["health"])
        self.assertFalse(show.is_error, text(show))
        self.assertNotIn("Qwertyński", whole(show))
        self.assertEqual(leaks(whole(show)), [])
        self.assertIn("PERSON_", text(show))
        # the server closed the host on exit: deny again
        self.assertFalse(self.sock.exists())
        self.assertIn("local engine not running", hook_side(self.env, sentence)["error"])


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
