"""piigate tests — on SYNTHETIC data only (fixtures.py). Run: tests/run.sh

They check: no substituted value in any output (files, MCP mail, SQL results), the gate (Read/Grep/Glob/Bash),
deny by default (Presidio down, Python crash, bad configuration, a cloud Ollama model) and reversing pseudonyms.
Inputs are mostly Polish on purpose — the filter detects Polish personal data.
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(TESTS_DIR))

TMP = Path(tempfile.mkdtemp(prefix="piigate-test-"))
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "filter-data")
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "config")
# fixed documents directory: the global sensitive directory is ~/Documents/piigate/Sensitive-data on every machine
os.environ["XDG_DOCUMENTS_DIR"] = str(Path.home() / "Documents")
SENSITIVE_HOME = "~/Documents/piigate/Sensitive-data"

# NER engine for the tests: the Presidio container (PIIGATE_PRESIDIO_URL); the local engine lives in the MCP server
PRESIDIO_URL = os.environ.get("PIIGATE_PRESIDIO_URL", "http://127.0.0.1:8719")
BASE_USER_CONFIG = {"engine": {"mode": "container", "container_url": PRESIDIO_URL}}


def engine_down(url: str = "http://127.0.0.1:9", timeout_s: float = 2) -> dict:
    """User configuration with an engine that does not answer (or is not on a loopback address)."""
    return {"engine": {"mode": "container", "container_url": url, "timeout_s": timeout_s}}


def set_config(changes: dict | None) -> None:
    """The test user configuration: BASE_USER_CONFIG merged with `changes` (None — only the base)."""
    folder = Path(os.environ["PIIGATE_CONFIG_DIR"])
    folder.mkdir(parents=True, exist_ok=True)
    merged = json.loads(json.dumps(BASE_USER_CONFIG))
    for k, v in (changes or {}).items():
        merged[k] = {**merged[k], **v} if isinstance(v, dict) and isinstance(merged.get(k), dict) else v
    (folder / "config.json").write_text(json.dumps(merged), encoding="utf-8")


set_config(None)
import fixtures as dt
from piigate import FilterError, analysis, anonymization, gate, config, files, table, text, verdict, engines
from piigate.pseudonym_map import PseudonymMap

FILES = dt.write_all(TMP / "sources")
VALUES = dt.values()
HOOK = ROOT / "hooks" / "run.sh"
CONFIG = config.load()
STRICT = json.loads(json.dumps(CONFIG))  # strict mode: content is checked also in repositories not marked as PHI
STRICT["sources"]["only_phi_projects"] = False
# a configured unfiltered tool (a local LLM subagent wrapper — its output bypasses the filter), Bash and MCP forms
LOCAL_AGENT = {
    "name": "local-agent",
    "commands": ["local-agent"],
    "mcp_tools": "^mcp__.*local-agent.*__",
    "dir_option": "--dir",
    "dir_param": "dir",
    "deny_options": {"--profile": ["phi"]},
}
LOCAL_AGENT_MCP = "mcp__plugin_local_local-agent__local_agent"
PRESIDIO_HEALTH = engines.presidio_health(CONFIG, timeout_s=150)
PRESIDIO = PRESIDIO_HEALTH.startswith("running")
PRESIDIO_SKIP = f"Presidio is not reachable at {PRESIDIO_URL} ({PRESIDIO_HEALTH})"


def encoded_forms(value: str) -> set[str]:
    """A value as it can appear inside raw mail or a URL: quoted-printable, base64 (UTF-8), percent-encoding."""
    import base64
    import quopri
    import urllib.parse

    raw = value.encode("utf-8")
    forms = {value, urllib.parse.quote(value)}
    forms.add(quopri.encodestring(raw).decode("ascii").replace("=\n", ""))
    if len(raw) >= 6:  # shorter base64 runs are too likely to occur by chance
        forms.add(base64.b64encode(raw).decode("ascii").rstrip("="))
    return forms


def leaks(text: str) -> list[str]:
    """Values found in the text — also in encoded form (a model decodes quoted-printable or base64 easily)."""
    return [w for w in VALUES if any(f in text for f in encoded_forms(w))]


def hook(mode: str, data: dict, env: dict | None = None) -> dict | None:
    result = subprocess.run(
        [str(HOOK), mode],
        input=json.dumps(data),
        capture_output=True,
        text=True,
        timeout=200,
        env={**os.environ, **(env or {})},
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout) if result.stdout.strip() else None


def mcp_mail(mail_text: str) -> dict:
    return {
        "hook_event_name": "PostToolUse",
        "cwd": str(TMP),
        "tool_name": "mcp__plugin_thunderbird-mcp_thunderbird-mail__getMessage",
        "tool_input": {"messageId": "1"},
        "tool_response": [
            {
                "type": "text",
                "text": json.dumps(
                    {
                        "from": f"{dt.PATIENTS[2]['first_name']} {dt.PATIENTS[2]['surname']} <{dt.PATIENTS[2]['email']}>",
                        "subject": f"Recepty {dt.PATIENTS[0]['surname']}",
                        "body": mail_text,
                        "attachments": [{"name": f"Recepty_{dt.PATIENTS[3]['surname']}.xlsx", "size": 2730}],
                    },
                    ensure_ascii=False,
                ),
            }
        ],
    }


class TestTables(unittest.TestCase):
    """Tabular data: structure and masks only — no Presidio (no detection)."""

    def test_csv_and_xlsx_without_values(self):
        for kind in ("csv", "xlsx"):
            with self.subTest(kind):
                result = files.describe_file(FILES[kind], CONFIG, source="files", rows=10)
                self.assertEqual(leaks(result), [])
                self.assertIn("data rows: 4", result)
                self.assertIn("PESEL", result)  # column type (from the header and the checksum)

    def test_xlsx_column_types(self):
        result = files.describe_file(FILES["xlsx"], CONFIG, source="files")
        self.assertRegex(result, r"\| Data urodzenia \| date \|")
        self.assertRegex(result, r"\| Telefon \| phone \|")

    def test_deterministic_masks(self):
        a = files.describe_file(FILES["csv"], CONFIG, source="files", rows=4)
        b = files.describe_file(FILES["csv"], CONFIG, source="files", rows=4)
        self.assertEqual(a, b)

    def test_sql_results(self):
        for name, content in (("symfony", dt.sql_symfony()), ("var_dump", dt.sql_var_dump()), ("psql", dt.sql_psql())):
            with self.subTest(name):
                tables = table.from_text(content)
                self.assertGreaterEqual(len(tables[0].rows), 4)
                result = table.describe(tables, CONFIG, source="SQL result", sample_rows=4)
                self.assertEqual(leaks(result), [])

    def test_command_output_safe_values(self):
        for name, content in (("symfony", dt.sql_symfony()), ("var_dump", dt.sql_var_dump()), ("psql", dt.sql_psql())):
            with self.subTest(name):
                result = table.describe(table.from_text(content), CONFIG, source="SQL result", safe_plain=True)
                self.assertEqual(leaks(result), [])
        p = dt.PATIENTS[0]
        content = (
            " ---- ---------------- --------------------- ------------ ---------- \n"
            "  id   status           created_at            birth_date   code      \n"
            " ---- ---------------- --------------------- ------------ ---------- \n"
            f"  7    refill_pending   2026-10-01 10:00:00   {p['born'] if 'urodzony' in p else '1980-02-03'}   RX_SENT   \n"
            f"  8    {p['first_name'].lower()}   2026-10-02 11:00:00   1975-05-06   {p['surname'].lower()}  \n"
            " ---- ---------------- --------------------- ------------ ---------- \n"
        )
        result = table.describe(table.from_text(content), CONFIG, source="SQL result", safe_plain=True)
        self.assertIn("| 7 | refill_pending | 2026-10-01 10:00:00 | d:", result)
        self.assertIn("RX_SENT", result)
        self.assertNotIn(p["first_name"].lower(), result)
        self.assertNotIn(p["surname"].lower(), result)
        self.assertNotIn("1975-05-06", result)
        self.assertTrue(table.is_personal_column("first_name") and table.is_personal_column("patientEmail"))
        self.assertFalse(table.is_personal_column("patient_id") or table.is_personal_column("prescription_item"))

    def test_schema_query_result(self):
        p = dt.PATIENTS[0]
        content = (
            " ------------- --------------- \n  column_name   column_type    \n ------------- --------------- \n"
            "  option_id     int unsigned   \n  updated_at    datetime       \n"
            f"  {p['surname']}   varchar(255)   \n  x             {p['email']}   \n ------------- --------------- \n"
        )
        result = table.describe(table.from_text(content), CONFIG, source="SQL result")
        self.assertIn("| option_id | int unsigned |", result)
        self.assertIn("| updated_at | datetime |", result)
        self.assertEqual(leaks(result), [])
        # an ordinary table with a "type" column is not a schema
        plain_table = " ------ ------ \n  name   type  \n ------ ------ \n  Jan    a     \n ------ ------ \n"
        self.assertIn("structure only", table.describe(table.from_text(plain_table), CONFIG, source="x"))
        self.assertNotIn("schema query result", table.describe(table.from_text(plain_table), CONFIG, source="x"))

    def test_unrecognized_output_is_denial(self):
        with self.assertRaises(FilterError):
            table.from_text(f"Pacjent {dt.PATIENTS[0]['first_name']} {dt.PATIENTS[0]['surname']} ma dług\n")
        # two lines of prose are not a one-column result (the "header" is not a column name)
        for content in (
            f"{dt.PATIENTS[0]['first_name']} {dt.PATIENTS[0]['surname']}\nma dług\n",
            "ERROR 1045 (28000): Access denied\nmysql: [Warning] Using a password\n",
        ):
            with self.subTest(content), self.assertRaises(FilterError):
                table.from_text(content)

    def test_single_column_results(self):
        """issue #9: SELECT COUNT(*), SELECT id … — one column in every supported layout."""
        for name, content in (
            ("symfony", " ------- \n  count  \n ------- \n  42     \n ------- \n"),
            ("mysql", "+-------+\n| count |\n+-------+\n|    42 |\n+-------+\n1 row in set (0.00 sec)\n"),
            ("psql", " count \n-------\n    42\n(1 row)\n"),
            ("mysql -B", "count\n42\n"),
            ("mysql -B COUNT(*)", "COUNT(*)\n42\n"),
        ):
            with self.subTest(name):
                tables = table.from_text(content)
                self.assertEqual(len(tables[0].rows), 1)
                result = table.describe(tables, CONFIG, source="SQL result", safe_plain=True)
                self.assertIn("columns: 1", result)
                self.assertRegex(result, r"\| 42 \|")
        # a one-column text result is masked like any other column
        names = [p["first_name"] for p in dt.PATIENTS[:3]]
        for name, content in (
            ("mysql", "+------------+\n| first_name |\n+------------+\n" + "".join(f"| {n} |\n" for n in names) + "+------------+\n"),
            ("psql", " first_name \n------------\n" + "".join(f" {n}\n" for n in names) + f"({len(names)} rows)\n"),
            ("mysql -B", "first_name\n" + "".join(f"{n}\n" for n in names)),
        ):
            with self.subTest(name + " text"):
                result = table.describe(table.from_text(content), CONFIG, source="SQL result", safe_plain=True)
                self.assertIn(f"data rows: {len(names)}", result)
                self.assertEqual(leaks(result), [])

    def test_cli_table_from_stdin(self):
        w = subprocess.run(
            [str(ROOT / "bin" / "piigate"), "table", "--rows", "3"],
            input=dt.sql_symfony(),
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(w.returncode, 0, w.stderr)
        self.assertEqual(leaks(w.stdout + w.stderr), [])


@unittest.skipUnless(PRESIDIO, PRESIDIO_SKIP)
class TestText(unittest.TestCase):
    """Free text: Presidio + Polish rules, stable pseudonyms, reversing."""

    def test_mail_pdf_attachments_without_values(self):
        for description, kw in (("eml", {}), ("eml-attachment-1", {"attachment": 1}), ("eml-attachment-2", {"attachment": 2})):
            with self.subTest(description):
                result = files.describe_file(FILES["eml"], CONFIG, source="mail", **kw)
                self.assertEqual(leaks(result), [])
        result = files.describe_file(FILES["pdf"], CONFIG, source="files")
        self.assertEqual(leaks(result), [])
        self.assertIn("PERSON_", result)
        self.assertIn("PRESCRIPTION_", result)

    def test_stable_pseudonym_and_reverse(self):
        p = dt.PATIENTS[0]
        pseudonym_map = PseudonymMap()
        a, _ = text.filter_text(f"Pacjentka {p['first_name']} {p['surname']}, tel. {p['phone']}.", CONFIG, pseudonym_map=pseudonym_map)
        b, _ = text.filter_text(f"Dzwoniła {p['first_name']} {p['surname']} z numeru {p['phone']}.", CONFIG, pseudonym_map=pseudonym_map)
        pa = next(s for s in a.split() if s.startswith("PERSON_")).strip(",.")
        self.assertIn(pa, b)
        self.assertIn(f"{p['first_name']} {p['surname']}", pseudonym_map.reverse(a))
        self.assertIn(p["phone"], pseudonym_map.reverse(a))

    def test_surname_inflection_same_pseudonym(self):
        p = dt.PATIENTS[0]
        result, _ = text.filter_text(
            f"Pani {p['first_name']} {p['surname']} prosi o kontakt. Recepta Pani Przykładowskiej jest gotowa.", CONFIG
        )
        self.assertNotIn("Przykładowsk", result)

    def test_hook_mail_mcp(self):
        result = hook("filter", mcp_mail(dt.mail_body(dt.PATIENTS[0], dt.PATIENTS[1])))
        result_text = json.dumps(result["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)
        self.assertEqual(leaks(result_text), [])
        self.assertEqual(leaks(json.dumps(result["hookSpecificOutput"]["updatedToolOutput"])), [])
        self.assertIn("PERSON_", result_text)

    def test_hook_mail_raw_source(self):
        """getMessage with rawSource: the RFC 2822 source (quoted-printable body, base64 attachments) is decoded
        before filtering — encoded Polish letters (=C5=82) would otherwise hide names from the rules and NER."""
        raw = FILES["eml"].read_bytes().decode("latin-1")
        data = mcp_mail("")
        data["tool_input"] = {"messageId": "1", "rawSource": True}
        data["tool_response"] = [{"type": "text", "text": json.dumps({"id": "1", "rawSource": raw})}]
        result = hook("filter", data)
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        result_text = json.dumps(out, ensure_ascii=False)
        self.assertEqual(leaks(result_text), [])
        self.assertEqual(leaks(json.dumps(out)), [])
        self.assertIn("PERSON_", result_text)
        self.assertNotIn("Content-Transfer-Encoding: base64", result_text)  # attachments are listed, not passed on
        self.assertIn("--attachment", result_text)  # … with the way to show them through the filter

    def test_hook_mail_encoded_backstop(self):
        """Encoded runs the decoder did not catch (a quoted-printable body pasted as plain text) are hidden."""
        p = dt.PATIENTS[1]
        import quopri

        body = quopri.encodestring(f"Pacjent {p['first_name']} {p['surname']} mieszka: {p['address']}.\n".encode()).decode()
        result = hook("filter", mcp_mail(body))
        self.assertEqual(leaks(json.dumps(result["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)), [])

    def test_cli_list_file_names_and_number(self):
        directory = FILES["xlsx"].parent
        result = files.file_list(directory, CONFIG)
        self.assertEqual(leaks(result), [])
        self.assertIn("faktura", result)
        number = next(int(w.split("|")[1]) for w in result.splitlines() if ".xlsx" in w)
        w = subprocess.run(
            [str(ROOT / "bin" / "piigate"), "show", str(directory), "--number", str(number)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        self.assertEqual(w.returncode, 0, w.stderr)
        self.assertIn("data rows: 4", w.stdout)
        self.assertEqual(leaks(w.stdout + w.stderr), [])

    def test_subject_and_body_same_pseudonym(self):
        p = dt.PATIENTS[0]
        result, _ = text.filter_text(
            f"Temat: recepta {p['surname']}\nPani {p['first_name']} {p['surname']} prosi o kontakt.", CONFIG
        )
        pseudonyms = set(re.findall(r"PERSON_\d+", result))
        self.assertEqual(len(pseudonyms), 1, result)


class TestGate(unittest.TestCase):
    def setUp(self):
        # not TMP — the filter map lives there (protected directory); strict mode: otherwise the plugin repo without
        # PHI would count as a public place
        self.b = gate.Gate(STRICT, str(ROOT))
        self.home = str(Path.home())

    def denial(self, tool, tool_input) -> bool:
        return self.b.decision(tool, tool_input) is not None

    def test_read(self):
        tb = f"{self.home}/Downloads/thunderbird.tmp/Recepty_Pomidorek.xlsx"
        self.assertTrue(self.denial("Read", {"file_path": tb}))
        self.assertTrue(self.denial("Read", {"file_path": f"{self.home}/Downloads/thunderbird.tmp/notatka.txt"}))
        self.assertTrue(self.denial("Read", {"file_path": f"{self.home}/Documents/piigate/Sensitive-data/pharmacy/export.json"}))
        self.assertTrue(self.denial("Read", {"file_path": str(FILES["pdf"])}))  # PDF outside the directories — by extension
        self.assertTrue(self.denial("Read", {"file_path": f"{self.home}/.local/share/piigate/map.sqlite"}))
        self.assertTrue(self.denial("Read", {"file_path": os.environ["PIIGATE_DATA_DIR"] + "/map.sqlite"}))
        self.assertFalse(self.denial("Read", {"file_path": str(ROOT / "README.md")}))
        reason = self.b.decision("Read", {"file_path": tb})
        self.assertIn("piigate_show", reason)

    def test_read_via_symlink(self):
        is_sensitive = TMP / "sensitive"
        is_sensitive.mkdir(exist_ok=True)
        (is_sensitive / "eksport.txt").write_text("x")
        cfg = json.loads(json.dumps(CONFIG))
        cfg["sources"]["directories"].append(str(is_sensitive))
        b = gate.Gate(cfg, str(TMP))
        dest = TMP / "link.txt"
        dest.unlink(missing_ok=True)
        dest.symlink_to(is_sensitive / "eksport.txt")
        self.assertIsNotNone(b.decision("Read", {"file_path": str(dest)}))
        self.assertIsNotNone(b.decision("Bash", {"command": f"cat {dest}"}))

    def test_grep_glob_edit(self):
        self.assertTrue(self.denial("Grep", {"pattern": "x", "path": f"{self.home}/Downloads/thunderbird.tmp"}))
        self.assertTrue(self.denial("Grep", {"pattern": "x", "glob": "*.csv", "path": str(FILES["csv"].parent)}))
        self.assertFalse(self.denial("Grep", {"pattern": "x", "glob": "*.csv"}))  # the plugin has no CSV files
        self.assertTrue(self.denial("Glob", {"pattern": "*", "path": f"{self.home}/Documents/piigate/Sensitive-data"}))
        self.assertFalse(self.denial("Glob", {"pattern": "**/*.py"}))
        self.assertTrue(self.denial("Grep", {"pattern": "Kowalski", "path": self.home}))
        self.assertTrue(self.denial("Glob", {"pattern": "**/*", "path": self.home}))
        self.assertTrue(self.denial("Glob", {"pattern": "Downloads/thunderbird.tmp/*", "path": self.home}))
        self.assertTrue(self.denial("Edit", {"file_path": f"{self.home}/.config/piigate/config.json"}))
        self.assertTrue(self.denial("Edit", {"file_path": str(FILES["csv"])}))
        self.assertFalse(self.denial("Write", {"file_path": str(TMP / "new.csv")}))

    def test_bash(self):
        cases = {
            # false positives: grep without -r with a glob, mysql services over ssh, heredoc into a file
            "grep -H worktrees ~/compose.todo6*.yml": False,
            "grep -rH worktrees ~/compose.todo6*.yml": True,
            "grep x ~/D*": True,
            "grep -d recurse x ~/*.yml": True,
            "ssh prod 'systemctl status mysql'": False,
            "ssh prod 'ls /etc/mysql; journalctl -u mariadb -n 20'": False,
            "ssh prod 'sudo systemctl restart mysql.service'": False,
            "ssh prod \"mysql -e 'select 1'; systemctl status mysql\"": True,
            "ssh prod 'sudo -u postgres psql -c \"select 1\"'": True,
            "cat > /tmp/note.md <<'EOF'\nssh prod 'bin/console dbal:run-sql \"SELECT 1\"'\n~/Documents/piigate/Sensitive-data/a.csv\nEOF": False,
            "cat <<'EOF' > /tmp/note.md\nmysql -e 'select 1'\nEOF": False,
            "cat > /tmp/s.sh <<'EOF'\ncat ~/Documents/piigate/Sensitive-data/a.csv\nEOF\nbash /tmp/s.sh": True,
            "python3 - <<'EOF'\nprint(open('/home/x/Sensitive-data/a.csv').read())\nEOF": True,
            "cat <<'EOF'\n~/Documents/piigate/Sensitive-data/a.csv\nEOF": True,
            "cat ~/Downloads/thunderbird.tmp/mail.eml": True,
            "cd ~/Downloads && head thunderbird.tmp/a.csv": True,
            "ls ~/Downloads/thunderbird.tmp/": True,
            "pdftotext faktura.pdf -": True,
            "python3 -c \"print(open('/home/x/Sensitive-data/a.txt').read())\"": True,
            "ssh prod 'cd /var/www && bin/console dbal:run-sql \"SELECT * FROM pacjent\"'": True,
            "ssh prod 'bin/console doctrine:query:sql \"SELECT 1\"' | piigate table": True,  # no 2>&1
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table; cat ~/.ssh/config": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table && echo ok": True,
            "ssh prod 'mysql -e \"select * from x\"' 2>&1 | tee /tmp/x | piigate table": True,  # tee: raw data in a file
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": False,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' |& piigate table --rows 3": False,
            "piigate show ~/Downloads/thunderbird.tmp/Recepty_Pomidorek.xlsx": False,
            'piigate show "$(ls ~/Downloads/thunderbird.tmp | head -1)"': True,
            "piigate list ~/Downloads/thunderbird.tmp": False,
            "piigate table < ~/Documents/piigate/Sensitive-data/export.csv": False,
            "cat ~/Documents/piigate/Sensitive-data/export.csv 2>&1 | piigate table": False,
            "piigate reverse raport.md": True,
            "sqlite3 ~/.local/share/piigate/map.sqlite .dump": True,
            "PIIGATE_CONFIG_DIR=/tmp/x piigate show a.pdf": True,
            "cp ~/Downloads/thunderbird.tmp/a.pdf ~/Documents/piigate/Sensitive-data/pharmacy/": False,
            "scp prod:/var/www/export.csv ~/Documents/piigate/Sensitive-data/pharmacy/": False,
            "git add tests/data.csv": True,  # a data file would end up in the repository
            # bypasses found in a security review
            "grep -r Kowalski ~": True,
            "rg -i pacjent ~/Downloads": True,
            "find ~ -name '*.eml'": True,
            "cat ~/Dow*/thunder*/mail.eml": True,
            "cat ~/Documents/piigate/Sensitive-{da,x}ta/a.txt": True,
            "./piigate table < ~/Documents/piigate/Sensitive-data/x.csv": True,
            "HOME=/tmp piigate show ~/Documents/piigate/Sensitive-data/x.csv": True,
            "cp ~/Documents/piigate/Sensitive-data/x.csv /tmp/x.txt": True,
            "cp ~/Downloads/thunderbird.tmp/a.pdf ~/Documents/piigate/Sensitive-data/pharmacy/a.pdf": False,
            "cat ~/Documents/piigate/Sensitive-data/x.csv > /tmp/y 2>&1 | piigate table": True,
            "python3 lib/cli.py reverse raport.md": True,
            "ls ~/Downloads": False,
            # second security review
            "cp -t /tmp ~/Documents/piigate/Sensitive-data/x.csv": True,
            "cp -at/tmp ~/Documents/piigate/Sensitive-data/x.csv": True,
            "rsync -av ~/Documents/piigate/Sensitive-data/ /tmp/copy/": True,
            "sort -o /tmp/x ~/Documents/piigate/Sensitive-data/x.csv 2>&1 | piigate table": True,
            "timeout 5 cat ~/Documents/piigate/Sensitive-data/x.csv 2>&1 | piigate table": True,
            "cat ~/Documents/piigate/Sensitive-dat{a..e}/x.txt": True,
            "pdftotext ~/Documents/piigate/Sensitive-data/a.pdf /tmp/a.txt 2>&1 | piigate text": True,
            "pdftotext ~/Documents/piigate/Sensitive-data/a.pdf - 2>&1 | piigate text": False,
            "markitdown ~/Documents/piigate/Sensitive-data/a.docx -o /tmp/a.md 2>&1 | piigate text": True,
            "docker cp container:/x.csv /tmp/ 2>&1 | piigate table < ~/Documents/piigate/Sensitive-data/x.csv": True,
            # third security review
            "cat ~/Documents/piigate/Sensitive-dat{a..z..2}/x.txt": True,
            "cat /home/x/{01..03}/a.txt": False,  # expanded correctly, nothing sensitive
            "cat ~/Documents/piigate/Sensitive-data/x.csv 2>&1 | mlr --icsv tee /tmp/x 2>&1 | piigate table": True,
            "docker exec db psql -c 'select 1' 2>&1 | piigate table < ~/Documents/piigate/Sensitive-data/x.csv": True,
            "ssh -E /tmp/log prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": True,
            "ssh -o LocalCommand='cp x /tmp' prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": True,
            "ssh -p 2222 prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": False,
            "ssh -vo LocalCommand=id prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": True,
            "ssh -oPermitLocalCommand=yes prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 -oLocalCommand=id | piigate table": True,
            "pdftotext ~/Documents/piigate/Sensitive-data/a.pdf - 2>&1 /tmp/a.txt | piigate text": True,
            "ssh -i ~/.ssh/k prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": True,
            "ssh -q -o BatchMode=yes -l deploy prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": False,
            "pdftotext -f 1 ~/Documents/piigate/Sensitive-data/a.pdf /tmp/a.txt - 2>&1 | piigate text": True,
            "pdftotext -f 1 -l 2 ~/Documents/piigate/Sensitive-data/a.pdf - 2>&1 | piigate text": False,
            # stages after piigate: they only trim / count piigate output (stdin), no files and no code execution
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | grep -v -E \"WARNING|pq.html\"": False,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table | head -n 20": False,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table | grep -i price | wc -l": False,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | sort -k2 | uniq -c | cut -d' ' -f1-3 | tail -5": False,
            "ssh -o ConnectTimeout=10 -o LogLevel=ERROR prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate table": False,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | grep x ~/Documents/piigate/Sensitive-data/a.csv": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | grep -e x ~/Documents/piigate/Sensitive-data/a.csv": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | grep -f ~/Documents/piigate/Sensitive-data/a.csv": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | grep -rn x ~/Documents/piigate/Sensitive-data": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | head ~/Documents/piigate/Sensitive-data/a.csv": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | sort -o /tmp/x": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | wc --files0-from=/tmp/lista": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | cat ~/Documents/piigate/Sensitive-data/a.csv": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | bash": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | xargs cat": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | piigate text | grep x > /tmp/y": True,
            "ssh prod 'bin/console dbal:run-sql \"SELECT 1\"' 2>&1 | grep x | wc -l": True,
            "mkdir -p ~/Documents/piigate/Sensitive-data/{pharmacy,shop}": False,
            "git status": False,
            "ls -la": False,
            "ssh prod 'df -h'": False,
            "cat README.md | head": False,
            "piigate show a.pdf\ncat a.pdf": True,
        }
        for command, denial in cases.items():
            with self.subTest(command):
                self.assertEqual(
                    self.denial("Bash", {"command": command}), denial, self.b.decision("Bash", {"command": command})
                )

    def test_brace_expansion(self):
        self.assertEqual(gate.expand_braces("a{01..03}"), ["a01", "a02", "a03"])
        self.assertEqual(gate.expand_braces("x{b,c}{1..2}"), ["xb1", "xb2", "xc1", "xc2"])
        self.assertEqual(gate.expand_braces("a{c..a}"), ["aa", "ab", "ac"])

    def test_cli_only_from_plugin(self):
        command = "piigate show ~/Documents/piigate/Sensitive-data/x.csv"
        planted = TMP / "planted"
        planted.mkdir(exist_ok=True)
        (planted / "piigate").write_text('#!/bin/sh\ncat "$2"\n')
        (planted / "piigate").chmod(0o755)
        saved_env = {k: os.environ.get(k) for k in ("CLAUDE_PLUGIN_ROOT", "PATH")}
        try:
            os.environ["CLAUDE_PLUGIN_ROOT"] = str(ROOT)
            os.environ["PATH"] = "/usr/bin:/bin"
            self.assertIsNone(gate.Gate(CONFIG, str(ROOT)).decision("Bash", {"command": command}))
            os.environ["PATH"] = f"{planted}:/usr/bin:/bin"
            self.assertIsNotNone(gate.Gate(CONFIG, str(ROOT)).decision("Bash", {"command": command}))
            os.environ["PATH"] = f"{ROOT / 'bin'}:/usr/bin:/bin"
            self.assertIsNone(gate.Gate(CONFIG, str(ROOT)).decision("Bash", {"command": command}))
            self.assertIsNone(
                gate.Gate(CONFIG, str(ROOT)).decision(
                    "Bash", {"command": f"{shlex.quote(str(ROOT / 'bin' / 'piigate'))} show ~/Documents/piigate/Sensitive-data/x.csv"}
                )
            )
        finally:
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    def test_hook_gate_read_attachment(self):
        result = hook(
            "gate",
            {
                "hook_event_name": "PreToolUse",
                "cwd": str(TMP),
                "tool_name": "Read",
                "tool_input": {"file_path": f"{self.home}/Downloads/thunderbird.tmp/Recepty_X.xlsx"},
            },
        )
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("piigate_show", result["hookSpecificOutput"]["permissionDecisionReason"])
        self.assertIsNone(
            hook(
                "gate",
                {
                    "hook_event_name": "PreToolUse",
                    "cwd": str(TMP),
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status"},
                },
            )
        )


class TestStatus(unittest.TestCase):
    def test_status_runs(self):
        """`piigate status`: engine, configuration and log summary — never a denial (it shows no data)."""
        w = subprocess.run([str(ROOT / "bin" / "piigate"), "status"], capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(w.returncode, 0, w.stdout + w.stderr)
        self.assertNotIn("denied", w.stdout + w.stderr)
        self.assertIn("Presidio", w.stdout)
        self.assertNotIn("{documents}", w.stdout)  # placeholders are shown expanded


class TestLinkHook(unittest.TestCase):
    """SessionStart hook: ~/.local/bin/piigate → bin/piigate of the INSTALLED plugin copy only."""

    def run_link(self, root: Path, home: Path) -> None:
        subprocess.run(["bash", str(root / "hooks" / "link.sh")], env={**os.environ, "HOME": str(home)}, check=True, timeout=30)

    def test_link_only_from_installed_copy(self):
        home = TMP / "link-home"
        (home / ".local/bin").mkdir(parents=True, exist_ok=True)
        link = home / ".local/bin/piigate"
        self.run_link(ROOT, home)  # development checkout (--plugin-dir): no link
        self.assertFalse(link.exists() or link.is_symlink())
        installed = home / ".claude/plugins/cache/piigate/piigate/1.0.0"
        shutil.copytree(ROOT / "hooks", installed / "hooks", dirs_exist_ok=True)
        shutil.copytree(ROOT / "bin", installed / "bin", dirs_exist_ok=True)
        self.run_link(installed, home)
        self.assertEqual(os.readlink(link), str(installed / "bin/piigate"))
        link.unlink()
        link.write_text("mine\n")  # a regular file the user put there is never overwritten
        self.run_link(installed, home)
        self.assertEqual(link.read_text(), "mine\n")


class TestProtectedFiles(unittest.TestCase):
    def test_engine_socket_directory_protected(self):
        """A model must not bind its own engine socket (it could answer "nothing found" to every analysis)."""
        runtime = TMP / "runtime"
        (runtime / "piigate").mkdir(parents=True, exist_ok=True)
        saved = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(runtime)
        try:
            g = gate.Gate(config.load(str(TMP)), str(TMP))
            sock = runtime / "piigate" / "engine.sock"
            for tool, tool_input in (
                ("Write", {"file_path": str(sock), "content": "x"}),
                ("Bash", {"command": f"python3 -c 'import socket; s=socket.socket(1); s.bind(\"{sock}\")'"}),
                ("Bash", {"command": f"rm {sock}"}),
            ):
                with self.subTest(tool=tool, input=tool_input):
                    self.assertIsNotNone(g.decision(tool, tool_input))
        finally:
            if saved is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = saved

    def test_cli_hides_map_and_key(self):
        PseudonymMap()  # creates the key and the map in PIIGATE_DATA_DIR
        folder = Path(os.environ["PIIGATE_DATA_DIR"])
        for file in ("key", "map.sqlite"):
            with self.subTest(file), self.assertRaises(FilterError):
                files.describe_file(folder / file, CONFIG, source="files")
        self.assertNotIn("key", files.file_list(folder.parent, CONFIG))
        cli = str(ROOT / "bin" / "piigate")
        for command in ("text", "table"):
            with self.subTest(command):
                w = subprocess.run([cli, command, str(folder / "key")], capture_output=True, timeout=60, check=False)
                self.assertEqual(w.returncode, 3)
                with open(folder / "key", "rb") as tool_input:
                    w = subprocess.run([cli, command], stdin=tool_input, capture_output=True, timeout=60, check=False)
                self.assertEqual(w.returncode, 3)
                self.assertEqual(w.stdout, b"")


class TestSensors(unittest.TestCase):
    def test_bash_pesel_hidden(self):
        p = dt.PATIENTS[1]
        result = hook(
            "filter",
            {
                "hook_event_name": "PostToolUse",
                "cwd": str(TMP),
                "tool_name": "Bash",
                "tool_input": {"command": "grep -r x ."},
                "tool_response": {
                    "stdout": f"file.txt: {p['pesel']}",
                    "stderr": "",
                    "interrupted": False,
                    "isImage": False,
                    "noOutputExpected": False,
                },
            },
        )
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn(p["pesel"], out["stdout"])
        self.assertEqual(set(out), {"stdout", "stderr", "interrupted", "isImage", "noOutputExpected"})

    def test_unchanged_without_replacement(self):
        self.assertIsNone(
            hook(
                "filter",
                {
                    "hook_event_name": "PostToolUse",
                    "cwd": str(TMP),
                    "tool_name": "Bash",
                    "tool_input": {"command": "ls"},
                    "tool_response": {"stdout": "a.txt\nb.txt", "stderr": "", "interrupted": False, "isImage": False},
                },
            )
        )

    def test_read_sensitive_after_gate(self):
        path = f"{Path.home()}/Downloads/thunderbird.tmp/x.txt"
        content = dt.mail_body(dt.PATIENTS[0], dt.PATIENTS[1])
        result = hook(
            "filter",
            {
                "hook_event_name": "PostToolUse",
                "cwd": str(TMP),
                "tool_name": "Read",
                "tool_input": {"file_path": path},
                "tool_response": {
                    "type": "text",
                    "file": {"filePath": path, "content": content, "numLines": 9, "startLine": 1, "totalLines": 9},
                },
            },
        )
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        self.assertEqual(leaks(json.dumps(out, ensure_ascii=False)), [])
        self.assertEqual(out["type"], "text")


class TestDefaultDeny(unittest.TestCase):
    """A filter failure → an error message, never the original."""

    def tearDown(self):
        set_config(None)

    def check_mail_denial(self, env=None):
        result = hook("filter", mcp_mail(dt.mail_body(dt.PATIENTS[0], dt.PATIENTS[1])), env)
        out = json.dumps(result["hookSpecificOutput"]["updatedToolOutput"], ensure_ascii=False)
        self.assertEqual(leaks(out), [])
        self.assertIn("Output hidden", out)

    def test_presidio_down(self):
        set_config(engine_down(timeout_s=3))
        self.check_mail_denial()
        with self.assertRaises(FilterError):
            files.describe_file(FILES["pdf"], config.load(), source="files")

    def test_presidio_outside_loopback(self):
        set_config(engine_down("http://example.com:3000"))
        self.check_mail_denial()

    def test_ollama_cloud_and_down(self):
        for model, url in (
            ("minimax-m3:cloud", "http://127.0.0.1:11434"),
            ("qwen2.5:7b-instruct", "http://127.0.0.1:9"),
        ):
            with self.subTest(model):
                set_config(
                    {
                        **engine_down(timeout_s=1),
                        "ollama": {"enabled": True, "model": model, "url": url, "timeout_s": 3},
                    }
                )
                self.check_mail_denial()

    def test_bad_config(self):
        folder = Path(os.environ["PIIGATE_CONFIG_DIR"])
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "config.json").write_text("{ this is not json", encoding="utf-8")
        self.check_mail_denial()
        result = hook(
            "gate",
            {"hook_event_name": "PreToolUse", "cwd": str(TMP), "tool_name": "Bash", "tool_input": {"command": "ls"}},
        )
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_python_does_not_start(self):
        fake = TMP / "no-python"
        fake.mkdir(exist_ok=True)
        (fake / "python3").write_text("#!/bin/sh\nexit 1\n")
        (fake / "python3").chmod(0o755)
        env = {"PATH": f"{fake}:{os.environ['PATH']}"}
        self.check_mail_denial(env)
        result = hook(
            "filter",
            {
                "tool_name": "Bash",
                "tool_input": {"command": "x"},
                "tool_response": {"stdout": dt.PATIENTS[0]["surname"], "stderr": ""},
            },
            env,
        )
        out = result["hookSpecificOutput"]["updatedToolOutput"]
        self.assertNotIn(dt.PATIENTS[0]["surname"], json.dumps(out, ensure_ascii=False))
        self.assertEqual(set(out), {"stdout", "stderr", "interrupted", "isImage", "noOutputExpected"})
        result = hook("gate", {"tool_name": "Read", "tool_input": {"file_path": "/etc/hostname"}}, env)
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")

    def test_cli_without_presidio_hides_original(self):
        set_config(engine_down(timeout_s=2))
        w = subprocess.run(
            [str(ROOT / "bin" / "piigate"), "show", str(FILES["eml"])],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertEqual(w.returncode, 3)
        self.assertEqual(leaks(w.stdout + w.stderr), [])


class TestReverse(unittest.TestCase):
    def test_agent_gets_denial(self):
        w = subprocess.run(
            [str(ROOT / "bin" / "piigate"), "reverse", "-"],
            input="PERSON_1",
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "CLAUDECODE": "1"},
            check=False,
        )
        self.assertEqual(w.returncode, 4)
        self.assertEqual(w.stdout, "")


@unittest.skipUnless(
    shutil.which("docker") and os.environ.get("PIIGATE_TEST_DB") == "1",
    "local database test: PIIGATE_TEST_DB=1 (throwaway postgres:17-alpine container)",
)
class TestAnonymizedLocalDb(unittest.TestCase):
    """A local database with anonymized data (UPDATE md5) → psql output through `piigate table`."""

    def test_psql(self):
        name = "piigate-test-pg"
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        subprocess.run(
            [
                "docker",
                "run",
                "-d",
                "--rm",
                "--name",
                name,
                "--network",
                "none",
                "-e",
                "POSTGRES_PASSWORD=test",
                "postgres:17-alpine",
            ],
            check=True,
            capture_output=True,
        )
        try:
            ready = 0  # pg_isready answers already during initdb — wait for 3 successful queries
            for _ in range(90):
                ok = (
                    subprocess.run(
                        ["docker", "exec", name, "psql", "-U", "postgres", "-qtAc", "SELECT 1"],
                        capture_output=True,
                        check=False,
                    ).returncode
                    == 0
                )
                ready = ready + 1 if ok else 0
                if ready >= 3:
                    break
                subprocess.run(["sleep", "1"], check=False)
            inserts = "".join(
                f"INSERT INTO pacjent VALUES ({i}, '{p['first_name']}', '{p['surname']}', '{p['pesel']}', '{p['phone']}');"
                for i, p in enumerate(dt.PATIENTS, 1)
            )
            sql = (
                "CREATE TABLE pacjent (id int, imie text, nazwisko text, pesel text, telefon text);"
                + inserts
                + "UPDATE pacjent SET nazwisko = 'anon_' || left(md5(nazwisko), 8);"
            )
            subprocess.run(
                ["docker", "exec", name, "psql", "-U", "postgres", "-qc", sql], check=True, capture_output=True
            )
            def query(sql: str) -> subprocess.CompletedProcess:
                return subprocess.run(
                    f"docker exec {name} psql -U postgres -c {shlex.quote(sql)} 2>&1 | "
                    f"{shlex.quote(str(ROOT / 'bin' / 'piigate'))} table --rows 4",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )

            result = query("SELECT * FROM pacjent")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("data rows: 4", result.stdout)
            self.assertEqual(leaks(result.stdout), [])
            self.assertNotIn("anon_", result.stdout)
            # one column (issue #9): a count in plain text, names masked
            result = query("SELECT count(*) FROM pacjent")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertRegex(result.stdout, rf"\| {len(dt.PATIENTS)} \|")
            result = query("SELECT imie FROM pacjent")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(leaks(result.stdout), [])
        finally:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)


class TestAnonymization(unittest.TestCase):
    """`piigate anonymize` / `piigate analyze`: copies without values, the same pseudonyms, the model report after the filter."""

    def setUp(self):
        self.cfg = json.loads(json.dumps(CONFIG))
        self.sensitive = TMP / "sensitive-anon"
        self.sensitive.mkdir(exist_ok=True)
        self.cfg["sources"]["directories"] = [str(self.sensitive)]
        self.cfg["anonymization"]["directory"] = str(TMP / "anonymized")

    def result_files(self, w) -> dict[str, str]:
        return {p.name: p.read_text(encoding="utf-8") for p in w.directory.iterdir()}

    def test_all_formats_without_values(self):
        if not PRESIDIO:
            self.skipTest(PRESIDIO_SKIP)
        for kind in ("csv", "xlsx", "pdf", "eml"):
            with self.subTest(kind):
                w = anonymization.anonymize(FILES[kind].name, FILES[kind].read_bytes(), self.cfg)
                files_in = self.result_files(w)
                self.assertTrue(files_in)
                for name, content in files_in.items():
                    self.assertEqual(leaks(name + content), [], name)
                self.assertEqual(leaks(anonymization.report(w)), [])
        w = anonymization.anonymize(FILES["csv"].name, FILES["csv"].read_bytes(), self.cfg)
        csv_ = next(iter(self.result_files(w).values()))
        self.assertIn("PERSON_", csv_)
        self.assertIn("Kwota: plain", anonymization.report(w))

    def test_same_pseudonyms_and_reverse(self):
        w = anonymization.anonymize(FILES["csv"].name, FILES["csv"].read_bytes(), self.cfg)
        content = next(iter(self.result_files(w).values()))
        self.assertIn(dt.PATIENTS[0]["pesel"], PseudonymMap().reverse(content))

    def test_column_flagged_but_amount_plain(self):
        w = anonymization.anonymize(
            FILES["csv"].name, FILES["csv"].read_bytes(), self.cfg, mask={"Kwota", "Lek"}
        )
        self.assertIn("Kwota: plain", anonymization.report(w))

    def test_write_only_to_allowed(self):
        with self.assertRaises(FilterError):
            anonymization.anonymize("a.txt", b"x", self.cfg, dest=str(TMP / "anywhere"))
        w = anonymization.anonymize("a.txt", b"x", self.cfg, dest=str(self.sensitive / "result"))
        self.assertTrue((self.sensitive / "result" / "a.txt").exists())
        self.assertEqual(oct(w.directory.stat().st_mode & 0o777), "0o700")

    @staticmethod
    def b64(t: str) -> str:
        import base64

        return base64.b64encode(t.encode()).decode()

    def test_symlink_in_output_dir(self):
        dest = self.sensitive / "result-symlink"
        dest.mkdir(exist_ok=True)
        victim = TMP / "victim.txt"
        victim.write_text("untouched")
        (dest / "a.txt").unlink(missing_ok=True)
        (dest / "a.txt").symlink_to(victim)
        with self.assertRaises(OSError):
            anonymization.anonymize("a.txt", b"x", self.cfg, dest=str(dest))
        self.assertEqual(victim.read_text(), "untouched")

    def test_fragments_from_model(self):
        # a lowercase nickname — the rules miss it (README: Limitations), the local model does not
        t = "Zgłoszenie od tego od ogórków z trzeciego piętra, znowu w sprawie leków."
        res, _ = anonymization.filter_fragments(t, self.cfg, PseudonymMap(), [("tego od ogórków", "PERSON")], rules_only=True)
        self.assertNotIn("ogórków", res)
        res, _ = anonymization.filter_fragments(t, self.cfg, PseudonymMap(), [("Nie ma tego w tekście", "PERSON")], rules_only=True)
        self.assertIn("ogórków", res)  # model hallucinations (strings not in the text) change nothing

    def fake_agent(self, response: dict | None) -> Path:
        """Stands in for `analysis.agent_command`: saves its argv and stdin, prints the given JSON (or fails)."""
        script = TMP / "fake-agent"
        tool_input = TMP / "fake-agent-stdin.txt"
        body = (
            f"printf '%s\\n' \"$@\" > {TMP / 'fake-agent-argv.txt'}\ncat > {tool_input}\n"
            + (
                f"cat <<'END'\n{json.dumps(response, ensure_ascii=False)}\nEND\n"
                if response is not None
                else "echo 'fake-agent: the model does not respond' >&2\nexit 2\n"
            )
        )
        script.write_text("#!/usr/bin/env bash\n" + body, encoding="utf-8")
        script.chmod(0o700)
        self.cfg["analysis"] = {"agent_command": [str(script)], "timeout_s": 60}
        return tool_input

    def test_analyze_report_filtered(self):
        if not PRESIDIO:
            self.skipTest(PRESIDIO_SKIP)
        p = dt.PATIENTS
        tool_input = self.fake_agent(
            {
                "sensitive_data": [{"category": "PESEL", "where": "mail, PESEL column", "count": 4}],
                "columns_to_mask": [{"file": "x.csv", "column": "Lek"}],
                "fragments_to_mask": [{"text": p[1]["surname"], "type": "PERSON"}],
                # the model "leaks" data in the summary — the report still must not contain it
                "summary": f"Pani {p[0]['first_name']} {p[0]['surname']} i pan {p[1]['surname']} — PESEL {p[0]['pesel']}.",
                # data "in disguise": the surname reversed and first name + surname in base64
                "answer": f"Dotyczy {p[2]['surname']}, tel. {p[2]['phone']}. Wspak: {p[0]['surname'][::-1]}, "
                f"zakodowane: {self.b64(p[1]['first_name'] + ' ' + p[1]['surname'])}.",
            }
        )
        report = analysis.analyze(FILES["eml"].name, FILES["eml"].read_bytes(), self.cfg, question="Kto pisze?")
        self.assertEqual(leaks(report), [])
        self.assertNotIn(p[0]["surname"][::-1], report)
        self.assertNotIn(self.b64(p[1]["first_name"] + " " + p[1]["surname"]), report)
        self.assertIn("## Summary", report)
        self.assertIn("PESEL — ", report)
        # the model got the original content (extracted text of the mail and its attachments) on stdin
        received = tool_input.read_text(encoding="utf-8")
        self.assertIn(p[0]["pesel"], received)
        self.assertIn("=== FILE:", received)
        self.assertIn("User's question: Kto pisze?", received)
        argv = (TMP / "fake-agent-argv.txt").read_text(encoding="utf-8").splitlines()
        self.assertEqual([argv[0], argv[2], argv[4]], ["--schema", "--dir", "--timeout"])
        self.assertEqual(list((self.sensitive / ".piigate-work").iterdir()), [])  # work directory removed

    def test_analyze_mail_via_mcp(self):
        if not PRESIDIO:
            self.skipTest(PRESIDIO_SKIP)
        tool_input = self.fake_agent(
            {"sensitive_data": [], "columns_to_mask": [], "fragments_to_mask": [], "summary": "x", "answer": ""}
        )
        self.cfg["anonymization"]["mail_mcp"] = ["python3", "-I", str(TESTS_DIR / "fake_mail_mcp.py")]
        mail = analysis.fetch_mail("Recepty", None, self.cfg, PseudonymMap())
        self.assertIsInstance(mail, tuple)
        report = analysis.analyze(*mail, self.cfg)
        self.assertEqual(leaks(report), [])
        self.assertIn("attachments: 2", report)
        self.assertIn(dt.PATIENTS[0]["pesel"], tool_input.read_text(encoding="utf-8"))  # the model saw the original

    def test_analyze_when_agent_down(self):
        if not PRESIDIO:
            self.skipTest(PRESIDIO_SKIP)
        self.fake_agent(None)
        report = analysis.analyze(FILES["csv"].name, FILES["csv"].read_bytes(), self.cfg)
        self.assertIn("FAILED", report)
        self.assertIn("anonymized copies", report)
        self.assertEqual(leaks(report), [])

    def test_gate(self):
        b = gate.Gate(self.cfg, str(ROOT))
        anon = TMP / "anonymized" / "x" / "a.csv"
        self.assertIsNone(b.decision("Read", {"file_path": str(anon)}))
        self.assertIsNotNone(b.decision("Read", {"file_path": str(self.sensitive / ".piigate-work" / "a.csv")}))
        cases = {
            # analyze/anonymize only through the MCP tools (piigate_analyze, piigate_anonymize)
            f"piigate analyze {self.sensitive}/x.xlsx --question 'ile wierszy'": True,
            f"piigate anonymize {self.sensitive}/x.csv -o {self.sensitive}/result": True,
            "piigate analyze --mail 'recepty październik' --number 2": True,
            f"cat {anon}": False,
            f"local-agent --profile phi --dir {self.sensitive} 'task'": True,  # raw output without the filter
            f"cat {self.sensitive}/x.csv | local-agent --profile read -": True,
        }
        self.cfg["unfiltered_tools"] = [LOCAL_AGENT]
        b = gate.Gate(self.cfg, str(ROOT))
        for command, denial in cases.items():
            with self.subTest(command):
                self.assertEqual(b.bash(command) is not None, denial)


class TestMcpValidation(unittest.TestCase):
    """MCP tool input validation, plain words, document numbers, Presidio 404, agent retry, the external agent wrapper."""

    def setUp(self):
        self.cfg = json.loads(json.dumps(CONFIG))
        self.sensitive = TMP / "sensitive-validation"
        self.sensitive.mkdir(exist_ok=True)
        self.cfg["sources"]["directories"] = [str(self.sensitive)]
        self.cfg["anonymization"]["directory"] = str(TMP / "anonymized-validation")

    def test_source_only_sensitive_data(self):
        file = self.sensitive / "a.txt"
        file.write_text("x")
        self.assertEqual(files.source(str(file), self.cfg), file.resolve())
        self.assertEqual(files.source(str(FILES["csv"]), self.cfg), FILES["csv"].resolve())  # extension from the configuration
        regular_file = TMP / "regular.txt"
        regular_file.write_text("x")
        secret = TMP / "id_secret"
        secret.write_text("x")
        (self.sensitive / "symlink.csv").unlink(missing_ok=True)
        (self.sensitive / "symlink.csv").symlink_to(secret)  # a .csv name, the target has no extension and is outside the directory
        pseudonym_map = Path(os.environ["PIIGATE_DATA_DIR"]) / "map.sqlite"
        for bad in (str(regular_file), "relative/a.txt", str(self.sensitive / "symlink.csv"), str(pseudonym_map), "/etc/passwd"):
            with self.subTest(bad), self.assertRaises(FilterError):
                files.source(bad, self.cfg)
        self.assertEqual(files.source(str(self.sensitive), self.cfg, directory=True), self.sensitive.resolve())
        with self.assertRaises(FilterError):
            files.source(str(TMP), self.cfg, directory=True)
        with self.assertRaises(FilterError):
            files.source(str(TMP), self.cfg, number=1)

    def test_plain_words_and_document_number(self):
        if not PRESIDIO:
            self.skipTest(PRESIDIO_SKIP)
        p = dt.PATIENTS[0]
        t = (
            f"Test filtra Ollamy i PHI. Faktura FV/2026/10/123 dla pani {p['first_name']} {p['surname']}, "
            f"tel. {p['phone']}, PESEL {p['pesel']}."
        )
        res, _ = text.filter_text(t, self.cfg, pseudonym_map=PseudonymMap())
        self.assertIn("Ollamy", res)
        self.assertIn("PHI", res)
        self.assertNotIn("PHONE_", res.split("dla pani")[0])  # the invoice number is not a phone number
        self.assertEqual(leaks(res), [])  # the person, phone and PESEL are still masked
        self.cfg["text"]["plain_words"] = []
        self.assertEqual(leaks(text.filter_text(t, self.cfg, pseudonym_map=PseudonymMap())[0]), [])

    def test_presidio_404_hint(self):
        import http.server
        import threading

        class NotFoundHandler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(404)
                self.end_headers()

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), NotFoundHandler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            self.cfg["engine"] = engine_down(f"http://127.0.0.1:{server.server_port}", 10)["engine"]
            with self.assertRaises(FilterError) as e:
                engines.presidio("Jan", self.cfg)
            self.assertIn("is the Presidio container running?", str(e.exception))
        finally:
            server.shutdown()

    def test_gate_local_agent(self):
        self.cfg["unfiltered_tools"] = [LOCAL_AGENT]
        b = gate.Gate(self.cfg, str(ROOT))
        w = self.sensitive
        denial = [
            f"local-agent --dir {w}/project 'how many files'",
            f"cd {w} && local-agent 'how many files'",
            f"D={w}; local-agent --dir $D x",
            "local-agent --dir \"$(echo ~/x)\" x",
            "local-agent --dir `pwd` x",
            f"bash -c 'local-agent --dir {w} x'",
            "bash -c 'local-agent --dir ~/repo x'",
            "eval local-agent --dir ~/repo x",
            "echo ~/repo | xargs local-agent --dir",
            "$HOME/.local/bin/local-agent --dir ~/repo x",
            f"~/.local/share/agents/local-agent/local-agent --dir {w} x",
            "local-agent --profile phi --dir ~/repo -",
            "local-agent --profile=phi --dir ~/repo -",
            f"cat {w}/a.eml | local-agent --dir ~/repo -",
            f"local-agent --dir={w} x",
            f"local-agent --dir {TMP} x",  # contains a sensitive directory
        ]
        for command in denial:
            with self.subTest(command):
                self.assertIsNotNone(b.bash(command))
        for command in ("local-agent --dir ~/repo 'which files set X'", "local-agent --help"):
            with self.subTest(command):
                self.assertIsNone(b.bash(command))
        self.assertIn("piigate_analyze", b.bash("piigate analyze --mail x"))
        # the tool name in arguments and text is data, not a call
        for command in (
            "grep -n dir tools/local-agent/local-agent $HOME/.config/x",
            "python3 - <<'EOF'\nprint('local-agent on $D and ~/.config')\nEOF\ngrep -c x notes.md",
            'T="python3 notes.py"; $T log 200 "local-agent on $D" "denied"',
            'git commit -qm "local-agent: fix $X"',
            "echo 'description `local-agent --dir $D`'",
            "ls ~/.config tools/local-agent",
            "cat > notes.md <<'EOF'\nRun local-agent --dir ~/repo first.\nEOF",
        ):
            with self.subTest(command):
                self.assertIsNone(b.bash(command))
        for command in (
            "A=local-agent; $A --dir ~/repo x",
            "A=local-agent; eval $A --dir ~/repo x",
            'echo "$(local-agent --dir $D x)"',
            "echo \"result: `local-agent --dir $D x`\"",
            "bash <<'EOF'\nlocal-agent --dir $D x\nEOF",
            "true\nlocal-agent --dir $D x",
            "timeout 60 local-agent --dir $D x",
            "env X=1 local-agent --dir $D x",
            "f() { local-agent --dir $D x; }; f",
            "find . -maxdepth 0 -exec local-agent --dir {} x \\;",
            "find ~/repo -maxdepth 0 -exec local-agent --dir {} x +",
            f"cat <<EOF | local-agent --dir {w} -\ntext\nEOF",
            "2>/dev/null local-agent --dir $D x",
            '"local-agen""t" --dir $D x',
            "l\\ocal-agent --dir $D x",
            'a=(local-agent --dir $D x); "${a[@]}"',
            "exec local-agent --dir $D x",
            "sudo -u someone local-agent --dir $D x",
            "echo \"it's $(local-agent --dir $D x)\"",
            'echo $(local-agen""t --dir ~/repo x)',
        ):
            with self.subTest(command):
                self.assertIsNotNone(b.bash(command))
        mcp = LOCAL_AGENT_MCP
        self.assertIsNotNone(b.decision(mcp, {"dir": str(w / "project"), "task": "x"}))
        self.assertIsNotNone(b.decision(mcp, {"dir": str(TMP), "task": "x"}))  # contains a sensitive directory
        self.assertIsNotNone(b.decision(mcp, {"dir": str(ROOT), "profile": "phi", "task": "x"}))
        self.assertIsNone(b.decision(mcp, {"dir": str(ROOT), "task": "x"}))
        self.assertIsNone(gate.Gate(self.cfg, str(w)).decision("mcp__other__tool", {"dir": str(w)}))  # not configured

    def test_invoked_only_as_command(self):
        """The tool is denied only when it is RUN (first word, after | ; && || & $( `, as an argument of sh -c, eval,
        xargs, env, sudo, timeout, nice, find -exec; a heredoc fed to a shell) — not when its name is quoted text."""
        self.cfg["unfiltered_tools"] = [LOCAL_AGENT]
        b = gate.Gate(self.cfg, str(ROOT))
        allowed = (
            'for n in 1 2; do url=$(gh issue create -R o/r --title "Red teaming of piigate and local-agent" '
            "--body-file $n.md); echo $url; done",
            'git commit -m "local-agent: deny sh -c $(x)"',
            "bash -c 'echo \"local-agent is configured\"'",
            'printf "%s\\n" "local-agent $HOME"',
        )
        for command in allowed:
            with self.subTest(command):
                self.assertIsNone(b.bash(command))
        denied = (
            "x=$(local-agent --dir ~/repo q)",
            "echo ~/repo | xargs local-agent --dir",
            "sh -c 'local-agent --dir ~/repo q'",
            "nice -n 5 local-agent --dir $D q",
            "ls; local-agent --dir `pwd` q",
            "true || local-agent --dir $D q",
            "sleep 1 & local-agent --dir $D q",
        )
        for command in denied:
            with self.subTest(command):
                self.assertIsNotNone(b.bash(command))

    def test_sensors_on_local_agent_output(self):
        p = dt.PATIENTS[0]
        data = {
            "hook_event_name": "PostToolUse",
            "cwd": str(TMP),
            "tool_name": LOCAL_AGENT_MCP,
            "tool_input": {"dir": str(ROOT), "task": "x"},
            "tool_response": [{"type": "text", "text": f"W pliku jest PESEL {p['pesel']}."}],
        }
        set_config({"unfiltered_tools": [LOCAL_AGENT]})
        try:
            self.assertNotIn(p["pesel"], json.dumps(hook("filter", data)))
            # gate: the MCP form on a sensitive directory
            pre = dict(data, hook_event_name="PreToolUse", tool_input={"dir": str(TMP), "task": "x"})
            self.assertEqual(hook("gate", pre)["hookSpecificOutput"]["permissionDecision"], "deny")
        finally:
            set_config(None)
        # not configured (default: no unfiltered tools) — an unrelated MCP tool: both hooks return nothing
        self.assertIsNone(hook("filter", data))
        self.assertIsNone(hook("gate", dict(data, hook_event_name="PreToolUse", tool_input={"dir": str(TMP)})))

    def test_retry_without_structured_output(self):
        """The first run answers in prose (exit 0, no JSON object) → one retry; prose twice → an error."""
        counter = TMP / "fake-agent-counter"
        counter.unlink(missing_ok=True)
        script = TMP / "fake-agent-retry"
        resp = {"sensitive_data": [], "columns_to_mask": [], "fragments_to_mask": [], "summary": "ok", "answer": ""}
        script.write_text(
            "#!/usr/bin/env bash\ncat >/dev/null\n"
            f"if [[ ! -e {counter} ]]; then touch {counter}; "
            "echo 'Sure! The file contains a list of prescriptions.'; exit 0; fi\n"
            f"echo '{json.dumps(resp)}'\n",
            encoding="utf-8",
        )
        script.chmod(0o700)
        self.cfg["analysis"] = {"agent_command": [str(script)], "timeout_s": 60}
        folder = analysis.work_dir(self.cfg)
        try:
            self.assertEqual(analysis.run_agent(folder, "", self.cfg)["summary"], "ok")
            self.assertTrue(counter.exists())
            prose = TMP / "fake-agent-prose"
            prose.write_text("#!/usr/bin/env bash\ncat >/dev/null\necho 'Just prose.'\n", encoding="utf-8")
            prose.chmod(0o700)
            self.cfg["analysis"]["agent_command"] = [str(prose)]
            with self.assertRaises(FilterError) as e:
                analysis.run_agent(folder, "", self.cfg)
            self.assertIn("not a JSON object", str(e.exception))
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_analyze_data_structured(self):
        if not PRESIDIO:
            self.skipTest(PRESIDIO_SKIP)
        script = TMP / "fake-agent-structured"
        p = dt.PATIENTS[1]
        resp = {"sensitive_data": [{"category": "PESEL", "where": f"wiersz {p['surname']}", "count": 3}],
               "columns_to_mask": [], "fragments_to_mask": [],
               "summary": f"Lista recept, m.in. {p['first_name']} {p['surname']}", "answer": "3 wiersze"}
        script.write_text(f"#!/usr/bin/env bash\ncat >/dev/null\ncat <<'K'\n{json.dumps(resp, ensure_ascii=False)}\nK\n")
        script.chmod(0o700)
        self.cfg["analysis"] = {"agent_command": [str(script)], "timeout_s": 60}
        d = analysis.analyze_data(FILES["csv"].name, FILES["csv"].read_bytes(), self.cfg, question="ile?")
        self.assertEqual(leaks(json.dumps(d, ensure_ascii=False)), [])
        self.assertEqual(d["model"]["answer"], "3 wiersze")
        self.assertEqual(d["model"]["sensitive_data"][0]["count"], 3)
        self.assertTrue(d["copies"]["files"])
        self.assertIsInstance(d["time_s"], float)
        self.assertEqual(analysis.report(d).count("## "), 4)


class TestContentVerdict(unittest.TestCase):
    """Content-based gate: outside sensitive directories an extension is only a reason to check the content with the rules."""

    SCHEMA = (
        "CREATE TABLE screens (\n  id INTEGER PRIMARY KEY,\n  nazwa TEXT NOT NULL,\n  status INTEGER DEFAULT 0,\n"
        "  utworzono TEXT DEFAULT '2026-10-25 12:00'\n);\nCREATE INDEX screens_status ON screens(status);\n"
    )
    UPDATE = "UPDATE screens SET status = 3, opis = 'proxy i kontenery, audyt WWW' WHERE id IN (12, 355);\n"

    def setUp(self):
        self.folder = TMP / "content-verdict"
        self.folder.mkdir(exist_ok=True)
        (Path(os.environ["PIIGATE_DATA_DIR"]) / "verdicts.json").unlink(missing_ok=True)
        self.b = gate.Gate(CONFIG, str(self.folder))
        p = dt.PATIENTS[0]
        self.files = {
            "schemat": self._file("0001_schemat.sql", self.SCHEMA),
            "update": self._file("update.sql", self.UPDATE),
            "pesel": self._file("pesele.csv", "id;pesel\n1;44051401359\n"),
            "email": self._file("kontakty.csv", f"id;kontakt\n1;{p['email']}\n"),
            "nazwisko": self._file("osoby.csv", f"id;osoba\n1;{p['first_name']} {p['surname']}\n"),
            "dump": self._file(
                "klienci.dump",
                "INSERT INTO klient VALUES "
                + ",".join(f"('{q['first_name']} {q['surname']}', '{q['email']}')" for q in dt.PATIENTS)
                + ";\n",
            ),
        }

    def _file(self, name: str, content: str) -> Path:
        p = self.folder / name
        p.write_text(content, encoding="utf-8")
        return p

    def decision(self, tool, tool_input):
        return gate.Gate(CONFIG, str(self.folder)).decision(tool, tool_input)

    def test_read_cat_cp_by_content(self):
        for k in ("schemat", "update"):
            with self.subTest(k):
                self.assertIsNone(self.decision("Read", {"file_path": str(self.files[k])}))
                self.assertIsNone(self.decision("Edit", {"file_path": str(self.files[k])}))
                self.assertIsNone(self.decision("Bash", {"command": f"cat {self.files[k]}"}))
                self.assertIsNone(
                    self.decision(
                        "Bash", {"command": f"npx wrangler d1 execute example-db --remote --file={self.files[k]}"}
                    )
                )
        self.assertIsNone(self.decision("Bash", {"command": "cp update.sql /tmp/copy-of-update.sql"}))  # the target does not exist
        self.assertIsNone(self.decision("Bash", {"command": "python3 gen.py > new.sql"}))  # write only
        for k in ("pesel", "email", "nazwisko", "dump"):
            with self.subTest(k):
                reason = self.decision("Read", {"file_path": str(self.files[k])})
                self.assertIsNotNone(reason)
                self.assertIn("contains personal data", reason)
                self.assertEqual(leaks(reason), [])  # categories and counts, no values
                self.assertIsNotNone(self.decision("Bash", {"command": f"cat {self.files[k]}"}))
                self.assertIsNotNone(self.decision("Bash", {"command": f"cp {self.files[k]} /tmp/x.txt"}))

    def test_bash_cautious(self):
        cases = {
            "cat missing.sql": True,  # no such file — the content cannot be checked
            "cat *.sql": True,  # glob
            "curl -s https://example.com/export > update.sql; cat update.sql": True,
            "curl -s https://example.com/e.csv": True,  # a URL with an extension — data from the network, not a file
            "curl -s https://example.com/export | tee new.csv | head": False,  # tee writes; the sensors run on the output
            "cp -t /tmp pesele.csv": True,
            "head -3 update.sql 0001_schemat.sql": False,
            "head -3 update.sql pesele.csv": True,
            "git add update.sql": False,
        }
        for command, denial in cases.items():
            with self.subTest(command):
                self.assertEqual(self.decision("Bash", {"command": command}) is not None, denial)

    def test_sensitive_dirs_unchanged(self):
        home = str(Path.home())
        self.assertIsNotNone(self.decision("Read", {"file_path": f"{home}/Documents/piigate/Sensitive-data/schemat.sql"}))
        self.assertIsNotNone(self.decision("Bash", {"command": "ssh prod 'mysql -e \"select 1\"'"}))

    def test_grep_by_glob(self):
        self.assertIsNotNone(self.decision("Grep", {"pattern": "x", "glob": "*.csv", "path": str(self.folder)}))
        clean_dir = self.folder / "clean"
        clean_dir.mkdir(exist_ok=True)
        shutil.copy(self.files["schemat"], clean_dir / "a.sql")
        self.assertIsNone(self.decision("Grep", {"pattern": "x", "glob": "*.sql", "path": str(clean_dir)}))
        self.assertIsNone(self.decision("Grep", {"pattern": "x", "type": "sql", "path": str(clean_dir)}))
        self.assertIsNotNone(self.decision("Grep", {"pattern": "x", "type": "csv", "path": str(self.folder)}))
        self.assertIsNone(self.decision("Grep", {"pattern": "x", "path": str(self.files["update"])}))
        # security review: the file list from rg (the same globs), an exclusion together with a type, braces
        for tool_input in ({"glob": "!*.sql", "type": "csv"}, {"glob": "*.{sql,csv}"}, {"glob": "*.sql,*.csv"}):
            with self.subTest(tool_input):
                self.assertIsNotNone(self.decision("Grep", {"pattern": "x", "path": str(self.folder), **tool_input}))
        self.assertIsNone(self.decision("Grep", {"pattern": "x", "path": str(clean_dir), "glob": "!*.csv"}))

    def test_formats_and_limits(self):
        s = verdict.Judge(CONFIG)
        self.assertEqual(s.file(str(FILES["pdf"])).result, verdict.PERSONAL)
        self.assertEqual(s.file(str(FILES["xlsx"])).result, verdict.PERSONAL)
        self.assertEqual(s.file(str(FILES["eml"])).result, verdict.UNKNOWN)  # mail — always through piigate
        self.assertEqual(s.file(str(self._file("old.xls", "x"))).result, verdict.UNKNOWN)
        self.assertEqual(s.file(str(self._file("bad.xlsx", "not a zip"))).result, verdict.UNKNOWN)
        cfg = json.loads(json.dumps(CONFIG))
        cfg["sources"]["content_check"] = {"limit_mb": 0}
        self.assertEqual(verdict.Judge(cfg).file(str(self.files["update"])).result, verdict.UNKNOWN)
        cfg["sources"]["content_check"] = {"enabled": False}
        self.assertIsNotNone(gate.Gate(cfg, str(self.folder)).decision("Read", {"file_path": str(self.files["update"])}))

    def test_verdict_cache(self):
        s = verdict.Judge(CONFIG)
        self.assertEqual(s.file(str(self.files["update"])).result, verdict.CLEAN)
        file = Path(os.environ["PIIGATE_DATA_DIR"]) / "verdicts.json"
        self.assertEqual(len(json.loads(file.read_text())["entries"]), 1)
        self.assertTrue(self.b.path_kind(str(file)) == "protected")
        self.files["update"].write_text(self.UPDATE + f"-- {dt.PATIENTS[1]['email']}\n", encoding="utf-8")
        self.assertEqual(verdict.Judge(CONFIG).file(str(self.files["update"])).result, verdict.PERSONAL)  # new sha256

    def test_no_false_positives(self):
        clean_texts = [
            "UPDATE s SET u = 'https://private-user-images.githubusercontent.com/44051401/44051401359-1a2b.gif' WHERE id=7;",
            "INSERT INTO h VALUES ('a44051401359f', 'sha 9f8e44051401359');",  # glued to a letter — a hash
            "INSERT INTO u VALUES ('admin@example.com'), ('x@demo.localhost');",
            "CREATE USER 'ro'@'127.0.0.1'; GRANT SELECT ON *.* TO 'ro'@'10.0.0.5';",
            "logowanie z 203.0.113.56 (documentation range, RFC 5737)",
        ]
        for t in clean_texts:
            with self.subTest(t):
                self.assertEqual(verdict.check_text(t, CONFIG), {})
        dirty = {
            "https://shop.example/order?pesel=44051401359": "PESEL",  # a query parameter, not a path
            f"kontakt: {dt.PATIENTS[0]['email']}": "EMAIL",
            "logowanie z 1.2.3.4": "IP",
        }
        for t, type_ in dirty.items():
            with self.subTest(t):
                self.assertIn(type_, verdict.check_text(t, CONFIG))

    def test_hooks(self):
        result = hook(
            "gate",
            {"cwd": str(self.folder), "tool_name": "Read", "tool_input": {"file_path": str(self.files["schemat"])}},
        )
        self.assertIsNone(result)
        # the file changed between the gate and the read — the filter checks what came back
        p = dt.PATIENTS[2]
        content = f"INSERT INTO k VALUES ('{p['first_name']} {p['surname']}', '{p['email']}');\n"
        result = hook(
            "filter",
            {
                "cwd": str(self.folder),
                "tool_name": "Read",
                "tool_input": {"file_path": str(self.files["schemat"])},
                "tool_response": {
                    "type": "text",
                    "file": {
                        "filePath": str(self.files["schemat"]),
                        "content": content,
                        "numLines": 1,
                        "startLine": 1,
                        "totalLines": 1,
                    },
                },
            },
        )
        self.assertEqual(leaks(json.dumps(result, ensure_ascii=False)), [])
        self.assertIn("contains personal data", json.dumps(result, ensure_ascii=False))
        # Bash: the file is clean at the gate, then overwritten in the same command — the filter checks the output
        bash = {
            "cwd": str(self.folder),
            "tool_name": "Bash",
            "tool_input": {"command": "wget -q https://example.com/export -O update.sql; cat update.sql"},
            "tool_response": {"stdout": content, "stderr": "", "interrupted": False, "isImage": False},
        }
        result = hook("filter", bash)
        self.assertEqual(leaks(json.dumps(result, ensure_ascii=False)), [])
        self.assertIn("contains personal data", json.dumps(result, ensure_ascii=False))
        bash["tool_input"] = {"command": "cat update.sql"}
        bash["tool_response"] = dict(bash["tool_response"], stdout=self.UPDATE)
        self.assertIsNone(hook("filter", bash))


class TestProjectFilters(unittest.TestCase):
    """Project filters (.claude/piigate.json): patterns with labels, columns, tables, directories — tightening only."""

    PROJECT_FILE = {
        "_description": "test project filters",
        "patterns": [{"pattern": r"\bPT-\d{6}\b", "label": "PATIENT_ID", "description": "patient number"}],
        "sensitive_columns": ["first_name"],
        "directories": ["var/exports"],
        "tables": ["patient"],
    }

    def setUp(self):
        self.folder = TMP / f"project-filters-{self._testMethodName}"
        shutil.rmtree(self.folder, ignore_errors=True)
        (self.folder / ".claude").mkdir(parents=True)
        (self.folder / "src" / "deep").mkdir(parents=True)
        shutil.rmtree(Path(os.environ["PIIGATE_DATA_DIR"]) / "projects", ignore_errors=True)
        self.write_project(self.PROJECT_FILE)

    def write_project(self, data) -> None:
        content = data if isinstance(data, str) else json.dumps(data)
        (self.folder / ".claude" / "piigate.json").write_text(content, encoding="utf-8")

    def cfg(self, cwd: Path | None = None) -> dict:
        return config.load(str(cwd or self.folder / "src" / "deep"))

    def decision(self, tool, tool_input):
        k = self.cfg()
        return gate.Gate(k, str(self.folder)).decision(tool, tool_input)

    def test_detection_and_patterns(self):
        k = self.cfg()
        self.assertEqual(k["project"]["root"], os.path.realpath(self.folder))
        saved_dir = os.environ.pop("CLAUDE_PROJECT_DIR", None)
        try:
            self.assertIsNone(config.load(str(TMP))["project"])  # outside the project — no filters
            # `cd /` in a project session does not disable the filters: the agent cannot change the session directory
            # (CLAUDE_PROJECT_DIR)
            os.environ["CLAUDE_PROJECT_DIR"] = str(self.folder)
            self.assertEqual(verdict.check_text("PT-123456", config.load("/")), {"PATIENT_ID": 1})
        finally:
            os.environ.pop("CLAUDE_PROJECT_DIR", None)
            if saved_dir is not None:
                os.environ["CLAUDE_PROJECT_DIR"] = saved_dir
        number_text = "Wizyta PT-123456 przełożona na jutro.\n"
        self.assertEqual(verdict.check_text(number_text, k), {"PATIENT_ID": 1})
        self.assertEqual(verdict.check_text(number_text, CONFIG), {})  # without the project the rules do not know it
        from piigate import sensors

        masked, n = sensors.mask(number_text, k)
        self.assertEqual(n, 1)
        self.assertNotIn("PT-123456", masked)
        self.assertIn("[PATIENT_ID hidden by piigate]", masked)
        result, counts = text.filter_text(number_text, k, rules_only=True)
        self.assertNotIn("PT-123456", result)
        self.assertRegex(result, r"PATIENT_ID_\d+")
        # gate verdict: a .sql file with a patient number → deny; the verdict cache tells projects apart
        file = self.folder / "src" / "wizyty.sql"
        file.write_text(f"UPDATE wizyta SET status = 2 WHERE pacjent = '{'PT-123456'}';\n", encoding="utf-8")
        self.assertEqual(verdict.Judge(CONFIG).file(str(file)).result, verdict.CLEAN)
        self.assertEqual(verdict.Judge(k).file(str(file)).result, verdict.PERSONAL)
        reason = self.decision("Read", {"file_path": str(file)})
        self.assertIn("PATIENT_ID 1", reason)
        self.assertNotIn("PT-123456", reason)

    def test_columns_directories_extensions(self):
        set_config({"tables": {"plain_columns": ["first_name", "kwota"]}})
        try:
            k = self.cfg()
            self.assertEqual(k["tables"]["plain_columns"], ["kwota"])  # a project cannot reveal it
        finally:
            set_config(None)
        k = self.cfg()
        self.assertIn("SENSITIVE_COLUMN", verdict.check_text("id;first_name\n1;Xq\n", k))
        self.assertIn("SENSITIVE_COLUMN", verdict.check_text("INSERT INTO k (id, first_name) VALUES (1, 'Xq');", k))
        self.assertEqual(verdict.check_text("CREATE TABLE k (id INT, first_name TEXT);\n", k), {})
        tab = table.from_csv("id;first_name;kwota\n1;Xq;12.50\n2;Yw;3.10\n")
        self.assertIn("sensitive column (project filters)", table.describe([tab], k, source="test"))
        decisions = anonymization.column_decisions(tab, k, set())
        self.assertEqual(decisions[1][0], "pseudonym")
        (self.folder / "var" / "exports").mkdir(parents=True)
        (self.folder / "var" / "exports" / "lista.txt").write_text("x\n", encoding="utf-8")
        self.assertIn("sensitive data directory", self.decision("Read", {"file_path": "var/exports/lista.txt"}))
        self.assertIsNone(self.decision("Read", {"file_path": "src/wizyty.txt"}))
        # Bash patterns with a sensitive directory in the repo: only those that can reach it
        for command, denial in {
            "ls *.md": False,
            "cat src/*.txt": False,
            "cat var/*": True,
            "cat v*/eksporty/lista.txt": True,
            "cat var/expo?ts/lista.txt": True,
            "grep -r x *": True,
        }.items():
            with self.subTest(command):
                self.assertEqual(self.decision("Bash", {"command": command}) is not None, denial)

    def test_tables_only_via_ssh(self):
        cases = {
            "ssh prod \"sqlite3 app.db 'SELECT * FROM patient'\"": True,
            "ssh prod \"sqlite3 app.db 'SELECT * FROM patient'\" 2>&1 | piigate table": False,
            "ssh prod \"docker exec db mycli -e 'select id from app.patient limit 5'\"": True,
            "ssh prod 'sqlite3 app.db \"SELECT * FROM visit\"'": False,  # a table not on the list
            "sqlite3 var/app.db 'SELECT * FROM patient'": False,  # local — sandbox, full control
            "docker exec db psql -c 'select * from patient'": False,
        }
        for command, denial in cases.items():
            with self.subTest(command):
                self.assertEqual(self.decision("Bash", {"command": command}) is not None, denial)

    def test_invalid_file_default_deny(self):
        invalid = {
            "loosening field": {"exempt_directories": ["~/Documents/piigate/Sensitive-data"]},
            "plain words": {"plain_words": ["Kowalski"]},
            "bad syntax": {"patterns": [{"pattern": "PT-(\\d{6}", "label": "PATIENT_ID"}]},
            "expensive": {"patterns": [{"pattern": "(a+)+$", "label": "BAD"}]},
            "alternation in a repetition": {"patterns": [{"pattern": "(?:a|ab)*c", "label": "BAD"}]},
            "lookbehind": {"patterns": [{"pattern": "(?<=x)\\d+", "label": "BAD"}]},
            "matches empty": {"patterns": [{"pattern": "\\d*", "label": "BAD"}]},
            "bad label": {"patterns": [{"pattern": "PT-\\d{6}", "label": "pacjent"}]},
            "no upper bound": {"patterns": [{"pattern": "PT-\\d+", "label": "BAD"}]},
            "adjacent unbounded": {"patterns": [{"pattern": "\\d*\\d*\\d*x", "label": "BAD"}]},
            "product of bounds": {"patterns": [{"pattern": "(?:(?:a{1,40}){1,40}){1,40}", "label": "BAD"}]},
            "alternation in a (bounded) repetition": {"patterns": [{"pattern": "(?:a|aa){1,64}x", "label": "BAD"}]},
            "variable width in a repetition": {"patterns": [{"pattern": "(?:a{1,10}){1,10}x", "label": "BAD"}]},
            "adjacent variable": {"patterns": [{"pattern": "\\d{1,64}\\d{1,64}x", "label": "BAD"}]},
            "atomic group with variable content": {"patterns": [{"pattern": "(?>(?:a|aa){1,64})x", "label": "BAD"}]},
            "group conditional": {"patterns": [{"pattern": "(a)?(?(1)b|c)", "label": "BAD"}]},
            "too many characters": {"patterns": [{"pattern": "[" + "".join(chr(c) for c in range(0x100, 0x150)) + "]", "label": "BAD"}]},
            "bad JSON": "{patterns: [",
        }
        file = str(self.folder / ".claude" / "piigate.json")
        for description, data in invalid.items():
            with self.subTest(description):
                shutil.rmtree(Path(os.environ["PIIGATE_DATA_DIR"]) / "projects", ignore_errors=True)
                self.write_project(data)
                self.assertIn("error", self.cfg()["project"])
                for tool, tool_input in (
                    ("Bash", {"command": "ls"}),
                    ("Read", {"file_path": str(self.folder / "README.md")}),
                    ("Grep", {"pattern": "x"}),
                ):
                    self.assertIn("the project filter file is invalid", self.decision(tool, tool_input))
                self.assertIsNotNone(self.decision("Edit", {"file_path": file}))  # the Edit result does not go through the filter
                for tool in ("Read", "Write"):
                    self.assertIsNone(self.decision(tool, {"file_path": file}))
                with self.assertRaises(FilterError):
                    text.filter_text("text", self.cfg(), rules_only=True)
        # bounded fixed-width repetitions and short alternations are fine
        for pat in (r"\b\d{3}(?:-\d{3}){2}\b", r"\b(?:PT|PX)-\d{6}\b", r"\bZAM/\d{4}/\d{5}\b", r"\b[A-Z]{2,3}\d{1,6}\b"):
            with self.subTest(pat):
                self.write_project({"patterns": [{"pattern": pat, "label": "CLUB_NUMBER"}]})
                self.assertNotIn("error", self.cfg()["project"])

    def test_cwd_error_keeps_session_filters(self):
        other = TMP / "project-filters-other"
        shutil.rmtree(other, ignore_errors=True)
        (other / ".claude").mkdir(parents=True)
        saved_dir = os.environ.get("CLAUDE_PROJECT_DIR")
        os.environ["CLAUDE_PROJECT_DIR"] = str(self.folder)
        try:
            # the agent in another directory makes an invalid project file linking to a file with a patient number
            data = self.folder / "src" / "notatka.txt"
            data.write_text("kontrola PT-777777\n", encoding="utf-8")
            (other / ".claude" / "piigate.json").symlink_to(data)
            k = config.load(str(other))
            self.assertIn("error", k["project"])
            self.assertEqual(verdict.check_text("PT-777777", k), {"PATIENT_ID": 1})  # the session filters still apply
            file = str(other / ".claude" / "piigate.json")
            self.assertIsNotNone(gate.Gate(k, str(other)).decision("Read", {"file_path": file}))  # a symlink — not exempt
            self.assertIsNotNone(gate.Gate(k, str(other)).decision("Bash", {"command": "ls"}))
            # a hard link is not exempt either
            (other / ".claude" / "piigate.json").unlink()
            os.link(data, other / ".claude" / "piigate.json")
            k = config.load(str(other))
            self.assertIsNotNone(gate.Gate(k, str(other)).decision("Read", {"file_path": file}))
            # a plain invalid file — the read is allowed, but content with a patient number is still hidden by the filter
            (other / ".claude" / "piigate.json").unlink()
            (other / ".claude" / "piigate.json").write_text("{bad json PT-777777", encoding="utf-8")
            k = config.load(str(other))
            self.assertIsNone(gate.Gate(k, str(other)).decision("Read", {"file_path": file}))
            result = hook(
                "filter",
                {
                    "cwd": str(other),
                    "tool_name": "Read",
                    "tool_input": {"file_path": file},
                    "tool_response": {
                        "type": "text",
                        "file": {"filePath": file, "content": "{bad json PT-777777", "numLines": 1, "startLine": 1, "totalLines": 1},
                    },
                },
            )
            self.assertNotIn("PT-777777", json.dumps(result, ensure_ascii=False))
        finally:
            if saved_dir is None:
                os.environ.pop("CLAUDE_PROJECT_DIR", None)
            else:
                os.environ["CLAUDE_PROJECT_DIR"] = saved_dir

    def test_entry_removal_requires_human(self):
        self.assertEqual(len(self.cfg()["project"]["patterns"]), 1)  # the first version — approved by itself
        appended = dict(self.PROJECT_FILE, sensitive_columns=["first_name", "last_name"])
        self.write_project(appended)
        self.assertEqual(self.cfg()["project"]["sensitive_columns"], ["first_name", "last_name"])
        self.write_project({"sensitive_columns": ["last_name"]})  # the model removes a pattern and a column
        p = self.cfg()["project"]
        self.assertEqual([w["label"] for w in p["patterns"]], ["PATIENT_ID"])  # still in force
        self.assertEqual(p["sensitive_columns"], ["first_name", "last_name"])
        self.assertTrue(p["pending"])
        (self.folder / ".claude" / "piigate.json").unlink()  # deleting the file does not loosen either
        self.assertEqual(len(self.cfg()["project"]["patterns"]), 1)
        self.write_project({"sensitive_columns": ["last_name"]})
        import cli as cli_mod

        os.environ["AI_AGENT"] = "1"
        try:
            current = os.getcwd()
            os.chdir(self.folder)
            try:
                self.assertEqual(cli_mod.main(["project", "approve"]), 4)  # an agent — denied
            finally:
                os.chdir(current)
        finally:
            del os.environ["AI_AGENT"]
        self.assertEqual(len(self.cfg()["project"]["patterns"]), 1)
        from piigate import project

        project.approve(str(self.folder))  # a human (piigate project approve)
        p = self.cfg()["project"]
        self.assertEqual((p["patterns"], p["sensitive_columns"], p["pending"]), ([], ["last_name"], {}))
        # the snapshot in the protected directory — out of the model's reach
        snapshot = next((Path(os.environ["PIIGATE_DATA_DIR"]) / "projects").glob("*.json"))
        self.assertIsNotNone(gate.Gate(self.cfg(), str(self.folder)).decision("Read", {"file_path": str(snapshot)}))

    def test_human_only_and_false_positives(self):
        cases = {
            "piigate reverse raport.md": True,
            "python3 lib/cli.py reverse raport.md": True,
            "bash -c 'piigate reverse raport.md'": True,
            "echo $(piigate reverse x)": True,
            "python3 -c \"import subprocess; subprocess.run(['piigate', 'reverse', 'x'])\"": True,
            "git commit -m 'piigate reverse: human only'": True,  # cautious — piigate followed by the subcommand
            "piigate project approve": True,
            "piigate project": False,
            "python3 notes.py log 200 local 'cli.py: reverse and approve from /dev/tty'": False,
            "git commit -m 'piigate: reverse the order of hints'": False,  # a mention, not a call
            "git commit -q -m 'filter: approve the snapshot, reverse is human only'": False,
            "git log --reverse --oneline | piigate text": False,  # the --reverse option is not the subcommand
            'python3 - "$f" <<\'EOF\'\nimport sys\nprint(sys.argv[1])\nEOF': False,
            "cat dane.c?v": True,
            "cat *.*": True,
            "cat x.[cC]sv": True,
        }
        for command, denial in cases.items():
            with self.subTest(command):
                self.assertEqual(gate.Gate(CONFIG, str(self.folder)).decision("Bash", {"command": command}) is not None, denial)

    def test_hooks(self):
        file = self.folder / "src" / "wizyty.sql"
        file.write_text("SELECT * FROM wizyta WHERE pacjent = 'PT-654321';\n", encoding="utf-8")
        result = hook("gate", {"cwd": str(self.folder), "tool_name": "Read", "tool_input": {"file_path": str(file)}})
        self.assertIn("PATIENT_ID", json.dumps(result, ensure_ascii=False))
        bash = {
            "cwd": str(self.folder / "src"),
            "tool_name": "Bash",
            "tool_input": {"command": "git log -1"},
            "tool_response": {"stdout": "naprawa dla PT-654321\n", "stderr": "", "interrupted": False, "isImage": False},
        }
        result = json.dumps(hook("filter", bash), ensure_ascii=False)
        self.assertNotIn("PT-654321", result)
        self.assertIn("[PATIENT_ID hidden by piigate]", result)
        self.write_project({"plain_words": ["x"]})
        result = hook("gate", {"cwd": str(self.folder), "tool_name": "Bash", "tool_input": {"command": "ls"}})
        self.assertIn("invalid", json.dumps(result, ensure_ascii=False))


class TestNameFilters(unittest.TestCase):
    """A project with a sensitive directory in its root ("Patient data"): a file name filter (--include=*.php, -name)
    is not a path — searching a code subdirectory must not be denied because of "." (an ancestor of the sensitive
    directory)."""

    def setUp(self):
        self.folder = TMP / "name-filters"
        shutil.rmtree(self.folder, ignore_errors=True)
        (self.folder / ".claude").mkdir(parents=True)
        (self.folder / "backend" / "src").mkdir(parents=True)
        (self.folder / "Patient data").mkdir()
        (self.folder / ".claude" / "piigate.json").write_text(
            json.dumps({"_description": "name filters test", "directories": ["Patient data"]}), encoding="utf-8"
        )
        shutil.rmtree(Path(os.environ["PIIGATE_DATA_DIR"]) / "projects", ignore_errors=True)

    def test_name_filter_is_not_path(self):
        b = gate.Gate(config.load(str(self.folder)), str(self.folder))
        cases = {
            "grep -ril -E 'altos|bloodwork' --include=*.php backend/src 2>/dev/null | head -30": False,
            "grep -r foo --include '*.php' --exclude-dir=vendor backend/src": False,
            "rg -g '*.php' foo backend/src": False,
            "rg --glob=*.php -t php foo backend": False,
            "find backend -name '*.php' -not -path '*/vendor/*'": False,
            "fd -e php . backend": False,
            # still denied: a data extension in the filter, recursion from the project root, the sensitive directory itself
            "grep -r foo --include=*.csv backend/src": True,
            "rg -g '*.xlsx' foo backend": True,
            "grep -r foo .": True,
            "grep -r foo --include=*.php .": True,
            "find . -name '*.php'": True,
            "grep -r foo 'Patient data'": True,
        }
        for command, denial in cases.items():
            with self.subTest(command):
                self.assertEqual(b.decision("Bash", {"command": command}) is not None, denial)

    def test_no_path_means_cwd_and_ignore_excludes_dir(self):
        """rg/fd without a path search cwd (with the sensitive directory) — denied; an .ignore listing that directory →
        allowed (rg and fd honour it), unless the command disables ignore files. grep does not know .ignore."""
        b = lambda: gate.Gate(config.load(str(self.folder)), str(self.folder))  # noqa: E731
        no_ignore = {"rg foo": True, "rg foo .": True, "fd php": True, "grep -r foo": True, "rg foo backend": False}
        for command, denial in no_ignore.items():
            with self.subTest(command):
                self.assertEqual(b().decision("Bash", {"command": command}) is not None, denial)
        (self.folder / ".ignore").write_text("# patient data\n/Patient data/\n", encoding="utf-8")
        with_ignore = {
            "rg foo": False,
            "rg -i -g '*.php' foo .": False,
            "fd -e php": False,
            "rg --no-ignore foo": True,
            "rg -uu foo": True,
            "rg -g '*.csv' foo": True,
            "grep -r foo .": True,
            "rg foo 'Patient data'": True,
        }
        for command, denial in with_ignore.items():
            with self.subTest(command):
                self.assertEqual(b().decision("Bash", {"command": command}) is not None, denial)
        (self.folder / ".ignore").write_text("/Patient data/\n!/Patient data/jawne.csv\n", encoding="utf-8")
        self.assertIsNotNone(b().decision("Bash", {"command": "rg foo"}))  # a negation in .ignore — no exception


class TestDetectionEdgeCases(unittest.TestCase):
    """Detection edge cases: titles before a surname, institutions, field labels, KRS, driving licence, IPv6, foreign
    phone numbers, common nouns that NER takes for persons."""

    def filters(self):
        """(label, rules_only): the rules always, with Presidio — when it is running."""
        return [("rules", True)] + ([("presidio", False)] if PRESIDIO else [])

    def test_titles_and_labels_before_surname(self):
        t = (
            "Dr hab. Testowy Zmyślak, inż. Gerwazy Wymyślony, ks. Bonifacy Zmyślnik, prof. Ksawery Zmyślony.\n"
            "Podpis: Hieronim Wydumany. Autorka: Bogumiła Wydumana. Opiekun: Gerwazy Zmyślnik.\n"
        )
        names = ["Zmyślak", "Gerwazy", "Wymyślony", "Bonifacy", "Zmyślnik", "Ksawery", "Zmyślony", "Hieronim",
                 "Wydumany", "Bogumiła", "Wydumana", "Testowy"]
        for description, only in self.filters():
            with self.subTest(description):
                result, _ = text.filter_text(t, CONFIG, rules_only=only)
                self.assertEqual([n for n in names if n in result], [], result)
                self.assertIn("Dr hab.", result)
                self.assertIn("Podpis:", result)

    def test_institutions_are_not_patients(self):
        t = "Szpital Wolski, Szpitala Wolskiego i Uniwersytet Warszawski. Kierownik Poradni oraz Dyrektor Szpitala.\n"
        for description, only in self.filters():
            with self.subTest(description):
                result, _ = text.filter_text(t, CONFIG, rules_only=only)
                self.assertNotIn("PERSON_", result)
                if not only:
                    self.assertIn("ORG_", result)
        self.assertEqual(verdict.check_text(t, CONFIG), {})

    def test_field_label_and_lowercase_outside_person(self):
        t = "Imię: Bożydar Nazwisko: Testowy. Pacjentka zgłosiła się rano, dr hab. przyjął ją o 9.\n"
        for description, only in self.filters():
            with self.subTest(description):
                result, _ = text.filter_text(t, CONFIG, rules_only=only)
                self.assertIn("Nazwisko:", result)
                self.assertNotIn("Bożydar", result)
                self.assertNotIn("Testowy", result)
                self.assertIn("zgłosiła się", result)
        self.assertEqual(verdict.check_text("Pacjentka zgłosiła się rano, dr hab. przyjął ją o 9.\n", CONFIG), {})

    def test_numbers_krs_driving_license_ipv6_foreign_phone(self):
        t = (
            "KRS: 0000123456, prawo jazdy nr ABC12345, tel. +49 30 1234567, "
            "IPv6 2a00:1450:4001:82a::200e, spotkanie o 10:30, adres MAC AA:BB:CC:DD:EE:FF.\n"
        )
        for description, only in self.filters():
            with self.subTest(description):
                result, _ = text.filter_text(t, CONFIG, rules_only=only)
                for value in ("0000123456", "ABC12345", "1234567", "2a00:1450"):
                    self.assertNotIn(value, result)
                for plain in ("KRS", "10:30", "AA:BB:CC:DD:EE:FF"):
                    self.assertIn(plain, result)
        counter = verdict.check_text(t, CONFIG)
        for type_ in ("NIP", "DOCUMENT", "PHONE", "IP"):
            self.assertIn(type_, counter)
        # a documentation / private / loopback address with a port and a time of day are not personal data
        self.assertEqual(
            verdict.check_text("listen [::1]:80; 127.0.0.1/::1:8765 fd00::5 2001:db8::1 ::ffff:127 o 12:45:30\n", CONFIG),
            {},
        )

    def test_docs_without_false_persons(self):
        """The labels "autor/podpis/kontakt" without a colon are ordinary words in documentation (gate verdict)."""
        t = (
            "biblioteka Node (autor Nodemailera), podpis DKIM, czy działa podpis DNSSEC. Autor PR wkleja tekst.\n"
            "## Kontakt\n\nPytania do zespołu. Kierownik projektu zatwierdza.\n"
        )
        self.assertEqual(verdict.check_text(t, CONFIG), {})

    @unittest.skipUnless(PRESIDIO, PRESIDIO_SKIP)
    def test_common_nouns_are_not_persons(self):
        result, _ = text.filter_text("Mama Zenobii przyszła z Babcią. Senior otrzymał skierowanie.\n", CONFIG)
        self.assertNotIn("Zenobii", result)
        self.assertIn("Babcią", result)
        self.assertIn("Senior", result)

    def test_gate_heredoc_with_sys_argv(self):
        """A false alarm: a script in a heredoc with `p=sys.argv[1]` and a pattern in an argument."""
        command = (
            "cd docs && python3 - \"$Z/notes.md\" <<'EOF'\nimport re,sys\np=sys.argv[1]; "
            "t=open(p,encoding='utf-8').read()\nopen(p,'w').write(t)\nEOF\n"
            "python3 notes.py log 7 local \"review of \\`conf/*.json\\` and \\`other/try*.txt\\`\" \"OK\"\n"
        )
        self.assertIsNone(gate.Gate(CONFIG, str(ROOT)).decision("Bash", {"command": command}))


class TestProjectSearch(unittest.TestCase):
    """piigate_search: code in plain text, free text with data as pseudonyms, tables without content — also when the
    pattern is a surname."""

    def setUp(self):
        self.folder = TMP / "project-search"
        shutil.rmtree(self.folder, ignore_errors=True)
        (self.folder / ".claude").mkdir(parents=True)
        (self.folder / "backend" / "src").mkdir(parents=True)
        (self.folder / "notatki").mkdir()
        data = self.folder / "Patient data"
        (self.folder / ".claude" / "piigate.json").write_text(
            json.dumps({"_description": "project search test", "directories": ["Patient data"]}), encoding="utf-8"
        )
        shutil.rmtree(Path(os.environ["PIIGATE_DATA_DIR"]) / "projects", ignore_errors=True)
        self.files = dt.write_all(data)
        p, q = dt.PATIENTS[0], dt.PATIENTS[1]
        (self.folder / "backend" / "src" / "Recepty.php").write_text(
            "<?php\n// eksport recept do CSV\nfunction przelicz_recepty(array $wiersze): int\n{\n"
            "    return count($wiersze);\n}\n",
            encoding="utf-8",
        )
        (self.folder / "notatki" / "spotkanie.md").write_text(
            f"# Spotkanie\n\nRecepta pani {q['first_name']} {q['surname']} (PESEL {q['pesel']}) do wyjaśnienia.\n"
            f"Telefon kontaktowy: {q['phone']}.\n",
            encoding="utf-8",
        )
        (data / "uwagi.txt").write_text(
            f"Pan {q['first_name']} {q['surname']} dzwonił w sprawie recepty.\nOddzwonić: {q['phone']}.\n",
            encoding="utf-8",
        )
        (self.folder / "backend" / "zrzut.sql").write_text(
            "CREATE TABLE pacjent (id int, nazwisko text, telefon text);\n"
            f"INSERT INTO pacjent (id, nazwisko, telefon) VALUES (1, '{p['surname']}', '{p['phone']}');\n"
            f"COPY public.pacjent (id, nazwisko, telefon) FROM stdin;\n2\t{q['surname']}\t{q['phone']}\n\\.\n",
            encoding="utf-8",
        )
        self.cfg = config.load(str(self.folder))

    def tearDown(self):
        set_config(None)

    def search(self, pattern, **kw):
        from piigate import search

        kw.setdefault("path", str(self.folder))
        return search.search(pattern, kw.pop("cfg", self.cfg), **kw)

    def whole(self, w: dict) -> str:
        return w["report"] + json.dumps(w, ensure_ascii=False)

    def test_groups_code_plain(self):
        w = self.search("przelicz_recepty")
        self.assertEqual([(t["file"], t["line"]) for t in w["plain"]], [("backend/src/Recepty.php", 3)])
        self.assertIn("function przelicz_recepty", w["plain"][0]["text"])
        self.assertEqual(w["text"], [])
        self.assertEqual(w["tables"], [])

    def test_surname_pattern_without_leaks(self):
        q = dt.PATIENTS[1]
        cfg = self.cfg
        if not PRESIDIO:  # without Presidio group 2 is denied — groups 1 and 3 still work
            set_config(engine_down(timeout_s=2))
            cfg = config.load(str(self.folder))
        w = self.search(q["surname"], cfg=cfg, context=1)
        self.assertEqual(leaks(self.whole(w)), [])
        self.assertEqual(w["plain"], [])
        tables = {(t["file"], t["column"]) for t in w["tables"]}
        self.assertIn(("Patient data/recepty-pazdziernik.csv", "Pacjent"), tables)
        self.assertIn(("backend/zrzut.sql", "nazwisko"), tables)
        self.assertTrue(any(t["file"].startswith("Patient data/Recepty ") for t in w["tables"]))  # xlsx
        self.assertTrue(all(t["count"] >= 1 for t in w["tables"]))
        if PRESIDIO:
            self.assertIsNone(w["text_denied"])
            text_files = {t["file"] for t in w["text"]}
            for expected in ("notatki/spotkanie.md", "Patient data/uwagi.txt", "Patient data/mail-recepty.eml"):
                self.assertIn(expected, text_files)
            self.assertNotIn(q["surname"], w["report"])
        else:
            self.assertIsNotNone(w["text_denied"])

    def test_presidio_down_denies_only_group_2(self):
        set_config(engine_down(timeout_s=2))
        cfg = config.load(str(self.folder))
        w = self.search("recept|pacjent", cfg=cfg, ignore_case=True)
        self.assertEqual(leaks(self.whole(w)), [])
        self.assertEqual(w["text"], [])
        self.assertIn("Presidio", w["text_denied"])
        self.assertTrue(any(t["file"] == "backend/src/Recepty.php" for t in w["plain"]))
        self.assertTrue(any(t["file"] == "backend/zrzut.sql" for t in w["tables"]))

    def test_protected_and_glob_and_limit(self):
        from piigate import search

        protected_file = Path(os.environ["PIIGATE_CONFIG_DIR"])
        protected_file.mkdir(parents=True, exist_ok=True)
        (protected_file / "note.txt").write_text("MARKER_X1\n", encoding="utf-8")
        (self.folder / "backend" / "src" / "marker.php").write_text("<?php // MARKER_X1\n", encoding="utf-8")
        with self.assertRaises(FilterError):
            search.search("MARKER_X1", self.cfg, path=str(protected_file))
        w = self.search("MARKER_X1", path=str(TMP))  # an ancestor of the protected directory — filter files skipped
        self.assertEqual({t["file"] for t in w["plain"]}, {"project-search/backend/src/marker.php"})
        w = self.search("MARKER_X1|przelicz", glob=["*.php"], limit=1)
        self.assertEqual(len(w["plain"]), 1)
        self.assertTrue(w["truncated"])
        with self.assertRaises(FilterError):
            self.search("x", path="relative/path")
        with self.assertRaises(FilterError):
            self.search("(unclosed")

    def test_pattern_not_in_report(self):
        w = self.search(f"{dt.PATIENTS[2]['surname']}|Pomidorek")
        self.assertNotIn(dt.PATIENTS[2]["surname"], self.whole(w))
        self.assertIn("pattern 1", w["report"])

    def test_gate_suggests_search_tool(self):
        b = gate.Gate(self.cfg, str(self.folder))
        for command in ("grep -r foo .", "rg foo"):
            with self.subTest(command):
                self.assertIn("piigate_search", b.decision("Bash", {"command": command}) or "")


class TestProjectDataDirs(unittest.TestCase):
    """Sensitive data and copies in the project directory (session, git repo root) instead of the global ones; always
    with a .gitignore."""

    def setUp(self):
        self.base = TMP / f"project-dirs-{self._testMethodName}"
        shutil.rmtree(self.base, ignore_errors=True)
        self.proj = self.base / "project"
        (self.proj / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.proj)], check=True)
        self.session = os.environ.pop("CLAUDE_PROJECT_DIR", None)

    def tearDown(self):
        os.environ.pop("CLAUDE_PROJECT_DIR", None)
        if self.session is not None:
            os.environ["CLAUDE_PROJECT_DIR"] = self.session

    def cfg(self) -> dict:
        return config.load(str(self.proj / "src"))

    def test_project_directories(self):
        k = self.cfg()
        p = os.path.realpath(self.proj)
        self.assertEqual(k["anonymization"]["directory"], f"{p}/Anonymized-data")
        self.assertIn(f"{p}/Sensitive-data", config.sensitive_dirs(k))
        self.assertIn(config.expand("~/Documents/piigate/Sensitive-data"), config.sensitive_dirs(k))  # the global one is still protected
        # the session directory comes first for copies; sensitive — both projects (the agent changes cwd)
        other = self.base / "session"
        other.mkdir()
        os.environ["CLAUDE_PROJECT_DIR"] = str(other)
        k = self.cfg()
        self.assertEqual(k["anonymization"]["directory"], f"{os.path.realpath(other)}/Anonymized-data")
        self.assertIn(f"{p}/Sensitive-data", config.sensitive_dirs(k))
        os.environ.pop("CLAUDE_PROJECT_DIR")
        # outside a project (no repo, no session) — the global directory
        outside = config.load(str(self.base))
        self.assertEqual(outside["anonymization"]["directory"], "{documents}/piigate/Anonymized-data")
        self.assertEqual(outside["in_project"], {"sensitive": [], "anonymized": []})
        # the home directory is not a project, not even as the session
        os.environ["CLAUDE_PROJECT_DIR"] = config.home_dir()
        self.assertEqual(config.project_roots(str(self.base)), [])

    def test_copy_in_project_with_gitignore(self):
        k = self.cfg()
        w = anonymization.anonymize("notatka.txt", b"Spotkanie we wtorek.\n", k)
        folder = self.proj / "Anonymized-data"
        self.assertEqual(os.path.realpath(w.directory.parent), os.path.realpath(folder))
        self.assertIn("*", (folder / ".gitignore").read_text(encoding="utf-8").splitlines())
        status = subprocess.run(
            ["git", "-C", str(self.proj), "status", "--porcelain", "--untracked-files=all"],
            capture_output=True, text=True, check=True,
        ).stdout
        self.assertEqual(status, "")
        # -o: the project's copy or sensitive directory — yes; the rest of the project — no
        w = anonymization.anonymize("a.txt", b"x", k, dest=str(self.proj / "Sensitive-data" / "result"))
        self.assertTrue((self.proj / "Sensitive-data" / ".gitignore").is_file())
        with self.assertRaises(FilterError):
            anonymization.anonymize("a.txt", b"x", k, dest=str(self.proj / "src" / "result"))

    def test_gate_and_gitignore_restore(self):
        sensitive, snapshots = self.proj / "Sensitive-data", self.proj / "Anonymized-data"
        sensitive.mkdir()
        snapshots.mkdir()
        (snapshots / ".gitignore").write_text("*.tmp\n", encoding="utf-8")  # someone else's .gitignore — `*` appended, not overwritten
        (sensitive / "lista.txt").write_text("Jan Kowalski\n", encoding="utf-8")
        (snapshots / "lista.csv").write_text("Osoba\nOSOBA_1\n", encoding="utf-8")
        b = gate.Gate(self.cfg(), str(self.proj / "src"))
        self.assertEqual((sensitive / ".gitignore").read_text(encoding="utf-8"), config.GITIGNORE)
        self.assertEqual((snapshots / ".gitignore").read_text(encoding="utf-8").splitlines()[0], "*.tmp")
        self.assertIn("*", (snapshots / ".gitignore").read_text(encoding="utf-8").splitlines())
        self.assertIsNotNone(b.decision("Read", {"file_path": str(sensitive / "lista.txt")}))
        self.assertIsNone(b.decision("Read", {"file_path": str(snapshots / "lista.csv")}))
        (sensitive / ".gitignore").unlink()
        gate.Gate(self.cfg(), str(self.proj / "src"))
        self.assertTrue((sensitive / ".gitignore").is_file())

    def test_symlinks_and_other_projects(self):
        # Anonymized-data as a symlink to a foreign directory — not a copy directory (no verdict exemption)
        foreign = self.base / "foreign"
        foreign.mkdir()
        (foreign / "export.csv").write_text("Imię,Nazwisko,PESEL\nJan,Kowalski,44051401458\n", encoding="utf-8")
        (self.proj / "Anonymized-data").symlink_to(foreign)
        k = self.cfg()
        self.assertNotIn(str(foreign), config.anonymized_dirs(k))
        self.assertIsNotNone(
            gate.Gate(k, str(self.proj)).decision("Read", {"file_path": str(self.proj / "Anonymized-data" / "export.csv")})
        )
        # a planted .gitignore → a file outside the directory: the hook does not write through a symlink
        dest = self.base / "bashrc"
        dest.write_text("echo ok\n", encoding="utf-8")
        (self.proj / "Sensitive-data").mkdir()
        (self.proj / "Sensitive-data" / ".gitignore").symlink_to(dest)
        gate.Gate(k, str(self.proj))
        self.assertEqual(dest.read_text(encoding="utf-8"), "echo ok\n")
        # Sensitive-data of another project (outside the session and the cwd repo) — protected by name
        other = self.base / "other-project" / "Sensitive-data"
        other.mkdir(parents=True)
        (other / "notatka.txt").write_text("x\n", encoding="utf-8")
        self.assertIsNotNone(gate.Gate(k, str(self.proj)).decision("Read", {"file_path": str(other / "notatka.txt")}))

    def test_project_search(self):
        """Grep over a project: without Sensitive-data or with it (its own .gitignore — rg skips it) passes; Glob (file
        names) and grep -r (does not know .gitignore) with an existing directory — denied."""
        b = lambda: gate.Gate(self.cfg(), str(self.proj))  # noqa: E731
        self.assertIsNone(b().decision("Grep", {"pattern": "x"}))
        self.assertIsNone(b().decision("Glob", {"pattern": "**/*.py"}))
        self.assertIsNone(b().decision("Bash", {"command": "rg x ."}))
        (self.proj / "Sensitive-data").mkdir()
        bb = b()  # creates the .gitignore
        self.assertIsNone(bb.decision("Grep", {"pattern": "x"}))
        self.assertIsNone(bb.decision("Bash", {"command": "rg x ."}))
        self.assertIsNotNone(bb.decision("Bash", {"command": "rg --no-ignore x ."}))
        self.assertIsNotNone(bb.decision("Glob", {"pattern": "**/*"}))
        self.assertIsNotNone(bb.decision("Bash", {"command": "grep -r x ."}))
        # a negation in .gitignore — rg could enter the directory
        (self.proj / "Sensitive-data" / ".gitignore").write_text("*\n!lista.txt\n", encoding="utf-8")
        self.assertIsNotNone(gate.Gate(self.cfg(), str(self.proj)).decision("Grep", {"pattern": "x"}))

    def test_model_work_dir_in_project(self):
        k = self.cfg()
        workdir = analysis.work_dir(k)
        try:
            self.assertEqual(workdir.parent.parent, Path(os.path.realpath(self.proj / "Sensitive-data")))
            self.assertTrue((self.proj / "Sensitive-data" / ".gitignore").is_file())
            self.assertEqual((self.proj / "Sensitive-data").stat().st_mode & 0o777, 0o700)
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


class TestPhiPlacesOnly(unittest.TestCase):
    """Denials only in PHI places: a repo without `.claude/piigate.json` has no content checks; listing names above
    a filter/sensitive directory; a directory name in a commit message."""

    def setUp(self):
        self.base = TMP / f"phi-places-{self._testMethodName}"
        shutil.rmtree(self.base, ignore_errors=True)
        self.repo = self.base / "repo"
        self.repo.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        # a package author's surname and an example IP address — in a repo without PHI not a reason to deny
        self.sql = self.repo / "statuses.sql"
        self.sql.write_text("-- autor: Jan Kowalski, serwer 8.8.8.8\nUPDATE x SET s = 1;\n", encoding="utf-8")
        self.session = os.environ.pop("CLAUDE_PROJECT_DIR", None)

    def tearDown(self):
        if self.session is not None:
            os.environ["CLAUDE_PROJECT_DIR"] = self.session

    def gate(self, cwd: Path | None = None, *, fresh: bool = True) -> gate.Gate:
        """fresh=True: the test repo in /tmp, created a moment ago, counts as public (the guards are off)."""
        c = str(cwd or self.repo)
        k = config.load(c)
        if fresh:
            k["sources"]["non_public"] = []
            k["sources"]["public_repo_min_age_h"] = 0
        return gate.Gate(k, c)

    def test_fresh_repo_and_downloads_not_public(self):
        """`git init` a moment ago, or a repo in /tmp, ~/Downloads — content still checked (the agent cannot lift the gate)."""
        self.assertIsNotNone(self.gate(fresh=False).decision("Read", {"file_path": str(self.sql)}))
        k = config.load(str(self.repo))
        k["sources"]["public_repo_min_age_h"] = 0  # age skipped, but /tmp is on the non-public list
        self.assertIsNotNone(gate.Gate(k, str(self.repo)).decision("Read", {"file_path": str(self.sql)}))

    def test_repo_without_phi(self):
        b = self.gate()
        self.assertIsNone(b.decision("Read", {"file_path": str(self.sql)}))
        self.assertIsNone(b.decision("Bash", {"command": f"cat {self.sql}"}))
        self.assertIsNone(b.decision("Bash", {"command": "ls statuses.*"}))
        self.assertIsNone(b.decision("Grep", {"pattern": "UPDATE", "glob": "*.sql"}))
        self.assertFalse(b.touches_extension(f"sed -n 1,5p {self.sql}"))
        self.assertTrue(b.touches_extension("ssh prod 'cat /var/x.sql'"))  # from a server — checked
        self.assertTrue(b.touches_extension("curl -s https://example.com/x.csv"))

    def test_phi_project_and_outside_repo(self):
        (self.repo / ".claude").mkdir()
        (self.repo / ".claude" / "piigate.json").write_text("{}", encoding="utf-8")
        self.assertIsNotNone(self.gate().decision("Read", {"file_path": str(self.sql)}))
        outside = self.base / "outside"
        outside.mkdir()
        file = outside / "export.sql"
        shutil.copy(self.sql, file)
        self.assertIsNotNone(self.gate(outside).decision("Read", {"file_path": str(file)}))

    def test_listing_names(self):
        b = self.gate()
        data = os.environ["PIIGATE_DATA_DIR"]  # the filter's protected directory (map) lies under TMP
        for command, denial in {
            f"ls -la {TMP} | grep -i -E 'narz|tools'": False,
            f"find {TMP} -maxdepth 3 -type d ( -iname '*narz*' -o -iname 'Tools' ) -not -path '*/.cache/*' 2>/dev/null": False,
            f"find {TMP} -maxdepth 2 -name '*.json'": False,  # only an ancestor of the filter directory — map file names are not data
            f"find {TMP} -name '*.json' -exec cat {{}} +": True,
            f"ls {data}": True,
            f"cat {data}/map.sqlite": True,
            "ls -la ~": False,
            "find ~ -maxdepth 3 -type d -iname '*narz*'": False,
            "find ~ -maxdepth 3 -type d ( -iname '*narz*' -o -iname 'Tools' ) -not -path '*/.cache/*' 2>/dev/null": False,
            "find ~ -maxdepth 3 -iname '*narz*'": True,  # file names in ~/Documents/piigate/Sensitive-data may be personal
            "ls -R ~": True,
            "tree -d -L 2 ~": False,
            "du -sh ~": False,
            "du -a ~": True,
            "find ~ -type d -o -name '*.pdf'": True,
            "find ~ ! -type d": True,
            "find ~ -type d -name ( -o -name x )": True,  # a parenthesis as the -name argument does not change the level
            "find ~ -type d -name ')' -o -name x": True,
            "find ~ -type d -print0": True,
            "du -ah ~": True,
            "du --al ~": True,
            "du -sh -d 1 ~": False,
            f"ls {TMP}; cat {data}/map.sqlite": True,
        }.items():
            with self.subTest(command):
                self.assertEqual(b.decision("Bash", {"command": command}) is not None, denial)

    def test_dir_name_in_commit(self):
        b = self.gate()
        self.assertIsNone(b.decision("Bash", {"command": 'git commit -q -m "copies in the project, Sensitive-data with .gitignore"'}))
        self.assertIsNone(b.decision("Bash", {"command": "git commit -am 'thunderbird.tmp — description'"}))
        self.assertIsNotNone(b.decision("Bash", {"command": "cat ~/Documents/piigate/Sensitive-data/x.txt"}))
        self.assertIsNotNone(b.decision("Bash", {"command": 'git commit -m "x" ~/Documents/piigate/Sensitive-data/a.txt'}))
        for command in (
            'git commit -m "$(cat ~/Documents/piigate/Sensitive-data/a.txt)"',
            "git commit -m \"`cat ~/Documents/piigate/Sensitive-data/a.txt`\"",
            'git commit -m "$(cat ~/.local/share/piigate/map.sqlite)"',
        ):
            with self.subTest(command):
                self.assertIsNotNone(b.decision("Bash", {"command": command}))

    def test_phi_project_nested(self):
        """A PHI project in a subdirectory of a repo without PHI: a search from the repo root and a glob check its files."""
        sub = self.repo / "subproject"
        (sub / ".claude").mkdir(parents=True)
        (sub / ".claude" / "piigate.json").write_text("{}", encoding="utf-8")
        shutil.copy(self.sql, sub / "export.sql")
        b = self.gate()
        self.assertIsNone(b.decision("Read", {"file_path": str(self.sql)}))  # a file of the repo without PHI — still read directly
        self.assertIsNotNone(b.decision("Read", {"file_path": str(sub / "export.sql")}))
        self.assertIsNotNone(b.decision("Grep", {"pattern": "UPDATE", "glob": "**/*.sql"}))
        self.assertIsNotNone(b.decision("Bash", {"command": "rg -t sql UPDATE ."}))
        self.assertTrue(b.touches_extension("cat subproject/*.sql"))
        self.assertTrue(b.touches_extension("cat sub*/*.sql"))  # the pattern prefix is not a directory
        # another repo without PHI, where the PHI project is only behind a symlink
        second = self.base / "second"
        second.mkdir()
        subprocess.run(["git", "init", "-q", str(second)], check=True)
        self.assertTrue(self.gate(second).is_public_tree(str(second)))
        (second / "link").symlink_to(sub)
        self.assertFalse(self.gate(second).is_public_tree(str(second)))

    def test_listing_without_globs_and_named_files(self):
        """The "names only" exemption does not cover globs/braces in the path or options reading names from a file."""
        b = self.gate()
        self.assertIsNotNone(b.decision("Bash", {"command": "ls ~/D*"}))  # the glob hits ~/Documents/piigate/Sensitive-data
        for command in ("ls ~/D*", "tree -d --fromfile ~", "du --files0-from=list ~", "ls ~/{a,b}", "ls -d ~"):
            with self.subTest(command):
                self.assertEqual(b._names_only(command, b._tokens(command)), command == "ls -d ~")

    def test_command_prefixes(self):
        """`X=1 grep -r … ~`, `env`/`nice`/`timeout` before a searcher — recursion must still be detected."""
        b = self.gate()
        for command in ("X=1 grep -r x ~", "env -i grep -r x ~", "nice -n 10 grep -r x ~", "timeout 5s rg x ~"):
            with self.subTest(command):
                self.assertIsNotNone(b.decision("Bash", {"command": command}))
        self.assertIsNone(b.decision("Bash", {"command": "LANG=C ls -la"}))

    def test_grep_with_glob_does_not_bypass_gitignore(self):
        (self.repo / "Sensitive-data").mkdir()
        os.environ["CLAUDE_PROJECT_DIR"] = str(self.repo)
        b = self.gate()
        self.assertTrue((self.repo / "Sensitive-data" / ".gitignore").is_file())
        self.assertIsNone(b.decision("Grep", {"pattern": "x"}))
        self.assertIsNotNone(b.decision("Grep", {"pattern": "x", "glob": "**/*.txt"}))
        self.assertIsNotNone(b.decision("Bash", {"command": "rg -g '*.txt' x ."}))
        self.assertIsNotNone(b.decision("Bash", {"command": "RIPGREP_CONFIG_PATH=/tmp/rc rg x ."}))
        (self.repo / ".ignore").write_text("!Sensitive-data/\n", encoding="utf-8")
        self.assertIsNotNone(self.gate().decision("Grep", {"pattern": "x"}))


PACKAGES_TSV = (
    "command\tgroup\tdnf\tapt\tdescription\n"
    "ripgrep\tsearch\tripgrep\tripgrep\tFast recursive search\n"
    "fd\tsearch\tfd-find\tfd-find\tSimple fast alternative to find\n"
    "bat\tview\tbat\tbat\tCat clone with syntax highlighting\n"
    "jq\tdata\tjq\tjq\tCommand-line JSON processor\n"
    "hunspell-pl\tspell\thunspell-pl\thunspell-pl\tHunspell Polish\n"
    "fonts-liberation\tfonts\tliberation-sans-fonts\tfonts-liberation\tLiberation Sans\n"
    "fonts-noto\tfonts\tgoogle-noto-sans-fonts\tfonts-noto-core\tNoto Sans\n"
    "shellcheck\tlint\tShellCheck\tshellcheck\tShell script analysis tool\n"
    "pandoc\tdocs\tpandoc\tpandoc\tUniversal document converter\n"
    "tesseract\tocr\ttesseract-langpack-pol\ttesseract-ocr-pol\tTesseract OCR Polish language data\n"
)


class TestFalseAlarms(unittest.TestCase):
    """Regressions for false denials: text arguments mentioning data file names, relative paths, a package list,
    globs under system directories, searches in a repo without PHI, mixed commands."""

    def setUp(self):
        self.base = TMP / f"false-alarms-{self._testMethodName}"
        shutil.rmtree(self.base, ignore_errors=True)
        self.session = os.environ.pop("CLAUDE_PROJECT_DIR", None)
        self.public = self.repo("public", phi=False)
        self.phi = self.repo("phi", phi=True)

    def tearDown(self):
        if self.session is not None:
            os.environ["CLAUDE_PROJECT_DIR"] = self.session

    def repo(self, name: str, *, phi: bool) -> Path:
        r = self.base / name
        r.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(r)], check=True)
        (r / "packages.tsv").write_text(PACKAGES_TSV, encoding="utf-8")
        (r / "compose.yml").write_text("services:\n  web:\n    image: nginx:1.27\n", encoding="utf-8")
        p = dt.PATIENTS[0]
        (r / "people.csv").write_text(
            f"imie,nazwisko,pesel,telefon\n{p['first_name']},{p['surname']},{p['pesel']},{p['phone']}\n", encoding="utf-8"
        )
        if phi:
            (r / ".claude").mkdir()
            (r / ".claude" / "piigate.json").write_text("{}", encoding="utf-8")
        return r

    def gate(self, cwd: Path) -> gate.Gate:
        """A test repo in /tmp created a moment ago counts as public (the age and location guards are off)."""
        k = config.load(str(cwd))
        k["sources"]["non_public"] = []
        k["sources"]["public_repo_min_age_h"] = 0
        return gate.Gate(k, str(cwd))

    def test_text_arguments_are_not_sources(self):
        for where in (self.public, self.phi):
            b = self.gate(where)
            for command in (
                'git commit -m "add packages.tsv and *.csv exports"',
                "git commit -F - <<'EOF'\nAdd packages.tsv, update *.csv\nEOF",
                "printf '%s\\n' 'see packages.tsv' '*.csv'",
                'echo "update packages.tsv and *.csv"',
                "cat > notes.md <<'EOF'\npackages.tsv lists *.csv files\nEOF",
            ):
                with self.subTest(where=where.name, command=command):
                    self.assertIsNone(b.bash(command))
        b = self.gate(self.phi)
        for command in (  # still denied: the text is read from a file with personal data
            "cat people.csv",
            "echo `cat people.csv`",
            'printf "%s" "$(cat people.csv)"',
            'echo "$(<people.csv)"',
            "printf '%s\\n' < people.csv",
            "git commit -F people.csv",
            'git commit -m "$(cat people.csv)"',
        ):
            with self.subTest(command):
                self.assertIsNotNone(b.bash(command))

    def test_quoted_heredoc_text_is_not_a_pattern(self):
        """Issue #1: `name.*` in the body of a heredoc fed to a non-shell is text (the shell expands no globs there, and
        no substitutions with a quoted delimiter) — not a pattern matching every data extension."""
        for where in (self.public, self.phi):
            b = self.gate(where)
            for command in (
                "python3 - <<'EOF'\nprint('zgoda.*')\nEOF",
                "cd x && python3 - <<'EOF'\ns = s.replace('a', \"only `kanal.*` and broadcast\")\nEOF",
                "gh issue create --title t --body-file - <<'EOF'\nonly `kanal.*` and `zgoda.*` here\nEOF",
                'python3 - <<"EOF"\nevents = ["kanal.*", "zgoda.*"]\nEOF',
            ):
                with self.subTest(where=where.name, command=command):
                    self.assertIsNone(b.bash(command))
        b = self.gate(self.phi)
        for command in (  # still denied: a shell runs the body, a real glob, a data file named in the body
            "bash <<'EOF'\ncat people.*\nEOF",
            "cat people.* <<'EOF'\npeople.*\nEOF",
            "python3 - <<'EOF'\nprint(open('people.csv').read())\nEOF",
            "python3 - <<EOF\nprint(\"`cat people.*`\")\nEOF",
            "cat *.*",
        ):
            with self.subTest(command):
                self.assertIsNotNone(b.bash(command))

    def test_pattern_under_plugin_cache(self):
        """Issue #1: a pattern under the plugin cache is denied only when it can reach piigate's own copy, not for
        other plugins' files (`cache/*/superpowers/…`)."""
        cache = self.base / "plugins" / "cache"
        own = cache / "piigate" / "piigate" / "1.0.3"
        other = cache / "official" / "superpowers" / "5.0.0" / "skills" / "brainstorming"
        for d in (own, other):
            d.mkdir(parents=True)
        saved = os.environ.get("CLAUDE_PLUGIN_ROOT")
        os.environ["CLAUDE_PLUGIN_ROOT"] = str(own)
        try:
            b = self.gate(self.public)
            for command in (
                f"ls -d {cache}/*/superpowers/*/skills/brainstorming",
                f"ls {cache}/official/*/5.0.0",
                f"bash {other}/start-server.sh",
                f"ls {cache}",
            ):
                with self.subTest(command):
                    self.assertIsNone(b.bash(command))
            for command in (  # still denied: the pattern can name piigate's copy or a directory above it
                f"ls {cache}/*/piigate",
                f"cat {cache}/*/*/*/config.json",
                f"cat {cache}/pii*/*/*/config.json",
                f"cat {cache}/**/config.json",
                f"cat {cache}/official/../*/piigate/1.0.3/config.json",
                f"grep -r x {cache}/*",
                f"cat {own}/config.json",
            ):
                with self.subTest(command):
                    self.assertIsNotNone(b.bash(command))
        finally:
            if saved is None:
                os.environ.pop("CLAUDE_PLUGIN_ROOT", None)
            else:
                os.environ["CLAUDE_PLUGIN_ROOT"] = saved

    def test_relative_paths_against_tool_cwd(self):
        """The hook resolves relative paths against the tool call's cwd, not its own working directory."""
        def bash(command: str) -> dict | None:
            return hook("gate", {"hook_event_name": "PreToolUse", "cwd": str(self.phi), "tool_name": "Bash",
                                 "tool_input": {"command": command}})

        self.assertIsNone(bash("cat packages.tsv"))  # found in cwd, clean content
        self.assertEqual(bash("cat people.csv")["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIsNone(self.gate(self.phi).bash("head -3 ./packages.tsv"))

    def test_package_list(self):
        self.assertIsNone(self.gate(self.public).decision("Read", {"file_path": str(self.public / "packages.tsv")}))
        cfg = config.load(str(self.phi))
        self.assertEqual(verdict.check_text(PACKAGES_TSV, cfg), {})  # no PERSON for "Liberation Sans", "Noto Sans"…
        self.assertIsNone(self.gate(self.phi).decision("Read", {"file_path": str(self.phi / "packages.tsv")}))
        self.assertIsNotNone(self.gate(self.phi).decision("Read", {"file_path": str(self.phi / "people.csv")}))

    def test_system_directories(self):
        for where in (self.public, self.phi):
            b = self.gate(where)
            for command in (
                "ls /usr/share/man/pl/man1/ls.1*",
                "ls /usr/share/doc/*",
                "ls /usr/lib/*",
                "sudo-like-tool install x 2>&1 | tail -4; ls /usr/share/man/pl/man1/ls.1*",
            ):
                with self.subTest(where=where.name, command=command):
                    self.assertIsNone(b.bash(command))
        self.assertIsNotNone(self.gate(self.phi).bash("ls ./*.c*v; cat p*.csv"))  # outside system directories

    def test_searches_in_repo_without_phi(self):
        b = self.gate(self.public)
        for command in (
            "find . -maxdepth 4 \\( -name 'compose*.y*ml' -o -name 'docker-compose*.y*ml' \\) | xargs grep -h image:",
            'grep -rliE -- "mjml|e-?mail template|szablon.*maili" .',
        ):
            with self.subTest(command):
                self.assertIsNone(b.bash(command))


class TestHumanApproval(unittest.TestCase):
    """Human consent by password: sudo -k -A true, with the rootwhy dialog as the askpass program.
    Fakes: sudo (password "secret") and rootwhy in PATH; the child process replaces _agent(), because the tests may
    run inside an agent session."""

    CODE = (
        f"import os, sys; sys.path.insert(0, {str(ROOT / 'lib')!r}); import cli; cli._agent = lambda: False; "
        "cli.SUDO = os.environ['FAKE_SUDO']; sys.exit(cli.main(sys.argv[1:]))"
    )
    # rootwhy as the askpass program: good / wrong password, cancel (like rootwhy: "cancelled" in the state file),
    # substituted (exit code 0 without a password — a PATH planted by the agent)
    FAKE_SCRIPTS = {
        "good": 'echo secret',
        "wrong": 'echo xxx',
        "cancel": 'echo cancelled > "$ROOTWHY_STATE"; exit 1',
        "substituted": 'exit 0',
    }

    def setUp(self):
        self.folder = TMP / f"human-approval-{self._testMethodName}"
        shutil.rmtree(self.folder, ignore_errors=True)
        (self.folder / ".claude").mkdir(parents=True)
        (self.folder / "bin").mkdir()
        shutil.rmtree(Path(os.environ["PIIGATE_DATA_DIR"]) / "projects", ignore_errors=True)
        self.write_project({"tables": ["patient", "visit"]})
        config.load(str(self.folder))  # the first snapshot
        self.write_project({"tables": ["patient"]})
        sudo = self.folder / "sudo"
        sudo.write_text(
            '#!/bin/sh\nprintf "%s\\n" "$@" > "$(dirname "$0")/call"\n'
            'printf "%s" "$ROOTWHY_REASON" > "$(dirname "$0")/reason"\n'
            'h=$("$SUDO_ASKPASS") || exit 1\n[ "$h" = secret ] && exit 0\nexit 1\n'
        )
        sudo.chmod(0o755)

    def write_project(self, data) -> None:
        (self.folder / ".claude" / "piigate.json").write_text(json.dumps(data), encoding="utf-8")

    def pending(self) -> dict:
        return config.load(str(self.folder))["project"]["pending"]

    def cli(self, argv: list[str], fake: str | None) -> subprocess.CompletedProcess:
        """fake None — no rootwhy in PATH."""
        file = self.folder / "bin" / "rootwhy"
        file.unlink(missing_ok=True)
        if fake is not None:
            file.write_text(f"#!/bin/sh\n{self.FAKE_SCRIPTS[fake]}\n")
            file.chmod(0o755)
        return subprocess.run(
            [sys.executable, "-I", "-c", self.CODE, *argv],
            cwd=self.folder,
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "PATH": f"{self.folder / 'bin'}:/usr/bin:/bin",
                "FAKE_SUDO": str(self.folder / "sudo"),
                "ROOTWHY_MODE": "inherited",  # inherited variables do not reach sudo
                "SUDO_ASKPASS": "/bin/true",
            },
            check=False,
        )

    def test_approve_with_password(self):
        self.assertEqual(self.pending(), {"tables": ["visit"]})
        for fake, message in (("cancel", "cancelled"), ("wrong", "the password was not confirmed"),
                     ("substituted", "the password was not confirmed")):
            with self.subTest(fake):
                w = self.cli(["project", "approve"], fake)
                self.assertEqual(w.returncode, 4, w.stderr)
                self.assertIn(message, w.stderr)
                self.assertEqual(self.pending(), {"tables": ["visit"]})
        w = self.cli(["project", "approve"], "good")
        self.assertEqual(w.returncode, 0, w.stderr)
        self.assertIn("approved", w.stdout)
        self.assertEqual(self.pending(), {})
        self.assertEqual((self.folder / "call").read_text().split(), ["-k", "-A", "--", "/usr/bin/true"])
        description = (self.folder / "reason").read_text()
        self.assertIn("visit", description)  # the dialog says what will stop applying
        self.assertLessEqual(len(description), 300)  # rootwhy's reason length limit

    def test_without_rootwhy_denied(self):
        w = self.cli(["project", "approve"], None)
        self.assertEqual(w.returncode, 4)
        self.assertIn("rootwhy not found in PATH", w.stderr)
        self.assertEqual(self.pending(), {"tables": ["visit"]})

    def test_reverse_requires_password(self):
        file = self.folder / "raport.txt"
        file.write_text("kontrola PERSON_999\n", encoding="utf-8")
        # good password: consent, but the output is not a terminal → output denied (2)
        for fake, expected in (("cancel", 4), ("substituted", 4), (None, 4), ("good", 2)):
            with self.subTest(fake):
                w = self.cli(["reverse", str(file)], fake)
                self.assertEqual(w.returncode, expected, w.stderr)
                self.assertEqual(w.stdout, "")

    @unittest.skipUnless(shutil.which("rootwhy"), "rootwhy not in PATH")
    def test_rootwhy_password_mode_only_for_sudo(self):
        w = subprocess.run(
            [shutil.which("rootwhy")],
            env={**os.environ, "ROOTWHY_MODE": "askpass", "ROOTWHY_STATE": os.devnull},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual((w.returncode, w.stdout), (1, ""))


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
