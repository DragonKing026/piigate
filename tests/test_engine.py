#!/usr/bin/env python3
"""Tests of the engine plumbing: the Unix socket to the in-memory local engine, engines.presidio in both modes,
model download checks and the container configuration. Standard library only — run: python3 -I tests/test_engine.py

No Presidio needed: the engine is a fake analyzer function. The real local engine (Presidio + spaCy via uv, ~1 GB of
models on first use) is tested only with PIIGATE_TEST_LOCAL_ENGINE=1 (PIIGATE_WHEEL_DIR: directory with already
downloaded model wheels, still checked against the pinned sha256).
"""

import hashlib
import io
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent
ROOT = TESTS_DIR.parent
sys.path.insert(0, str(ROOT / "lib"))

# short directory: a Unix socket path is limited to ~107 bytes
TMP = Path(tempfile.mkdtemp(prefix="pge-"))
os.environ["PIIGATE_DATA_DIR"] = str(TMP / "data")
os.environ["PIIGATE_CONFIG_DIR"] = str(TMP / "config")
os.environ.pop("PIIGATE_SOCKET", None)

from piigate import FilterError, config, engine_socket, engines, local_engine  # noqa: E402


def fake_analyze(text: str, language: str, threshold: float) -> list[dict]:
    """Regex stand-in for Presidio: two capitalized words → PERSON, 'w <Capitalized>' → LOCATION, FV/… → PHONE."""
    out = []
    for m in re.finditer(r"\b[A-ZŁŚŻ][a-ząćęłńóśźż]+ [A-ZŁŚŻ][a-ząćęłńóśźż]+\b", text):
        out.append({"entity_type": "PERSON", "start": m.start(), "end": m.end(), "score": 0.9})
    for m in re.finditer(r"\bw ([A-ZŁŚŻ][a-ząćęłńóśźż]+)", text):
        out.append({"entity_type": "LOCATION", "start": m.start(1), "end": m.end(1), "score": 0.8})
    for m in re.finditer(r"FV/\d+/\d+/\d+", text):
        out.append({"entity_type": "PHONE_NUMBER", "start": m.start(), "end": m.end(), "score": 0.5})
    for m in re.finditer(r"\bOllamy\b", text):
        out.append({"entity_type": "PERSON", "start": m.start(), "end": m.end(), "score": 0.7})
    for m in re.finditer(r"\bXYZ-\d+\b", text):
        out.append({"entity_type": "SOMETHING_NEW", "start": m.start(), "end": m.end(), "score": 0.6})
    return [r for r in out if r["score"] >= threshold]


class SocketCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="s", dir=TMP))
        self.path = self.dir / "engine.sock"
        os.environ["PIIGATE_SOCKET"] = str(self.path)
        self.hosts: list[engine_socket.Host] = []

    def tearDown(self):
        for h in self.hosts:
            h.close()
        os.environ.pop("PIIGATE_SOCKET", None)

    def host(self, analyze=fake_analyze, status=lambda: "fake") -> engine_socket.Host:
        h = engine_socket.Host(analyze, status, self.path)
        self.hosts.append(h)
        return h


class TestSocket(SocketCase):
    def test_round_trip(self):
        self.assertTrue(self.host().try_bind())
        answer = engine_socket.request(
            {"op": "analyze", "text": "dla Zenobia Przykładowska", "language": "pl", "score_threshold": 0.3}, 5
        )
        self.assertEqual(answer, [{"entity_type": "PERSON", "start": 4, "end": 25, "score": 0.9}])
        self.assertEqual(engine_socket.request({"op": "health"}, 5), {"status": "fake"})
        self.assertTrue(engine_socket.alive())
        with self.assertRaises(engine_socket.EngineUnavailable):
            engine_socket.request({"op": "drop_tables"}, 5)

    def test_analyzer_error_is_returned_as_error(self):
        def broken(*a):
            raise RuntimeError("model missing")

        self.assertTrue(self.host(analyze=broken).try_bind())
        with self.assertRaises(engine_socket.EngineUnavailable) as e:
            engine_socket.request({"op": "analyze", "text": "x"}, 5)
        self.assertIn("model missing", str(e.exception))
        self.assertNotIsInstance(e.exception, engine_socket.EngineNotRunning)

    def test_socket_mode_and_peer_uid(self):
        self.assertTrue(self.host().try_bind())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        with a, b:
            self.assertEqual(engine_socket._peer_uid(a), os.getuid())

    def test_foreign_peer_gets_no_answer(self):
        self.assertTrue(self.host().try_bind())
        original = engine_socket._peer_uid
        engine_socket._peer_uid = lambda conn: os.getuid() + 1
        try:
            with self.assertRaises(engine_socket.EngineUnavailable):
                engine_socket.request({"op": "analyze", "text": "Jan Kowalski"}, 5)
        finally:
            engine_socket._peer_uid = original

    def test_second_host_refuses_then_takes_over(self):
        first, second = self.host(status=lambda: "first"), self.host(status=lambda: "second")
        self.assertTrue(first.try_bind())
        self.assertFalse(second.try_bind())
        self.assertEqual(engine_socket.request({"op": "health"}, 5), {"status": "first"})
        first.close()
        self.assertFalse(self.path.exists())
        self.assertFalse(engine_socket.alive())
        self.assertTrue(second.try_bind())
        self.assertEqual(engine_socket.request({"op": "health"}, 5), {"status": "second"})

    def test_stale_socket_file_is_replaced(self):
        self.path.write_text("left over by a crashed host")
        self.assertTrue(self.host().try_bind())
        self.assertTrue(engine_socket.alive())

    def test_oversized_request(self):
        self.assertTrue(self.host().try_bind())
        original = engine_socket.MAX_REQUEST
        engine_socket.MAX_REQUEST = 1000
        try:
            with self.assertRaises(engine_socket.EngineUnavailable) as e:
                engine_socket.request({"op": "analyze", "text": "x" * 5000}, 5)
            self.assertNotIsInstance(e.exception, engine_socket.EngineNotRunning)
        finally:
            engine_socket.MAX_REQUEST = original

    def test_no_host(self):
        with self.assertRaises(engine_socket.EngineNotRunning):
            engine_socket.request({"op": "health"}, 2)
        self.assertFalse(engine_socket.alive())

    def test_runtime_dir_is_private(self):
        runtime = TMP / "runtime"
        runtime.mkdir(mode=0o700, exist_ok=True)
        old = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = str(runtime)
        try:
            d = engine_socket.runtime_dir()
            self.assertEqual(d, runtime / "piigate")
            self.assertEqual(stat.S_IMODE(d.stat().st_mode), 0o700)
            d.chmod(0o755)
            with self.assertRaises(engine_socket.EngineUnavailable):
                engine_socket.runtime_dir()
        finally:
            if old is None:
                os.environ.pop("XDG_RUNTIME_DIR")
            else:
                os.environ["XDG_RUNTIME_DIR"] = old


def local_cfg(**engine) -> dict:
    cfg = config.load()
    cfg["engine"] = {**cfg["engine"], "mode": "local", **engine}
    return cfg


class TestEnginesLocal(SocketCase):
    def test_default_mode_is_local(self):
        self.assertEqual(config.load()["engine"]["mode"], "local")
        for old in ("presidio_url", "presidio_threshold", "presidio_timeout_s"):
            self.assertNotIn(old, config.load()["text"])

    def test_presidio_through_socket(self):
        self.assertTrue(self.host().try_bind())
        t = "Test filtra Ollamy. Faktura FV/2026/10/123 dla Zenobia Przykładowska, mieszka w Krakowie. Kod XYZ-7."
        found = {(t[f.start:f.end], f.type_) for f in engines.presidio(t, local_cfg())}
        self.assertIn(("Zenobia Przykładowska", "PERSON"), found)
        self.assertIn(("Krakowie", "ADDRESS"), found)
        self.assertIn(("FV/2026/10/123", "NUMBER"), found)  # PHONE with letters/slashes → NUMBER
        self.assertIn(("XYZ-7", "NUMBER"), found)  # unknown type → NUMBER
        self.assertNotIn("Ollamy", {v for v, _ in found})  # plain word
        self.assertTrue(engines.presidio_health(local_cfg()).startswith("running"))
        # threshold is passed on
        self.assertNotIn(("Krakowie", "ADDRESS"), {(t[f.start:f.end], f.type_) for f in engines.presidio(t, local_cfg(threshold=0.85))})

    def test_languages_limited_by_config(self):
        seen = []

        def recording(text, language, threshold):
            seen.append(language)
            return []

        self.assertTrue(self.host(analyze=recording).try_bind())
        english = "Dear Sir, please find the results and the report for your patient with this letter. " * 3
        engines.presidio(english, local_cfg())
        self.assertEqual(seen, ["pl", "en"])
        seen.clear()
        engines.presidio(english, local_cfg(languages=["pl"]))
        self.assertEqual(seen, ["pl"])

    def test_no_host_denies(self):
        with self.assertRaises(FilterError) as e:
            engines.presidio("Jan Kowalski", local_cfg(timeout_s=2))
        self.assertIn("local engine not running", str(e.exception))
        self.assertIn("engine.mode=container", str(e.exception))
        self.assertFalse(engines.presidio_health(local_cfg()).startswith("running"))

    def test_engine_error_denies(self):
        self.assertTrue(self.host(analyze=lambda *a: {"not": "a list"}).try_bind())
        with self.assertRaises(FilterError):
            engines.presidio("Jan Kowalski", local_cfg())

    def test_unknown_mode_denies(self):
        with self.assertRaises(FilterError):
            engines.presidio("Jan Kowalski", local_cfg(mode="cloud"))


class TestEnginesContainer(unittest.TestCase):
    def test_outside_loopback(self):
        cfg = local_cfg(mode="container", container_url="http://example.com:3000")
        with self.assertRaises(FilterError) as e:
            engines.presidio("Jan Kowalski", cfg)
        self.assertIn("outside loopback", str(e.exception))

    def test_container_down(self):
        cfg = local_cfg(mode="container", container_url="http://127.0.0.1:9", timeout_s=2)
        with self.assertRaises(FilterError):
            engines.presidio("Jan Kowalski", cfg)
        self.assertFalse(engines.presidio_health(cfg).startswith("running"))

    def test_description(self):
        self.assertIn("127.0.0.1:8719", engines.engine_description(local_cfg(mode="container")))
        self.assertIn("local", engines.engine_description(local_cfg()))


def fake_wheel(name: str, version: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(f"{name}/{name}-{version}/config.cfg", "[nlp]\nlang = \"pl\"\n")
        z.writestr(f"{name}/__init__.py", "")
    return buf.getvalue()


class TestModels(unittest.TestCase):
    def setUp(self):
        self.data = Path(tempfile.mkdtemp(prefix="m", dir=TMP))
        self.wheels = self.data / "wheels"
        self.wheels.mkdir()
        self.saved_env = {k: os.environ.get(k) for k in ("PIIGATE_DATA_DIR", "PIIGATE_WHEEL_DIR")}
        os.environ["PIIGATE_DATA_DIR"] = str(self.data / "piigate")
        os.environ["PIIGATE_WHEEL_DIR"] = str(self.wheels)
        self.saved_models = json.loads(json.dumps(local_engine.MODELS))
        m = local_engine.MODELS["pl"]
        self.wheel = fake_wheel(m["name"], m["version"])
        (self.wheels / f"{m['name']}-{m['version']}-py3-none-any.whl").write_bytes(self.wheel)

    def tearDown(self):
        local_engine.MODELS.clear()
        local_engine.MODELS.update(self.saved_models)
        for k, v in self.saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_sha256_mismatch_discards(self):
        local_engine.MODELS["pl"]["sha256"] = "0" * 64
        with self.assertRaises(local_engine.ModelError) as e:
            local_engine.model_path("pl")
        self.assertIn("sha256 mismatch", str(e.exception))
        models = local_engine.models_dir()
        self.assertEqual(list(models.iterdir()), [])  # nothing unpacked, the temporary download is gone
        with self.assertRaises(local_engine.ModelError):
            local_engine.model_path("pl", download=False)

    def test_matching_wheel_unpacked(self):
        local_engine.MODELS["pl"]["sha256"] = hashlib.sha256(self.wheel).hexdigest()
        logs = []
        path = local_engine.model_path("pl", log=logs.append)
        self.assertTrue((path / "config.cfg").is_file())
        self.assertTrue(path.is_relative_to(Path(os.environ["PIIGATE_DATA_DIR"]) / "models"))
        self.assertTrue(logs)
        self.assertEqual(local_engine.model_path("pl", download=False), path)  # cached, no second copy
        # a changed pin invalidates the unpacked copy
        local_engine.MODELS["pl"]["sha256"] = "1" * 64
        with self.assertRaises(local_engine.ModelError):
            local_engine.model_path("pl", download=False)

    def test_unsafe_wheel_path(self):
        m = local_engine.MODELS["pl"]
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("../../evil.txt", "x")
        bad = buf.getvalue()
        (self.wheels / f"{m['name']}-{m['version']}-py3-none-any.whl").write_bytes(bad)
        m["sha256"] = hashlib.sha256(bad).hexdigest()
        with self.assertRaises(local_engine.ModelError):
            local_engine.model_path("pl")
        self.assertFalse((self.data / "evil.txt").exists())


def yaml_block(text: str, key: str) -> list[str]:
    """Lines of the block under `key:` (more indented than the key), comments and blank lines dropped."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == f"{key}:":
            indent = len(line) - len(line.lstrip())
            out = []
            for nxt in lines[i + 1:]:
                if not nxt.strip() or nxt.lstrip().startswith("#"):
                    continue
                if len(nxt) - len(nxt.lstrip()) <= indent:
                    break
                out.append(nxt.strip())
            return out
    raise AssertionError(f"{key} not found")


class TestContainerConfig(unittest.TestCase):
    yaml = (ROOT / "docker" / "analyzer.yaml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")

    def test_mapping_equals_local_engine(self):
        mapping = dict(line.split(": ", 1) for line in yaml_block(self.yaml, "model_to_presidio_entity_mapping"))
        self.assertEqual(mapping, local_engine.ENTITY_MAPPING)
        ignored = [line.removeprefix("- ") for line in yaml_block(self.yaml, "labels_to_ignore")]
        self.assertEqual(ignored, local_engine.IGNORED_LABELS)
        self.assertIn("low_confidence_score_multiplier: 0.4", self.yaml)

    def test_same_languages_and_recognizers(self):
        self.assertEqual(
            [line.removeprefix("- ") for line in yaml_block(self.yaml, "supported_languages")], ["pl", "en"]
        )
        names = re.findall(r"- name: (\w+)", self.yaml)
        expected = ["SpacyRecognizer", *(c for c in local_engine.RECOGNIZERS), "PlPeselRecognizer"]
        self.assertEqual(names, expected)
        models = re.findall(r"model_name: (\w+)", self.yaml)
        self.assertEqual(models, [local_engine.MODELS["pl"]["name"], local_engine.MODELS["en"]["name"]])

    def test_dockerfile_pins(self):
        m = local_engine.MODELS["pl"]
        self.assertIn(f"PL_MODEL_SHA256={m['sha256']}", self.dockerfile)
        self.assertIn(f"{m['name']}-{m['version']}-py3-none-any.whl", self.dockerfile)
        bases = re.findall(r"^ARG (?:BUILDER|BASE)=(\S+)$", self.dockerfile, re.M)
        self.assertEqual(len(bases), 2)
        for b in bases:
            self.assertRegex(b, r":2\.2\.366(-distroless)?@sha256:[0-9a-f]{64}$")
        server = (ROOT / "server.py").read_text(encoding="utf-8")
        self.assertIn('"presidio-analyzer==2.2.366"', server)  # the local engine uses the same Presidio release


def server_dependencies() -> list[str]:
    line = next(x for x in (ROOT / "server.py").read_text(encoding="utf-8").splitlines() if x.startswith("# dependencies"))
    return json.loads(line.split("=", 1)[1])


@unittest.skipUnless(os.environ.get("PIIGATE_TEST_LOCAL_ENGINE") == "1", "real local engine: PIIGATE_TEST_LOCAL_ENGINE=1")
class TestRealLocalEngine(unittest.TestCase):
    def test_polish_sentence(self):
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(ROOT / 'lib')!r})\n"
            "from piigate.local_engine import LocalAnalyzer\n"
            "a = LocalAnalyzer(['pl', 'en'], log=lambda m: print(m, file=sys.stderr))\n"
            "t = 'Pani Zenobia Przykładowska mieszka w Krakowie, PESEL 44051401359.'\n"
            "r = a.analyze(t, 'pl', 0.3)\n"
            "print(json.dumps({'status': a.status(), 'hits': [[x['entity_type'], t[x['start']:x['end']]] for x in r]}))\n"
        )
        cmd = ["uv", "run", "--quiet", "--no-project", "--python", ">=3.11,<3.15"]
        for dep in server_dependencies():
            cmd += ["--with", dep]
        data = TMP / "real"
        env = {**os.environ, "PIIGATE_DATA_DIR": str(data)}
        r = subprocess.run([*cmd, "python", "-c", code], capture_output=True, text=True, env=env, timeout=3600, check=False)
        self.assertEqual(r.returncode, 0, r.stderr[-3000:])
        out = json.loads(r.stdout.strip().splitlines()[-1])
        types = {k for k, _ in out["hits"]}
        self.assertIn("PERSON", types, out)
        self.assertIn("LOCATION", types, out)
        self.assertIn("PL_PESEL", types, out)
        self.assertTrue(out["status"].startswith("loaded"), out)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
