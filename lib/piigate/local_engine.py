"""Local engine: Presidio Analyzer + spaCy models inside the MCP server process (no Docker).

Models are not shipped with piigate (pl_core_news_lg is GPL-3.0, see README "Model license"): on first use they are
downloaded from explosion/spacy-models, checked against the sha256 pinned below and unpacked into the data dir; a
file that does not match is deleted and the engine refuses to start. Nothing is installed into Python — spaCy loads
the unpacked model directory by path.

Imported only by the MCP server (needs presidio-analyzer and spacy from its `uv run --script` dependencies).
"""

import hashlib
import os
import shutil
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

MODELS = {
    "pl": {
        "name": "pl_core_news_lg",
        "version": "3.8.0",
        "sha256": "3bc7296cd4d67fa9ee0904b25401b0e9a9a772d5c4756edf54143a2ff4c9dcc0",
        "license": "GPL-3.0",
    },
    "en": {
        "name": "en_core_web_lg",
        "version": "3.8.0",
        "sha256": "293e9547a655b25499198ab15a525b05b9407a75f10255e405e8c3854329ab63",
        "license": "MIT",
    },
}
URL = "https://github.com/explosion/spacy-models/releases/download/{name}-{version}/{name}-{version}-py3-none-any.whl"

# same mapping as docker/analyzer.yaml
ENTITY_MAPPING = {
    "persName": "PERSON",
    "placeName": "LOCATION",
    "geogName": "LOCATION",
    "orgName": "ORGANIZATION",
    "date": "DATE_TIME",
    "PER": "PERSON",
    "PERSON": "PERSON",
    "FAC": "LOCATION",
    "LOC": "LOCATION",
    "GPE": "LOCATION",
    "ORG": "ORGANIZATION",
    "DATE": "DATE_TIME",
    "NORP": "NRP",
}
IGNORED_LABELS = [
    "time", "TIME", "CARDINAL", "EVENT", "LANGUAGE", "LAW", "MONEY", "ORDINAL", "PERCENT", "PRODUCT", "QUANTITY",
    "WORK_OF_ART",
]
# predefined recognizers for every language (as in docker/analyzer.yaml; plus SpacyRecognizer, and PlPeselRecognizer for pl)
RECOGNIZERS = [
    "EmailRecognizer", "PhoneRecognizer", "IbanRecognizer", "CreditCardRecognizer", "IpRecognizer", "DateRecognizer",
]

class ModelError(Exception):
    pass


def models_dir() -> Path:
    """<data dir>/models: PIIGATE_DATA_DIR (tests), else $XDG_DATA_HOME/piigate, else ~/.local/share/piigate."""
    if os.environ.get("PIIGATE_DATA_DIR"):
        base = Path(os.environ["PIIGATE_DATA_DIR"])
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share") / "piigate"
    d = base / "models"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def model_path(lang: str, *, download: bool = True, log=None) -> Path:
    """Directory spaCy can load. Downloads and verifies the wheel when missing (or raises ModelError)."""
    m = MODELS[lang]
    target = models_dir() / f"{m['name']}-{m['version']}"
    inner = target / m["name"] / f"{m['name']}-{m['version']}"
    pin = target / ".sha256"
    if (inner / "config.cfg").is_file() and pin.is_file() and pin.read_text().strip() == m["sha256"]:
        return inner
    if not download:
        raise ModelError(f"model {m['name']} {m['version']} not downloaded yet")
    url = URL.format(**m)
    if log:
        log(f"downloading {m['name']} {m['version']} ({m['license']}) from {url}")
    with tempfile.TemporaryDirectory(dir=models_dir()) as tmp:
        wheel = Path(tmp) / "model.whl"
        local = Path(os.environ.get("PIIGATE_WHEEL_DIR", "/nonexistent")) / url.rsplit("/", 1)[1]
        try:
            if local.is_file():  # offline install: same file, still checked below
                shutil.copyfile(local, wheel)
            else:
                urllib.request.urlretrieve(url, wheel)  # noqa: S310 — fixed https URL
        except OSError as e:
            raise ModelError(f"download of {m['name']} failed: {e}") from None
        got = _sha256(wheel)
        if got != m["sha256"]:
            raise ModelError(f"{m['name']}: sha256 mismatch (expected {m['sha256']}, got {got}) — file discarded")
        unpacked = Path(tmp) / "unpacked"
        with zipfile.ZipFile(wheel) as z:
            for info in z.infolist():
                dest = (unpacked / info.filename).resolve()
                if not dest.is_relative_to(unpacked.resolve()):
                    raise ModelError(f"{m['name']}: unsafe path in wheel: {info.filename}")
            z.extractall(unpacked)
        (unpacked / ".sha256").write_text(m["sha256"] + "\n")
        shutil.rmtree(target, ignore_errors=True)
        unpacked.rename(target)
    if not (inner / "config.cfg").is_file():
        raise ModelError(f"{m['name']}: unexpected wheel layout")
    return inner


class LocalAnalyzer:
    """Lazy Presidio AnalyzerEngine; the first analyze() loads (and if needed downloads) the models."""

    def __init__(self, languages: list[str], log=None):
        self.languages = [lang for lang in languages if lang in MODELS]
        self.log = log
        self._engine = None
        self._lock = threading.Lock()
        self._analyze_lock = threading.Lock()  # spaCy pipelines are not guaranteed to be thread-safe
        self._error: str | None = None
        self.loaded_at: float | None = None

    def _build(self):
        from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_analyzer import predefined_recognizers as pr

        nlp_conf = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": lang, "model_name": str(model_path(lang, log=self.log))} for lang in self.languages],
            "ner_model_configuration": {
                "model_to_presidio_entity_mapping": ENTITY_MAPPING,
                "low_confidence_score_multiplier": 0.4,
                "low_score_entity_names": [],
                "labels_to_ignore": IGNORED_LABELS,
            },
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_conf).create_engine()
        registry = RecognizerRegistry(supported_languages=self.languages)
        for lang in self.languages:
            registry.add_recognizer(pr.SpacyRecognizer(supported_language=lang))
            for name in RECOGNIZERS:
                registry.add_recognizer(getattr(pr, name)(supported_language=lang))
        if "pl" in self.languages:
            registry.add_recognizer(pr.PlPeselRecognizer(supported_language="pl"))
        return AnalyzerEngine(nlp_engine=nlp_engine, registry=registry, supported_languages=self.languages)

    def engine(self):
        with self._lock:
            if self._engine is None:
                if self.log:
                    self.log(f"loading the local engine ({', '.join(self.languages)})")
                try:
                    self._engine = self._build()
                    self.loaded_at = time.time()
                    self._error = None
                    if self.log:
                        self.log("local engine loaded")
                except Exception as e:
                    self._error = f"{type(e).__name__}: {e}"
                    raise
            return self._engine

    def analyze(self, text: str, language: str, threshold: float) -> list[dict]:
        if language not in self.languages:  # never skip silently — the caller refuses
            raise ValueError(f"language {language!r} is not loaded (engine.languages: {', '.join(self.languages)})")
        engine = self.engine()
        with self._analyze_lock:
            results = engine.analyze(text=text, language=language, score_threshold=threshold)
        return [{"entity_type": r.entity_type, "start": r.start, "end": r.end, "score": r.score} for r in results]

    def status(self) -> str:
        if self._engine is not None:
            return f"loaded ({', '.join(self.languages)})"
        if self._error:
            return f"failed: {self._error}"
        return "not loaded yet (loads on first use)"
