"""Pseudonym map (SQLite, local, 0600) and deterministic masks.

Text pseudonym: <LABEL>_<n> — the same value always gets the same number (key: HMAC of the normalized value).
Table mask: <class>:<6 hex> — HMAC of the value, the original is not stored (irreversible).
The HMAC key (32 random bytes) sits next to the map; without it the digests cannot be brute-forced with a
dictionary (e.g. of birth dates).
"""

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import unicodedata
from pathlib import Path

from . import config

PSEUDONYM_RE = re.compile(r"\b([A-Z][A-Z_]*[A-Z])_(\d+)\b")


def _prepare_dir() -> Path:
    folder = config.data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    return folder


def _key(folder: Path) -> bytes:
    file = folder / "key"
    if not file.exists():
        fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    return file.read_bytes()


def normalize(type_: str, value: str) -> str:
    w = unicodedata.normalize("NFC", value).casefold()
    w = re.sub(r"\s+", " ", w).strip(" \t.,;:()[]\"'")
    if type_ in {"PHONE", "PESEL", "NIP", "ACCOUNT", "CARD", "PRESCRIPTION"}:
        w = re.sub(r"\D", "", w)
    return w


class PseudonymMap:
    def __init__(self):
        folder = _prepare_dir()
        self._key = _key(folder)
        file = folder / "map.sqlite"
        is_new = not file.exists()
        self._db = sqlite3.connect(file, timeout=30)
        if is_new:
            os.chmod(file, 0o600)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS pseudonyms ("
            " digest TEXT PRIMARY KEY, label TEXT NOT NULL, number INTEGER NOT NULL, original TEXT NOT NULL)"
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_label_number ON pseudonyms (label, number)")
        self._db.commit()

    def digest(self, text: str) -> str:
        return hmac.new(self._key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def mask_value(self, value: str, mask_class: str) -> str:
        """Mask of a table value: same value → same mask (joins, grouping), without the original."""
        return f"{mask_class}:{self.digest('mask\0' + value)[:6]}"

    def pseudonym(self, type_: str, label: str, value: str, number: int | None = None) -> str:
        """Stable pseudonym of a value; `number` — assign an existing number (inflected surname, a single name part)."""
        digest = self.digest(f"{type_}\0{normalize(type_, value)}")
        row = self._db.execute("SELECT label, number FROM pseudonyms WHERE digest = ?", (digest,)).fetchone()
        if row:
            return f"{row[0]}_{row[1]}"
        with self._db:
            if number is None:
                number = self._db.execute(
                    "SELECT COALESCE(MAX(number), 0) + 1 FROM pseudonyms WHERE label = ?", (label,)
                ).fetchone()[0]
            self._db.execute(
                "INSERT OR IGNORE INTO pseudonyms (digest, label, number, original) VALUES (?, ?, ?, ?)",
                (digest, label, number, value),
            )
        return f"{label}_{number}"

    def reverse(self, text: str) -> str:
        def substitute(m: re.Match) -> str:
            row = self._db.execute(
                "SELECT original FROM pseudonyms WHERE label = ? AND number = ? ORDER BY rowid LIMIT 1",
                (m.group(1), int(m.group(2))),
            ).fetchone()
            return row[0] if row else m.group(0)

        return PSEUDONYM_RE.sub(substitute, text)

    def stats(self) -> dict[str, int]:
        return dict(
            self._db.execute(
                "SELECT label, COUNT(DISTINCT number) FROM pseudonyms GROUP BY label ORDER BY label"
            ).fetchall()
        )
