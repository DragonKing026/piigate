"""Unix socket between the hooks/CLI and the engine held in memory by the MCP server (local engine mode).

Standard library only: the hooks import this module, the heavy engine (Presidio + spaCy) lives in the MCP server.
The protocol mirrors Presidio's REST `/analyze`, so the caller treats both engines alike: one JSON line in
(`{"op": "analyze", "text", "language", "score_threshold"}` or `{"op": "health"}`), one JSON line out
(a list of `{"entity_type", "start", "end", "score"}`, `{"status": ...}` or `{"error": ...}`).

The socket lives in a 0700 directory of the user's runtime dir and the server accepts only peers with the same uid
(SO_PEERCRED). Several Claude Code sessions share one engine: the first MCP server that finds no live socket binds it
(under an flock), the others are clients and take over when the host goes away.
"""

import fcntl
import json
import os
import socket
import struct
import sys
import threading
from collections.abc import Callable
from pathlib import Path

MAX_REQUEST = 8 * 1024 * 1024


class EngineUnavailable(Exception):
    """No answer from the engine (crashed, timed out, refused the request) — the caller must refuse, never pass data on."""


class EngineNotRunning(EngineUnavailable):
    """Nobody serves the socket (no MCP server with the local engine is running)."""


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR")
    if base and Path(base).is_dir() and Path(base).stat().st_uid == os.getuid():
        d = Path(base) / "piigate"
    else:
        d = Path.home() / ".local/share/piigate/run"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = d.stat()
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise EngineUnavailable(f"{d}: not a private directory of this user (owner/mode) — refusing to use it")
    return d


def socket_path() -> Path:
    return Path(os.environ.get("PIIGATE_SOCKET") or runtime_dir() / "engine.sock")


def request(payload: dict, timeout_s: float, path: Path | None = None) -> object:
    """Send one request, return the decoded answer. Any failure → EngineUnavailable."""
    path = path or socket_path()
    data = (json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(max(0.1, timeout_s))
            try:
                s.connect(str(path))
            except (FileNotFoundError, ConnectionRefusedError) as e:
                raise EngineNotRunning(f"local engine not running ({path}: {type(e).__name__})") from None
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while chunk := s.recv(65536):
                chunks.append(chunk)
        answer = json.loads(b"".join(chunks) or b"null")
    except (OSError, ValueError) as e:
        raise EngineUnavailable(f"local engine ({path}): {type(e).__name__}: {e}") from None
    if isinstance(answer, dict) and "error" in answer:
        raise EngineUnavailable(f"local engine: {answer['error']}")
    if answer is None:
        raise EngineUnavailable("local engine: empty answer")
    return answer


def alive(path: Path | None = None, timeout_s: float = 2) -> bool:
    try:
        return isinstance(request({"op": "health"}, timeout_s, path), dict)
    except EngineUnavailable:
        return False


def _peer_uid(conn: socket.socket) -> int:
    if hasattr(socket, "SO_PEERCRED"):  # Linux: struct ucred {pid, uid, gid}
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        return struct.unpack("3i", creds)[1]
    if sys.platform == "darwin":  # SOL_LOCAL=0, LOCAL_PEERCRED=1: struct xucred {u_int version; uid_t uid; ...}
        creds = conn.getsockopt(0, 1, 76)
        return struct.unpack_from("=I", creds, 4)[0]
    raise OSError("peer credentials are not supported on this platform")


class Host:
    """Serves `analyze(text, language, threshold) -> list[dict]` on the socket in daemon threads."""

    def __init__(self, analyze: Callable[[str, str, float], list[dict]], status: Callable[[], str], path: Path | None = None):
        self.analyze, self.status = analyze, status
        self.path = path or socket_path()
        self._lock_file = None
        self._sock: socket.socket | None = None

    def try_bind(self) -> bool:
        """Become the host unless a live one exists. Returns True when this process now serves the socket."""
        if alive(self.path):
            return False
        lock = open(self.path.with_suffix(".lock"), "w")  # noqa: SIM115 — held for the life of the host
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            lock.close()
            return False
        if alive(self.path):  # another process won the race between our check and the lock
            lock.close()
            return False
        self.path.unlink(missing_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        old = os.umask(0o177)
        try:
            s.bind(str(self.path))
        finally:
            os.umask(old)
        s.listen(16)
        self._sock, self._lock_file = s, lock
        threading.Thread(target=self._loop, daemon=True, name="piigate-engine").start()
        return True

    def _loop(self) -> None:
        while self._sock is not None:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            try:
                if _peer_uid(conn) != os.getuid():
                    return
                conn.settimeout(30)
                buf = b""
                while len(buf) <= MAX_REQUEST and (chunk := conn.recv(65536)):
                    buf += chunk
                if len(buf) > MAX_REQUEST:
                    answer: object = {"error": "request too large"}
                else:
                    req = json.loads(buf)
                    if req.get("op") == "health":
                        answer = {"status": self.status()}
                    elif req.get("op") == "analyze":
                        answer = self.analyze(
                            str(req["text"]), str(req.get("language", "pl")), float(req.get("score_threshold", 0))
                        )
                    else:
                        answer = {"error": "unknown op"}
            except Exception as e:  # noqa: BLE001 — every failure goes back as an error, the client refuses
                answer = {"error": f"{type(e).__name__}: {e}"}
            try:
                conn.sendall((json.dumps(answer, ensure_ascii=False) + "\n").encode("utf-8"))
            except OSError:
                pass

    @property
    def bound(self) -> bool:
        return self._sock is not None

    def close(self) -> None:
        s, self._sock = self._sock, None
        if s is not None:
            try:
                s.shutdown(socket.SHUT_RDWR)  # wakes the accept() of the serving thread
            except OSError:
                pass
            s.close()
            self.path.unlink(missing_ok=True)
        if self._lock_file is not None:
            self._lock_file.close()
            self._lock_file = None
