"""`piigate mcp-wrap -- COMMAND…` — a stdio pass-through in front of an MCP server (issue #39).

Claude Code sends an MCP error (a `tools/call` result with `isError: true`, or a JSON-RPC error response) to the model
through `PostToolUseFailure`, which cannot rewrite it — the piigate output filter never sees it, and a mail server may
echo its input or a header there ("Folder not found: …"). The wrapper turns such an error into an ordinary result with
the same text and a leading note, so `PostToolUse` runs and the filter covers it like any other result.

Everything else passes byte for byte; the wrapper has no filter logic of its own and works without the plugin enabled.
"""

import json
import signal
import subprocess
import sys
import threading

NOTE = "[piigate mcp-wrap: the tool reported an error]"


def convert(line: bytes, calls: set, lock: threading.Lock) -> bytes:
    """A server line → the same line, or (a response to `tools/call` that is an error) an ordinary result."""
    try:
        message = json.loads(line)
    except ValueError:
        return line
    if not isinstance(message, dict) or "method" in message or "id" not in message:
        return line
    key = json.dumps(message["id"])
    with lock:
        if key not in calls:
            return line
        calls.discard(key)
    error = message.get("error")
    result = message.get("result")
    if isinstance(error, dict):
        text = f"{NOTE} error {error.get('code')}: {error.get('message', '')}"
        message.pop("error")
        message["result"] = {"content": [{"type": "text", "text": text}]}
    elif isinstance(result, dict) and result.get("isError"):
        result["isError"] = False
        result["content"] = [{"type": "text", "text": NOTE}, *(result.get("content") or [])]
    else:
        return line
    return (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")


def _note_calls(line: bytes, calls: set, lock: threading.Lock) -> None:
    """Remember the ids of the client's `tools/call` requests (only their responses are converted)."""
    try:
        message = json.loads(line)
    except ValueError:
        return
    if isinstance(message, dict) and message.get("method") == "tools/call" and "id" in message:
        with lock:
            calls.add(json.dumps(message["id"]))


def run(command: list[str]) -> int:
    if not command:
        print("usage: piigate mcp-wrap -- COMMAND [ARGS…]   (piigate mcp-wrap --check: the wrapper is available)", file=sys.stderr)
        return 2
    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except OSError as e:
        print(f"piigate mcp-wrap: cannot start the server: {type(e).__name__}", file=sys.stderr)
        return 127
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda s, _f: child.send_signal(s))
    calls: set = set()
    lock = threading.Lock()

    def client_to_server() -> None:
        try:
            for line in sys.stdin.buffer:
                _note_calls(line, calls, lock)
                child.stdin.write(line)
                child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            try:
                child.stdin.close()
            except OSError:
                pass

    threading.Thread(target=client_to_server, daemon=True).start()
    out = sys.stdout.buffer
    try:
        for line in child.stdout:
            out.write(convert(line, calls, lock))
            out.flush()
    except BrokenPipeError:
        child.terminate()
    return child.wait()
