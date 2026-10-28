"""A fake Thunderbird MCP server (stdio) with a SYNTHETIC mail — for the end-to-end test of the mail hook.

Tools as in thunderbird-mail: searchMessages, getMessage. Content from fixtures.py (invented patients).
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fixtures as dt

P = dt.PATIENTS
MAIL = {
    "id": "fake-1",
    "from": f"{P[2]['first_name']} {P[2]['surname']} <{P[2]['email']}>",
    "to": "rozliczenia@przyklad-firma.test",
    "subject": f"Recepty — {P[0]['surname']}, {P[1]['surname']}",
    "date": "2026-10-19T10:00:00+02:00",
    "body": dt.mail_body(P[0], P[1]),
    "attachments": [{"name": f"Recepty_{P[3]['surname']}.xlsx", "size": 2730}],
}
TOOLS = [
    {
        "name": "searchMessages",
        "description": "Searches mail (fake)",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}},
    },
    {
        "name": "getMessage",
        "description": "Returns a mail by id (fake)",
        "inputSchema": {"type": "object", "properties": {"messageId": {"type": "string"}}},
    },
]


def send(o: dict) -> None:
    sys.stdout.write(json.dumps(o, ensure_ascii=False) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    m = json.loads(line)
    mid, rpc_method = m.get("id"), m.get("method")
    if rpc_method == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": mid,
                "result": {
                    "protocolVersion": m["params"].get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "thunderbird-fake", "version": "0"},
                },
            }
        )
    elif rpc_method == "tools/list":
        send({"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOLS}})
    elif rpc_method == "tools/call":
        name = m["params"]["name"]
        arguments = m["params"].get("arguments") or {}
        if name == "searchMessages":
            result = [{**{k: MAIL[k] for k in ("id", "from", "subject", "date")}, "folderPath": "mailbox://fake/Inbox"}]
        elif arguments.get("rawSource"):  # like the add-on: the RFC 2822 source as a Latin-1 string (bytes 1:1)
            import tempfile

            with tempfile.TemporaryDirectory() as folder:
                files = dt.write_all(Path(folder))
                raw = files["eml"].read_bytes()
            result = {"id": MAIL["id"], "subject": MAIL["subject"], "rawSource": raw.decode("latin-1")}
        else:
            result = MAIL
        send(
            {
                "jsonrpc": "2.0",
                "id": mid,
                "result": {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False, indent=1)}]},
            }
        )
    elif mid is not None:
        send({"jsonrpc": "2.0", "id": mid, "result": {}})
