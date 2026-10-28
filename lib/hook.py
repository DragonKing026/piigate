"""piigate hooks: `gate` (PreToolUse) and `filter` (PostToolUse). Input: the hook JSON on stdin.

Deny by default: any exception → the gate denies, the filter replaces the output with an error message.
(A crash of the PostToolUse hook itself — even with onFailure: "block" — would show the model the original, so
errors are caught here, and hooks/run.sh guards the Python start-up and the time limit.)
"""

import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

ERROR_MESSAGE = (
    "[piigate] Output hidden — the filter could not process it safely (deny by default): {error}\n"
    "The original was NOT shown. Diagnosis: `piigate status`. Do not try to read the source bypassing the filter."
)


def _log(entry: dict) -> None:
    """Decision log without content (tool, decision, counters) — for diagnosis."""
    try:
        from piigate import config

        folder = config.data_dir()
        folder.mkdir(parents=True, exist_ok=True)
        entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), **entry}
        with open(folder / "decisions.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:  # noqa: BLE001, S110 — the log must never stop the filter
        pass


def describe_error(e: Exception) -> str:
    """Message text only for the filter's own errors; other exceptions (ValueError: … 'Kowalski') may quote data — type only."""
    from piigate import FilterError

    if isinstance(e, FilterError):
        return str(e)
    return f"{type(e).__name__} (details hidden — they may contain data; log: piigate status)"


def _deny(reason: str) -> dict:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _replacement(result) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "updatedToolOutput": result}}


def error_result(tool: str, response, message: str):
    """A message shaped like the tool's own output (Claude Code ignores any other shape and shows the original)."""
    if tool == "Bash":
        return {"stdout": message, "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False}
    if tool == "Read":
        file = (response or {}).get("file", {}) if isinstance(response, dict) else {}
        return {
            "type": "text",
            "file": {
                "filePath": file.get("filePath", ""),
                "content": message + "\n",
                "numLines": 1,
                "startLine": 1,
                "totalLines": 1,
            },
        }
    if tool == "Grep" and isinstance(response, dict):
        w = dict(response)
        w.update({"content": message, "filenames": [], "numFiles": 0, "numLines": 1, "totalLines": 1})
        return w
    return [{"type": "text", "text": message}]


def gate(data: dict) -> dict | None:
    from piigate import gate as gate_mod
    from piigate import config

    tool = data.get("tool_name", "")
    cfg = config.load(data.get("cwd") or None)
    if tool.startswith("mcp__") and not gate_mod.unfiltered_entry(gate_mod.unfiltered_tools(cfg), tool):
        return None  # the hook matches every MCP tool; only those in `unfiltered_tools` are checked
    reason = gate_mod.Gate(cfg, data.get("cwd", "")).decision(tool, data.get("tool_input") or {})
    if reason:
        _log({"hook": "gate", "tool": tool, "decision": "deny", "reason": denial_kind(reason)})
        return _deny(reason)
    return None


def denial_kind(reason: str) -> str:
    """Denial category and rule for the log — without paths or file names (they may contain data). The substrings
    match the messages in piigate/gate.py and piigate/project.py — keep them in sync."""
    categories = (
        ("output does not go through the filter", "unfiltered-tool"),
        ("sensitive data directory", "sensitive-dir"),
        ("database query", "ssh-query"),
        ("pseudonym map", "filter-files"),
        ("filter file", "filter-files"),
        ("disabled in Bash", "mcp-piigate"),
    )
    category = next((k for regex, k in categories if regex in reason), "data-file")
    rule = reason.split(";", 1)[1].split(". Instead", 1)[0] if ";" in reason else ""
    rule = re.sub(r"`[^`]*`|\S*[/~]\S*|\([^)]*\)", "…", rule).strip()[:120]
    return f"{category}: {rule}" if rule else category


def _mcp_blocks(response) -> list:
    """MCP result blocks (a list or {content: [...]}) → list of blocks."""
    if isinstance(response, dict) and isinstance(response.get("content"), list):
        return response["content"]
    if isinstance(response, list):
        return response
    if isinstance(response, str):
        return [{"type": "text", "text": response}]
    return [{"type": "text", "text": json.dumps(response, ensure_ascii=False)}]


def output_filter(data: dict):
    from piigate import gate as gate_mod
    from piigate import sensors, config, text
    from piigate.pseudonym_map import PseudonymMap

    from piigate import project

    cfg = config.load(data.get("cwd") or None)
    tool = data.get("tool_name", "")
    resp = data.get("tool_response")
    inp = data.get("tool_input") or {}
    mail = any(re.search(w, tool) for w in cfg.get("mail_mcp", []))
    unfiltered = gate_mod.unfiltered_entry(gate_mod.unfiltered_tools(cfg), tool)
    if tool.startswith("mcp__") and not mail and not unfiltered:
        return None  # the hook matches every MCP tool; only mail and `unfiltered_tools` outputs are filtered
    if reason := project.error_denial(cfg, tool, inp, data.get("cwd", "")):
        # the gate should have denied (invalid project filter file) — the output is withheld
        return _replacement(error_result(tool, resp, ERROR_MESSAGE.format(error=reason)))
    if (cfg.get("project") or {}).get("error") and tool == "Read" and isinstance(resp, dict):
        # exempt read of the invalid project file: its content still goes through the rules (it may have been swapped)
        from piigate import verdict

        file = resp.get("file")
        content = file.get("content") if isinstance(file, dict) else None
        if not isinstance(content, str) or verdict.check_text(content, cfg):
            return _replacement(
                error_result("Read", resp, ERROR_MESSAGE.format(error="the project filter file contains personal data"))
            )

    # mail (e.g. Thunderbird MCP): every text block through the full text filter
    if mail:
        pseudonym_map = PseudonymMap()
        blocks = []
        overall: dict[str, int] = {}
        for b in _mcp_blocks(resp):
            if isinstance(b, dict) and b.get("type") == "text":
                t, counts = text.filter_text(str(b.get("text", "")), cfg, source="mail", pseudonym_map=pseudonym_map)
                for k, v in counts.items():
                    overall[k] = overall.get(k, 0) + v
                blocks.append({"type": "text", "text": t})
            else:
                blocks.append(
                    {
                        "type": "text",
                        "text": f"[piigate: skipped block {b.get('type') if isinstance(b, dict) else type(b).__name__}]",
                    }
                )
        blocks.append({"type": "text", "text": text.summary(overall)})
        _log({"hook": "filter", "tool": tool, "decision": "mail", "pseudonyms": overall})
        return _replacement(blocks)

    # output of an unfiltered MCP tool (the gate allowed it on a non-sensitive directory): sensors as for Bash
    if unfiltered:
        blocks, n = [], 0
        for block in _mcp_blocks(resp):
            if isinstance(block, dict) and block.get("type") == "text":
                t, k = sensors.mask(str(block.get("text", "")), cfg)
                n += k
                blocks.append({"type": "text", "text": t})
            else:
                blocks.append(block)
        if n:
            _log({"hook": "filter", "tool": tool, "decision": "sensors", "count": n})
            return _replacement(blocks)
        return None

    b = gate_mod.Gate(cfg, data.get("cwd", ""))
    if tool == "Read" and isinstance(resp, dict):
        path = inp.get("file_path", "")
        if b.path_kind(path) in ("protected", "sensitive", "extension"):
            # the gate should have denied — if the read got through (e.g. gate disabled), the content is withheld
            _log({"hook": "filter", "tool": tool, "decision": "sensitive-read-blocked"})
            return _replacement(
                error_result(
                    "Read",
                    resp,
                    ERROR_MESSAGE.format(error="read of a sensitive file bypassing the gate — use `piigate show`"),
                )
            )
        file = resp.get("file")
        if b.has_extension(path) and isinstance(file, dict) and isinstance(file.get("content"), str):
            # the gate allowed a file with clean content — check what actually came back (the file may have changed)
            from piigate import verdict

            if counter := verdict.check_text(file["content"], cfg):
                _log({"hook": "filter", "tool": tool, "decision": "personal-content", "pseudonyms": counter})
                return _replacement(
                    error_result(
                        "Read",
                        resp,
                        ERROR_MESSAGE.format(
                            error=f"the file contains personal data ({verdict.describe_counter(counter)}) — use piigate_show"
                        ),
                    )
                )
        if isinstance(file, dict) and isinstance(file.get("content"), str):
            new_text, n = sensors.mask(file["content"], cfg)
            if n:
                w = json.loads(json.dumps(resp))
                w["file"]["content"] = new_text
                _log({"hook": "filter", "tool": tool, "decision": "sensors", "count": n})
                return _replacement(w)
        return None

    if tool == "Bash" and isinstance(resp, dict):
        command = inp.get("command", "")
        reason = b.bash(command)
        if reason:  # the gate would have denied — should not happen; the output is withheld
            return _replacement(error_result("Bash", resp, ERROR_MESSAGE.format(error="command with a sensitive source")))
        if b.touches_extension(command):
            from piigate import verdict

            output = "\n".join(str(resp.get(p) or "") for p in ("stdout", "stderr"))
            if counter := verdict.check_text(output, cfg):
                _log({"hook": "filter", "tool": tool, "decision": "personal-content", "pseudonyms": counter})
                error = f"the output contains personal data ({verdict.describe_counter(counter)}) — use piigate_show / `| piigate text`"
                return _replacement(error_result("Bash", resp, ERROR_MESSAGE.format(error=error)))
        w = dict(resp)
        n = 0
        for field_name in ("stdout", "stderr"):
            if isinstance(w.get(field_name), str) and w[field_name]:
                w[field_name], k = sensors.mask(w[field_name], cfg)
                n += k
        if n:
            _log({"hook": "filter", "tool": tool, "decision": "sensors", "count": n})
            return _replacement(w)
        return None

    if tool == "Grep" and isinstance(resp, dict) and isinstance(resp.get("content"), str):
        new_text, n = sensors.mask(resp["content"], cfg)
        if n:
            return _replacement(dict(resp, content=new_text))
    return None


def _location(e: Exception) -> str:
    """File:line of the error (no content) for the log."""
    import traceback

    tb = traceback.extract_tb(e.__traceback__)
    return f"{Path(tb[-1].filename).name}:{tb[-1].lineno}" if tb else ""


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        data = json.load(sys.stdin)
    except Exception as e:  # noqa: BLE001
        data = {}
        error = f"invalid hook input: {e}"
    else:
        error = None
    try:
        if error:
            raise RuntimeError(error)
        result = gate(data) if mode == "gate" else output_filter(data) if mode == "filter" else None
        if mode not in ("gate", "filter"):
            raise RuntimeError(f"unknown hook mode: {mode}")
    except Exception as e:  # noqa: BLE001 — deny by default on any error
        description = describe_error(e)
        _log(
            {
                "hook": mode,
                "tool": data.get("tool_name"),
                "decision": "error",
                "error": description[:300],
                "location": _location(e),
            }
        )
        if mode == "gate":
            result = _deny(
                f"piigate: gate error ({description}) — call blocked (deny by default). Diagnosis: `piigate status`."
            )
        else:
            result = _replacement(
                error_result(data.get("tool_name", ""), data.get("tool_response"), ERROR_MESSAGE.format(error=description))
            )
    if result:
        sys.stdout.write(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
