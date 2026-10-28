"""piigate — viewing sensitive data through the filter (for the agent) and reversing pseudonyms (for a human only).

Every error → a message without data and exit code 3; the output never contains the unfiltered original.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from piigate import FilterError, analysis, anonymization, config, files, project, table, text, engines
from piigate.pseudonym_map import PseudonymMap

HELP = """\
piigate — sensitive data (PHI/PII) through a filter before it reaches the model.

  piigate show FILE [--rows N] [--attachment N]  CSV/XLSX/ODS → structure; PDF/EML/DOCX/ODT/TXT → text with pseudonyms
  piigate list DIR                               files with filtered names and numbers
  piigate show DIR --number N                    file no. N from `piigate list DIR`
  COMMAND 2>&1 | piigate table [--rows N]        SQL/CSV/TSV result from stdin → structure (not recognized = denied)
  COMMAND 2>&1 | piigate text [--source S]       text from stdin → pseudonyms (S: mail, files, prod)
  piigate anonymize FILE [-o DIR] [--mask-columns A,B]
                                                 anonymized copy (CSV/TXT, the same pseudonyms) in ~/Anonymized-data
  piigate analyze FILE [--question "…"] [-o DIR] a local model reads the original: which sensitive data,
                                                 a summary without it, an answer + an anonymized copy
  piigate analyze --mail "QUERY" [--number N] [--question "…"]
                                                 the same for a Thunderbird mail (with attachments)
  piigate status                                 Presidio, Ollama, configuration, number of pseudonyms
  piigate project                                project filters (.claude/piigate.json): in force and pending
  piigate project approve                        HUMAN ONLY: the current project file becomes the approved snapshot
                                                 (only then do removed entries stop applying)
  piigate reverse [FILE|-] [-o OUTPUT]           HUMAN ONLY: pseudonyms → originals (in the terminal or into a
                                                 file in a sensitive directory); an agent is denied
"""


def _protected_inodes(cfg: dict) -> set[tuple[int, int]]:
    result = set()
    for k in config.protected_dirs(cfg):
        for p in Path(k).rglob("*") if Path(k).is_dir() else []:
            try:
                st = p.stat()
                result.add((st.st_dev, st.st_ino))
            except OSError:
                pass
    return result


def _input(file: str | None, cfg: dict) -> bytes:
    """A file or stdin — never a filter file (map, key, configuration), also not through a symlink or `< file`."""
    if file and file != "-":
        path = Path(config.expand_tilde(file))
        if files._is_protected(path, cfg):
            raise FilterError("filter file (map, key, configuration) — not accessible")
        return path.read_bytes()
    if sys.stdin.isatty():
        raise FilterError("no data on stdin (use: COMMAND 2>&1 | piigate …)")
    st = os.fstat(sys.stdin.fileno())
    if (st.st_dev, st.st_ino) in _protected_inodes(cfg):
        raise FilterError("stdin is a filter file (map, key, configuration) — not accessible")
    return sys.stdin.buffer.read()


AGENTS = ("claude", "codex", "gemini", "copilot", "aider", "opencode", "ollama")


def _ancestors() -> list[str]:
    """Names and command lines of ancestor processes (/proc) — an agent cannot change them with an environment variable."""
    result = []
    pid = os.getppid()
    for _ in range(64):
        if pid <= 1:
            break
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
            stat = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            break
        result.append(cmd)
        pid = int(stat.rsplit(")", 1)[1].split()[1])
    return result


def _agent() -> bool:
    if any(os.environ.get(z) for z in ("CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "AI_AGENT", "CODEX_SANDBOX")):
        return True
    return any(
        Path(k.split(" ", 1)[0]).name.casefold().startswith(AGENTS) or "/claude" in k.split(" ", 1)[0]
        for k in _ancestors()
    )


SUDO = "/usr/bin/sudo"


def _confirm(command: str, description: str) -> bool:
    """Human consent: the user's password verified by sudo (`sudo -k -A true` — changes nothing), with the password
    dialog from rootwhy in askpass mode. The agent does not know the password, whereas a "YES" typed on /dev/tty could
    be typed by the agent itself from its own pseudo-terminal. Consent is decided by sudo, not by the exit code of the
    rootwhy found in PATH: a substituted program can at most supply a wrong password. The environment is stripped of
    inherited ROOTWHY_*/JAKO_ROOT_*/SUDO_* variables."""
    rootwhy = shutil.which("rootwhy")
    if rootwhy is None:
        print(
            f"piigate {command}: denied — rootwhy not found in PATH (https://github.com/DragonKing026/rootwhy).",
            file=sys.stderr,
        )
        return False
    description = f"piigate {command}: {description}"
    if len(description) > 290:
        description = description[:289] + "…"
    fd, state = tempfile.mkstemp(prefix="piigate-consent.", dir=os.environ.get("XDG_RUNTIME_DIR") or None)
    os.close(fd)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ROOTWHY_", "JAKO_ROOT_", "SUDO_"))}
    env.update(
        PATH="/usr/bin:/bin",
        SUDO_ASKPASS=os.path.realpath(rootwhy),
        ROOTWHY_MODE="askpass",
        ROOTWHY_STATE=state,
        ROOTWHY_REASON=description,
        ROOTWHY_EXPLAIN=json.dumps({"/usr/bin/true": "password check only — changes nothing"}),
    )
    try:
        code = subprocess.run(
            [SUDO, "-k", "-A", "--", "/usr/bin/true"], env=env, stdin=subprocess.DEVNULL, check=False
        ).returncode
        cancelled = Path(state).read_text().strip() == "cancelled"
    finally:
        Path(state).unlink(missing_ok=True)
    if code and cancelled:
        print(f"piigate {command}: cancelled.", file=sys.stderr)
    elif code:
        print(f"piigate {command}: denied — the password was not confirmed (sudo, exit code {code}).", file=sys.stderr)
    return code == 0


def reverse(arg, cfg: dict) -> int:
    if _agent():
        print(
            "piigate reverse: denied — the command was run by an AI agent. Reversing pseudonyms is for a human only, "
            "in their own terminal (password in the rootwhy dialog).",
            file=sys.stderr,
        )
        return 4
    # the actual protection: the user's password in the rootwhy dialog
    if not _confirm("reverse", f"show the ORIGINAL personal data ({arg.file or 'stdin'}) — pseudonyms to real data."):
        return 4
    content = _input(arg.file, cfg).decode("utf-8", "replace")
    result = PseudonymMap().reverse(content)
    if arg.o:
        dest = Path(config.expand(arg.o))
        if not any(str(dest).startswith(k.rstrip("/") + "/") for k in config.sensitive_dirs(cfg)):
            print(
                "piigate reverse: -o only into a sensitive directory (e.g. ~/Sensitive-data/…) — the model cannot reach it there.",
                file=sys.stderr,
            )
            return 2
        dest.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(result)
        print(f"saved: {dest}", file=sys.stderr)
        return 0
    if not sys.stdout.isatty():
        print(
            "piigate reverse: output only to a terminal or with -o into a sensitive directory (not to a pipe or a file).",
            file=sys.stderr,
        )
        return 2
    sys.stdout.write(result)
    return 0


def _source_file(arg, cfg: dict) -> Path:
    """File to anonymize/analyze: a regular file (or a number from `piigate list`), not a filter file, up to 100 MB."""
    if not arg.file:
        raise FilterError(f"give a file: piigate {arg.command} FILE")
    path = Path(config.expand_tilde(arg.file))
    if arg.number is not None:
        path = files.file_from_list(path, arg.number, cfg)
    if files._is_protected(path, cfg):
        raise FilterError("filter file (map, key, configuration) — not accessible")
    if not path.is_file():
        raise FilterError("no such file (or it is a directory — use piigate list and --number)")
    if path.stat().st_size > files.FILE_LIMIT:
        raise FilterError("file over 100 MB")
    return path


def _project_description(p: dict) -> list[str]:
    if p.get("error"):
        return [f"project filters {p['file']}: ERROR — {p['error']} (the filter denies everything in the project)"]
    result = [
        f"project filters {p['file']} (the union of the file and the approved snapshot applies):",
        "  patterns: " + (", ".join(f"{w['label']} = {w['pattern']}" for w in p["patterns"]) or "—"),
    ]
    result += [f"  {field_name}: {', '.join(p[field_name]) or '—'}" for field_name in project.LIST_FIELDS]
    if p["pending"]:
        result.append(
            "  removed from the file, still in force until `piigate project approve` (human): "
            + json.dumps(p["pending"], ensure_ascii=False)
        )
    return result


def project_cmd(arg, cfg: dict) -> int:
    p = cfg.get("project")
    if arg.file in (None, "show"):
        print("\n".join(_project_description(p)) if p else f"no project filters ({project.FILE} in a parent directory)")
        return 0
    if arg.file != "approve":
        raise FilterError("usage: piigate project [show|approve]")
    if _agent():
        print(
            "piigate project approve: denied — the command was run by an AI agent. Approval (removing entries from the "
            "project filters) is for a human only, in their own terminal.",
            file=sys.stderr,
        )
        return 4
    root = project.find(os.getcwd())
    if root is None:
        raise FilterError(f"no {project.FILE} in a parent directory")
    current = project.load_current(root)
    try:
        old = project.load_snapshot(root) or {}
    except FilterError:
        old = {}
    removed = project.missing(current, old)
    if not _confirm(
        "project approve",
        f"project filters {root} — will stop applying: {json.dumps(removed, ensure_ascii=False) or '—'}.",
    ):
        return 4
    project.approve(root)
    print(f"approved: {Path(root) / project.FILE}")
    return 0


def status(cfg: dict) -> int:
    folder = config.data_dir()
    print(
        f"configuration: {config.DEFAULT_CONFIG} + {config.config_dir() / 'config.json'}"
        f" ({'present' if (config.config_dir() / 'config.json').is_file() else 'missing — defaults'})"
    )
    print(f"sensitive directories: {', '.join(cfg['sources']['directories'])}")
    if p := cfg.get("project"):
        print("\n".join(_project_description(p)))
    print(f"Presidio {cfg['text']['presidio_url']}: {engines.presidio_health(cfg)}")
    o = cfg["ollama"]
    print(
        f"Ollama: {'enabled for ' + ', '.join(o['sources']) + ' — ' + engines.ollama_health(cfg) if o['enabled'] else 'disabled'}"
    )
    if (folder / "map.sqlite").exists():
        stat = PseudonymMap().stats()
        print("pseudonyms in the map: " + (", ".join(f"{k} {v}" for k, v in stat.items()) or "none"))
    else:
        print("pseudonym map: still empty")
    log_file = folder / "decisions.log"
    if log_file.exists():
        last = log_file.read_text(encoding="utf-8").splitlines()[-5:]
        print("last log entries (without content):")
        for w in last:
            print("  " + w)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="piigate", add_help=False, usage=HELP)
    p.add_argument("command", nargs="?", default="help")
    p.add_argument("file", nargs="?")
    p.add_argument("--rows", dest="rows", type=int)
    p.add_argument("--attachment", dest="attachment", type=int)
    p.add_argument("--number", dest="number", type=int)
    p.add_argument("--source", dest="source", default="files", choices=["mail", "files", "prod"])
    p.add_argument("-o")
    p.add_argument("--question", dest="question", default="")
    p.add_argument("--mail", dest="mail_query")
    p.add_argument("--mask-columns", dest="mask_columns", default="")
    p.add_argument("-h", "--help", action="store_true")
    arg = p.parse_args(argv)
    if arg.help or arg.command == "help":
        print(HELP)
        return 0
    try:
        cfg = config.load(os.getcwd())
        if arg.command not in ("status", "project"):
            project.require_valid(cfg)
        if arg.command == "show":
            if not arg.file:
                raise FilterError("give a file: piigate show FILE")
            path = Path(config.expand_tilde(arg.file))
            if arg.number is not None:  # a file from `piigate list` (names are masked, hence by number)
                path = files.file_from_list(path, arg.number, cfg)
            print(
                files.describe_file(path, cfg, source=arg.source, rows=arg.rows, attachment=arg.attachment), end=""
            )
        elif arg.command == "list":
            print(files.file_list(Path(config.expand_tilde(arg.file or ".")), cfg), end="")
        elif arg.command == "table":
            tables = table.from_text(table._decode(_input(arg.file, cfg)), "result")
            print(
                table.describe(tables, cfg, source="command output", sample_rows=arg.rows, safe_plain=True),
                end="",
            )
        elif arg.command == "text":
            result, counts = text.filter_text(table._decode(_input(arg.file, cfg)), cfg, source=arg.source)
            print(text.summary(counts))
            print(result, end="" if result.endswith("\n") else "\n")
        elif arg.command == "anonymize":
            path = _source_file(arg, cfg)
            mask = {k.strip() for k in arg.mask_columns.split(",") if k.strip()}
            result = anonymization.anonymize(path.name, path.read_bytes(), cfg, dest=arg.o, mask=mask)
            print(anonymization.report(result), end="")
        elif arg.command == "analyze":
            if arg.mail_query is not None:
                pseudonym_map = PseudonymMap()
                mail = analysis.fetch_mail(arg.mail_query, arg.number, cfg, pseudonym_map)
                if isinstance(mail, str):  # several messages — a list to choose from
                    print(mail, end="")
                    return 0
                name, data = mail
                print(analysis.analyze(name, data, cfg, question=arg.question, dest=arg.o, pseudonym_map=pseudonym_map), end="")
            else:
                path = _source_file(arg, cfg)
                print(analysis.analyze(path.name, path.read_bytes(), cfg, question=arg.question, dest=arg.o), end="")
        elif arg.command == "reverse":
            return reverse(arg, cfg)
        elif arg.command == "status":
            return status(cfg)
        elif arg.command == "project":
            return project_cmd(arg, cfg)
        else:
            raise FilterError(f"unknown command: {arg.command} (piigate help)")
    except FilterError as e:
        print(f"[piigate] denied: {e}", file=sys.stderr)
        return 3
    except FileNotFoundError:
        print("[piigate] denied: no such file", file=sys.stderr)
        return 3
    except Exception as e:  # noqa: BLE001 — a foreign exception message may quote data
        print(f"[piigate] denied: error {type(e).__name__} (details hidden — they may contain data)", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
