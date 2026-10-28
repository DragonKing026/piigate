"""Configuration: plugin defaults + ~/.config/piigate/config.json (dicts are merged, lists replaced)."""

import json
import os
import pwd
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # plugin directory
DEFAULT_CONFIG = ROOT / "config.json"


def config_dir() -> Path:
    # PIIGATE_CONFIG_DIR is for tests only; the gate denies Bash commands that set PIIGATE_*.
    return Path(os.environ.get("PIIGATE_CONFIG_DIR") or Path(home_dir()) / ".config" / "piigate")


def data_dir() -> Path:
    return Path(os.environ.get("PIIGATE_DATA_DIR") or Path(home_dir()) / ".local" / "share" / "piigate")


def _merge(base: dict, changes: dict) -> dict:
    result = dict(base)
    for k, v in changes.items():
        if isinstance(v, dict) and isinstance(result.get(k), dict):
            result[k] = _merge(result[k], v)
        else:
            result[k] = v
    return result


def load(cwd: str | None = None) -> dict:
    """cwd — working directory (hook, piigate CLI, MCP server): adds the project filters from `.claude/piigate.json` of this
    directory and of the session directory (`CLAUDE_PROJECT_DIR`), plus the in-project data directories."""
    cfg = json.loads(DEFAULT_CONFIG.read_text(encoding="utf-8"))
    user_cfg = config_dir() / "config.json"
    if user_cfg.is_file():
        cfg = _merge(cfg, json.loads(user_cfg.read_text(encoding="utf-8")))
    from . import project  # lazy import: project uses this module

    if cwd is None:
        return _add_project_dirs(project.apply(cfg, None), [])
    # the agent can change cwd (`cd /`) but not CLAUDE_PROJECT_DIR (the session directory); the union of both projects' filters applies
    cfg = project.apply(cfg, [cwd, os.environ.get("CLAUDE_PROJECT_DIR")])
    return _add_project_dirs(cfg, project_roots(cwd))


# --- in-project directories --------------------------------------------------------------------------

GITIGNORE = "# piigate: sensitive data or filtered copies — nothing in this directory goes into git\n*\n"


def _outside_home(folder: Path) -> bool:
    """A directory below home (not home itself, not one of its ancestors, not /)."""
    d = Path(home_dir())
    return folder != d and folder not in d.parents and folder != Path("/")


def git_root(cwd: str | None) -> str | None:
    """Nearest ancestor with `.git` (a directory or a worktree file) — without running git (the gate runs on every tool call)."""
    if not cwd:
        return None
    p = Path(os.path.realpath(cwd))
    for folder in (p, *p.parents):
        if not _outside_home(folder):
            return None
        if (folder / ".git").exists():
            return str(folder)
    return None


def project_roots(cwd: str | None) -> list[str]:
    """The session directory (`CLAUDE_PROJECT_DIR`, the agent cannot change it) and the git root of the working
    directory — the first one holds the copies. Without a session or repo (home directory, /tmp): empty, the global
    directories apply."""
    result = []
    session = os.environ.get("CLAUDE_PROJECT_DIR")
    for k in (os.path.realpath(session) if session else None, git_root(cwd)):
        if k and _outside_home(Path(k)) and k not in result:
            result.append(k)
    return result


def _add_project_dirs(cfg: dict, roots: list[str]) -> dict:
    names = cfg.get("project_directories", {})
    anon_cfg = cfg.setdefault("anonymization", {})
    anon_cfg["directories"] = [anon_cfg.get("directory", DEFAULT_ANONYMIZED)]  # all copy directories — the gate allows reading them directly
    w = cfg["in_project"] = {"sensitive": [], "anonymized": []}
    if n := names.get("sensitive"):
        w["sensitive"] = [os.path.join(k, n) for k in roots]
        z = cfg["sources"]
        z["directories"] = list(z["directories"]) + [k for k in w["sensitive"] if k not in z["directories"]]
    if n := names.get("anonymized"):
        # a symlink instead of a directory (`ln -s ~/Downloads Anonymized-data`) would lift content checks from its target — skipped
        w["anonymized"] = [os.path.join(k, n) for k in roots if not os.path.islink(os.path.join(k, n))]
        if w["anonymized"]:
            anon_cfg["directory"] = w["anonymized"][0]
            anon_cfg["directories"] = w["anonymized"] + anon_cfg["directories"]
    return cfg


def anonymized_dirs(cfg: dict) -> list[str]:
    """The copy directory (first) and the others — the global one stays readable in a project session too."""
    anon_cfg = cfg.get("anonymization", {})
    result = [expand(k) for k in [anon_cfg.get("directory", DEFAULT_ANONYMIZED), *anon_cfg.get("directories", [])]]
    return list(dict.fromkeys(result))


def ensure_gitignore(folder: str | Path) -> None:
    """`.gitignore` with `*` in an existing in-project data directory — appended when missing or when `*` is gone.
    The hook writes with the user's permissions: neither the directory nor the file may be a symlink (a planted
    `.gitignore -> ~/.bashrc`)."""
    p = Path(folder) / ".gitignore"
    try:
        if os.path.islink(folder) or not Path(folder).is_dir() or os.path.islink(p):
            return
        fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "r+", encoding="utf-8") as f:
            f.seek(0)
            content = f.read()
            if "*" not in content.splitlines():
                f.write(("\n" if content and not content.endswith("\n") else "") + ("\n" if content else "") + GITIGNORE)
    except (OSError, UnicodeDecodeError):
        pass  # a missing .gitignore does not weaken the gate; a read-only directory stays as it is


def ensure_project_gitignore(cfg: dict) -> None:
    for k in [*cfg.get("in_project", {}).get("sensitive", []), *cfg.get("in_project", {}).get("anonymized", [])]:
        ensure_gitignore(k)


def home_dir() -> str:
    """Home directory from the user database, not from $HOME (the model could prefix a command with HOME=…)."""
    return pwd.getpwuid(os.getuid()).pw_dir


DOCUMENTS = "{documents}"  # placeholder in config paths: the XDG documents directory
DEFAULT_ANONYMIZED = DOCUMENTS + "/piigate/Anonymized-data"


def documents_dir() -> str:
    """XDG documents directory: `XDG_DOCUMENTS_DIR` from the environment or ~/.config/user-dirs.dirs, else ~/Documents.
    The gate denies Bash commands that mention XDG_DOCUMENTS_DIR (a prefix would move the sensitive directories for `piigate`)."""
    value = os.environ.get("XDG_DOCUMENTS_DIR", "")
    if not value:
        try:
            text = (Path(home_dir()) / ".config" / "user-dirs.dirs").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        if m := re.search(r'^\s*XDG_DOCUMENTS_DIR\s*=\s*"?([^"\n]*)"?\s*$', text, re.M):
            value = m.group(1)
    if value.startswith("$HOME"):
        value = home_dir() + value[len("$HOME") :]
    elif value.startswith("~"):
        value = home_dir() + value[1:]
    if not value or not os.path.isabs(value) or os.path.realpath(value) == os.path.realpath(home_dir()):
        value = os.path.join(home_dir(), "Documents")  # user-dirs.dirs sets a disabled dir to $HOME
    return value.rstrip("/")


def expand_tilde(path: str) -> str:
    if path == DOCUMENTS or path.startswith(DOCUMENTS + "/"):
        return documents_dir() + path[len(DOCUMENTS) :]
    if path == "~" or path.startswith("~/"):
        return home_dir() + path[1:]
    return os.path.expanduser(path)


def expand(path: str) -> str:
    return os.path.realpath(expand_tilde(os.path.expandvars(path)))


def sensitive_dirs(cfg: dict) -> list[str]:
    return [expand(k) for k in cfg["sources"]["directories"]]


def protected_dirs(cfg: dict) -> list[str]:
    result = [expand(k) for k in cfg["protected"]]
    result += [str(data_dir().resolve()), str(config_dir().resolve())]
    # the local engine's socket directory: a model that binds its own socket there could answer "nothing found"
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if runtime:
        result.append(str(Path(runtime).resolve() / "piigate"))
    # the installed plugin copy (cache) — otherwise the model could loosen the default configuration
    plugin = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if plugin and "/plugins/cache/" in plugin:
        result.append(expand(plugin))
    return sorted(set(result))
