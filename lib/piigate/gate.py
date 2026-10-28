"""Gate (PreToolUse): denies direct reads of sensitive sources, with a hint about what to use instead.

Returns None (allow) or the denial reason (shown to the model). The gate analyses the command text — code that
builds a path at run time (`python -c` with string concatenation, base64, variables) gets around it; this limitation
is documented in the README. Rule: with a sensitive source only a single pipeline through the plugin's real `piigate`
is allowed (followed only by grep/head/tail/wc/sort/uniq/cut on its output), or a command with no content in its
output and its target inside a sensitive directory. Tools listed in `unfiltered_tools` (their output bypasses the
filter, e.g. a local LLM subagent) are denied on sensitive data and in forms where their directory is unknown.
"""

import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

from . import config, project, verdict

# Message substrings are matched by hook.denial_kind (log categories) — keep them in sync.
HINT = (
    "Instead use the piigate MCP tools (their output goes through the filter): piigate_show (a file: CSV/XLSX/ODS → "
    "structure; PDF/EML/DOCX/TXT → text with pseudonyms), piigate_list + piigate_show(number), piigate_search (search a "
    "project that has sensitive directories: code in plain text, free text with pseudonyms, tables without values), "
    "piigate_analyze (local model: what is in a file or an email, a summary without the data), piigate_anonymize (a copy "
    "you can read directly); in Bash `<command> 2>&1 | piigate table` (SQL results) and `<command> 2>&1 | piigate text`. "
    "The piigate skill describes the rules; working around the gate is forbidden."
)
MCP_PIIGATE = (
    "piigate: `piigate analyze` / `piigate anonymize` are disabled in Bash — use the MCP tools piigate_analyze / "
    "piigate_anonymize (the piigate plugin's MCP server; parameters: path or mail_query, number, question, mask_columns). "
    "Their output is filtered."
)
UNFILTERED_HINT = (
    "Its output does not go through the filter. For sensitive data use piigate_analyze (piigate), which filters the "
    "model output; call the tool's MCP form (if it has one) on a directory without sensitive data."
)
# an unfiltered tool in Bash with variables, substitutions, eval, `sh -c`, xargs, source — its directory is unknown
OPAQUE_FORMS = re.compile(r"[$`]|\beval\b|\b(?:ba|z|da|k)?sh\s+(?:-\w+\s+)*-\w*c|\bxargs\b|\bsource\b|(?:^|[\s;&|])\.\s")
# commands that run their arguments (or stdin as a script): the tool's name as their argument = a call
LAUNCHERS = {
    "bash", "sh", "zsh", "dash", "ksh", "fish", "eval", "source", ".", "exec", "command", "builtin", "env", "sudo",
    "doas", "nohup", "setsid", "time", "timeout", "nice", "ionice", "stdbuf", "chrt", "taskset", "xargs", "parallel",
    "find", "fd", "watch", "flock", "script", "unbuffer", "alias", "function", "export", "declare", "typeset",
    "local", "readonly", "trap",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish"}
# launchers followed directly by the command and its own arguments (`timeout 60 tool --dir X`): the arguments are known
DIRECT_LAUNCHERS = {
    "exec", "command", "builtin", "env", "sudo", "doas", "nohup", "setsid", "time", "timeout", "nice", "ionice",
    "stdbuf", "chrt", "taskset", "unbuffer",
}
SHELL_KEYWORDS = {"{", "}", "!", "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "case"}
REDIRECT_ALONE = re.compile(r"\d*(?:[<>]+&?|&>+)\d*-?")
REDIRECT_GLUED = re.compile(r"\d*(?:[<>]+&?|&>+)\S+")


def _flat(text: str) -> str:
    """Text without quotes and backslashes — a name glued from quotes ("local-agen""t", l\\ocal-agent) stays visible."""
    return re.sub(r"[\"'\\]", "", text)


HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*(['\"]?)([\w.-]+)\1")
RG_IGNORE_FILES = (".ignore", ".rgignore", ".fdignore")
SUBSTITUTION = re.compile(r"\$\(|`|\$\{|<\(|>\(|\$[A-Za-z_]")
FIND_WITH_ARG = {"-type", "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-maxdepth", "-mindepth"}
# a repo here does not make files public (downloads, temporary files)
NON_PUBLIC = ["~/Downloads", "~/Pobrane", "/tmp", "/var/tmp", "/dev/shm"]
# installed software (man pages, package docs, libraries) — a data extension or a glob there is not a sensitive source
SYSTEM_DIRS = ["/usr", "/lib", "/lib64", "/bin", "/sbin"]
# commands whose arguments are text printed back (not files they read)
TEXT_COMMANDS = {"echo", "printf"}
WRAPPERS = {"env", "command", "nice", "nohup", "time", "timeout", "stdbuf", "ionice"}
RG_GLOBS = re.compile(r"^(?:-g|--glob|--iglob|-G|--file-search-regex)(?:=|$)|^-g.+")
# commands that print names only (no content), and find actions that read, execute or write
LISTING_COMMANDS = {"ls", "find", "tree", "du"}
FIND_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"}
# output from the network / a server / a database — not a public place, even with a relative file name
NETWORK_COMMANDS = {"ssh", "scp", "rsync", "sftp", "curl", "wget", "http", "https", "mysql", "mariadb", "psql", "docker", "kubectl"}
FORBIDDEN_OPERATORS = {";", "&&", "||", "&", ";;", "(", ")", "<<<", "\n", "&|", ";&", "|&&"}
REDIRECTS = {">", ">>", ">&", "&>", "&>>", ">|", "<", "<<", "<>", "<&"}
PIIGATE_SUBCOMMANDS = {"show", "list", "table", "text", "status", "help", "--help", "-h"}
# earlier pipeline stages before piigate: reading commands only (allow-list), no writing to files
# (no psql/mysql/mlr/docker — they can run code or write a file locally; database queries go through ssh,
# where the command runs on the server)
PIPE_SOURCES = {
    "cat",
    "head",
    "tail",
    "zcat",
    "bzcat",
    "xzcat",
    "ssh",
    "pdftotext",
    "grep",
    "cut",
    "iconv",
    "jq",
    "markitdown",
}
# stages after piigate: they only trim or count the already filtered output. Command → (options taking a value in a
# separate token, forbidden short option letters, forbidden long options). A positional argument other than the grep
# pattern = a file name, i.e. a read bypassing piigate — denied; writing (sort -o) and reading files (grep -f/-r) too.
AFTER_PIIGATE = {
    "grep": ({"-e", "--regexp", "-m", "--max-count", "-A", "-B", "-C"}, "frRdD",
             ("--file", "--recursive", "--dereference-recursive", "--directories", "--devices", "--include",
              "--exclude")),
    "head": ({"-n", "-c", "--lines", "--bytes"}, "", ()),
    "tail": ({"-n", "-c", "--lines", "--bytes"}, "", ()),
    "wc": (set(), "", ("--files0-from",)),
    "sort": ({"-k", "--key", "-t", "--field-separator"}, "oT",
             ("--output", "--files0-from", "--temporary-directory", "--compress-program")),
    "uniq": ({"-f", "-s", "-w"}, "", ()),
    "cut": ({"-d", "-f", "-c", "-b", "--delimiter", "--fields", "--characters", "--bytes"}, "", ()),
}
SSH_FLAGS = set("qTC46")  # ssh in a pipeline: only these flags without a value
SSH_WITH_VALUE = {"-p", "-l"}
SSH_O_KEYS = {
    "port", "user", "connecttimeout", "batchmode", "stricthostkeychecking", "serveraliveinterval", "loglevel",
}


def strip_2to1(tokens: list[str]) -> list[str]:
    """Removes every `2 >& 1` triple — validation must cover EVERY remaining token (also those after 2>&1)."""
    result, k = [], 0
    while k < len(tokens):
        if tokens[k : k + 3] == ["2", ">&", "1"]:
            k += 3
            continue
        result.append(tokens[k])
        k += 1
    return result


def ssh_valid(arguments: list[str]) -> bool:
    """Allow-list of ssh options (like getopt: char by char in a cluster) — anything else is denied."""
    arguments = strip_2to1(arguments)
    k = 0
    while k < len(arguments):
        t = arguments[k]
        if not t.startswith("-") or t == "-":
            k += 1  # host, remote command
            continue
        if t in SSH_WITH_VALUE:
            k += 2
            continue
        if t == "-o" or t.startswith("-o"):
            value = t[2:] if len(t) > 2 else (arguments[k + 1] if k + 1 < len(arguments) else "")
            if re.split(r"[=\s]", value.strip(), maxsplit=1)[0].casefold() not in SSH_O_KEYS:
                return False
            k += 1 if len(t) > 2 else 2
            continue
        if re.fullmatch(r"-p\d+", t):
            k += 1
            continue
        if not all(ch in SSH_FLAGS for ch in t[1:]):
            return False  # -vo…, -E, -F, -i, -L, -R, -D, -S, -J…
        k += 1
    return True


PDFTOTEXT_WITH_VALUE = {"-f", "-l", "-r", "-x", "-y", "-W", "-H", "-enc", "-eol", "-opw", "-upw", "-fixed", "-margin"}
OUTPUT_OPTIONS = re.compile(r"^(?:-o|-O|--output(?:=.*)?|--out(?:=.*)?|-o.+|--output-file(?:=.*)?)$")
SEARCHERS = {
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "find",
    "fd",
    "tree",
    "du",
    "tar",
    "zip",
    "7z",
    "rga",
    "locate",
    "fselect",
    "fclones",
    "zgrep",
}
GREP_RECURSE = re.compile(r"(?:^|\s)(?:-d\s*recurse|--directories(?:=|\s+)recurse)\b")
# `ssh host 'systemctl status mysql'`, `ls /etc/mysql`, `mysql.service` — a service / path, not a database query
DB_CLIENT = re.compile(r"\b(?:mysql|mariadb|psql)\b")
SERVICE_COMMANDS = re.compile(
    r"(?:^|[\s'\"])(?:systemctl|service|journalctl|which|whereis|type|man|apt|apt-get|dnf|yum|rpm|dpkg)\s[^'\";&|]*$"
)


def strip_db_services(text: str) -> str:
    """Occurrences of mysql/mariadb/psql that are a service or package name or part of a path — replaced with `_`."""

    def substitute(m: re.Match) -> str:
        before, after = text[: m.start()], text[m.end() : m.end() + 2]
        if (before[-1:] and before[-1] in "/.-_") or re.match(r"[/.\-_]\w", after):
            return "_"
        segment = re.split(r"[;&|]|&&|\|\|", before)[-1]
        return "_" if SERVICE_COMMANDS.search(segment) else m.group()

    return DB_CLIENT.sub(substitute, text)
RECURSIVE_FLAGS = re.compile(r"^-(?:[a-zA-Z]*[rR][a-zA-Z]*|-recursive|-dereference-recursive)$")
# searchers: family → options whose value is a file-name filter (not a path), and options that supply the pattern
FAMILIES = {
    "grep": "grep", "egrep": "grep", "fgrep": "grep", "zgrep": "grep",
    "rg": "rg", "rga": "rg", "ag": "ag", "ack": "ag", "fd": "fd", "fdfind": "fd", "find": "find",
}
NAME_FILTERS = {
    "grep": {"--include", "--exclude", "--exclude-dir"},
    "rg": {"-g", "--glob", "--iglob", "-t", "--type", "-T", "--type-not"},
    "ag": {"-G", "--file-search-regex", "--ignore", "--ignore-dir", "--type"},
    "fd": {"-e", "--extension", "-E", "--exclude", "-t", "--type"},
    "find": {"-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-regex", "-iregex", "-lname", "-ilname"},
}
# pattern from an option (-e/-f) — then the first positional argument is already a path; also a short-flag group with e/f
PATTERN_OPTIONS = {"grep": re.compile(r"^(?:-[a-zA-Z]*[ef]|--regexp|--file)$"), "rg": re.compile(r"^(?:-[a-zA-Z]*[ef]|--regexp|--file)$")}
# rg, fd, ag honour .ignore (rg also .rgignore, fd .fdignore) — also outside a git repository
IGNORE_FILES = {"rg": (".ignore", ".rgignore"), "fd": (".ignore", ".fdignore"), "ag": (".ignore",)}
NO_IGNORE = re.compile(r"^(?:--no-ignore\S*|--unrestricted|-[a-zA-Z]*u[a-zA-Z]*|-I|--skip-vcs-ignores|-U)$")
COPY_COMMANDS = {"cp", "mv", "scp", "rsync"}  # copying: all paths inside a sensitive directory
COPY_FLAGS = re.compile(r"^(?:-[aprRvinfuzPq]+|--(?:archive|recursive|verbose|progress|preserve|no-clobber))$")


def _find_dirs_only(arguments: list[str]) -> bool:
    """The find expression prints directories only — allow-listed forms: `-type d` at the top level (no `!`/`-not`
    before it), name/depth tests with an argument (`-name X`, `-iname`, `-path`, `-maxdepth N`…), parentheses,
    `!`/`-not`, `-a`; alternation (`-o`) only inside parentheses. Test arguments are skipped when counting parentheses
    (`-name ')'`); other tests and actions — denied. `find ~ -type d ( -iname a -o -iname b ) -not -path '*/x/*'` yes,
    `-type d -o -name x` no."""
    depth, has_type_d, i = 0, False, 0
    paths = True
    while i < len(arguments):
        t = arguments[i]
        if paths and not t.startswith(("-", "(", "!")):
            i += 1
            continue
        paths = False
        if t in FIND_WITH_ARG:
            if i + 1 >= len(arguments):
                return False
            if t == "-type":
                if depth == 0 and arguments[i + 1] == "d" and not (i and arguments[i - 1] in ("!", "-not")):
                    has_type_d = True
            i += 2
            continue
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
            if depth < 0:
                return False
        elif t in ("-o", "-or"):
            if depth == 0:
                return False
        elif t not in ("!", "-not", "-a", "-and"):
            return False  # unknown test or action (-print0, -printf, -newer…)
        i += 1
    return has_type_d and depth == 0


def _du_dirs_only(arguments: list[str]) -> bool:
    """du without -a: only allow-listed options (-s -h -c -x, -d N, --max-depth=N, --summarize, --human-readable), the rest are paths."""
    i = 0
    while i < len(arguments):
        t = arguments[i]
        if t == "-d" and i + 1 < len(arguments) and arguments[i + 1].isdigit():
            i += 2
            continue
        if t.startswith("-") and not (
            re.fullmatch(r"-[shcx]+|-d\d+|--max-depth=\d+|--summarize|--human-readable|--total|--one-file-system", t)
        ):
            return False
        i += 1
    return True


def _inside(path: str, directories: list[str]) -> bool:
    return any(path == k or path.startswith(k.rstrip("/") + "/") for k in directories)


def _ancestor(path: str, directories: list[str]) -> bool:
    """Whether any of the directories lies UNDER the path (searching ~ covers ~/Documents/piigate/Sensitive-data)."""
    return any(_inside(k, [path]) for k in directories)


def _path(s: str, cwd: str) -> str:
    s = config.expand_tilde(os.path.expandvars(s))
    return os.path.realpath(s if os.path.isabs(s) else os.path.join(cwd, s))


def expand_braces(t: str, limit: int = 64) -> list[str]:
    """a{b,c}d → [abd, acd], a{1..3} / a{x..z} → sequences (like bash; limited number of variants)."""
    m = re.search(r"\{([^{}]*,[^{}]*|-?\d+\.\.-?\d+(?:\.\.-?\d+)?|[A-Za-z]\.\.[A-Za-z])\}", t)
    if not m or limit <= 0:
        return [t]
    content = m.group(1)
    if "," in content:
        variants = content.split(",")
    elif re.fullmatch(r"[A-Za-z]\.\.[A-Za-z]", content):
        a, b = ord(content[0]), ord(content[-1])
        variants = [chr(c) for c in range(min(a, b), max(a, b) + 1)]
    else:
        texts = content.split("..")
        parts = [int(x) for x in texts]
        step = abs(parts[2]) if len(parts) > 2 and parts[2] else 1
        a, b = parts[0], parts[1]
        widths = (
            max(len(texts[0]), len(texts[1]))
            if re.match(r"-?0\d", texts[0] + " " + texts[1]) or re.search(r"(?:^|-)0\d", texts[1])
            else 0
        )  # {01..03} → 01 02 03
        variants = [str(x).zfill(widths) for x in range(min(a, b), max(a, b) + 1, step)][:256]
    result = []
    for variant in variants:
        result += expand_braces(t[: m.start()] + variant + t[m.end() :], limit - 1)
    return result[:256]


def unfiltered_tools(cfg: dict) -> list[dict]:
    """Entries of `unfiltered_tools`: {name, commands: [Bash command names], mcp_tools: regex of MCP tool names,
    dir_option: Bash option naming the directory, dir_param: the MCP parameter, deny_options: {option: [values]}}."""
    result = []
    for e in cfg.get("unfiltered_tools") or []:
        if not isinstance(e, dict) or not isinstance(e.get("commands", []), list):
            raise ValueError("unfiltered_tools: every entry is an object with a list `commands`")
        commands = {str(c) for c in e.get("commands", []) if str(c)}
        result.append({**e, "name": str(e.get("name") or next(iter(sorted(commands)), "tool")), "commands": commands})
    return result


def unfiltered_entry(entries: list[dict], tool: str) -> dict | None:
    """The `unfiltered_tools` entry whose `mcp_tools` regex matches the MCP tool name."""
    return next((e for e in entries if e.get("mcp_tools") and re.search(e["mcp_tools"], tool)), None)


class Gate:
    def __init__(self, cfg: dict, cwd: str):
        self.cfg = cfg
        self.cwd = cwd or os.getcwd()
        self.sensitive = config.sensitive_dirs(cfg)
        self.protected = config.protected_dirs(cfg)
        self.exempt = [config.expand(k) for k in cfg["sources"].get("exempt_directories", [])]
        self.system = [os.path.realpath(config.expand(k)) for k in cfg["sources"].get("system_directories", SYSTEM_DIRS)]
        # copies made by `piigate anonymize/analyze` — read directly (a .csv extension does not block), sensors still apply
        self.anonymized = config.anonymized_dirs(cfg)
        # in-project data directories: `.gitignore` restored on every run (the directory may have been created by hand)
        config.ensure_project_gitignore(cfg)
        # `Sensitive-data` of any project (not only the session's and the cwd repo's) — by path component name
        self.sensitive_name = (cfg.get("project_directories") or {}).get("sensitive") or None
        self.project_sensitive = [config.expand(k) for k in cfg.get("in_project", {}).get("sensitive", [])]
        self.extensions = tuple(e.casefold() for e in cfg["sources"]["extensions"])
        # an extension outside the sensitive directories is only a reason to check the content
        self.judge = verdict.Judge(cfg)
        self.verdicts: dict[str, verdict.Verdict] = {}
        self.commands = [re.compile(w) for w in cfg["sources"]["commands"]]
        self.no_content = [p.split() for p in cfg["sources"].get("commands_without_output", [])]
        # text markers: directory names (they also catch `cd ~/Downloads && cat thunderbird.tmp/x` and `python -c`)
        self.markers = [Path(k).name for k in self.sensitive if len(Path(k).name) >= 6]
        self.protected_markers = ["piigate/map", "piigate/key", "piigate/engine", ".local/share/piigate", ".config/piigate"]
        plugin = os.environ.get("CLAUDE_PLUGIN_ROOT")
        self.cli = os.path.realpath(os.path.join(plugin, "bin", "piigate")) if plugin else None
        # tools whose output bypasses the filter (config `unfiltered_tools`): name, Bash commands, MCP tool regex…
        self.unfiltered = unfiltered_tools(cfg)
        # content of files with a data extension is checked only in PHI projects and outside git repositories
        self.only_phi_projects = cfg["sources"].get("only_phi_projects", True)
        self._public_dirs: dict[str, bool] = {}
        self._phi_under: dict[str, bool] = {}
        self._text = ""  # current Bash command (_touches)

    # --- paths ----------------------------------------------------------------------------------

    def has_extension(self, s: str) -> bool:
        """A file with a sensitive-data extension outside the exemptions (without checking content)."""
        p = _path(s, self.cwd)
        return (
            p.casefold().endswith(self.extensions)
            and not _inside(p, self.exempt + self.anonymized + self.system)
            and not self.is_public(p)
        )

    def is_public(self, s: str) -> bool:
        """A place without PHI: inside a git repository that is not a PHI project (no `.claude/piigate.json` and no
        approved snapshot), outside the sensitive directories. Content of .sql/.csv/.pdf… files is not checked there
        (package authors' names, example addresses). Outside repos (~/Downloads, /tmp) and in PHI projects it is."""
        if not self.only_phi_projects:
            return False
        p = _path(s, self.cwd)
        if _inside(p, self.sensitive + self.protected) or self._in_project_sensitive(s, p):
            return False
        directory = p if os.path.isdir(p) else os.path.dirname(p)
        if directory not in self._public_dirs:
            self._public_dirs[directory] = self._repo_public(directory)
        return self._public_dirs[directory]

    def is_public_tree(self, s: str) -> bool:
        """Like `is_public`, and for a directory (search root, glob) also: there is no PHI project under it (a nested
        repo or a subdirectory with `.claude/piigate.json`, an approved snapshot of project filters)."""
        if not self.is_public(s):
            return False
        p = _path(s, self.cwd)
        return not os.path.isdir(p) or not self._phi_project_under(p)

    def _phi_project_under(self, p: str) -> bool:
        if p in self._phi_under:
            return self._phi_under[p]
        result = False
        for file in project.snapshot_dir().glob("*.json"):  # project file deleted, the approved snapshot remains
            try:
                root = json.loads(file.read_text(encoding="utf-8")).get("path", "")
            except (OSError, ValueError, AttributeError):
                result = True  # unreadable snapshot — be careful
                break
            if _inside(root, [p]):
                result = True
                break
        if not result:
            try:
                r = subprocess.run(
                    ["rg", "--files", "--follow", "--hidden", "--no-ignore", "--no-config", "--glob", f"**/{project.FILE}", "--", p],
                    capture_output=True, text=True, timeout=3, check=False,
                )
                result = r.returncode not in (0, 1) or bool(r.stdout.strip())
            except (OSError, subprocess.TimeoutExpired):
                result = True  # unknown — check the content as before
        self._phi_under[p] = result
        return result

    def _repo_public(self, directory: str) -> bool:
        """A repo without a PHI marker that was not created a moment ago (`git init ~/Downloads` does not lift the
        check): outside download and temporary locations (`sources.non_public`), `.git` older than
        `public_repo_min_age_h` (inode change time — `touch` cannot turn it back)."""
        z = self.cfg["sources"]
        if _inside(directory, [config.expand(k) for k in z.get("non_public", NON_PUBLIC)]):
            return False
        root = config.git_root(directory)
        if root is None or project.find(directory) is not None:
            return False
        git = os.path.join(root, ".git")
        # the .git directory changes ctime on every commit — what counts are the entries `git init` creates once
        # (worktree: the .git file); moving and linking also refresh ctime
        candidates = [git] if os.path.isfile(git) else [os.path.join(git, n) for n in ("description", "info", "hooks")]
        mtimes = []
        for k in candidates:
            try:
                mtimes.append(os.lstat(k).st_ctime)
            except OSError:
                pass
        return bool(mtimes) and (time.time() - min(mtimes)) / 3600 >= z.get("public_repo_min_age_h", 24)

    def touches_extension(self, command: str) -> bool:
        """The Bash command names a file with a data extension — the filter then also checks its output (the file may
        have changed after the gate's verdict: `wget … -O x.sql; cat x.sql`). Conservative, by text: any `.sql`/`.csv`…
        in the command or an extension name in braces (`x.{sql,txt}`) — a false alarm only costs an output check."""
        text = re.sub(r"[\"'\\]", "", command).casefold()  # a.c""sv, a.c\sv
        if any(e in text for e in self.extensions):
            return not self._files_public(command)
        names = "|".join(re.escape(e.lstrip(".")) for e in self.extensions)
        return bool(re.search(rf"\{{[^}}]*\b(?:{names})\b", text))

    def _files_public(self, command: str) -> bool:
        """Every file with a data extension named in the command lies in a public place — the output is not checked.
        Network commands (ssh, curl, database clients…) and tokens that are not paths — checked."""
        tokens = self._tokens(command)
        if tokens is None or any(Path(t).name in NETWORK_COMMANDS for t in tokens):
            return False
        paths = [t.split("=", 1)[-1] for t in tokens if any(e in t.casefold() for e in self.extensions)]
        if not paths or any(re.search(r"\s|^[\w.@-]+:", s) for s in paths):
            return False
        return all(self.is_public_tree(self._pattern_root(s)) for s in paths)

    def _pattern_root(self, s: str) -> str:
        """For a pattern (`dir/pre*/x.sql`, `a{b,c}`) the nearest existing directory before the first wildcard —
        checked together with its subtree; a plain path is returned unchanged."""
        name_prefix = re.split(r"[*?\[{]", s, maxsplit=1)[0]
        if name_prefix == s:
            return s
        k = _path(name_prefix or ".", self.cwd)
        while not os.path.isdir(k) and k != os.path.dirname(k):
            k = os.path.dirname(k)
        return k

    def _stage_public(self, stage: list[str], skip: set[int], no_path: bool) -> bool:
        """All of the searcher's paths (or cwd when there are none) are in public places."""
        paths = [
            t
            for i, t in enumerate(stage)
            if i and i not in skip and not t.startswith("-") and not re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t)
        ]
        return all(self.is_public_tree(t) for t in (paths if paths and not no_path else [self.cwd]))

    @staticmethod
    def _commit_message(stage: list[str]) -> set[int]:
        """Indices of the `git commit|tag -m …` message — text, not a path (a directory name in a change description)."""
        if len(stage) < 2 or Path(stage[0]).name != "git" or not ({"commit", "tag"} & set(stage[1:3])):
            return set()
        result = set()
        for i, t in enumerate(stage[:-1]):
            if re.fullmatch(r"-[a-zA-Z]*m|--message", t):
                result.add(i + 1)
        result |= {i for i, t in enumerate(stage) if t.startswith("--message=")}
        # `-m "$(cat …)"` — the shell runs the substitution: such a message is a command, not text
        return {i for i in result if not SUBSTITUTION.search(stage[i])}

    def _text_args(self, stage: list[str]) -> set[int]:
        """Indices of tokens that are text, not paths: a commit message, and echo/printf arguments (printed back, not
        read) — except redirections, their targets and tokens with a command substitution."""
        result = self._commit_message(stage)
        if stage and stage[0] in TEXT_COMMANDS:
            targets = self._write_targets(stage)
            result |= {
                i
                for i, t in enumerate(stage)
                if i
                and i not in targets
                and t not in REDIRECTS
                and not re.fullmatch(r"\d*[<>]+&?\d*", t)
                and not (i > 0 and stage[i - 1] in ("<", "<>", "<&"))
                and not re.search(r"\$\(|`|<\(", t)
            }
        return result

    def _strip_commit_message(self, tokens: list[str] | None, text: str) -> str:
        """The command text without commit messages and echo/printf text (for the directory-name markers)."""
        if tokens is None:
            return text
        stages = self._stages_loose(tokens)
        if not any(self._text_args(e) for e in stages):
            return text
        return " ".join(t for e in stages for i, t in enumerate(e) if i not in self._text_args(e))

    def _names_only(self, command: str, tokens: list[str] | None) -> bool:
        """The command only lists names (ls, find without actions, tree, du) of directories that CONTAIN a filter or
        sensitive directory (`ls ~`, `find ~ -maxdepth 3 -type d -iname '*proj*'`) — no content comes back. Not inside a
        sensitive/protected directory; descending into an ancestor of a sensitive directory only by directories (ls
        without -R, find -type d, tree -d), because data file names can be personal. The other stages (`| grep x`)
        are judged separately like a normal command."""
        if tokens is None or "\n" in command.strip() or re.search(r"\$\(|`|<\(|>\(|\$\{", command):
            return False
        stages: list[list[str]] = [[]]
        for t in tokens:
            if t in (";", "&&", "||", "|", "|&"):
                stages.append([])
            elif t in FORBIDDEN_OPERATORS and t not in ("(", ")"):
                return False
            else:
                stages[-1].append(t)
        rest: list[str] = []
        listing = 0
        for stage in (e for e in stages if e):
            cmd = Path(stage[0]).name
            if stage[0] != cmd or cmd not in LISTING_COMMANDS:  # /tmp/ls, ./find — no
                if "(" in stage or ")" in stage:
                    return False
                rest += [*stage, ";"]
                continue
            listing += 1
            if any(z in " ".join(stage) for z in self.markers + self.protected_markers):
                return False
            arguments = list(stage[1:])
            if len(arguments) >= 3 and arguments[-1] == "/dev/null" and arguments[-2] == ">" and arguments[-3].isdigit():
                arguments = arguments[:-3]  # 2 > /dev/null (as the tokenizer splits it)
            elif len(arguments) >= 2 and arguments[-1] == "/dev/null" and re.fullmatch(r"\d?>|&>", arguments[-2]):
                arguments = arguments[:-2]
            if any(t in REDIRECTS or t in FIND_ACTIONS or "from" in t.casefold() for t in arguments):
                return False  # tree --fromfile, du --files0-from, find -files0-from read names from a file
            if cmd == "find":
                paths = []
                for t in arguments:
                    if t.startswith(("-", "(", "!")):
                        break
                    paths.append(t)
            else:
                paths = [t for t in arguments if not t.startswith("-")] or ["."]
            for s in paths or ["."]:
                if re.search(r"[*?\[{]", s):
                    return False  # glob/braces in the path — the inside of a sensitive directory cannot be checked here
                p = _path(s, self.cwd)
                if _inside(p, self.protected + self.sensitive) or self._in_project_sensitive(s, p):
                    return False
                if _ancestor(p, [k for k in self.sensitive if self._counts_under(k, False, p)]) or self._contains_project_sensitive(p):
                    if cmd == "ls" and any(re.fullmatch(r"-[a-zA-Z]*R[a-zA-Z]*|--recursive", t) for t in arguments):
                        return False
                    if cmd == "find" and not _find_dirs_only(arguments):
                        return False
                    if cmd == "du" and not _du_dirs_only(arguments):
                        return False
                    if cmd == "tree" and not any(re.fullmatch(r"-[a-zA-Z]*d[a-zA-Z]*", t) for t in arguments):
                        return False
        if not listing:
            return False
        if not rest:
            return True
        kind, _ = self._touches(" ".join(rest), rest)
        return kind is None

    def _in_project_sensitive(self, s: str, p: str) -> bool:
        """The path (as given or resolved) passes through a directory named `project_directories.sensitive`."""
        n = self.sensitive_name
        return bool(n) and (n in Path(p).parts or n in Path(os.path.join(self.cwd, s)).parts)

    def _hidden_by_gitignore(self, k: str, anywhere: bool = False) -> bool:
        """An in-project data directory that a search from an ancestor will not show: it does not exist, or it lies in a
        git repo and has its own `.gitignore` with `*` and no negation (rg — Grep, and rg/fd/ag in Bash without
        --no-ignore — skips it)."""
        if not anywhere and k not in self.project_sensitive:
            return False
        if not os.path.lexists(k):
            return True
        g = os.path.join(k, ".gitignore")
        if os.path.islink(k) or os.path.islink(g) or not os.path.isfile(g) or not config.git_root(k):
            return False
        if os.environ.get("RIPGREP_CONFIG_PATH") or any(os.path.lexists(os.path.join(k, n)) for n in RG_IGNORE_FILES):
            return False  # rg configuration (--no-ignore) or an .ignore inside (it takes precedence over .gitignore)
        try:
            lines = [x.strip() for x in Path(g).read_text(encoding="utf-8").splitlines()]
        except (OSError, UnicodeDecodeError):
            return False
        return "*" in lines and not any(x.startswith("!") for x in lines)

    @staticmethod
    def _negations_on_path(base: str, k: str) -> bool:
        """An ignore file with a negation (`!…`) in the base or in a directory between the base and k — it could restore files."""
        directory = base
        while True:
            for name in RG_IGNORE_FILES:  # a negation in a higher .gitignore cannot override `*` of a deeper .gitignore
                try:
                    if any(x.strip().startswith("!") for x in (Path(directory) / name).read_text(encoding="utf-8").splitlines()):
                        return True
                except FileNotFoundError:
                    pass
                except (OSError, UnicodeDecodeError):
                    return True
            if directory == os.path.dirname(k) or not _inside(k, [directory]) or directory == k:
                return False
            directory = os.path.join(directory, os.path.relpath(k, directory).split(os.sep, 1)[0])

    def _counts_under(self, k: str, searching: bool, base: str) -> bool:
        """Whether the sensitive directory k makes an ancestor sensitive: a project directory that does not exist has
        nothing to protect; Grep (searching) also skips an existing one with `.gitignore`."""
        if k not in self.project_sensitive:
            return True
        if not os.path.lexists(k):
            return False
        return not (searching and self._hidden_by_gitignore(k) and not self._negations_on_path(base, k))

    def _contains_project_sensitive(self, p: str, searching: bool = False) -> bool:
        """A search of a parent directory (a directory of projects) would reach `<project>/Sensitive-data` — two levels
        down are checked (the project directory and a directory of projects); deeper only the configured list."""
        n = self.sensitive_name
        if not n or not os.path.isdir(p):
            return False
        try:
            candidates = [os.path.join(p, n)] + [
                os.path.join(p, d.name, n) for d in os.scandir(p) if d.is_dir(follow_symlinks=False)
            ]
        except OSError:
            return False
        return any(os.path.isdir(k) and not (searching and self._hidden_by_gitignore(k, anywhere=True)) for k in candidates)

    def path_kind(
        self, s: str, *, ancestor: bool = False, content: bool = True, searching: bool = False, protected: bool = True
    ) -> str | None:
        """'protected' | 'sensitive' | 'extension' | None; ancestor=True — also a directory containing a sensitive one.
        content=True: a file with an extension whose content the rules found clean is not 'extension'.
        searching=True (Grep): in-project data directories hidden by `.gitignore` do not make an ancestor sensitive.
        protected=False: protected directories are not checked (a pattern that cannot reach them)."""
        p = _path(s, self.cwd)
        if protected and (_inside(p, self.protected) or (ancestor and _ancestor(p, self.protected))):
            return "protected"
        if (
            _inside(p, self.sensitive)
            or (
                ancestor
                and (
                    _ancestor(p, [k for k in self.sensitive if self._counts_under(k, searching, p)])
                    or self._contains_project_sensitive(p, searching)
                )
            )
            or self._in_project_sensitive(s, p)
        ):
            return "sensitive"
        if self.has_extension(p):
            if content:
                w = self.verdicts[p] = self.verdicts.get(p) or self.judge.file(p)
                if w.result == verdict.CLEAN:
                    return None
            return "extension"
        return None

    def describe_verdict(self, s: str) -> str:
        """Why a file with an extension is denied — categories and counts or the reason, without values."""
        w = self.verdicts.get(_path(s, self.cwd))
        if w is None or w.result == verdict.CLEAN:
            return (
                "a file type that usually holds personal data (a pattern or a write target — its content cannot be checked)"
            )
        if w.result == verdict.PERSONAL:
            return f"the file contains personal data (filter rules: {w.description})"
        return f"a file type that usually holds personal data, and its content cannot be checked: {w.description}"

    def _path_reason(self, kind: str, s: str, tool: str) -> str:
        if kind == "protected":
            return (
                f"piigate: {s} is a filter file (pseudonym map, key or configuration) or a directory containing one — "
                "off-limits to the model. Only a human changes the configuration; reversing pseudonyms: a human, "
                "`piigate reverse` in their own terminal."
            )
        what = (
            "a sensitive data directory (or a directory containing one)"
            if kind == "sensitive"
            else self.describe_verdict(s)
        )
        if tool in ("Edit", "Write", "NotebookEdit"):
            return f"piigate: {tool} on {s} denied — {what} (the edit result shows the file content). {HINT}"
        return f"piigate: direct read of {s} denied — {what}. {HINT}"

    # --- decision -------------------------------------------------------------------------------

    def decision(self, tool: str, tool_input: dict) -> str | None:
        if reason := project.error_denial(self.cfg, tool, tool_input, self.cwd):
            return reason
        if tool in ("Read", "Edit", "Write", "NotebookEdit"):
            s = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
            kind = self.path_kind(s, content=tool != "Write") if s else None
            if kind == "extension" and tool == "Write":
                return None  # a new CSV/SQL file with content from the model — nothing sensitive comes back
            return self._path_reason(kind, s, tool) if kind else None
        if tool in ("Grep", "Glob"):
            s = tool_input.get("path") or self.cwd
            # an rg glob takes precedence over .gitignore — with one, Grep would enter the data directory
            kind = self.path_kind(s, ancestor=True, searching=tool == "Grep" and not tool_input.get("glob"))
            if kind in ("protected", "sensitive") or (kind == "extension" and tool == "Grep"):
                return self._path_reason(kind, s, tool)
            patterns = " ".join(
                str(tool_input.get(k) or "") for k in ("pattern", "glob", "type") if tool == "Glob" or k != "pattern"
            ).casefold()
            if any(z.casefold() in patterns for z in self.markers + self.protected_markers):
                return f"piigate: {tool} reaches into a sensitive directory (pattern). {HINT}"
            if (
                tool == "Grep"
                and any(e.lstrip(".") in patterns for e in self.extensions)
                and (reason := self._grep_by_files(s, tool_input))
            ):
                return f"piigate: Grep over {patterns.strip()} files denied — {reason}. {HINT}"
            return None
        if tool == "Bash":
            return self.bash(tool_input.get("command") or "")
        if entry := unfiltered_entry(self.unfiltered, tool):
            return self.unfiltered_mcp(entry, tool_input)
        return None

    def _grep_by_files(self, s: str, tool_input: dict) -> str | None:
        """Grep with a data-extension glob/type: None when every matching file has clean content (file count limited by
        the configuration); otherwise the reason. The file list comes from `rg --files` with the same `--glob`/`--type`
        (the same glob engine as Grep), with `--hidden --no-ignore` — more files than Grep will search; an rg error = deny."""
        glob = str(tool_input.get("glob") or "").strip()
        type_ = str(tool_input.get("type") or "").strip()
        directory = _path(s, self.cwd)
        if not os.path.isdir(directory):
            return None if os.path.isfile(directory) else "the path does not exist"  # path_kind has already checked a file
        arguments = ["rg", "--files", "--null", "--hidden", "--no-ignore", "--no-config", "--glob", "!.git"]
        for part in glob.split():  # Grep: parts separated by spaces and by commas outside braces
            arguments += [a for g in re.split(r",(?![^{]*\})", part) if g for a in ("--glob", g)]
        if type_:
            arguments += ["--type", type_]
        try:
            result = subprocess.run(
                [*arguments, "--", directory], capture_output=True, text=True, timeout=5, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            return "cannot determine the file list (rg unavailable or the tree is too large) — narrow `path`"
        if result.returncode not in (0, 1):  # 1 = no files
            return f"rg --files: exit code {result.returncode} (bad glob or type?)"
        matched = [p for p in result.stdout.split("\0") if p and self.has_extension(p)]  # \0: names containing a newline
        limit = self.judge.opts["max_files"]
        if len(matched) > limit:
            return f"over {limit} matching files — too many to check their content in the gate"
        for full_path in matched:
            if self.path_kind(full_path) is not None:
                return f"{os.path.relpath(full_path, directory)}: {self.describe_verdict(full_path)}"
        return None

    @staticmethod
    def _strip_heredocs(command: str) -> str:
        """Removes heredoc bodies — they are stdin data; kept when a shell receives the heredoc (the body = a script)."""
        result: list[str] = []
        end: list[str] = []
        for line in command.split("\n"):
            if end:
                if line.strip() == end[0]:
                    end.pop(0)
                continue
            result.append(line)
            for m in HEREDOC.finditer(line):
                stage = re.split(r"[|;&()]", line[: m.start()])[-1].split()
                words = [s for s in stage if s not in SHELL_KEYWORDS and not re.match(r"^\w+=", s)]
                if not (words and Path(words[0]).name in LAUNCHERS):
                    end.append(m.group(2))
        return "\n".join(result)

    def _heredoc_text(self, command: str) -> tuple[str, set[str]]:
        """Heredoc bodies read by a non-shell (`python3 - <<'X'`, `gh … --body-file - <<X`): the shell expands no globs
        there, and nothing at all with a quoted delimiter. Returns the command without the quoted bodies (where
        substitutions are looked for) and the tokens found only in the bodies (no glob — `name.*` is text). A body fed
        to a shell or a launcher is a script — unchanged."""
        outside: list[str] = []  # without quoted text bodies
        shell: list[str] = []  # without any text bodies
        body: list[str] = []
        end: list[tuple[str, bool | None]] = []
        for line in command.split("\n"):
            if end and line.strip() != end[0][0] and end[0][1] is not None:
                body.append(line)
                if not end[0][1]:
                    outside.append(line)  # unquoted delimiter: $(…) and `…` still run
                continue
            if end and line.strip() == end[0][0]:
                end.pop(0)
            elif not end:
                for m in HEREDOC.finditer(line):
                    stage = re.split(r"[|;&()]", line[: m.start()])[-1].split()
                    words = [s for s in stage if s not in SHELL_KEYWORDS and not re.match(r"^\w+=", s)]
                    script = not words or Path(words[0]).name in LAUNCHERS
                    # (delimiter, text body: quoted delimiter or not; None — a script)
                    end.append((m.group(2), None if script else bool(m.group(1))))
            outside.append(line)
            shell.append(line)
        if end or not body:
            return command, set()  # an unterminated heredoc — unchanged
        inner = self._tokens("\n".join(body)) or "\n".join(body).split()
        rest = self._tokens("\n".join(shell)) or "\n".join(shell).split()
        return "\n".join(outside), set(inner) - set(rest)

    @staticmethod
    def _substitutions(text: str) -> list[str]:
        """Contents of $(…), <(…), >(…) and `…` outside single quotes (substitution works in double quotes too)."""
        result, i, apostrophe = [], 0, False
        while i < len(text):
            z = text[i]
            if apostrophe:
                apostrophe = z != "'"
            elif z == "\\":
                i += 1
            elif z == "'" and text.count('"', 0, i) % 2 == 0:
                apostrophe = True
            elif z == "`":
                j = text.find("`", i + 1)
                j = len(text) if j < 0 else j
                result.append(text[i + 1 : j])
                i = j
            elif z in "$<>" and text[i + 1 : i + 2] == "(":
                depth, j = 1, i + 2
                while j < len(text) and depth:
                    depth += {"(": 1, ")": -1}.get(text[j], 0)
                    j += 1
                result.append(text[i + 2 : j - 1])
                i = j - 1
            i += 1
        return result

    def _invocations(self, command: str, names: set[str], depth: int = 0) -> list[list[str] | None]:
        """Where the command RUNS one of `names` (matched by the base name, also glued from quotes): the argv of each
        call (from the name on), or None for a call whose arguments the gate cannot determine — inside a substitution,
        `sh -c`, eval, xargs, find -exec, a variable holding the name. A call is the first word of a simple command
        (after keywords, assignments and redirections; after | ; && || & newline, in a heredoc fed to a shell) or the
        argument of a launcher. The name inside an argument (a commit message, an issue title, a grep pattern) or in a
        heredoc body written to a file or fed to a non-shell is data. Unparsable quotes — [None] (when in doubt, a call)."""
        if not any(n in _flat(command) for n in names):
            return []
        text = self._strip_heredocs(command)
        if not any(n in _flat(text) for n in names):
            return []
        if depth > 8:
            return [None]
        found: list[list[str] | None] = []
        for inner in self._substitutions(text):
            if self._invocations(inner, names, depth + 1):
                found.append(None)
        lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()\n")
        lex.whitespace = " \t\r"
        lex.whitespace_split = True
        lex.commenters = ""
        try:
            tokens = list(lex)
        except ValueError:
            return [None]
        stages: list[list[str]] = [[]]
        for t in tokens:
            if re.fullmatch(r"[;&|()\n]+", t):
                stages.append([])
            else:
                stages[-1].append(t)

        def is_name(t: str) -> bool:
            return Path(t).name in names

        def first_word(stage: list[str]) -> int:
            k = 0
            while k < len(stage):  # keywords, assignments and redirections before the command
                t = stage[k]
                if t in SHELL_KEYWORDS or re.match(r"^\w+=", t) or REDIRECT_GLUED.fullmatch(t):
                    k += 1
                elif REDIRECT_ALONE.fullmatch(t):
                    k += 2
                else:
                    break
            return k

        # `A=tool; $A …`, `A=tool; eval $A` — any expansion may run a name assigned before
        dynamic = "$" in text
        for stage in stages:
            k = first_word(stage)
            if dynamic and any(
                re.match(r"^\w+=", t) and any(is_name(w) for w in t.split("=", 1)[1].split()) for t in stage[:k]
            ):
                found.append(None)
            if k >= len(stage):
                continue
            word = stage[k]
            if is_name(word):
                found.append(stage[k:])
                continue
            cmd = Path(word).name
            if cmd not in LAUNCHERS:
                continue
            rest = stage[k + 1 :]
            if cmd in SHELLS or cmd == "eval":
                # `sh -c 'script'`, `eval code`: the script is a command; `bash tool` runs it too
                scripts = [" ".join(rest)] if cmd == "eval" else rest
                if any(is_name(t) or self._invocations(t, names, depth + 1) for t in scripts):
                    found.append(None)
                continue
            j = next((i for i, t in enumerate(rest) if is_name(t)), None)
            if j is not None:
                found.append(rest[j:] if cmd in DIRECT_LAUNCHERS else None)  # xargs, find -exec, parallel: unknown
        return found

    def unfiltered_mcp(self, entry: dict, tool_input: dict) -> str | None:
        """The MCP form of an unfiltered tool: its directory parameter (or the working directory) must not be or
        contain a sensitive directory; `deny_options` apply to parameters named like the option without dashes."""
        name = entry["name"]
        param = entry.get("dir_param")
        s = str(tool_input.get(param) or "") if param else ""
        kind = self.path_kind(s or self.cwd, ancestor=True)
        if kind in ("protected", "sensitive"):
            return (
                f"piigate: {name} on {s or 'the working directory'} denied — sensitive data (or a directory containing "
                f"it). {UNFILTERED_HINT}"
            )
        for option, values in (entry.get("deny_options") or {}).items():
            if str(tool_input.get(option.lstrip("-")) or "") in values:
                return f"piigate: {name} with {option.lstrip('-')}={tool_input.get(option.lstrip('-'))} denied. {UNFILTERED_HINT}"
        return None

    def unfiltered_bash(self, entry: dict, command: str, tokens: list[str] | None, calls: list) -> str | None:
        """An unfiltered tool run in Bash: denied for sensitive data in the command, a denied option, a form the gate
        cannot expand (its directory unknown), and a directory (its `dir_option`, `cd` targets, else the working
        directory) that is or contains a sensitive directory. The tool itself may check more, on the real path."""
        name = entry["name"]
        kind, what = self._touches(command, tokens if tokens is not None else command.split())
        if kind in ("protected", "sensitive", "command"):
            return f"piigate: {name} on sensitive data ({what}) denied. {UNFILTERED_HINT}"
        for option, values in (entry.get("deny_options") or {}).items():
            for v in values:
                if re.search(rf"(?<![\w-]){re.escape(option)}(?:=|\s+)['\"]?{re.escape(v)}(?![\w-])", command):
                    return f"piigate: {name} with `{option} {v}` denied. {UNFILTERED_HINT}"
        if tokens is None or None in calls or OPAQUE_FORMS.search(command):
            return (
                f"piigate: {name} with a variable, substitution, eval, `sh -c`, xargs or find -exec denied — the gate "
                f"cannot check which directory it gets. {UNFILTERED_HINT}"
            )
        option = entry.get("dir_option")
        directories = []
        for argv in calls:
            given = None
            for i, t in enumerate(argv[1:], 1):
                if option and t == option and i + 1 < len(argv):
                    given = argv[i + 1]
                elif option and t.startswith(option + "="):
                    given = t.split("=", 1)[1]
            directories.append(given or self.cwd)
        for stage in self._stages_loose(tokens):  # `cd X && tool …` runs it in X
            if Path(stage[0]).name in ("cd", "pushd"):
                directories.append(stage[1] if len(stage) > 1 else "~")
        for d in directories:
            if self.path_kind(d, ancestor=True) in ("protected", "sensitive"):
                return f"piigate: {name} on {d} denied — sensitive data (or a directory containing it). {UNFILTERED_HINT}"
        return None

    # --- Bash -----------------------------------------------------------------------------------

    @staticmethod
    def _tokens(command: str) -> list[str] | None:
        lex = shlex.shlex(command, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        try:
            return list(lex)
        except ValueError:
            return None

    def _token_kind(self, t: str, recursion: bool, content: bool = True, literal: bool = False) -> tuple[str, str] | None:
        """literal=True: the token comes from a heredoc body read by a non-shell — the shell expands no globs there, so
        `name.*` is text, not a pattern for every extension (a fixed data extension `*.csv` still counts)."""
        candidates = [t]
        if "=" in t:  # --file=…, VAR=… — the whole token only when it is an existing path (otherwise a missing file = deny)
            candidates = ([t] if os.path.lexists(_path(t, self.cwd)) else []) + [t.split("=", 1)[1]]
        if re.match(r"^[\w.@-]+:[~/]", t):
            candidates.append(t.split(":", 1)[1])  # scp host:path
        for k0 in candidates:
            variants = expand_braces(k0)
            if any(re.search(r"\{[^{}]*(?:,|\.\.)[^{}]*\}", w) for w in variants):
                return "sensitive", f"{k0} (braces the gate cannot expand — denied as a precaution)"
            for k in variants:
                if re.search(r"[*?\[]", k):  # a pattern: fixed prefix and extension
                    name_prefix = re.split(r"[*?\[]", k, maxsplit=1)[0]
                    directory = name_prefix if name_prefix.endswith("/") else (os.path.dirname(name_prefix) or ".")
                    ancestor = recursion or "/" in k[len(name_prefix) :]
                    r = self.path_kind(directory, ancestor=ancestor)
                    rest = k[len(directory) :].lstrip("/") if "/" in name_prefix else k
                    if r == "protected" and not self._pattern_reaches(directory, rest, self.protected):
                        # `cache/*/superpowers/…` under the plugin cache does not name piigate's own copy
                        r = self.path_kind(directory, ancestor=ancestor, protected=False)
                    if not r and not recursion and "/" not in k[len(name_prefix) :]:
                        # a pattern without recursion only reaches entries directly in the directory: `ls *.md` in a
                        # repo with a sensitive directory deeper down passes, `cat ~/Sens*` does not (project dirs in a repo)
                        r = self._pattern_hits_dir(directory, k.rsplit("/", 1)[-1])
                    if r:
                        return r, directory
                    if (
                        re.search(r"\.[\w*?\[\]]*$", k)
                        and (k.casefold().endswith(self.extensions) or (not literal and self._pattern_hits_extension(k)))
                        and not _inside(_path(directory, self.cwd), self.system)
                        and not self.is_public_tree(directory)
                    ):
                        return "extension", k  # *.csv or *.c?v / *.*
                    continue
                r = self.path_kind(k, ancestor=recursion, content=content)
                if r:
                    return r, k
        return None

    def _pattern_reaches(self, directory: str, rest: str, directories: list[str]) -> bool:
        """Whether the pattern `rest` (relative to `directory`) can name one of `directories`, an entry inside it or a
        directory above it — compared segment by segment, so `cache/*/superpowers/…` does not reach cache/piigate/….
        `**`, `.` and `..` reach everything (when in doubt — reaches)."""
        base = _path(directory, self.cwd)
        segments = [s for s in rest.split("/") if s]
        for k in directories:
            if _inside(base, [k]):
                return True
            if not _inside(k, [base]):
                continue
            pairs = list(zip(os.path.relpath(k, base).split(os.sep), segments))
            if any("**" in s or s in (".", "..") for _, s in pairs) or all(fnmatch.fnmatchcase(p, s) for p, s in pairs):
                return True
        return False

    def _pattern_hits_dir(self, directory: str, pattern: str) -> str | None:
        """A protected/sensitive directory lying directly in `directory` whose name the pattern matches (or lying deeper
        under an entry the pattern matches — `cat ~/D*` reaches ~/Documents/piigate/Sensitive-data/…, `ls *` reaches var/
        with var/exports)."""
        base = _path(directory, self.cwd)
        for kind, directories in (("protected", self.protected), ("sensitive", self.sensitive)):
            for k in directories:
                if not _inside(k, [base]) or k == base:
                    continue
                first = os.path.relpath(k, base).split(os.sep, 1)[0]
                if fnmatch.fnmatchcase(first, pattern):
                    return kind
        return None

    @staticmethod
    def _searcher_args(stage: list[str]) -> tuple[set[int], list[str], bool]:
        """grep/rg/fd/ag/find: (indices of tokens that are not paths — the pattern and name filters; the name filter
        values; whether no path = searching cwd). When in doubt a token stays a path (and is checked)."""
        family = FAMILIES.get(Path(stage[0]).name) if stage else None
        if not family:
            return set(), [], False
        option_filters = NAME_FILTERS.get(family, set())
        pattern_option = PATTERN_OPTIONS.get(family)
        skip: set[int] = set()
        filters: list[str] = []
        positional: list[int] = []
        from_option = False
        options_end = False
        i = 1
        while i < len(stage):
            t = stage[i]
            if t in REDIRECTS or re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t):
                i += 2  # redirection target (2>/dev/null) — not a command argument
                continue
            if not options_end and t == "--":
                options_end = True
            elif not options_end and len(t) > 1 and t.startswith("-"):
                name, eq, value = t.partition("=")
                if name in option_filters:
                    skip.add(i)
                    if eq:
                        filters.append(value)
                    elif i + 1 < len(stage):
                        skip.add(i + 1)
                        filters.append(stage[i + 1])
                        i += 1
                elif pattern_option and pattern_option.match(name):
                    from_option = True
            else:
                positional.append(i)
            i += 1
        if family in ("grep", "rg", "ag", "fd") and positional and not from_option:
            skip.add(positional.pop(0))  # the first positional argument is the pattern
        recursive = family in ("rg", "ag", "fd") or any(RECURSIVE_FLAGS.match(t) for t in stage[1:])
        return skip, filters, family != "find" and recursive and not positional

    def _data_filter(self, v: str) -> bool:
        """A name filter (*.csv, x.c?v, csv for -t/-e) that covers files with a data extension."""
        cf = v.casefold().strip("'\"")
        return (
            cf.endswith(self.extensions)
            or self._pattern_hits_extension(cf)
            or cf.lstrip(".") in {e.lstrip(".") for e in self.extensions}
        )

    def _ignore_excludes(self, t: str, family: str, stage: list[str]) -> bool:
        """rg/fd/ag from directory t: every sensitive directory under t is excluded by an entry in .ignore
        (.rgignore/.fdignore) in t or in an intermediate directory, with no negation (!) in those files and no flags
        that disable ignore files."""
        if any(NO_IGNORE.match(x) for x in stage[1:]):
            return False
        base = _path(t, self.cwd)
        if not os.path.isdir(base):
            return False
        # the data directory's .gitignore is enough only without globs (-g takes precedence over ignoring),
        # without rg configuration in the command and without negations in ignore files on the way
        gitignore_suffices = not any(RG_GLOBS.match(x) for x in stage[1:]) and "RIPGREP_CONFIG_PATH" not in self._text
        sub = [
            k
            for k in self.sensitive
            if _inside(k, [base])
            and k != base
            and not (gitignore_suffices and self._hidden_by_gitignore(k) and not self._negations_on_path(base, k))
        ]
        if _inside(base, self.sensitive):
            return False
        if not sub:
            return True  # only project directories are left, which rg/fd/ag will not search anyway (.gitignore)
        for k in sub:
            excluded = False
            directory = base
            while True:
                for name in IGNORE_FILES[family]:
                    file = Path(directory) / name
                    try:
                        lines = file.read_text(encoding="utf-8").splitlines() if file.is_file() else []
                    except OSError:
                        return False
                    entries = [x.strip() for x in lines if x.strip() and not x.strip().startswith("#")]
                    if any(x.startswith("!") for x in entries):
                        return False  # a negation may restore a file from the sensitive directory
                    relp = os.path.relpath(k, directory)
                    if any(re.sub(r"(?:/\*\*)?/*$", "", x).lstrip("/") == relp for x in entries):
                        excluded = True
                next_word = os.path.join(directory, os.path.relpath(k, directory).split(os.sep, 1)[0])
                if excluded or next_word == k:
                    break
                directory = next_word
            if not excluded:
                return False
        return True

    def _pattern_hits_extension(self, k: str) -> bool:
        """Whether the pattern can hit a file with a data extension: `*.c?v`, `*.*`, `ls.1*`, `x.[cC]sv` — yes;
        `*.yml`, `*.php`, `sys.argv[1]` — no. After the last `*` the pattern must be able to end like the extension."""
        name = k.rsplit("/", 1)[-1].casefold()
        if not re.search(r"\.[^.]*[*?\[]", name):  # a wildcard after a dot (`p*`, `*/vendor/*` are not checked here)
            return False
        extensions = [e.casefold() for e in self.extensions]
        if "[" in name:  # character classes: by the part after the last dot
            if "." not in name:
                return False
            ending = name.rsplit(".", 1)[1]
            return "*" in ending or any(fnmatch.fnmatchcase(e.lstrip("."), ending) for e in extensions)

        def compatible(e: str, tail: str) -> bool:  # some name can end with both e and tail (`?` = any character)
            return all(c == "?" or c == x for c, x in zip(reversed(tail), reversed(e)))

        if "*" in name:
            return any(compatible(e, name.rsplit("*", 1)[1]) for e in extensions)
        return any(len(name) >= len(e) and compatible(e, name) and len(name) > len(e) for e in extensions)

    @staticmethod
    def _write_targets(stage: list[str]) -> set[int]:
        """Indices of tokens the stage only writes to (no content to check): after > >> >| &> &>>, tee arguments,
        -o/--output, the cp/mv target (without -t and redirections)."""
        dests = {i + 1 for i, t in enumerate(stage[:-1]) if t in (">", ">>", ">|", "&>", "&>>")}
        dests |= {i + 1 for i, t in enumerate(stage[:-1]) if i and t in ("-o", "--output")}
        dests |= {i for i, t in enumerate(stage) if i and re.match(r"^--(?:output|out)=", t)}
        cmd = Path(stage[0]).name if stage else ""
        if cmd == "tee":
            dests |= {i for i, t in enumerate(stage) if i and not t.startswith("-") and t not in REDIRECTS}
        if cmd in ("cp", "mv") and not any(
            t in REDIRECTS or re.match(r"^-[a-zA-Z]*t|^--target", t) for t in stage[1:]
        ):
            positional = [i for i, t in enumerate(stage) if i and not t.startswith("-")]
            if len(positional) >= 2:
                dests.add(positional[-1])
        return dests

    def _touches(self, command: str, tokens: list[str]) -> tuple[str | None, str]:
        """The strongest reason: protected > sensitive > command > extension."""
        text = command.replace("\\ ", " ")
        self._text = text
        if any(z in self._strip_commit_message(tokens, text) for z in self.protected_markers):
            return "protected", "a filter file"
        if re.search(r"PIIGATE_\w+|XDG_DOCUMENTS_DIR", text):
            return "protected", "PIIGATE_* / XDG_DOCUMENTS_DIR variables (they change where the filter looks)"
        stages = self._strip_prefixes(self._stages_loose(tokens))
        outside, literal = self._heredoc_text(text)
        kinds: dict[str, str] = {}
        dests = [self._write_targets(stage) for stage in stages]
        # paths the command reads (everything except write targets) — a write target read in the same command
        # (`curl … > x.csv; cat x.csv`) gets its content only after the gate's check
        read_paths = {
            _path(k, self.cwd)
            for stage, c in zip(stages, dests)
            for i, t in enumerate(stage)
            if i not in c
            for k in (t, t.split("=", 1)[-1])
            if k and not re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", k)
        }
        for stage, c in zip(stages, dests):
            cmd = Path(stage[0]).name if stage else ""
            # grep without -r/-R/-d recurse reads only the given files (skips directories) — the pattern `../x*.yml`
            # does not reach subdirectories; rg, fd, ag, find… search the tree by default
            recursion = (
                (cmd in SEARCHERS and FAMILIES.get(cmd) != "grep")
                or any(RECURSIVE_FLAGS.match(t) for t in stage)
                or (FAMILIES.get(cmd) == "grep" and GREP_RECURSE.search(" ".join(stage)) is not None)
            )
            skip, filters, no_path = self._searcher_args(stage)
            skip |= self._text_args(stage)
            for v in filters:  # --include=*.csv, -t csv: the name filter reaches for data files
                if self._data_filter(v) and not self._stage_public(stage, skip, no_path):
                    kinds.setdefault("extension", v)
            family = FAMILIES.get(cmd)
            if no_path:  # rg foo, fd php, grep -r foo — they search cwd
                stage = [*stage, "."]
            for i, t in enumerate(stage):
                if i in skip or not t or re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t):
                    continue
                if family in IGNORE_FILES and i and self._ignore_excludes(t, family, stage):
                    r = self._token_kind(t, False, content=i not in c)  # sensitive directories under t are skipped (.ignore)
                    if not r and _ancestor(_path(t, self.cwd), self.protected):
                        r = ("protected", t)
                else:
                    r = self._token_kind(t, recursion, content=i not in c, literal=t in literal)
                if r and r[0] == "extension" and i in c and _path(r[1], self.cwd) not in read_paths:
                    continue  # write only — no content comes back to the model
                if r:
                    kinds.setdefault(*r)
        paths_text = self._strip_commit_message(tokens, text)
        for z in self.markers:
            if z in paths_text:
                kinds.setdefault("sensitive", z)
        queries_text = strip_db_services(paths_text)
        for w in self.commands:
            if w.search(queries_text):
                kinds.setdefault("command", "a database query on a server")
        # substitutions inside quotes (`echo "$(cat x.csv)"`, backticks) stay one token above — checked as commands
        for inner in self._substitutions(outside):
            if inner.strip() and inner.strip() != text.strip():
                r, w = self._touches(inner, self._tokens(inner) or inner.split())
                if r:
                    kinds.setdefault(r, w)
        self._text = text
        for r in ("protected", "sensitive", "command", "extension"):
            if r in kinds:
                return r, kinds[r]
        return None, ""

    @staticmethod
    def _strip_prefixes(stages: list[list[str]]) -> list[list[str]]:
        """`X=1 rg …`, `env rg …`, `nice grep -r …` — the command is rg/grep, not the assignment or the wrapper (otherwise
        the searcher would escape detection). Assignments are checked as a separate stage (the value may be a path)."""
        result = []
        for stage in stages:
            i = 0
            while i < len(stage) and (
                re.fullmatch(r"[A-Za-z_]\w*=.*", stage[i]) or (Path(stage[i]).name in WRAPPERS and i + 1 < len(stage))
            ):
                i += 1
                while Path(stage[i - 1]).name in WRAPPERS and i < len(stage) and stage[i].startswith("-"):
                    i += 1  # env -i, nice -n 10, timeout -k 5 30 (numbers are skipped by the loop below)
                while i < len(stage) and re.fullmatch(r"\d+(?:\.\d+)?[smhd]?", stage[i]) and i + 1 < len(stage):
                    i += 1
            if i:
                result.append(["env", *stage[:i]])
            if stage[i:]:
                result.append(stage[i:])
        return result

    @staticmethod
    def _stages_loose(tokens: list[str]) -> list[list[str]]:
        """Simple commands split on any operator (for detection, not for allowing)."""
        stages: list[list[str]] = [[]]
        for t in tokens:
            if t in FORBIDDEN_OPERATORS or t in ("|", "|&") or re.fullmatch(r"[;&|()]+", t):
                stages.append([])
            else:
                stages[-1].append(t)
        return [e for e in stages if e]

    @staticmethod
    def _stages(tokens: list[str]) -> tuple[list[list[str]], list[str]] | None:
        """Pipeline stages and joiners; None when there are operators other than | and |&."""
        stages: list[list[str]] = [[]]
        joiners: list[str] = []
        for t in tokens:
            if t in ("|", "|&"):
                stages.append([])
                joiners.append(t)
            elif t in FORBIDDEN_OPERATORS or re.fullmatch(r"[;&()]+", t) or re.fullmatch(r"\|[|&]+.*", t):
                return None
            else:
                stages[-1].append(t)
        return stages, joiners

    def _is_piigate(self, word: str) -> bool:
        """The plugin's real `piigate`: a bare `piigate` from PATH or the path to bin/piigate — not a `./piigate`
        planted by the model."""
        if self.cli is None:  # tests without the plugin: bare `piigate` only
            return word == "piigate"
        if word == "piigate":
            # Claude Code adds the plugin's bin/ to the PATH of the Bash shell, not of the hook: no other `piigate` in
            # the hook's PATH means Bash will hit the plugin's piigate; any other (e.g. planted in ~/.local/bin) → deny
            found = shutil.which("piigate")
            return found is None or os.path.realpath(found) == self.cli
        return os.path.realpath(_path(word, self.cwd)) == self.cli

    def _piigate_safe(self, command: str, tokens: list[str]) -> str | None:
        """None = correct use of piigate (all output through the filter); otherwise the denial reason."""
        if "\n" in command.strip():
            return "multi-line command — with a sensitive source only one command on one line"
        if re.search(r"\$\(|`|<\(|>\(|\$\{", command):
            return "substitution ($(…), `…`, <(…), ${…}) — not allowed with a sensitive source"
        split_result = self._stages(tokens)
        if split_result is None:
            return "operators ; && || & ( ) — with a sensitive source only a single pipeline ending in piigate"
        stages, joiners = split_result
        piigate_index = next((i for i, e in enumerate(stages) if e and self._is_piigate(e[0])), None)
        if piigate_index is None:
            return (
                "the output does not go to the plugin's piigate (a pipeline stage must start with `piigate`, with no "
                "variables before it and no planted `./piigate` scripts)"
            )
        piigate_stage = stages[piigate_index]
        if len(piigate_stage) < 2 or piigate_stage[1] not in PIIGATE_SUBCOMMANDS:
            return "unknown piigate subcommand (allowed: show, list, table, text, status)"
        for stage in stages[piigate_index + 1 :]:
            if reason := self._stage_after_piigate(stage):
                return reason
        for j, stage in enumerate(stages[:piigate_index]):
            if not stage:
                return "empty pipeline stage"
            cmd = stage[0]
            if cmd not in PIPE_SOURCES:
                return (
                    f"stage `{cmd}` is not on the list of reading commands ({', '.join(sorted(PIPE_SOURCES))}) — "
                    "others can write raw data or run code outside the filter"
                )
            if cmd == "ssh" and not ssh_valid(stage[1:]):
                return (
                    "ssh in a pipeline only with the options -p, -l, -q, -T, -C, -4, -6 and -o Port|User|ConnectTimeout|"
                    "BatchMode|StrictHostKeyChecking|ServerAliveInterval"
                )
            if cmd == "pdftotext":
                arguments = strip_2to1(stage[1:])
                positional, k = [], 0
                while k < len(arguments):
                    t = arguments[k]
                    if t in PDFTOTEXT_WITH_VALUE:
                        k += 2
                        continue
                    if t == "-" or not t.startswith("-"):
                        positional.append(t)
                    k += 1
                if len(positional) != 2 or positional[1] != "-":
                    return "pdftotext in a pipeline only to stdout (`pdftotext FILE -`)"
            if cmd != "ssh" and any(OUTPUT_OPTIONS.match(t) for t in stage[1:]):  # ssh -o: key list above
                return "an option writing to a file (-o/--output) in an earlier stage — raw data outside the filter"
            rest = list(stage)
            for k in range(len(rest) - 2):
                if rest[k : k + 3] == ["2", ">&", "1"]:
                    rest[k : k + 3] = ["", "", ""]
            if any(t in REDIRECTS or re.fullmatch(r"\d*[<>]+&?\d*", t) for t in rest if t):
                return "a redirection in an earlier stage (raw data in a file) — only `2>&1` is allowed"
            if joiners[j] != "|&" and not any(stage[k : k + 3] == ["2", ">&", "1"] for k in range(len(stage))):
                return (
                    "stderr of an earlier stage would reach the model unfiltered — add `2>&1` before `|` "
                    "(or use `|&`)"
                )
        return None

    @staticmethod
    def _stage_after_piigate(stage: list[str]) -> str | None:
        """A stage after piigate: grep/head/tail/wc/sort/uniq/cut on stdin only, without reading files and without writing."""
        allowed = ", ".join(sorted(AFTER_PIIGATE))
        if not stage or stage[0] not in AFTER_PIIGATE:
            return f"stage `{stage[0] if stage else ''}` after piigate — only {allowed} are allowed (on piigate's output)"
        with_value, letters, long_opts = AFTER_PIIGATE[stage[0]]
        arguments = strip_2to1(stage[1:])
        positional, pattern_option, k = 0, False, 0
        while k < len(arguments):
            t = arguments[k]
            if t in REDIRECTS or re.fullmatch(r"\d*[<>]+&?\d*", t):
                return "a redirection after piigate — output to the screen only"
            if t.startswith("--"):
                if t.split("=", 1)[0] in long_opts:
                    return f"`{stage[0]} {t}` after piigate reads or writes a file"
                if t in with_value:
                    pattern_option |= t == "--regexp"
                    k += 1
            elif t.startswith("-") and len(t) > 1:
                if any(c in letters for c in t[1:]):
                    return f"`{stage[0]} {t}` after piigate reads or writes a file"
                if t in with_value:
                    pattern_option |= t == "-e"
                    k += 1
            else:
                positional += 1
            k += 1
        if positional > (1 if stage[0] == "grep" and not pattern_option else 0):
            return f"`{stage[0]}` after piigate with a file name — it may only read piigate's output (stdin)"
        return None

    def _no_content(self, tokens: list[str]) -> bool:
        """cp/mv/scp/rsync into a sensitive directory, mkdir/rm/sha256sum… — no content comes back to the model."""
        split_result = self._stages(tokens)
        if split_result is None or len(split_result[0]) != 1:
            return False
        stage = split_result[0][0]
        if not any(stage[: len(p)] == p for p in self.no_content):  # exactly the name (not ./cp, not /tmp/cp)
            return False
        if any(t in REDIRECTS or t.startswith(("/dev/", "/proc/")) or t == "-" for t in stage[1:]):
            return False
        cmd = stage[0]
        if cmd in COPY_COMMANDS:
            # simple flags only; every path (sources and target) inside a sensitive directory, a source may be remote
            if any(t.startswith("-") and not COPY_FLAGS.match(t) for t in stage[1:]):
                return False
            arguments = [t for t in stage[1:] if not t.startswith("-")]
            if len(arguments) < 2 or re.match(r"^[\w.@-]+:", arguments[-1]):
                return False  # no target, or a copy TO a server — a human decides
            for a in arguments:
                if re.match(r"^[\w.@-]+:", a) and cmd in ("scp", "rsync"):
                    continue
                if not all(_inside(_path(w, self.cwd), self.sensitive) for w in expand_braces(a)):
                    return False
            return True
        return True

    def _human_only(self, command: str, tokens: list[str] | None) -> str | None:
        """`piigate reverse` and `piigate project approve` — human only. A mention in data (a log message, a commit,
        `piigate: reverse …`) is not a call; with a substitution, eval, a variable holding the name or unparsable
        quotes — conservatively, by the words alone. The CLI also refuses an agent and asks for the user's password."""
        for word, description in (
            ("reverse", "`piigate reverse` (restoring the originals)"),
            ("approve", "`piigate project approve` (approving project filters, including removals)"),
        ):
            if not re.search(rf"(?<![\w-]){word}(?![\w-])", command):  # not the --reverse option (sort, git log)
                continue
            flat = _flat(command)
            standalone = re.search(r"(?<![\w./-])piigate(?![\w.-])", flat)
            suspicious = tokens is None or re.search(r"\$\(|`|<\(|\$\{|\beval\b", command) or (
                standalone and "$" in command
            )
            prefix = r"(?:project['\",\s]+)?" if word == "approve" else ""
            # `piigate reverse`, also in code: subprocess.run(['piigate', 'reverse', …])
            call = re.search(rf"(?<![\w./-])piigate['\",\s]+{prefix}{word}(?![\w-])", command) or any(
                c is None or (word in c and (word != "approve" or "project" in c))
                for c in self._invocations(command, {"piigate"})
            )
            piigate_stage = tokens is not None and any(
                word in stage
                and any(Path(t).name in ("piigate", "cli.py") for t in stage)  # piigate, bash piigate, python3 lib/cli.py
                for stage in self._stages_loose(tokens)
            )
            if suspicious or call or piigate_stage:
                return (
                    f"piigate: {description} is for a human only, in their own terminal — never through the agent. "
                    "Show the human the command to run."
                )
        return None

    @staticmethod
    def _strip_file_heredocs(command: str) -> str:
        """The body of a heredoc written to a file (`cat > x <<EOF`, `cat <<EOF > x`, `tee x <<EOF`) — text written by
        the model, nothing is read or run; the write target stays in the command and the gate checks it."""
        result: list[str] = []
        end: list[str] = []
        dests: list[str] = []
        for line in command.split("\n"):
            if end:
                if line.strip() == end[0]:
                    end.pop(0)
                    result.append(line)
                continue
            result.append(line)
            for m in HEREDOC.finditer(line):
                stage = re.split(r"\||;|&&|\|\||\(|\)", line)
                stage = next((e for e in stage if m.group() in e), "").split()
                if not stage:
                    continue
                if stage[0] == "cat":
                    dest = [stage[i + 1] if t in (">", ">>") and i + 1 < len(stage) else t.lstrip(">")
                           for i, t in enumerate(stage) if t.startswith(">")]
                elif stage[0] == "tee":
                    dest = [t for t in stage[1:] if not t.startswith(("-", "<"))]
                else:
                    dest = []
                # `git commit -F - <<EOF`: the body is the commit message (stdin), nothing is read or run
                message = (
                    stage[0] == "git"
                    and {"commit", "tag"} & set(stage[1:3])
                    and re.search(r"\s(?:-[a-zA-Z]*F\s+-|--file(?:=|\s+)-)(?:\s|$)", " ".join(stage) + " ")
                )
                if [c for c in dest if c] or message:
                    end.append(m.group(2))
                    dests += [c.strip("'\"") for c in dest if c]
        text = "\n".join(result)
        if end or any(text.count(Path(c).name) > 1 for c in dests):
            return command  # an unterminated heredoc or the written file used later (`bash s.sh`) — unchanged
        return text

    def bash(self, command: str) -> str | None:
        command = self._strip_file_heredocs(command)
        tokens = self._tokens(command)
        if reason := self._human_only(command, tokens):
            return reason
        if re.search(r"\b(?:analyze|anonymize)\b", command) and any(
            c is None or c[1:2] in (["analyze"], ["anonymize"]) for c in self._invocations(command, {"piigate"})
        ):
            return MCP_PIIGATE
        for entry in self.unfiltered:
            calls = self._invocations(command, entry["commands"]) if entry["commands"] else []
            if calls and (reason := self.unfiltered_bash(entry, command, tokens, calls)):
                return reason
        if tokens is None:
            kind, _ = self._touches(command, command.split())
            if kind:
                return (
                    f"piigate: cannot parse the command (quotes) with a sensitive source. {HINT}"
                )
            return None
        kind, what = self._touches(command, tokens)
        if kind is None:
            return None
        if kind in ("protected", "sensitive") and self._names_only(command, tokens):
            return None
        if kind == "protected":
            return (
                f"piigate: the command touches {what} — the pseudonym map, key and filter configuration are off-limits "
                "to the model (only a human changes them and reverses pseudonyms)."
            )
        if kind != "command" and self._no_content(tokens):
            return None
        reason = self._piigate_safe(command, tokens)
        if reason is None:
            return None
        p = _path(what, self.cwd) if kind == "sensitive" else ""
        if p and not _inside(p, self.sensitive) and _ancestor(p, self.sensitive):
            sub = ", ".join(os.path.relpath(k, p) for k in self.sensitive if _inside(k, [p]))
            what = (
                f"{what} — contains a sensitive directory: {sub}; search the code subdirectory, use piigate_search (MCP) or "
                f"exclude it with the entry `/{sub.split(', ')[0]}/` in an .ignore file (honoured by rg, fd, ag; not grep)"
            )
        description = {
            "sensitive": f"a sensitive data directory ({what})",
            "command": "output of a database query on a server (production data)",
            "extension": f"{self.describe_verdict(what)} ({what})",
        }[kind]
        return f"piigate: command denied — {description}; {reason}. {HINT}"
