"""Gate (PreToolUse): denies direct reads of sensitive sources, with a hint about what to use instead.

Returns None (allow) or the denial reason (shown to the model). The gate analyses the command text — code that
builds a path at run time (`python -c` with string concatenation, base64, variables) gets around it; this limitation
is documented in the README. Rule: with a sensitive source only a single pipeline through the plugin's real `piigate`
is allowed (followed only by grep/head/tail/wc/sort/uniq/cut on its output), or a command with no content in its
output and its target inside a sensitive directory. Tools listed in `unfiltered_tools` (their output bypasses the
filter, e.g. a local LLM subagent) are denied on sensitive data and in forms where their directory is unknown.

Principle (#23): deny only when the output of a command can bring the CONTENT of sensitive data into the model's context.
Location and content decide — never a file type or a name alone: a file that does not exist has no content (creating it
is fine), names are not content (ls, find, tree, git status…), text arguments (commit messages, issue bodies, patterns,
echo) are not paths, and a data-extension glob is expanded and every match is judged by its content.
"""

import fnmatch
import glob
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
# commands that never run what they are given (a file written earlier in the same command may be their argument)
NON_RUNNING = {"ls", "rm", "stat", "mv", "cp", "touch", "mkdir", "chmod", "diff", "echo", "printf", "true", "test", "["}
# dotfiles and directories whose content later runs by itself (seeding): writing there while the command names a
# sensitive path is refused
SEEDING = re.compile(
    r"(?:/\.git/hooks/|/\.(?:bashrc|bash_profile|bash_login|profile|zshrc|zshenv|zprofile|zlogin|bash_logout)$|/\.config/fish/"
    r"|/\.config/autostart/|/\.config/systemd/user/|/\.xinitrc$|/\.xprofile$|/var/spool/cron/"
    r"|/\.ssh/(?:rc|config)$|/\.gitconfig$|/\.git/config$|/\.config/environment\.d/|/\.envrc$|/\.local/bin/"
    r"|/\.claude/(?:settings[^/]*\.json|hooks/)|/BASH_ENV/ENV)"
)
# commands that do not read the content of the files they are given
NO_READ_COMMANDS = {"stat", "touch", "rm", "rmdir", "mkdir", "test", "[", "ln", "chmod", "chown", "chgrp", "file"}
COPY_INSIDE = {"cp", "mv", "install", "dd", "rsync", "ln"}
GLOB_LIMIT = 200  # data files judged per glob / search root; more — denied as a precaution
WALK_LIMIT = 100000  # directory entries visited when looking for data files under a search root
REDIRECT_ALONE = re.compile(r"\d*(?:[<>]+&?|&>+)\d*-?")
REDIRECT_GLUED = re.compile(r"\d*(?:[<>]+&?|&>+)\S+")


def _flat(text: str) -> str:
    """Text without quotes and backslashes — a name glued from quotes ("local-agen""t", l\\ocal-agent) stays visible."""
    return re.sub(r"[\"'\\]", "", text)


HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*(['\"]?)([\w.-]+)\1")
RG_IGNORE_FILES = (".ignore", ".rgignore", ".fdignore")
# directory walk for a sensitive directory below a search root: intermediate directories, visited-directory budget, skipped names
TREE_DEPTH = 3
TREE_BUDGET = 20000
TREE_SKIP = {".git", "node_modules"}
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
CHAIN_SAFE = {
    "ls", "tree", "du", "cat", "head", "tail", "wc", "stat", "file", "echo", "printf", "true",
    "grep", "egrep", "fgrep", "rg", "fd", "find",
}
LS_LONG_PLAIN = {"--color", "--all", "--almost-all", "--directory", "--classify", "--human-readable", "--size", "--inode"}
# GNU getopt accepts any unambiguous prefix of a long option: `--rec`, `--recur`… are --recursive (`--re` is ambiguous)
_RECURSIVE_LONG = r"-rec(?:u(?:r(?:s(?:i(?:v(?:e)?)?)?)?)?)?"
RECURSIVE_FLAGS = re.compile(rf"^-(?:\w*[rR]\w*|{_RECURSIVE_LONG}|-dereference-recursive)$")
# -r/-R is not recursion here (jq -r raw output, gh -R repository, sort -r reverse, sed -r ERE, curl -r range…) —
# otherwise a jq filter with `[]` counts as a pattern searched from cwd. Other commands keep the flag (deny by default).
NOT_RECURSIVE_R = {"jq", "gojq", "yq", "gh", "sort", "sed", "date", "curl", "ssh", "less", "bat", "head", "tail", "tac"}
# only -R is recursion (ls -r reverse order, chmod -r removes the read permission)
RECURSIVE_UPPER_ONLY = re.compile(rf"^(?:-\w*R\w*|-{_RECURSIVE_LONG})$")
UPPER_ONLY_COMMANDS = {"ls", "chmod", "chown", "chgrp"}


def _recursive_flag(cmd: str, stage: list[str]) -> bool:
    """The stage has a flag that makes its command recurse into directories."""
    if cmd in NOT_RECURSIVE_R:
        return False
    flags = RECURSIVE_UPPER_ONLY if cmd in UPPER_ONLY_COMMANDS else RECURSIVE_FLAGS
    return any(flags.match(t) for t in stage[1:])


def _listing_paths(cmd: str, arguments: list[str]) -> list[str]:
    """Path operands of ls/find/tree/du (none — they list cwd): find — the words before the expression, the others —
    the words that are not options."""
    if cmd == "find":
        paths = []
        for t in arguments:
            if t.startswith(("-", "(", "!")):
                break
            paths.append(t)
        return paths
    return [t for t in arguments if not t.startswith("-")]
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


# --- option allow-lists (#23) ---------------------------------------------------------------------------------------
# A command is judged by its OPTIONS, not by its name: `git log` prints commit messages, `git log -U1` prints file
# content. One parser (`_scan`) understands short clusters (-am, -U1, -Fplik, -xcat), glued values (--format=%H,
# -x=cat) and `--`; a spec lists the options that neither show file content nor run a command. Anything else — an
# unknown option, an abbreviated long option — makes the stage an ordinary reader.


def _scan(args: list[str], s1: set[str] | str = "", l1: set[str] | tuple = ()) -> tuple[list[tuple], list[int]]:
    """Options and positionals of `args`. Options: (name, value, name index, value index or None) with name `-x` or
    `--long`; s1 — short options that take a value (glued or the next word), l1 — long options that take a value
    (glued with `=` or the next word). Positionals: indices into `args` (everything after `--` too)."""
    opts: list[tuple] = []
    positional: list[int] = []
    i = 0
    while i < len(args):
        t = args[i]
        if t == "--":
            positional += range(i + 1, len(args))
            break
        if t.startswith("--"):
            name, eq, value = t.partition("=")
            if eq:
                opts.append((name, value, i, None))
            elif name[2:] in l1 and i + 1 < len(args):
                opts.append((name, args[i + 1], i, i + 1))
                i += 1
            else:
                opts.append((name, None, i, None))
        elif t.startswith("-") and len(t) > 1:
            for j, c in enumerate(t[1:], 1):
                if c in s1:
                    rest = t[j + 1 :]
                    if rest:
                        opts.append((f"-{c}", rest, i, None))
                    elif i + 1 < len(args):
                        opts.append((f"-{c}", args[i + 1], i, i + 1))
                        i += 1
                    else:
                        opts.append((f"-{c}", None, i, None))
                    break
                opts.append((f"-{c}", None, i, None))
        else:
            positional.append(i)
        i += 1
    return opts, positional


def _spec(s0="", s1="", l0=(), l1=(), lg=(), files=()):
    return {"s0": set(s0), "s1": set(s1), "l0": set(l0), "l1": set(l1), "lg": set(lg), "files": set(files)}


def _allowed(args: list[str], spec: dict) -> tuple[list[int], list[str]] | None:
    """The positionals (indices) and the values of file options when every option is in the spec, else None."""
    opts, positional = _scan(args, spec["s1"], spec["l1"])
    files: list[str] = []
    for name, value, _, _ in opts:
        if name.startswith("--"):
            n = name[2:]
            known = n in spec["l1"] or n in spec["lg"] or (n in spec["l0"] and value is None)
        else:
            known = name[1] in spec["s0"] or name[1] in spec["s1"]
        if not known:
            return None
        # every option that names a file (`--pathspec-from-file`, `--exclude-from`, `--file`, `--template`, `--blob`…)
        if value and (name in spec["files"] or (name.startswith("--") and re.search(r"file|from|template|blob|reference|config", name))):
            files.append(value)
    return positional, files


_LOG0 = (
    "oneline graph decorate no-decorate stat shortstat numstat name-only name-status summary all branches tags remotes "
    "abbrev-commit no-abbrev-commit no-merges merges first-parent reverse follow topo-order date-order author-date-order "
    "no-color left-right cherry cherry-pick cherry-mark boundary full-history simplify-by-decoration source "
    "walk-reflogs relative-date no-walk parents children graph-all merge-base"
).split()
_LOG1 = "max-count skip since until after before author committer grep format pretty date min-parents max-parents glob exclude".split()
_LOGG = "color abbrev decorate pretty format stat date no-walk show-notes".split()
# diff/stash show: only these format options (names, counts), plus the scope options; --check, --exit-code alone,
# -U, -p… print or imply the patch. DIFF_NAMES_ONLY = the options that make the output names/counts.
_DIFFN = "name-only name-status stat numstat shortstat summary cached staged quiet no-patch no-renames exit-code".split()
DIFF_NAMES_ONLY = {"--name-only", "--name-status", "--stat", "--numstat", "--shortstat", "--summary", "--quiet", "--no-patch", "-s"}
GIT_LOG = _spec("q0123456789", "n", _LOG0, _LOG1, _LOGG)
GIT_DIFF_NAMES = _spec("zMqs", "", _DIFFN, (), "stat find-renames color abbrev".split())
GIT_SPECS = {
    "status": _spec("sbzquonal", "", "short branch porcelain long ignored no-renames renames show-stash ahead-behind "
                    "no-ahead-behind no-column column".split(), (), "porcelain untracked-files ignored ignore-submodules column find-renames".split()),
    "log": GIT_LOG,
    "reflog": GIT_LOG,
    "add": _spec("AunvfN", "", "all update dry-run verbose force intent-to-add ignore-errors renormalize no-all ignore-removal sparse refresh pathspec-file-nul".split(),
                 ("pathspec-from-file",), ("chmod",), ("--pathspec-from-file",)),
    "commit": _spec("aqsn", "mCcFt", "all quiet signoff no-verify amend no-edit allow-empty allow-empty-message dry-run short porcelain "
                    "branch reset-author no-post-rewrite status no-status".split(), "message author date cleanup fixup squash "
                    "reuse-message reedit-message file template trailer".split(), ("gpg-sign", "untracked-files"), ("-F", "-t", "--file", "--template")),
    "merge": _spec("qvn", "msXF", "ff-only no-ff ff squash no-commit commit abort continue quit quiet verbose no-edit edit no-verify "
                   "stat no-stat allow-unrelated-histories autostash no-autostash signoff".split(), "message strategy strategy-option file into-name".split(),
                   ("log", "gpg-sign", "cleanup"), ("-F", "--file")),
    "worktree": _spec("fq", "bB", "force detach checkout no-checkout lock quiet porcelain verbose dry-run guess-remote track no-track orphan".split(),
                      "reason expire".split(), ()),
    "branch": _spec("avrlDdfmMcCq", "u", "all verbose remotes list delete force move copy show-current quiet unset-upstream track no-track "
                    "edit-description".split(), "set-upstream-to contains no-contains merged no-merged sort format points-at".split(),
                    ("color", "abbrev", "column", "merged", "no-merged", "contains", "no-contains")),
    "push": _spec("uqvfnd", "o", "all tags force dry-run set-upstream delete prune quiet verbose no-verify follow-tags atomic mirror no-thin progress".split(),
                  "push-option repo".split(), ("force-with-lease", "signed", "force-if-includes", "recurse-submodules", "porcelain", "thin")),
    "fetch": _spec("aqvfnptu", "j", "all append quiet verbose force dry-run prune tags no-tags prune-tags update-head-ok multiple atomic "
                   "set-upstream unshallow no-recurse-submodules progress".split(), "depth deepen shallow-since shallow-exclude jobs filter".split(),
                   ("recurse-submodules", "negotiate-tip", "porcelain")),
    "pull": _spec("qvfrnpa", "sX", "ff-only no-ff ff rebase no-rebase autostash no-autostash quiet verbose all tags prune force squash "
                  "no-commit commit no-edit edit stat no-stat dry-run update-head-ok".split(), "strategy strategy-option depth jobs".split(),
                  ("rebase", "recurse-submodules", "gpg-sign", "log")),
    "checkout": _spec("qfmt", "bB", "force quiet detach track no-track merge ours theirs ignore-other-worktrees guess no-guess progress "
                      "no-progress overlay no-overlay".split(), "orphan conflict pathspec-from-file".split(), ("recurse-submodules",),
                      ("--pathspec-from-file",)),
    "switch": _spec("qfdm", "cC", "detach force discard-changes guess no-guess track no-track merge quiet progress ignore-other-worktrees".split(),
                    "create force-create orphan conflict".split(), ("recurse-submodules",)),
    "restore": _spec("SWq", "s", "staged worktree quiet ours theirs merge overlay no-overlay progress ignore-unmerged ignore-skip-worktree-bits".split(),
                     "source pathspec-from-file".split(), ("recurse-submodules",), ("--pathspec-from-file",)),
    "reset": _spec("q", "", "soft mixed hard merge keep quiet no-refresh refresh no-recurse-submodules".split(), ("pathspec-from-file",),
                   ("recurse-submodules",), ("--pathspec-from-file",)),
    "rebase": _spec("qvfn", "sX", "continue abort skip quit autostash no-autostash keep-base root force-rebase no-ff ff quiet verbose stat "
                    "no-stat reapply-cherry-picks no-fork-point fork-point update-refs no-update-refs".split(), "onto strategy strategy-option whitespace".split(),
                    ("rebase-merges", "gpg-sign", "empty")),
    "tag": _spec("alfdsn", "muF", "list delete annotate force sign no-sign create-reflog".split(), "message file local-user sort contains "
                 "no-contains points-at merged no-merged format".split(), ("color", "column"), ("-F", "--file")),
    "remote": _spec("vfn", "tm", "verbose tags no-tags fetch push add delete dry-run auto".split(), ("mirror",), ()),
    "ls-files": _spec("cdmoksuvtzfiX", "xX", "cached deleted modified others ignored stage unmerged killed exclude-standard full-name error-unmatch "
                      "directory no-empty-directory resolve-undo deduplicate recurse-submodules eol sparse".split(),
                      "exclude exclude-from exclude-per-directory format with-tree".split(), (), ("-X", "--exclude-from")),
    "ls-tree": _spec("drltz", "", "name-only name-status full-name full-tree long".split(), ("format",), ("abbrev",)),
    "rev-parse": _spec("q", "", "show-toplevel git-dir abbrev-ref short verify is-inside-work-tree show-prefix show-cdup absolute-git-dir "
                       "git-common-dir symbolic-full-name quiet is-bare-repository show-superproject-working-tree".split(), ("git-path",),
                       ("short", "abbrev-ref")),
    "rev-list": _spec("n0123456789", "n", "count all reverse no-merges merges first-parent objects left-right no-walk abbrev-commit parents "
                      "children topo-order date-order boundary branches tags remotes quiet".split(),
                      "max-count since until after before author committer grep skip max-parents min-parents".split()),
    "describe": _spec("", "", "tags always long all contains first-parent exact-match".split(), "match exclude candidates".split(),
                      ("dirty", "broken", "abbrev")),
    "merge-base": _spec("a", "", "all octopus is-ancestor independent fork-point".split()),
    "name-rev": _spec("", "", "tags all name-only no-undefined always".split(), "refs exclude".split()),
    "show-ref": _spec("d", "", "heads tags verify head dereference quiet exists".split(), (), ("hash", "abbrev")),
    "for-each-ref": _spec("", "", "shell perl python tcl ignore-case".split(), "format sort count points-at merged no-merged contains no-contains".split()),
    "symbolic-ref": _spec("dq", "m", "short quiet delete".split()),
    "count-objects": _spec("vH", "", "verbose human-readable".split()),
    "ls-remote": _spec("q", "", "heads tags refs quiet get-url symref".split(), ("sort",)),
    "mv": _spec("fnkv", "", "force dry-run verbose".split()),
    "rm": _spec("fnrq", "", "force dry-run cached quiet ignore-unmatch sparse".split(), ("pathspec-from-file",), (), ("--pathspec-from-file",)),
    "clean": _spec("fdnxXq", "e", "force dry-run quiet".split()),
    "init": _spec("q", "b", "quiet bare".split(), "initial-branch separate-git-dir".split()),
    "clone": _spec("qvnsl", "bj", "bare mirror quiet verbose no-checkout shallow-submodules recursive single-branch no-tags local "
                   "no-hardlinks shared progress sparse no-single-branch".split(), "branch origin depth jobs reference separate-git-dir filter "
                   "shallow-since shallow-exclude".split(), ("recurse-submodules",)),
    "cherry-pick": _spec("nxeq", "mXs", "continue abort skip quit no-commit edit no-edit signoff ff allow-empty keep-redundant-commits "
                         "allow-empty-message".split(), "mainline strategy strategy-option".split(), ("gpg-sign",)),
    "revert": _spec("neq", "mXs", "continue abort skip quit no-commit edit no-edit signoff allow-empty".split(), "mainline strategy strategy-option".split(),
                    ("gpg-sign",)),
    "gc": _spec("", "", "auto quiet aggressive".split()),
}
# `git config` only to read (a key = get; two words set a value — alias.x, core.pager, core.sshCommand run commands)
GIT_CONFIG_READ = _spec("lz", "", "list local global system worktree get get-all get-regexp show-origin show-scope name-only null bool int path "
                        "includes no-includes".split())
# subcommands that copy content out of a repository: with a repository (or a source) in a sensitive directory they are readers
GIT_EXPORT = {"clone", "worktree", "mv", "push", "fetch", "pull", "remote", "ls-remote"}  # a sensitive source/repository = a read
# `file`: only options that do not read a magic/names file or look inside archives; on documents and images it prints
# metadata (author, title, camera) — a read
FILE_SPEC = _spec("bihL0", "", "mime mime-type mime-encoding brief dereference no-dereference null".split())
FILE_METADATA = re.compile(r"\.(?:docx?|xlsx?|pptx?|odt|ods|odp|pdf|jpe?g|png|gif|webp|heic|tiff?|rtf|msg|eml)$", re.I)
# filters that may follow a lister of a sensitive directory: only options that read stdin and print text
FILTER_SPECS = {
    "grep": _spec("ivcnEFGwxoqHhsPzZ", "emABC", "ignore-case invert-match count line-number extended-regexp fixed-strings word-regexp "
                  "line-regexp only-matching quiet no-messages null null-data no-filename with-filename".split(), "regexp max-count after-context before-context context".split(), ("color",)),
    "head": _spec("qvz0123456789", "nc", "quiet silent verbose zero-terminated".split(), "lines bytes".split()),
    "tail": _spec("qvz0123456789", "nc", "quiet silent verbose zero-terminated".split(), "lines bytes".split()),
    "wc": _spec("lwcmL", "", "lines words bytes chars max-line-length".split()),
    "sort": _spec("rnuzfbdgMhVRsi", "kt", "reverse numeric-sort unique zero-terminated ignore-case ignore-leading-blanks dictionary-order "
                  "general-numeric-sort month-sort human-numeric-sort version-sort random-sort stable".split(), "key field-separator".split()),
    "uniq": _spec("cduiz", "fsw", "count repeated unique ignore-case zero-terminated".split(), "skip-fields skip-chars check-chars".split()),
    "cut": _spec("szn", "dfcb", "only-delimited complement zero-terminated".split(), "delimiter fields characters bytes output-delimiter".split()),
    "tr": _spec("cdst", "", "complement delete squeeze-repeats truncate-set1".split()),
    "column": _spec("tx", "sto", "table".split()),
    "nl": _spec(""), "tac": _spec(""), "rev": _spec(""), "basename": _spec("as"), "dirname": _spec(""), "cat": _spec("nAbeEstTuv"),
}
GH_FILE_LONG = {"field", "raw-field", "body-file", "input", "notes-file", "file", "template", "source"}
# gh subcommands that run commands or change how gh runs them
GH_EXEC = {"alias", "extension", "ext", "config", "codespace", "cs", "ssh-key", "browse", "completion"}


class QuotedToken(str):
    """A word that came whole from one quoted fragment: no glob, no brace expansion (issue #19). `quote` is the kind of
    quote: a single-quoted word is literal text — no `$(…)`, backtick or `$VAR` substitution inside it (issue #23)."""

    quoted = True
    quote = ""

    def __new__(cls, value: str, quote: str = ""):
        obj = super().__new__(cls, value)
        obj.quote = quote
        return obj

    @property
    def single(self) -> bool:
        return self.quote == "'"


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
        self.sensitive_name = config.sensitive_name(cfg)
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
        self._tree: dict[tuple[str, bool], tuple[list[str], bool]] = {}  # directory walks (_contains_project_sensitive)
        self._found: dict[str, list[str]] = {}  # directory → sensitive directories found below it by the walk
        self._oversized: set[str] = set()  # directories whose tree was too large to walk
        self._text = ""  # current Bash command (_touches)
        self._raw = ""  # the Bash command as given (before heredoc bodies written to files are cut out)
        self._textual = True  # text arguments are only text (False: the command executes text it prints)
        self._written: set[str] = set()  # data files the current command writes (a read of one has no verdict yet)
        self._appears: dict[str, set[int]] = {}  # missing data file → stages that name it
        self._names_seen: set[tuple[str, ...]] = set()  # stages that listed names inside a sensitive directory (#23)
        self.notes: dict[str, str] = {}  # why a path without a verdict is denied (describe_verdict)

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
        if re.search(rf"\{{[^}}]*\b(?:{names})\b", text):
            return True
        # a glob that matched nothing before the command ran (`python gen.py; cat out.*`, `cat ./out.cs?`) may match what
        # the command created: its output is checked for personal data
        tokens = self._tokens(command) or command.split()
        return any(re.search(r"[*?\[]", t) and not self._files_public_pattern(t) for t in tokens)

    def _files_public_pattern(self, t: str) -> bool:
        return self.is_public_tree(self._pattern_root(t))

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

    def _substituting(self, t: str) -> bool:
        """The word contains a substitution the shell runs. A single-quoted word is literal text (#23) — unless the
        command feeds text to a shell/interpreter (`echo '$(cat x)' | bash`, see `_executes_text`)."""
        return bool(SUBSTITUTION.search(t)) and not (getattr(t, "single", False) and self._textual)

    def _commit_message(self, stage: list[str]) -> set[int]:
        """Indices of message text — not a path (a directory name in a change description): `git commit|tag -m …`,
        `gh issue|pr … --title/--body/--search/--comment` (not `--body-file`/`-F`, which read a file) and the query of
        `gh search <kind> …`."""
        cmd = Path(stage[0]).name if stage else ""
        result = set()
        if len(stage) >= 2 and cmd == "git" and {"commit", "tag"} & set(stage[1:3]):
            options, long_options = r"-[a-zA-Z]*m|--message", ("--message",)
        elif len(stage) >= 3 and cmd == "gh" and stage[1] in ("issue", "pr"):
            options, long_options = r"-[tbSc]|--title|--body|--search|--comment", ("--title", "--body", "--search", "--comment")
        elif len(stage) >= 3 and cmd == "gh" and stage[1] == "search":
            options, long_options = r"--(?:repo|owner)|-R", ()
            values = {i + 1 for i, t in enumerate(stage[:-1]) if re.fullmatch(options, t)}
            result = {i for i, t in enumerate(stage) if i > 2 and not t.startswith("-") and i not in values}
        else:
            return set()
        if long_options:
            result |= {i + 1 for i, t in enumerate(stage[:-1]) if re.fullmatch(options, t)}
            result |= {i for i, t in enumerate(stage) if t.split("=", 1)[0] in long_options and "=" in t}
        # `-m "$(cat …)"` — the shell runs the substitution: such a message is a command, not text
        return {i for i in result if i < len(stage) and not self._substituting(stage[i])}

    @staticmethod
    def _program_text(stage: list[str]) -> set[int]:
        """Indices of the sed/awk program (the first operand or the -e/--expression value; awk -F/-v values): shell
        quoting already kept it one word and unexpanded, so it is not a glob or braces — but it is still code (sed `r`,
        awk `getline`), so it stays checked as a plain path and for directory names. `-f` program files stay paths."""
        cmd = Path(stage[0]).name if stage else ""
        if cmd == "gh":  # -q/--jq: a jq filter, -t/--template: a Go template (issue #19: `.m // "-"`)
            text = {i + 1 for i, t in enumerate(stage[:-1]) if t in ("-q", "--jq", "-t", "--template")}
            text |= {i for i, t in enumerate(stage) if t.split("=", 1)[0] in ("--jq", "--template") and "=" in t}
            return {i for i in text if i < len(stage)}
        if cmd in ("jq", "gojq", "yq"):
            return Gate._jq_program(stage)
        if cmd not in ("sed", "gsed", "awk", "gawk", "mawk", "nawk"):
            return set()
        sed = cmd.endswith("sed")
        # option → whether its value is program text (True), a file (False); letters that end the cluster with a value
        values = {"e": True, "f": False} if sed else {"e": True, "f": False, "v": True, "F": True, "E": False, "i": False, "l": False}
        glued_rest = "il" if sed else ""  # sed -i[SUFFIX], -l N: the rest of the cluster is their value
        long_values = (
            {"--expression": True, "--file": False, "--line-length": None}
            if sed
            else {"--source": True, "--file": False, "--assign": True, "--field-separator": True, "--include": False,
                  "--load": False, "--exec": False}
        )
        text: set[int] = set()
        positional: list[int] = []
        program_option = False
        i = 1
        while i < len(stage):
            t = stage[i]
            if t in REDIRECTS or re.fullmatch(r"\d*[<>]+&?\d*", t):
                i += 2
                continue
            if t == "--":
                positional += range(i + 1, len(stage))
                break
            if t.startswith("--"):
                name, eq, _ = t.partition("=")
                if name in long_values:
                    program_option |= name in ("--expression", "--file", "--source", "--exec")
                    if long_values[name]:
                        text.add(i if eq else i + 1)
                    i += 0 if eq else 1
            elif t.startswith("-") and len(t) > 1:
                for j, c in enumerate(t[1:], 1):
                    if c in glued_rest:
                        if c == "l" and j == len(t) - 1:
                            i += 1
                        break
                    if c in values:
                        program_option |= c in "efE"
                        if values[c]:
                            text.add(i if j < len(t) - 1 else i + 1)
                        i += 0 if j < len(t) - 1 else 1
                        break
            else:
                positional.append(i)
            i += 1
        if not program_option and positional:
            text.add(positional[0])
        return {i for i in text if i < len(stage)}

    @staticmethod
    def _jq_program(stage: list[str]) -> set[int]:
        """jq/gojq/yq: the filter — the first operand (after a yq `eval`/`ea` subcommand), unless -f/--from-file gives
        a program file; `--arg/--argjson NAME VALUE` values are text too. Files (`--slurpfile/--rawfile NAME FILE`, the
        operands after the filter) stay paths."""
        # option → number of values that follow it; `text` values are not paths
        values = {"--arg": 2, "--argjson": 2, "--slurpfile": 2, "--rawfile": 2, "--indent": 1, "-L": 1,
                  "--library-path": 1, "--from-file": 1, "-f": 1, "--front-matter": 1, "-p": 1, "--input-format": 1,
                  "-o": 1, "--output-format": 1}
        text: set[int] = set()
        positional: list[int] = []
        from_file = False
        i = 1
        while i < len(stage):
            t = stage[i]
            if t in REDIRECTS or re.fullmatch(r"\d*[<>]+&?\d*", t):
                i += 2
                continue
            if t == "--":
                positional += range(i + 1, len(stage))
                break
            name = t.split("=", 1)[0]
            if name in values and "=" not in t:
                from_file |= name in ("-f", "--from-file")
                if name in ("--arg", "--argjson"):
                    text |= {i + 1, i + 2}
                i += values[name] + 1
                continue
            if t.startswith("-") and len(t) > 1:
                from_file |= name in ("-f", "--from-file")
            else:
                positional.append(i)
            i += 1
        if Path(stage[0]).name == "yq" and positional and stage[positional[0]] in ("eval", "e", "eval-all", "ea"):
            positional.pop(0)
        if not from_file and positional:
            text.add(positional[0])
        return {i for i in text if i < len(stage)}

    def _text_args(self, stage: list[str]) -> set[int]:
        """Indices of tokens that are text, not paths: a commit message, an issue/PR title or body, and echo/printf
        arguments (printed back, not read) — except redirections, their targets and tokens with a substitution the
        shell runs. Not when the command executes text it prints (`_textual`)."""
        if not self._textual:
            return set()
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
                and not (re.search(r"\$\(|`|<\(", t) and not getattr(t, "single", False))
            }
        return result

    def _safe_receiver(self, core: list[str]) -> bool:
        """A stage that receives piped text and certainly only filters/prints it: a text filter with allow-listed options
        (FILTER_SPECS), piigate, or an allow-listed git/gh stage. Everything else — a shell, an interpreter, `at`,
        `crontab -`, `sudo`, `ssh`, `flock`, `watch`, `xargs`, `sed` (its `e` command) — may run the text."""
        if not core:
            return False
        if self._is_piigate(core[0]):
            return True
        if core[0] == "tee":  # prints its input and writes files (a file used again is checked in `_executes_text`)
            return _allowed([t for t in core[1:] if t.startswith("-")], _spec("ai", "", ("append", "ignore-interrupts"))) is not None
        if core[0] in FILTER_SPECS:
            args = [t for t in strip_2to1(core[1:]) if not re.fullmatch(r"\d*[<>]+&?\d*|/dev/null", t)]
            return _allowed(args, FILTER_SPECS[core[0]]) is not None
        return self._stage_class(core) == "remote"

    def _safe_stage(self, core: list[str]) -> bool:
        """A stage that certainly does not run a file or text it is given."""
        return (
            Path(core[0]).name in NON_RUNNING
            or core[0] in FILTER_SPECS
            or core[0] == "tee"
            or self._is_piigate(core[0])
            or self._stage_class(core) in ("remote", "names")
        )

    def _script_stages(self, tokens: list[str]) -> tuple[list[list[str]], list[tuple[int, int, str]], bool]:
        """The command's stages (prefixes cut), the write targets (stage, token index, path) and whether text reaches a
        stage that is not a known filter (a pipe into anything else, `<(…)`, `>(…)`, `| (…)`)."""
        stages: list[list[str]] = []
        writes: list[tuple[int, int, str]] = []
        unsafe_pipe = False
        piped, previous, stage = False, "", []
        for t in [*tokens, ";"]:
            if t == "(" and previous in ("<", ">", "|", "|&"):
                unsafe_pipe = True
            if not (t in FORBIDDEN_OPERATORS or t in ("|", "|&") or re.fullmatch(r"[;&|()]+", t)):
                stage.append(t)
                previous = t
                continue
            parts = self._strip_prefixes([stage]) if stage else []
            core = parts[-1] if parts else []
            if stage and piped and not self._safe_receiver(core):
                unsafe_pipe = True
            if core:
                stages.append(core)
                writes += [(len(stages) - 1, i, os.path.normpath(core[i])) for i in self._write_targets(core) if i < len(core)]
            piped = t in ("|", "|&")
            previous, stage = t, []
        return stages, writes, unsafe_pipe

    def _executes_text(self, tokens: list[str]) -> bool:
        """Text arguments (a commit message, an issue body, echo/printf) are text only if nothing runs them: every stage
        that receives piped text is a known filter (allow-list, `_safe_receiver`), there is no process substitution or
        subshell fed by a pipe, and when the command writes a file (`> s.sh`, `tee`, `-o`) no LATER stage can run it —
        any stage that is not a known non-running one (a glob or variable as the command word, `./x`, a shell, an
        interpreter, `eval`, `.`, `for … do`) counts, whatever name the file is given. Otherwise the text is code."""
        stages, writes, unsafe_pipe = self._script_stages(tokens)
        if unsafe_pipe:
            return True
        if writes:
            first = min(k for k, _, _ in writes)
            if any(not self._safe_stage(core) for core in stages[first + 1 :]):
                return True
        written = {w for _, _, w in writes if w != "." and not w.startswith("/dev/")}
        for n, core in enumerate(stages):
            if self._safe_stage(core):
                continue
            # the stage's own write target is not a use of the file — but only where the target really is one
            # (`> file`, tee, curl -o…); `ssh -o ProxyCommand=./s.sh` or a script name inside a code string is a use
            plain = core[0] in ("tee", "curl", "wget", "cp", "mv", "install", "rsync", "dd", "sort", "pdftotext")
            ignore = {i for k, i, _ in writes if k == n and (plain or (i and core[i - 1] in (">", ">>", ">|", "&>", "&>>")))}
            for i, w in enumerate(core):
                if i not in ignore and any(name in w for name in written):
                    return True
        return False

    def _unvettable_script(self, tokens: list[str]) -> bool:
        """A file is written from text that the gate cannot read as a literal (`printf '…%s…' x > s.sh`, `echo "$x" >
        s.sh`) and a later stage may run it: the written code can name a sensitive path built at run time."""
        stages, writes, _ = self._script_stages(tokens)
        if not writes:
            return False
        first = min(k for k, _, _ in writes)
        if all(self._safe_stage(core) for core in stages[first + 1 :]):
            return False
        for k, _, target in writes:
            core = stages[k]
            scripty = re.search(r"\.(?:sh|bash|zsh|ksh|fish|py|pl|rb|js|php|mk)$", target) or "." not in os.path.basename(target)
            if scripty and core[0] in ("echo", "printf", "cat", "tee") and any(
                ("%" in t and core[0] == "printf") or (re.search(r"\$", t) and not getattr(t, "single", False)) for t in core[1:]
            ):
                return True
        return False

    def _stage_class(self, stage: list[str]) -> str:
        """'names' — a program that prints names or metadata, not content (#23): ls, tree, du, find and fd without a
        content action, stat, file, cd; 'remote' — a git subcommand whose OPTIONS are all on the allow-list (GIT_SPECS)
        or gh (GitHub): no local file content comes back; '' — anything else, judged as a reader."""
        cmd = Path(stage[0]).name if stage else ""
        if not stage or stage[0] != cmd:  # /tmp/ls, ./git — an arbitrary program
            return ""
        arguments = stage[1:]
        if any(self._substituting(t) for t in arguments):
            return ""
        if cmd in ("cd", "pushd", "popd"):
            return "names"
        if cmd in ("ls", "tree", "du", "find", "fd", "fdfind", "stat", "file"):
            return "names" if self._lists_only(cmd, arguments) else ""
        if cmd in COPY_INSIDE:
            return "names" if self._copies_inside(cmd, arguments) else ""
        if cmd == "gh":
            sub = next((t for t in arguments if not t.startswith("-")), "")
            if any(re.match(r"~[+-]", t) for t in arguments):  # a tilde the gate cannot expand: judged as a reader
                return ""
            return "" if sub in GH_EXEC else "remote"
        if cmd == "git":
            return "remote" if self._git_call(arguments) is not None else ""
        return ""

    def _copies_inside(self, cmd: str, arguments: list[str]) -> bool:
        """cp/mv/install/dd/rsync/ln where EVERY operand (sources and targets) lies in a sensitive directory: the data
        stays there and the command prints at most names (#23)."""
        if cmd == "dd":
            pairs = dict(t.split("=", 1) for t in arguments if "=" in t and not t.startswith("-"))
            if "of" not in pairs:
                return False  # without of= dd writes the data to stdout
            operands = [pairs[k] for k in ("if", "of") if k in pairs]
        else:
            operands = [t.split("=", 1)[1] if t.startswith("--") else t for t in arguments if not t.startswith("-") or "=" in t]
            if len(operands) < 2:
                return False
        symbolic = cmd == "ln" and any(re.fullmatch(r"-[a-zA-Z]*s[a-zA-Z]*|--symbolic", t) for t in arguments)
        resolved = []
        for k, t in enumerate(operands):
            if symbolic and k < len(operands) - 1:
                continue  # a symlink's target is text, relative to the link's directory (below)
            real = self._operand_locations(t)
            if real is None:
                return False
            resolved += real
        if symbolic and len(operands) >= 2:
            # the link's TARGET (relative to the link's directory) must stay in the sensitive directory too: a symlink
            # that leads out is a way to carry the data away
            link_dir = os.path.dirname(os.path.join(self.cwd, operands[-1]))
            for t in operands[:-1]:
                target = t if os.path.isabs(t) else os.path.join(link_dir, t)
                resolved.append(os.path.realpath(target))
        return all(self._resolved_sensitive(p) for p in resolved)

    def _operand_locations(self, t: str) -> list[str] | None:
        """The real locations a copy operand may name: realpath (`..` and symlinks followed, a missing leaf keeps its
        parent's), a leading tilde and braces expanded like the shell, every match of a pattern by its own real location
        (a match may be a symlink leading out); None when the location cannot be known here — a variable, a
        substitution, or a pattern that climbs out after its prefix (`S/*/../../`, review of #23)."""
        if re.search(r"[$`]", t):
            return None
        result: list[str] = []
        for w in expand_braces(t):
            if re.search(r"\{[^{}]*(?:,|\.\.)[^{}]*\}", w):
                return None  # braces beyond the expansion limit
            prefix = re.split(r"[*?\[]", w)[0] or "."
            if prefix == w:
                result.append(_path(w, self.cwd))
                continue
            if ".." in w[len(prefix) :].split("/"):
                return None
            pattern = os.path.join(self.cwd, config.expand_tilde(w))  # an absolute pattern replaces cwd
            result += [_path(prefix, self.cwd)] + [os.path.realpath(m) for m in glob.glob(pattern)]
        return result

    def _resolved_sensitive(self, p: str) -> bool:
        """An ALREADY RESOLVED path lies in a sensitive directory (by the real location, never by a name in the text)."""
        return _inside(p, self.sensitive) or bool(self.sensitive_name and self.sensitive_name in Path(p).parts)

    @staticmethod
    def _fd_exec(arguments: list[str]) -> bool:
        """fd runs a command for its results (-x, -X, --exec, --exec-batch, however glued: -xcat, -Hxcat, -x=cat)."""
        opts, _ = _scan(arguments, "eEtdSxXjcoD", {"extension", "exclude", "type", "max-depth", "min-depth", "size", "exec",
                                                    "exec-batch", "threads", "color", "changed-within", "changed-before", "owner",
                                                    "search-path", "base-directory", "path-separator", "ignore-file", "max-results"})
        return any(name in ("-x", "-X", "--exec", "--exec-batch") for name, *_ in opts)

    def _lists_only(self, cmd: str, arguments: list[str]) -> bool:
        """The lister prints names/metadata only: no action that runs or reads (find -exec…, fd -x, a names file)."""
        if any("from" in t.casefold() for t in arguments):  # --fromfile, --files0-from, --files-from
            return False
        if cmd == "find":
            return not any(t in FIND_ACTIONS for t in arguments)
        if cmd.startswith("fd"):
            return not self._fd_exec(arguments)
        if cmd == "file":
            parsed = _allowed(arguments, FILE_SPEC)
            return parsed is not None and not any(
                FILE_METADATA.search(arguments[k]) or re.search(r"[*?\[{]", arguments[k]) for k in parsed[0]
            )
        return True

    def _repo_dir(self, repo_dirs: list[str]) -> str:
        base = self.cwd
        for d in repo_dirs:
            base = _path(d, base)
        return base

    def _git_call(self, arguments: list[str]) -> dict | None:
        """`git [-C dir]… <subcommand> <options>` when the subcommand is in GIT_SPECS and EVERY option is on its
        allow-list (no patches, no `-c`/`--exec`/`--upload-pack`, no `-U1`…); else None — the stage is a reader.
        Returns {sub, args, files (values of file options), repo (directory it works in)}."""
        repo_dirs: list[str] = []
        i = 0
        while i < len(arguments):
            t = arguments[i]
            if t == "-C" and i + 1 < len(arguments):
                repo_dirs.append(arguments[i + 1])
                i += 2
            elif t in ("--no-pager", "-P", "--paginate", "-p", "--no-optional-locks"):
                i += 1
            elif t.startswith("-"):
                return None
            else:
                break
        if i >= len(arguments):
            return None
        sub, rest = arguments[i], arguments[i + 1 :]
        if any(t.startswith("ext::") or re.search(r"\$\(|`", t) for t in rest):
            return None
        names_option = False
        if sub == "stash":
            action = next((t for t in rest if not t.startswith("-")), "push")
            if action == "list":
                spec = GIT_LOG
            elif action == "show":
                spec, names_option = GIT_DIFF_NAMES, True
            elif action in ("push", "save", "pop", "apply", "drop", "clear", "branch", "create", "store"):
                spec = _spec("uaqk", "m", "include-untracked all keep-index no-keep-index quiet staged index".split(), "message pathspec-from-file".split(), (), ("--pathspec-from-file",))
            else:
                return None
        elif sub == "diff":
            spec, names_option = GIT_DIFF_NAMES, True
        elif sub == "config":
            spec = GIT_CONFIG_READ
        else:
            spec = GIT_SPECS.get(sub)
        if spec is None or (parsed := _allowed(rest, spec)) is None:
            return None
        positional, files = parsed
        words = [rest[k] for k in positional]
        if names_option and not any(
            name in DIFF_NAMES_ONLY for name, *_ in _scan(rest, spec["s1"], spec["l1"])[0]
        ):
            return None  # `git diff` / `stash show` without a names option print the changes themselves
        if sub == "config" and len(words) > 1:
            return None  # a key and a value: setting alias.*, core.pager, core.sshCommand… runs commands
        base = self._repo_dir(repo_dirs)
        in_sensitive = lambda w: self.path_kind(_path(w, base)) == "sensitive"  # noqa: E731
        if sub in GIT_EXPORT:
            leaves = lambda w: not in_sensitive(w)  # noqa: E731
            if sub == "mv":
                if words and (any(in_sensitive(w) for w in words[:-1]) or self.path_kind(base) == "sensitive") and leaves(words[-1]):
                    return None
            elif sub == "worktree":
                if words[:1] == ["add"] and len(words) > 1 and self.path_kind(base) == "sensitive" and leaves(words[1]):
                    return None
            elif any(in_sensitive(w) for w in words) or (sub == "push" and self.path_kind(base) == "sensitive"):
                return None
        return {"sub": sub, "words": words, "files": files, "repo": base}

    @staticmethod
    def _redirect_sources(stage: list[str]) -> list[str]:
        return [stage[i + 1] for i, t in enumerate(stage[:-1]) if t in ("<", "<>", "<&")]

    def _remote_paths(self, stage: list[str], c: set[int]) -> list[str]:
        """The local files a git-metadata / gh stage may read: redirect sources, values of file options (`-F`,
        `-t`, `--body-file`, `--input`, `-f key=@file`, glued or not), and for gh positional arguments that name a
        local path or glob (gist create, release upload; a `#label` suffix is cut)."""
        found = self._redirect_sources(stage)
        if stage[0] == "git":
            call = self._git_call(stage[1:]) or {}
            repo = call.get("repo", self.cwd)  # file options are relative to the repository (`git -C D commit -F x`)
            return found + [t if os.path.isabs(t) else os.path.join(repo, t) for t in call.get("files", []) if t != "-"]
        text = self._text_args(stage)
        opts, positional = _scan(stage[1:], set("FfqtHXRbBdlLmaAecpr"), GH_FILE_LONG)
        for name, value, _, _ in opts:
            if not value:
                continue
            if name in ("-F", "-f", "--field", "--raw-field"):
                if "=@" in value:
                    found.append(value.split("=@", 1)[1])
                elif value.startswith("@"):
                    found.append(value[1:])
                elif "=" not in value:  # api: key=value; secret set -f FILE, issue create -F FILE
                    found.append(value)
            elif name in ("--body-file", "--input", "--notes-file", "--file") and value != "-":
                found.append(value)
            elif name == "--source":  # `gh repo create --source=DIR --push` uploads the whole directory
                found.append(value)
        skip = c | text | self._program_text(stage)
        candidates = [stage[k + 1] for k in positional if k + 1 not in skip]
        # any option value that names a local path (`--source=dir`, `gist edit -a FILE`); jq/template programs and text excluded
        candidates += [v for _, v, i, vi in opts if v and (vi if vi is not None else i) + 1 not in skip]
        for t in candidates:
            clean = t.split("#", 1)[0]
            glob_chars = re.search(r"[*?\[]", clean)
            local = os.path.lexists(clean if os.path.isabs(clean) else os.path.join(self.cwd, clean))
            if (glob_chars or local) and (glob_chars or "/" in clean or re.search(r"\.\w+$", clean)):
                found.append(clean)
        return found

    def _marker_text(self, tokens: list[str] | None, text: str, protected: bool = False) -> str:
        """The command text for the directory-name markers: without text arguments (commit messages, issue bodies,
        echo/printf, search patterns and name filters) and without the stages that print names only or work on
        GitHub/git metadata (a name in their arguments is not an access). protected=True: names-only stages stay (the
        filter's own files are off-limits even to `ls`)."""
        if tokens is None:
            return text
        parts: list[str] = []
        for stage in self._stages_loose(tokens):
            for core in self._strip_prefixes([stage]):
                kind = self._stage_class(core)
                if kind == "remote" or (kind == "names" and not protected):
                    continue
                skip = self._text_args(core) | self._searcher_args(core)[0]
                if not protected:
                    skip |= self._write_targets(core)  # writing into a directory shows nothing
                parts += [t for i, t in enumerate(core) if i not in skip]
        return " ".join(parts)

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
        """A recursive search of `p` would reach a directory named `project_directories.sensitive` below it — in a
        project, a directory of projects, `.claude/worktrees/<name>/`… Found by walking the tree (breadth first, at most
        TREE_DEPTH directories deep, no symlinks, not `.git` or `node_modules`), because the git worktree registry and
        the configured list are files the agent can change. A tree of more than TREE_BUDGET directories cannot be
        checked: denied (fail closed — otherwise a planted pile of directories would exhaust the budget)."""
        n = self.sensitive_name
        if not n or not os.path.isdir(p):
            return False
        key = (p, searching)
        if key not in self._tree:
            self._tree[key] = self._walk_for_sensitive(p, n, searching)
        found, too_large = self._tree[key]
        if too_large:
            self._oversized.add(p)
        elif found:
            self._found[p] = found
        return too_large or bool(found)

    def _walk_for_sensitive(self, p: str, n: str, searching: bool) -> tuple[list[str], bool]:
        found: list[str] = []
        level = [p]
        visited = 0
        for depth in range(TREE_DEPTH + 1):
            following: list[str] = []
            for directory in level:
                visited += 1
                if visited > TREE_BUDGET:
                    return found, True
                try:
                    with os.scandir(directory) as entries:
                        names = [(e.name, e.path) for e in entries if e.is_dir(follow_symlinks=False)]
                except OSError:
                    continue
                for name, path in names:
                    if name == n:
                        if not (searching and self._hidden_by_gitignore(path, anywhere=True)):
                            found.append(path)
                    elif name not in TREE_SKIP and depth < TREE_DEPTH:
                        following.append(path)
            level = following
        return found, False

    def path_kind(
        self, s: str, *, ancestor: bool = False, content: bool = True, searching: bool = False, protected: bool = True
    ) -> str | None:
        """'protected' | 'sensitive' | 'extension' | None; ancestor=True — also a directory containing a sensitive one.
        'extension' = an EXISTING file with a data extension whose content has personal data or cannot be checked
        (#23: a missing file, a directory and a clean file are None). content=False: a write target — not judged.
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
        if content and self.has_extension(p) and os.path.isfile(p):
            # #23: only an existing file has content to judge (a missing one is being created; names are not content)
            w = self.verdicts[p] = self.verdicts.get(p) or self.judge.file(p)
            if w.result != verdict.CLEAN:
                return "extension"
        return None

    def describe_verdict(self, s: str) -> str:
        """Why a file with an extension is denied — categories and counts or the reason, without values."""
        p = _path(s, self.cwd)
        if note := self.notes.get(p) or self.notes.get(s):
            return note
        w = self.verdicts.get(p)
        if w is None or w.result == verdict.CLEAN:
            return "a data file whose content cannot be checked before the command runs"
        if w.result == verdict.PERSONAL:
            return f"the file contains personal data (filter rules: {w.description})"
        return f"the file's content cannot be checked, so it may hold personal data: {w.description}"

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
        if kind == "extension":  # a false positive: only a human exempts a single file (the model cannot edit the config)
            what += f"; if it is a false positive, a human can add the path {_path(s, self.cwd)} to `sources.exempt_directories`"
        if tool in ("Edit", "Write", "NotebookEdit"):
            return f"piigate: {tool} on {s} denied — {what} (the edit result shows the file content). {HINT}"
        return f"piigate: direct read of {s} denied — {what}. {HINT}"

    # --- decision -------------------------------------------------------------------------------

    def decision(self, tool: str, tool_input: dict) -> str | None:
        if reason := project.error_denial(self.cfg, tool, tool_input, self.cwd):
            return reason
        if tool in ("Read", "Edit", "Write", "NotebookEdit"):
            s = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
            # Write: new content from the model, nothing comes back (a data file is not judged); a missing file has no content
            kind = self.path_kind(s, content=tool != "Write") if s else None
            if tool == "Write" and kind in ("sensitive", "extension"):
                kind = None  # #23: Write returns nothing of the file (Edit and Read show it)
            return self._path_reason(kind, s, tool) if kind else None
        if tool in ("Grep", "Glob"):
            s = tool_input.get("path") or self.cwd
            # an rg glob takes precedence over .gitignore — with one, Grep would enter the data directory
            if tool == "Glob":
                # #23: file names are not content — Glob is denied only inside the filter's own directories
                if self.path_kind(s) == "protected":
                    return self._path_reason("protected", s, tool)
                patterns = " ".join(str(tool_input.get(k) or "") for k in ("pattern", "glob", "type")).casefold()
                if any(z.casefold() in patterns for z in self.protected_markers):
                    return f"piigate: {tool} reaches into the filter's files (pattern). {HINT}"
                return None
            kind = self.path_kind(s, ancestor=True, searching=not tool_input.get("glob"))
            if kind in ("protected", "sensitive", "extension"):
                return self._path_reason(kind, s, tool)
            patterns = " ".join(str(tool_input.get(k) or "") for k in ("glob", "type")).casefold()
            if any(z.casefold() in patterns for z in self.markers + self.protected_markers):
                return f"piigate: {tool} reaches into a sensitive directory (pattern). {HINT}"
            if any(e.lstrip(".") in patterns for e in self.extensions) and (reason := self._grep_by_files(s, tool_input)):
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
        globs = str(tool_input.get("glob") or "").strip()
        type_ = str(tool_input.get("type") or "").strip()
        directory = _path(s, self.cwd)
        if not os.path.isdir(directory):
            return None  # a file (path_kind has already judged it) or a missing path (no content)
        arguments = ["rg", "--files", "--null", "--hidden", "--no-ignore", "--no-config", "--glob", "!.git"]
        for part in globs.split():  # Grep: parts separated by spaces and by commas outside braces
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

    def _heredoc_text(self, command: str) -> tuple[str, set[str], set[str], str]:
        """Heredoc bodies read by a non-shell (`python3 - <<'X'`, `gh … --body-file - <<X`): the shell expands no globs
        there, and nothing at all with a quoted delimiter. Returns the command without the quoted bodies (where
        substitutions are looked for), the tokens found only in the bodies (no glob — `name.*` is text), the subset
        found only in quoted bodies (no `$VAR` expansion either) and the bodies' text. A body fed to a shell or a
        launcher is a script — unchanged."""
        outside: list[str] = []  # without quoted text bodies
        shell: list[str] = []  # without any text bodies
        body: list[str] = []
        unquoted: list[str] = []  # bodies with an unquoted delimiter
        end: list[tuple[str, bool | None]] = []
        for line in command.split("\n"):
            if end and line.strip() != end[0][0] and end[0][1] is not None:
                body.append(line)
                if not end[0][1]:
                    outside.append(line)  # unquoted delimiter: $(…) and `…` still run
                    unquoted.append(line)
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
            return command, set(), set(), ""  # an unterminated heredoc — unchanged
        text = "\n".join(body)
        inner = self._tokens(text) or text.split()
        rest = set(self._tokens("\n".join(shell)) or "\n".join(shell).split())
        expanded = set(self._tokens("\n".join(unquoted)) or "\n".join(unquoted).split()) if unquoted else set()
        return "\n".join(outside), set(inner) - rest, set(inner) - rest - expanded, text

    @staticmethod
    def _substitutions(text: str) -> list[str]:
        """Contents of $(…), <(…), >(…) and `…` that the shell runs: unquoted or in double quotes, never inside single
        quotes (#23: a single-quoted word is literal — its backticks and `$(` are text)."""
        result, i, single, double = [], 0, False, False
        while i < len(text):
            z = text[i]
            if single:
                single = z != "'"
            elif z == "\\":
                i += 1
            elif z == "'" and not double:
                single = True
            elif z == '"':
                double = not double
            elif z == "`":
                j = text.find("`", i + 1)
                j = len(text) if j < 0 else j
                result.append(text[i + 1 : j])
                i = j
            elif (z == "$" or (z in "<>" and not double)) and text[i + 1 : i + 2] == "(":
                depth, j = 1, i + 2
                while j < len(text) and depth:
                    depth += {"(": 1, ")": -1}.get(text[j], 0)
                    j += 1
                result.append(text[i + 2 : j - 1])
                i = j - 1
            i += 1
        return result

    @staticmethod
    def _without_single_quoted(command: str) -> str:
        """The command with the insides of single-quoted words emptied (`'…'` → `''`): what the local shell may expand."""
        result, single, double, i = [], False, False, 0
        while i < len(command):
            z = command[i]
            if single:
                if z == "'":
                    single = False
                    result.append(z)
            elif z == "\\" and i + 1 < len(command):
                result.append(command[i : i + 2])
                i += 1
            else:
                single = z == "'" and not double
                double = double != (z == '"')
                result.append(z)
            i += 1
        return "".join(result)

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
        # an unquoted newline separates commands like `;` (issue #21): shlex would treat it as blank space, and
        # `echo x<newline>cat <dir>/a.txt` would look like one `echo` stage. It becomes the token "\n". A
        # backslash-newline is removed and joins the words around it, as in bash (`Sens\<nl>itive` is one word).
        marked, quote, i = [], "", 0
        while i < len(command):
            z = command[i]
            if z == "\\" and quote != "'" and i + 1 < len(command):
                if command[i + 1] != "\n":
                    marked.append(command[i : i + 2])
                i += 2
                continue
            if quote:
                quote = "" if z == quote else quote
            elif z in "'\"":
                quote = z
            elif z == "\n":
                z = " \x00 "
            marked.append(z)
            i += 1
        text = "".join(marked)
        lex = shlex.shlex(text, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        try:
            words = list(lex)
        except ValueError:
            return None
        flags = Gate._quoted_words(text)
        if flags is None or len(flags) != len(words):
            flags = [""] * len(words)
        return [QuotedToken(t, q) if q else ("\n" if t == "\x00" else t) for t, q in zip(words, flags)]

    @staticmethod
    def _quoted_words(text: str) -> list[str] | None:
        """For every token of `text` (as shlex splits it): the quote character (`'` or `"`) when the token is one whole
        quoted fragment, alone or after `--option=` — the shell neither globs nor brace-expands it — otherwise "". A
        token with any unquoted character, escaped or not (`''*`, `'a'b`, `\\*`), is not. None when the scan cannot be
        trusted."""
        flags: list[str] = []
        i, n = 0, len(text)
        while i < n:
            z = text[i]
            if z in " \t\r":
                i += 1
            elif z in ";&|()<>":
                while i < n and text[i] in ";&|()<>":
                    i += 1
                flags.append("")
            else:
                before, quotes, after, quote = "", 0, False, ""
                while i < n and text[i] not in " \t\r;&|()<>":
                    z = text[i]
                    if z == "\\":
                        after = after or quotes > 0
                        before += "\\" if not quotes else ""
                        i += 2
                    elif z in "'\"":
                        j = i + 1
                        while j < n and text[j] != z:
                            j += 2 if z == '"' and text[j] == "\\" else 1
                        if j >= n:
                            return None
                        after = after or quotes > 0
                        quotes += 1
                        quote = z
                        i = j + 1
                    else:
                        if quotes:
                            after = True
                        else:
                            before += z
                        i += 1
                flags.append(quote if quotes == 1 and not after and re.fullmatch(r"(?:--[\w-]+=)?", before) else "")
        return flags

    def _token_kind(
        self, t: str, recursion: bool, content: bool = True, literal: bool = False, verbatim: bool = False
    ) -> tuple[str, str] | None:
        """literal=True: the token comes from a heredoc body read by a non-shell — the shell expands no globs there, so
        `name.*` is text, not a pattern for every extension (a fixed data extension `*.csv` still counts).
        verbatim=True: a quoted word the shell neither globs nor brace-expands (a sed/awk program) — a plain path."""
        candidates = [t]
        if "=" in t:  # --file=…, VAR=… — the whole token only when it is an existing path (otherwise a missing file = deny)
            candidates = ([t] if os.path.lexists(_path(t, self.cwd)) else []) + [t.split("=", 1)[1]]
        if re.match(r"^[\w.@-]+:[~/]", t):
            candidates.append(t.split(":", 1)[1])  # scp host:path
        if verbatim:
            for k in candidates:
                if r := self.path_kind(k, ancestor=recursion, content=content):
                    return r, k
            return None
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
                    # #23: a glob is expanded; every match is judged by its content (no match — no content)
                    if content and (r := self._glob_kind(k, recursion, literal)):
                        return r
                    continue
                r = self.path_kind(k, ancestor=recursion, content=content)
                if r:
                    return r, k
        return None

    def _glob_kind(self, k: str, recursion: bool, literal: bool) -> tuple[str, str] | None:
        """A glob (`*.csv`, `dir/*`): the files it matches NOW, each judged like a plain path (a match in a sensitive
        directory, a data file with personal data or an unverifiable one); a data file the command writes and the
        pattern would match is denied too (its content comes after the check). `literal` (text of a heredoc read by a
        non-shell): only a pattern ending in a data extension counts. More than GLOB_LIMIT data files — denied."""
        if literal and not k.casefold().endswith(self.extensions):
            return None
        pattern = config.expand_tilde(os.path.expandvars(k))
        pattern = pattern if os.path.isabs(pattern) else os.path.join(self.cwd, pattern)
        matches, deadline = [], time.monotonic() + 3
        for m in glob.iglob(pattern, recursive=True):
            matches.append(m)
            if len(matches) > 20000 or time.monotonic() > deadline:
                return self._note("extension", pattern, "the pattern matches too many files to check in the gate — narrow it")
        judged = 0
        for m in sorted(matches):
            p = os.path.realpath(m)
            if self.has_extension(p) and os.path.isfile(p):
                judged += 1
                if judged > GLOB_LIMIT:
                    return self._note(
                        "extension", pattern, f"the pattern matches over {GLOB_LIMIT} data files — too many to check in the gate"
                    )
            if r := self.path_kind(m, ancestor=recursion):
                return r, m
        for w in sorted(self._written):
            if fnmatch.fnmatchcase(w, pattern):
                return self._note("extension", w, "a data file this command writes and the pattern would read — checked only after it runs")
        return None

    def _note(self, kind: str, what: str, note: str) -> tuple[str, str]:
        """A denial that has no file verdict: remembered for the message."""
        self.notes[what] = note
        return kind, what

    def _walk_data(self, root: str) -> tuple[str, str] | None:
        """A content search (grep -r --include=*.csv, find … -exec) from `root`: the data files under it, each judged by
        its content. Not for a public tree; entries or data files over the limits — denied as a precaution."""
        base = _path(root, self.cwd)
        if self.is_public_tree(root):
            return None
        if os.path.isfile(base):
            return (kind, root) if (kind := self.path_kind(base)) else None
        judged = visited = 0
        for directory, names, files in os.walk(base):
            names[:] = [n for n in names if n != ".git"]
            visited += len(names) + len(files)
            if visited > WALK_LIMIT:
                return self._note("extension", base, "the tree is too large to check its data files in the gate — narrow the path")
            for name in files:
                p = os.path.join(directory, name)
                if self.has_extension(p):
                    judged += 1
                    if judged > GLOB_LIMIT:
                        return self._note(
                            "extension", base, f"over {GLOB_LIMIT} data files under it — too many to check in the gate"
                        )
                    if kind := self.path_kind(p):
                        return kind, p
        return None

    def _literal_kind(
        self, t: str, quoted: bool, body: str, recursion: bool, content: bool
    ) -> tuple[str, str] | None:
        """A token found only in a heredoc body read by a non-shell. A dotted name that only ever appears as a call
        (`json.dump(`) is code, not a file. A quoted body gets no `$VAR` expansion — `${CLAUDE_PLUGIN_ROOT}` there is
        another program's text, not piigate's root. Punctuation around a name (`['/x/map'],`) is stripped for the
        protected/sensitive check only (a missing `name.csv),` in prose is not a data file)."""
        if re.fullmatch(r"[A-Za-z_]\w*(?:\.\w+)+", t):
            uses = list(re.finditer(rf"(?<![\w./~-]){re.escape(t)}(?![\w./-])", body))
            if uses and all(re.match(r"\s*\(", body[m.end() :]) for m in uses):
                return None
        if quoted:
            t = re.sub(r"\$(?:\{\w+\}|\w+)", "_", t)
        if r := self._token_kind(t, recursion, content=content, literal=True):
            return r
        bare = re.sub(r"[\]),;:}\"'`]+$", "", t)
        if not re.search(r"[\])}]", bare):
            bare = re.sub(r"^[\[({\"'`]+", "", bare)
        if bare and bare != t and (r := self._token_kind(bare, recursion, content=content, literal=True)):
            return r if r[0] in ("protected", "sensitive") else None
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
                elif family == "grep" and not name.startswith("--"):
                    # a short cluster: the first option that takes a value ends it (`-ie pat`, `-A3`, `-d recurse`,
                    # `-drecurse`); the value of -m/-A/-B/-C/-d/-D is not a pattern or a path
                    for j, c in enumerate(name[1:], 1):
                        if c in "ef":
                            from_option = True
                            break
                        if c in "mABCdD":
                            if not name[j + 1 :] and not eq and i + 1 < len(stage):
                                skip.add(i + 1)
                                i += 1
                            break
                elif family == "grep" and not eq and name in ("--directories", "--devices") and i + 1 < len(stage):
                    skip.add(i + 1)
                    i += 1
                elif pattern_option and pattern_option.match(name):
                    from_option = True
            else:
                positional.append(i)
            i += 1
        if family in ("grep", "rg", "ag", "fd") and positional and not from_option:
            skip.add(positional.pop(0))  # the first positional argument is the pattern
        recursive = (
            family in ("rg", "ag", "fd")
            or any(RECURSIVE_FLAGS.match(t) for t in stage[1:])
            or (family == "grep" and GREP_RECURSE.search(" ".join(stage)) is not None)
        )
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
            dests |= {
                i
                for i, t in enumerate(stage)
                if i and not t.startswith("-") and t not in REDIRECTS and stage[i - 1] not in ("<", "<>", "<&")
            }
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
        saved = (self._textual, self._written, self._appears)
        self._textual = not self._executes_text(tokens)
        try:
            return self._touches_inner(command, tokens, text)
        finally:
            self._textual, self._written, self._appears = saved
            self._text = text

    def _touches_inner(self, command: str, tokens: list[str], text: str) -> tuple[str | None, str]:
        if any(z in self._marker_text(tokens, text, protected=True) for z in self.protected_markers):
            return "protected", "a filter file"
        if re.search(r"PIIGATE_\w+|XDG_DOCUMENTS_DIR", self._marker_text(tokens, text, protected=True)):
            return "protected", "PIIGATE_* / XDG_DOCUMENTS_DIR variables (they change where the filter looks)"
        stages, dirs = [], []
        for stage, ds in zip(self._stages_loose(tokens), self._stage_dirs(command, tokens)):
            for s in self._strip_prefixes([stage]):
                stages.append(s)
                dirs.append(ds)
        outside, literal, verbatim, body = self._heredoc_text(text)
        kinds: dict[str, str] = {}
        dests = [self._write_targets(stage) for stage in stages]
        # data files the command writes, and the stages that name a data file which does not exist yet: such a file gets
        # its content only after the gate's check (`curl … > x.csv; cat x.csv`, `python gen.py x.csv && cat x.csv`)
        self._written, self._appears = set(), {}
        for n, (stage, c, ds) in enumerate(zip(stages, dests, dirs)):
            for d in ds:
                for i, t in enumerate(stage):
                    if not t or re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t):
                        continue
                    for k in {t, t.split("=", 1)[-1]}:
                        p = _path(k, d)
                        if not p.casefold().endswith(self.extensions) or not self.has_extension(p):
                            continue
                        if i in c:
                            self._written.add(p)
                        if not os.path.exists(p):
                            self._appears.setdefault(p, set()).add(n)
        own = self.cwd
        try:
            for stage, c, ds in zip(stages, dests, dirs):
                for d in ds:  # every directory the stage may run in (issue #18: `cd sub && ls -d */`)
                    self.cwd = d
                    for r in self._stage_kinds(stage, c, text, literal, verbatim, body):
                        if d != own and os.path.lexists(_path(r[1], d)):
                            r = (r[0], _path(r[1], d))  # the message resolves `what` against the session directory
                        kinds.setdefault(*r)
        finally:
            self.cwd = own
        # seeding: writing a file that runs later (.git/hooks, shell rc files, autostart, cron) in a command that names a
        # sensitive path — the text written may be a command that reads it
        mentions = (self._raw or text).casefold()
        if any(m.casefold() in mentions for m in self.markers) or "sensitive" in kinds:
            for stage, c, ds in zip(stages, dests, dirs):
                for d in ds:
                    targets = [_path(stage[i], d) for i in c if i < len(stage)]
                    if stage[0] == "crontab":
                        targets.append("/var/spool/cron/")
                    if any(re.match(r"(?:BASH_ENV|ENV)=", t) for t in stage):
                        targets.append("/BASH_ENV/ENV variable (a file that every shell starts with)")
                    if hit := next((t for t in targets if SEEDING.search(t)), None):
                        kinds.setdefault("sensitive", f"{hit} (a file that runs later, in a command naming a sensitive path)")
        if self._unvettable_script(tokens):
            kinds.setdefault("sensitive", "a script written from text built at run time and then run in the same command")
        paths_text = self._marker_text(tokens, text)
        for z in self.markers:
            if z in paths_text:
                kinds.setdefault("sensitive", z)
        queries_text = strip_db_services(paths_text)
        for w in self.commands:
            if w.search(queries_text):
                kinds.setdefault("command", "a database query on a server")
        # substitutions inside quotes (`echo "$(cat x.csv)"`, backticks) stay one token above — checked as commands, in
        # every directory a stage may run in (`cd sub && echo "$(cat ../x.csv)"` reads from sub, not the session dir)
        everywhere = list(dict.fromkeys(d for ds in dirs for d in ds)) or [own]
        for inner in self._substitutions(outside):
            if inner.strip() and inner.strip() != text.strip():
                try:
                    for d in everywhere:
                        self.cwd = d
                        r, w = self._touches(inner, self._tokens(inner) or inner.split())
                        if r:
                            kinds.setdefault(r, _path(w, d) if d != own and os.path.lexists(_path(w, d)) else w)
                finally:
                    self.cwd = own
        for r in ("protected", "sensitive", "command", "extension"):
            if r in kinds:
                return r, kinds[r]
        return None, ""

    @staticmethod
    def _chain_safe(stage: list[str]) -> bool:
        """A stage that certainly keeps the working directory and runs no shell or other code: a plain (unwrapped,
        no assignments) reader or lister from CHAIN_SAFE without an option that executes something."""
        if not stage or stage[0] not in CHAIN_SAFE:
            return False
        cmd = stage[0]
        for t in stage[1:]:
            if cmd == "find" and t in FIND_ACTIONS:
                return False
            if cmd == "rg" and t.startswith(("--pre", "--hostname-bin")):
                return False
            if cmd == "fd" and (t in ("-x", "-X") or t.startswith(("--exec", "-x", "-X"))):
                return False
        return True

    @staticmethod
    def _cd_target(stage: list[str]) -> str | None:
        """The literal directory of `cd X` / `cd -L|-P X` / `pushd X` (redirections ignored), None for anything else —
        `cd -`, `cd ~-`, `cd $X`, a glob, `pushd -n X`, `pushd +1`, a second operand."""
        if stage[0] not in ("cd", "pushd"):
            return None
        args, skip = [], 0
        for j, a in enumerate(stage[1:], 1):  # without redirections (`cd x 2>/dev/null`, `cd x &>f`)
            follows = stage[j + 1] if j + 1 < len(stage) else ""
            if skip:
                skip -= 1
            elif a in REDIRECTS or re.fullmatch(r"\d?>&?|&>>?", a):
                skip = 1  # the file after it
            elif a.isdigit() and (follows in REDIRECTS or re.fullmatch(r"\d?>&?|&>>?", follows)):
                skip = 2  # the descriptor, the operator and the file
            else:
                args.append(a)
        while args and (args[0] == "--" or (stage[0] == "cd" and args[0] in ("-L", "-P"))):
            args.pop(0)
        if len(args) > 1:
            return None
        target = args[0] if args else "~"
        if not target or target[0] in "-+" or re.search(r"[$`*?\[\]{}\\()!]", target):
            return None
        if "~" in target and target != "~" and not target.startswith("~/"):
            return None
        return target

    def _stage_dirs(self, command: str, tokens: list[str]) -> list[list[str]]:
        """For every stage of _stages_loose: the directories it may run in (the session directory is always one).
        The directory is narrowed only while the command is a chain of `&&` that consists of `cd X` / `pushd X` with a
        literal X and plain readers or listers (CHAIN_SAFE): then each stage runs in the last literal target. Anything
        else — another operator (`;`, `||`, `|`, `&`, a newline, a parenthesis), a wrapper (`builtin`, `command`, `env`,
        `eval`), an assignment, a function or alias, `popd`, a non-literal `cd` (`cd -`, `cd "$D"`), a shell — ends the
        narrowing for the rest of the command: from there every stage is checked in the session directory and in every
        directory the literal `cd`s reached (relative to each of them). `cd` through CDPATH is not followed."""
        seen = [self.cwd]  # every directory a stage may run in
        sure = [self.cwd]  # where the stage runs while the narrowing holds
        narrow = True
        result: list[list[str]] = []
        stage: list[str] = []
        depth = 0
        for t in [*tokens, ";"]:
            if t in ("(", ")") and self._find_paren(stage, t, depth):
                depth += 1 if t == "(" else -1
                stage.append(t)
                continue
            if not (t in FORBIDDEN_OPERATORS or t in ("|", "|&") or re.fullmatch(r"[;&|()]+", t)):
                stage.append(t)
                continue
            depth = 0
            if stage:
                target = self._cd_target(stage)
                if narrow and target is None and not self._chain_safe(stage):
                    narrow = False
                result.append(list(sure if narrow else seen))
                if target is not None:
                    moved = [_path(target, d) for d in (sure if narrow else seen)]
                    seen += [d for d in moved if d not in seen]
                    if narrow:
                        sure = moved
                stage = []
            if t != "&&":
                narrow = False
        return result

    @staticmethod
    def _ls_plain(stage: list[str]) -> bool:
        """An `ls` that certainly does not recurse: only short option clusters, `--` and a few known long options (GNU
        ls accepts abbreviated long options, so any other long one — `--recur` — is not trusted)."""
        for t in stage[1:]:
            if t == "--":
                break
            if t.startswith("--"):
                if t.split("=", 1)[0] not in LS_LONG_PLAIN:
                    return False
            elif t.startswith("-") and not re.fullmatch(r"-[A-QS-Za-z0-9]*", t):
                return False
        return True

    def _stage_kinds(
        self, stage: list[str], c: set[int], text: str, literal, verbatim, body: str
    ) -> list[tuple[str, str]]:
        """Reasons the stage touches data, resolved against self.cwd."""
        found: list[tuple[str, str]] = []
        cmd = Path(stage[0]).name if stage else ""
        kind_of_stage = self._stage_class(stage)
        original = tuple(stage)
        if kind_of_stage == "remote":  # git metadata / gh: only the local files it is told to read
            if cmd == "git":  # `git ls-files Sensitive-data` prints names — they must not be piped on to a reader
                call = self._git_call(stage[1:]) or {}
                self._record_names(stage, [call.get("repo", self.cwd), *call.get("words", [])])
            return [r for t in self._remote_paths(stage, c) if (r := self._token_kind(t, False))]
        # grep without -r/-R/-d recurse reads only the given files (skips directories) — the pattern `../x*.yml`
        # does not reach subdirectories; rg, fd, ag, find… search the tree by default
        recursion = (
            (cmd in SEARCHERS and FAMILIES.get(cmd) != "grep")
            or _recursive_flag(cmd, stage)
            or (FAMILIES.get(cmd) == "grep" and GREP_RECURSE.search(" ".join(stage)) is not None)
        )
        skip, filters, no_path = self._searcher_args(stage)
        if cmd in LISTING_COMMANDS and stage[0] == cmd and not no_path:
            # `ls -R`, `tree`, `find`, `du -a` without a path list cwd (a redirection — `2 > /dev/null` as the
            # tokenizer splits it — is not an operand)
            redirect = [t in REDIRECTS or re.fullmatch(r"\d?>&?|&>>?", t) is not None for t in stage]
            redirected = {i + 1 for i, r in enumerate(redirect) if r}
            redirected |= {i for i, t in enumerate(stage[:-1]) if t.isdigit() and redirect[i + 1]}
            arguments = [
                t for i, t in enumerate(stage[1:], 1)
                if i not in redirected and t not in REDIRECTS and not re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t)
            ]
            no_path = not _listing_paths(cmd, arguments)
        skip |= self._text_args(stage)
        program = self._program_text(stage)
        family = FAMILIES.get(cmd)
        if kind_of_stage != "names" and any(self._data_filter(v) for v in filters) and self._reads_content(stage, family):
            # #23: a name filter (--include=*.csv, -t csv) is not a denial by itself — the data files it can reach are
            # judged by their content
            roots = [
                t
                for i, t in enumerate(stage)
                if i and i not in skip and not t.startswith("-") and not re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t)
            ]
            if family == "find":
                roots = _listing_paths(cmd, stage[1:])
            for root in roots if roots and not no_path else [self.cwd]:
                if r := self._walk_data(root):
                    found.append(r)
        if cmd == "git":  # `git show HEAD:dir/file`, `git cat-file -p :file` — a path in the repository, from its root
            root = config.git_root(self.cwd) or self.cwd
            for t in stage[1:]:
                if m := re.fullmatch(r"[\w.^~@{}/-]*:(?!/)(.+)", t):
                    if r := self._token_kind(os.path.join(root, m.group(1)), False):
                        found.append(r)
        if no_path:  # rg foo, fd php, grep -r foo — they search cwd
            stage = [*stage, "."]
        for i, t in enumerate(stage):
            if i in skip or not t or re.fullmatch(r"[|<>&;()]+|\d?>&?\d?", t):
                continue
            if i == 0 and re.fullmatch(r"[\w.+@-]+", t) and not t.casefold().endswith(self.extensions):
                continue  # the command word is looked up in PATH, not in the working directory (`cd D && pwd`)
            read = i not in c and kind_of_stage != "names"  # a write target and a name listing read no content
            if family in IGNORE_FILES and i and self._ignore_excludes(t, family, stage):
                r = self._token_kind(t, False, content=read)  # sensitive directories under t are skipped (.ignore)
                if not r and _ancestor(_path(t, self.cwd), self.protected):
                    r = ("protected", t)
            elif i in program and getattr(t, "quoted", False):
                # this very word is one quoted fragment (`'…'`, `--jq='…'`): no glob, no braces (an unquoted
                # `sed ~/D*` expands into the file operands; a same-looking quoted word elsewhere changes nothing)
                r = self._token_kind(t, False, content=read, verbatim=True)
            elif t in literal:
                r = self._literal_kind(t, t in verbatim, body, recursion, content=read)
            else:
                r = self._token_kind(t, recursion, content=read)
            if not r and i not in c and cmd not in NO_READ_COMMANDS:
                r = self._pending_write(t)
            if r and i in c and r[0] in ("sensitive", "extension"):
                r = None  # a write target: nothing comes back (#23); the filter's own files stay protected
            if r and kind_of_stage == "names":
                # names are not content (#23); only the filter's own files stay off-limits (listing an ancestor of
                # their directory shows just the names of its entries; a pattern is judged by where it can reach)
                if r[0] == "sensitive":
                    self._names_seen.add(original)
                inside = _inside(_path(r[1], self.cwd), self.protected) or re.search(r"[*?\[{]", t)
                r = r if r[0] == "protected" and inside else None
            if r:
                found.append(r)
        return found

    def _record_names(self, stage: list[str], candidates: list[str]) -> None:
        """The stage names a path inside a sensitive directory and only prints names: remembered, so that `bash` can
        check where the names go (`find Sensitive-data | xargs cat` would read what the listing found)."""
        for t in candidates:
            if self.path_kind(t) == "sensitive" or (os.path.isabs(t) is False and self.path_kind(_path(t, self.cwd)) == "sensitive"):
                self._names_seen.add(tuple(stage))
                return

    def _names_flow_ok(self, command: str, tokens: list[str]) -> bool:
        """Names of files inside a sensitive directory (a lister, `git ls-files`) may reach the screen only: the command
        has no substitution, background job or subshell, and each pipeline holding such a lister continues only through
        text filters (NAME_FILTERS_OK) with no redirection to a file — otherwise `xargs cat`, `$(find …)`, `> list`
        would turn the names into a read."""
        if re.search(r"\$\(|`|<\(|>\(", self._without_single_quoted(command)):
            return False
        allowed = {";", "&&", "||", "\n", "|", "|&"}
        pipeline: list[list[str]] = [[]]
        pipelines: list[list[list[str]]] = []
        depth = 0
        previous = ""
        for t in tokens:
            if t in ("(", ")") and self._find_paren(pipeline[-1], t, depth):  # find's `\( … \)`
                depth += 1 if t == "(" else -1
                pipeline[-1].append(t)
            elif t in ("(", ")"):  # a subshell group `(cd D && ls)`: its output must not be piped on either
                if t == "(" and previous in ("|", "|&"):
                    return False
                pipelines.append(pipeline)
                pipeline = [[]]
            elif t in ("|", "|&"):
                if previous == ")":
                    return False
                pipeline.append([])
            elif t in (";", "&&", "||", "\n"):
                pipelines.append(pipeline)
                pipeline = [[]]
            elif t in FORBIDDEN_OPERATORS or re.fullmatch(r"[;&()]+", t) or re.fullmatch(r"\|[|&]+.*", t):
                if t not in allowed:
                    return False
            else:
                pipeline[-1].append(t)
            previous = t
        pipelines.append(pipeline)
        for stages in pipelines:
            cores = [
                parts[-1]
                for stage in stages
                if stage and (parts := self._strip_prefixes([stage]))
                if not (parts[-1][0] == "env" and stage[0] != "env")  # only assignments: prints nothing
            ]
            if not any(tuple(e) in self._names_seen for e in cores):
                continue
            for e in cores:
                rest = list(strip_2to1(e))
                for k in range(len(rest) - 1):  # `2>/dev/null`, `>/dev/null`, `&>/dev/null`
                    if rest[k] and re.fullmatch(r"\d?>|&>", rest[k]) and rest[k + 1] == "/dev/null":
                        rest[k] = rest[k + 1] = ""
                if any(t in REDIRECTS or re.fullmatch(r"\d*[<>]+&?\d*", t) for t in rest if t):
                    return False
                if tuple(e) in self._names_seen:
                    if e[0] == "tree" and any(OUTPUT_OPTIONS.match(t) for t in e[1:]):  # tree -o FILE writes the listing
                        return False
                elif e[0] not in FILTER_SPECS:
                    return False
                else:
                    args = [t for t in rest[1:] if t]
                    parsed = _allowed(args, FILTER_SPECS[e[0]])
                    if parsed is None or (e[0] in ("uniq", "cat") and any(args[k] != "-" for k in parsed[0])):
                        return False  # an option that reads or writes a file (sort -o, --files0-from, --compress-program)
        return True

    def _reads_content(self, stage: list[str], family: str | None) -> bool:
        """The searcher returns file content (matching lines), or runs a command on the files it finds."""
        if family in ("grep", "rg", "ag"):
            return True
        if family == "find":
            return any(t in FIND_ACTIONS for t in stage[1:])
        if family == "fd":
            return self._fd_exec(stage[1:])
        return False

    def _pending_write(self, t: str) -> tuple[str, str] | None:
        """A data file that this command writes in another stage (or names in several stages while it does not exist
        yet): reading it in the same command — its content is unknown at the gate (#23)."""
        for k in dict.fromkeys((t, t.split("=", 1)[-1])):
            p = _path(k, self.cwd)
            if not p.casefold().endswith(self.extensions):
                continue
            if p in self._written or (not os.path.exists(p) and len(self._appears.get(p, ())) >= 2):
                return self._note(
                    "extension", p, "a data file that an earlier stage of this command writes — its content cannot be checked before it runs"
                )
        return None

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
    def _find_paren(stage: list[str], t: str, depth: int) -> bool:
        """The parenthesis `t` is an argument of `find` (`find . -type d ( -name a -o -name b )`), not a subshell or the
        `(` of `$(…)` / `<(…)` — the stage keeps it (#23, so that a names-only `find` stays one stage)."""
        if not stage or stage[0] != "find":
            return False
        return (t == "(" and stage[-1] not in ("$", "<", ">")) or (t == ")" and depth > 0)

    @staticmethod
    def _stages_loose(tokens: list[str]) -> list[list[str]]:
        """Simple commands split on any operator (for detection, not for allowing)."""
        stages: list[list[str]] = [[]]
        depth = 0
        for t in tokens:
            if t in ("(", ")") and Gate._find_paren(stages[-1], t, depth):
                depth += 1 if t == "(" else -1
                stages[-1].append(t)
            elif t in FORBIDDEN_OPERATORS or t in ("|", "|&") or re.fullmatch(r"[;&|()]+", t):
                stages.append([])
                depth = 0
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
        if "\n" in tokens:
            return "multi-line command — with a sensitive source only one command on one line"
        if re.search(r"\$\(|`|<\(|>\(|\$\{", self._without_single_quoted(command)):
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
                real = self._operand_locations(a)  # the same resolution as _copies_inside (globs, symlinks, `..`)
                if real is None or not all(_inside(p, self.sensitive) for p in real):
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
            # piigate, bash piigate, python3 lib/cli.py — the program run by the stage (after assignments, launchers,
            # interpreters and their options), followed by the subcommand; `gh … -R o/piigate --search …` is not a call
            piigate_stage = tokens is not None and any(
                word in stage[k + 1 :] for stage in self._stages_loose(tokens) if (k := self._runs_piigate(stage)) is not None
            )
            if suspicious or call or piigate_stage:
                return (
                    f"piigate: {description} is for a human only, in their own terminal — never through the agent. "
                    "Show the human the command to run."
                )
        return None

    @staticmethod
    def _runs_piigate(stage: list[str]) -> int | None:
        """Index of `piigate` / `cli.py` when the stage may run it: it is the command word, or the command word is a
        launcher or an interpreter (`sudo -u x python3 -I lib/cli.py`, `bash piigate` — when in doubt, a call); None
        when it is an argument of another command (`gh … -R o/piigate`)."""
        k = next((k for k, t in enumerate(stage) if not (t in SHELL_KEYWORDS or re.match(r"^\w+=", t))), None)
        if k is None:
            return None
        name = Path(stage[k]).name
        if name not in ("piigate", "cli.py") and not (
            name in LAUNCHERS or re.fullmatch(r"(?:python|pypy)[\d.]*|uv|uvx|pipx", name)
        ):
            return None
        return next((j for j in range(k, len(stage)) if Path(stage[j]).name in ("piigate", "cli.py")), None)

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

    def _marker_only_dir(self, operand: str) -> str | None:
        """The operand (no shell metacharacters) names a piigate data directory — not a symlink — that holds nothing but
        the untouched `.gitignore` marker: its real path, else None."""
        if re.search(r"[;&|()<>\n$`*?\[{~\\]", operand) or not operand:
            return None
        given = os.path.join(self.cwd, operand)
        real = os.path.realpath(given)
        names = {n for n in ((self.cfg.get("project_directories") or {}).values()) if n}
        data = {*self.project_sensitive, *(config.expand(k) for k in self.cfg.get("in_project", {}).get("anonymized", []))}
        if os.path.islink(given.rstrip("/")) or not os.path.isdir(real) or not (real in data or os.path.basename(real) in names):
            return None
        marker = os.path.join(real, ".gitignore")
        try:
            if os.listdir(real) != [".gitignore"] or os.path.islink(marker):
                return None
            if Path(marker).read_text(encoding="utf-8") != config.GITIGNORE:
                return None
        except (OSError, UnicodeDecodeError):
            return None
        return real

    def _marker_only_rmdir(self, tokens: list[str] | None) -> str | None:
        """The whole command is one `rmdir` of a piigate data directory that holds nothing but the `.gitignore` marker
        (#7): it would fail with "Directory not empty", because the gate recreates the marker on every run. Denied with
        the one-command recipe — the command could not succeed anyway. Anything else (more files, an edited marker, a
        compound command, an option other than -p/-v) is left to rmdir itself."""
        if not tokens or tokens[0] != "rmdir" or any(re.search(r"[;&|()<>\n]", t) for t in tokens):
            return None
        options = [t for t in tokens[1:] if t.startswith("-")]
        if any(not (t == "--" or t in ("--parents", "--verbose") or re.fullmatch(r"-[pv]+", t)) for t in options):
            return None
        operands = [t for t in tokens[1:] if not t.startswith("-") or t == "--"]
        operands = [t for t in operands if t != "--"]
        if len(operands) != 1 or self._marker_only_dir(operands[0]) is None:
            return None
        d = shlex.quote(operands[0].rstrip("/") or operands[0])
        return (
            f"piigate: `rmdir {d}` would fail with \"Directory not empty\" — the directory holds only the piigate marker "
            "`.gitignore`, which the gate recreates on every command. Remove the marker and the directory in one command "
            f"(rmdir refuses if anything else is in it): `rm {d}/.gitignore && rmdir {d}`."
        )

    def _marker_recipe(self, tokens: list[str] | None) -> bool:
        """The whole command is exactly `rm <dir>/.gitignore && rmdir <dir>` (the same literal <dir>, no options) for a
        directory that holds only the untouched marker — the one compound command the gate lets through next to a data
        directory. Nothing else qualifies."""
        if not tokens or len(tokens) != 5 or tokens[0] != "rm" or tokens[2] != "&&" or tokens[3] != "rmdir":
            return False
        target, directory = tokens[1], tokens[4]
        if target != directory.rstrip("/") + "/.gitignore" or directory.startswith("-") or directory.endswith("/"):
            return False
        return self._marker_only_dir(directory) is not None

    def bash(self, command: str, files: bool = True) -> str | None:
        """None = allow, otherwise the denial reason. files=False (the PostToolUse safety net): data files are not judged
        again — a file the command created is checked through its output instead."""
        if "\x00" in command:
            return "piigate: command denied — a NUL byte in the command"
        self._raw = command
        command = self._strip_file_heredocs(command)
        tokens = self._tokens(command)
        if reason := self._human_only(command, tokens):
            return reason
        if reason := self._marker_only_rmdir(tokens):
            return reason
        if self._marker_recipe(tokens):
            return None
        if re.search(r"\b(?:analyze|anonymize)\b", command) and any(
            c is None or c[1:2] in (["analyze"], ["anonymize"]) for c in self._invocations(command, {"piigate"})
        ):
            return MCP_PIIGATE
        for entry in self.unfiltered:
            calls = self._invocations(command, entry["commands"]) if entry["commands"] else []
            if calls and (reason := self.unfiltered_bash(entry, command, tokens, calls)):
                return reason
        self._names_seen = set()
        if tokens is None:
            kind, _ = self._touches(command, command.split())
            kind = kind or ("sensitive" if self._names_seen else None)
            if kind and (kind != "extension" or files):
                return (
                    f"piigate: cannot parse the command (quotes) with a sensitive source. {HINT}"
                )
            return None
        kind, what = self._touches(command, tokens)
        if kind is None and self._names_seen and not self._names_flow_ok(command, tokens):
            return (
                "piigate: command denied — the names of files in a sensitive data directory are passed on (xargs, a "
                "substitution, a loop, a file or another program) and would turn the listing into a read; a listing may "
                f"be filtered only by grep/head/tail/sort/uniq/cut/wc. {HINT}"
            )
        if kind is None or (kind == "extension" and not files):
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
        if p and not _inside(p, self.sensitive):
            below = [k for k in self.sensitive if _inside(k, [p]) and os.path.lexists(k)]
            below += [k for k in self._found.get(p, []) if k not in below]
            if below:
                sub = ", ".join(os.path.relpath(k, p) for k in below)
                entries = ", ".join(f"`/{x}/`" for x in sub.split(", "))
                what = (
                    f"{what} — contains a sensitive directory: {sub}; search the code subdirectory, use piigate_search (MCP) or "
                    f"exclude {'them' if ',' in sub else 'it'} with the {'entries' if ',' in sub else 'entry'} {entries} in an .ignore "
                    "file (honoured by rg, fd, ag; not grep)"
                )
            elif p in self._oversized:
                what = (
                    f"{what} — the directory tree is too large to check for sensitive directories (over {TREE_BUDGET} "
                    "directories); search a narrower directory or use piigate_search (MCP)"
                )
        description = {
            "sensitive": f"a sensitive data directory ({what})",
            "command": "output of a database query on a server (production data)",
            "extension": f"{self.describe_verdict(what)} ({what})",
        }[kind]
        return f"piigate: command denied — {description}; {reason}. {HINT}"
