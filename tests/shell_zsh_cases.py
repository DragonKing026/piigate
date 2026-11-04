"""zsh corpus for the gate (issue 340): what the Bash tool's shell does when it is zsh, and what the gate makes of it.

The agent's Bash tool runs commands in the user's login shell (`$SHELL=/usr/bin/zsh` on the development machine), but
shell.py parses `shfmt -ln bash` and the old gate was written with bash in mind. Every case here is a command line with
a feature that is zsh-only or means something else in zsh. For each case `measure()` records

    old     the decision of the current gate (`Gate.bash`): deny | allow
    bash    `shfmt -ln bash`: ok (n calls) | error (message)
    zsh     `shfmt -ln zsh`:  ok (n calls) | error (message)
    real    what zsh really does with the line, run in a throw-away directory with dummy files (zsh -f -c):
            `reads` — the canary of the dummy "sensitive" file reached the output; `runs` — code planted in a
            glob qualifier / `${(e)…}` ran; plus the first output line

`hole` is true when the old gate ALLOWS a line that really reads the dummy sensitive file: a potential hole in 1.0.10.

Everything happens in a temporary directory with dummy files; no network, nothing outside the directory is touched.
Run: `python3 -I tests/shell_zsh_cases.py` (table), `--json FILE` (the same as JSON).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))

CANARY = "CANARY-SENSITIVE-ROW"
EXEC = "EXEC-42"  # printed only by code that really ran (`$((40+2))` is computed, never in the line itself)
SENSITIVE_NAME = "Sensitive-data"


@dataclass(frozen=True)
class ZshCase:
    name: str
    command: str
    what: str  # the zsh feature


# `S*/p*.csv` is the dummy sensitive file seen through a glob that does not spell out the directory name (so the text
# markers of the gate do not catch it): a hole shows where the gate looks only at what it can recognise as a path.
UP = f"../{SENSITIVE_NAME}"  # the commands run in `work/`, a sibling of the sensitive directory (a glob here must not reach it)
HIDDEN = "../S*/p*.csv"
VISIBLE = f"{UP}/people.csv"

CASES: list[ZshCase] = [
    ZshCase("qualifier-e-visible", f"echo *(e:'cat {VISIBLE} >&2':)", "glob qualifier `(e:code:)` runs code per match"),
    ZshCase("qualifier-e-hidden", f"echo *(e:'cat {HIDDEN} >&2':)", "the same, the path only as a glob inside the code string"),
    ZshCase("qualifier-e-after-glob", f"echo *.csv(e:'cat {HIDDEN} >&2':)", "qualifier after a data-extension glob"),
    ZshCase("qualifier-e-names-ls", f"ls *(e:'cat {HIDDEN} >&2':)", "a names-only command (`ls`) with a code qualifier"),
    ZshCase("qualifier-e-echo-exec", "echo *(e:'echo EXEC-$((40+2)) >&2':)", "qualifier code, harmless — shows that it runs"),
    ZshCase("qualifier-plus-func", f"f() {{ cat {HIDDEN} >&2; }}; echo *(+f)", "glob qualifier `(+func)` calls a function"),
    ZshCase("qualifier-plus-func-name-only", "echo *(+f)", "`(+f)` with the function defined elsewhere (not in this line)"),
    ZshCase("qualifier-dot-hidden", f"cat {HIDDEN[:-4]}(.)", "plain qualifier `(.)` on a sensitive glob"),
    ZshCase("temp-file-subst", f"cat =(cat {HIDDEN})", "`=(cmd)`: a temporary file with the command's output"),
    ZshCase("temp-file-subst-visible", f"cat =(cat {VISIBLE})", "`=(cmd)` with the path spelled out"),
    ZshCase("equals-expansion-visible", f"=cat {VISIBLE}", "`=cat` is the path of cat; a plain word in bash"),
    ZshCase("equals-expansion-hidden", f"=cat {HIDDEN}", "`=cat` with a hidden glob"),
    ZshCase("equals-ls-names", f"=ls {UP}", "`=ls` is not the name `ls` for the gate's names-only class"),
    ZshCase("param-flag-e-hidden", f"x='$(cat {HIDDEN} >&2)'; echo ${{(e)x}}", "`${(e)x}` expands $(…) inside the value"),
    ZshCase("param-flag-e-visible", f"x='$(cat {VISIBLE} >&2)'; echo ${{(e)x}}", "`${(e)x}`, path spelled out"),
    ZshCase("param-flag-P", f"n=x; x={HIDDEN}; cat ${{(P)n}}", "`${(P)n}`: the value of the variable named by n (no globbing)"),
    ZshCase("param-glob-subst", f"x={HIDDEN}; cat ${{~x}}", "`${~x}`: the value is globbed"),
    ZshCase("no-word-splitting", f"x='{HIDDEN} y'; cat $x", "zsh does not split or glob an unquoted `$x` (bash does)"),
    ZshCase("cmd-subst-null-read", f"echo $(<{VISIBLE})", "`$(<file)` reads the file"),
    ZshCase("cmd-subst-null-read-hidden", f"echo $(<{HIDDEN})", "`$(<glob)`: zsh expands the glob, bash does not"),
    ZshCase("null-cmd-read-visible", f"< {VISIBLE}", "`<file` without a command: zsh runs READNULLCMD (a pager = cat)"),
    ZshCase("null-cmd-read-hidden", f"< {HIDDEN}", "`<glob` without a command"),
    ZshCase("repeat", f"repeat 1 cat {HIDDEN}", "`repeat N cmd`: bash sees a command named repeat"),
    ZshCase("repeat-do-done", f"repeat 1 do cat {HIDDEN}; done", "`repeat N do … done`"),
    ZshCase("background-disown-pipe", f"cat {HIDDEN} &|", "`&|` — background and disown"),
    ZshCase("background-disown-bang", f"cat {HIDDEN} &!", "`&!` — background and disown"),
    ZshCase("foreach", f"foreach f ({HIDDEN})\ncat $f\nend", "`foreach f (words) … end`"),
    ZshCase("foreach-visible", f"foreach f ({VISIBLE})\ncat $f\nend", "`foreach`, path spelled out"),
    ZshCase("anonymous-function", f"() {{ cat $1; }} {HIDDEN}", "anonymous function with arguments"),
    ZshCase("always-block", f"{{ echo a; }} always {{ cat {HIDDEN}; }}", "`{ … } always { … }`"),
    ZshCase("always-block-no-semicolon", f"{{ echo a }} always {{ cat {HIDDEN} }}", "the same without `;` before `}` (zsh allows it)"),
    ZshCase("print-r-names", f"print -r -- {HIDDEN}", "`print -r --` prints the pattern's expansion: names only"),
    ZshCase("print-names-only-visible", f"print -r -- {UP}/*", "`print` of a sensitive glob: names only"),
    ZshCase("noglob-hidden", f"noglob cat {HIDDEN}", "`noglob`: no expansion, so cat gets the literal pattern (no read)"),
    ZshCase("noglob-visible", f"noglob cat {VISIBLE}", "`noglob` with the real path"),
    ZshCase("autoload-fpath", "fpath=(.); autoload -Uz hook; hook", "a function body read from a file in fpath"),
    ZshCase("global-alias", f"alias -g P='{HIDDEN}'\ncat P", "a global alias expands in any word (here on the next line)"),
    ZshCase("suffix-alias", f"alias -s csv=cat\n{VISIBLE}", "a suffix alias runs the handler on a bare file name"),
    ZshCase("zsh-modifier-colon", f"cat ${{{HIDDEN}:a}}", "`${…:a}` history-style modifier (absolute path)"),
    ZshCase("hash-table-path", f"hash -d d={UP}\ncat ~d/people.csv", "a named directory `~d` set by `hash -d`"),
    ZshCase("brace-ccl", f"cat {UP}/people.cs{{v}}", "a single-element brace (zsh: BRACE_CCL differs); bash keeps it"),
    ZshCase("extendedglob-negation", "setopt extendedglob; cat ../S*/^x.csv", "`^pattern` negation needs EXTENDED_GLOB"),
    ZshCase("globsubst-option", f"setopt globsubst; x={HIDDEN}; cat $x", "`setopt globsubst` makes `$x` glob like bash"),
    ZshCase("cmd-name-from-param", f"c=cat; $c {HIDDEN}", "a command name in a variable (unknown to the gate in both shells)"),
    ZshCase("control-cat-visible", f"cat {VISIBLE}", "control: a plain read, same in both shells"),
    ZshCase("control-cat-hidden-glob", f"cat {HIDDEN}", "control: a plain read through a glob"),
    ZshCase("control-no-read", "cat x.csv", "control: a plain read of a clean file"),
]


# ---------------------------------------------------------------------------------------------------- the world


class World:
    """A throw-away directory: the dummy sensitive directory, clean files, a gate configuration that knows the directory."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="piigate-zsh-"))
        self.work = self.root / "work"
        self.work.mkdir()
        (self.root / SENSITIVE_NAME).mkdir()
        (self.root / SENSITIVE_NAME / "people.csv").write_text(CANARY + "\n", encoding="utf-8")
        for name in ("x.csv", "s.csv"):
            (self.work / name).write_text("plain\n", encoding="utf-8")
        (self.work / "hook").write_text(f"cat {HIDDEN}\n", encoding="utf-8")
        (self.work / "ln").symlink_to("../" + SENSITIVE_NAME)  # a symlink into the dummy sensitive directory

    def gate(self, factory=None):
        from piigate import config, gate

        os.environ.setdefault("PIIGATE_CONFIG_DIR", str(self.root / "cfg"))
        os.environ.setdefault("PIIGATE_DATA_DIR", str(self.root / "data"))
        cfg = config.load(str(self.work))
        cfg["sources"]["directories"] = [str(self.root / SENSITIVE_NAME)]
        cfg["sources"]["only_phi_projects"] = False
        cfg["in_project"] = {"sensitive": [], "anonymized": []}
        return (factory or gate.Gate)(cfg, str(self.work))

    def real(self, command: str, mode: str = "f") -> dict:
        """Runs the line in zsh (no rc files) inside the directory; a minimal environment, 5 s.
        mode "f": `zsh -f -c LINE`. mode "cc": the way Claude Code starts a command — `zsh -c` with
        `setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL`, then `eval LINE` (glob qualifiers work only after a `setopt`)."""
        env = {"HOME": str(self.root), "PATH": "/usr/bin:/bin", "ZDOTDIR": str(self.root / "nozdot")}
        zsh = shutil.which("zsh")
        if not zsh:
            return {"available": False}
        argv = [zsh, "-f", "-c", command]
        if mode == "bash":
            bash = shutil.which("bash")
            if not bash:
                return {"available": False}
            argv = [bash, "--noprofile", "--norc", "-c", command]
        if mode == "cc":
            env["PIIGATE_LINE"] = command
            argv = [zsh, "-f", "-c", 'setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; eval "$PIIGATE_LINE"']
        try:
            done = subprocess.run(
                argv,
                cwd=self.work,
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            return {"available": True, "timeout": True, "reads": False, "runs": False, "out": ""}
        out = (done.stdout + done.stderr).strip()
        first = out.splitlines()[0][:100] if out else ""
        return {
            "available": True,
            "rc": done.returncode,
            "reads": CANARY in out,
            "runs": EXEC in out,
            "out": first,
        }

    def close(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def shfmt_result(command: str, dialect: str) -> dict:
    from piigate import shell

    try:
        calls = shell.parse(command, cwd="/w", dialect=dialect)
    except shell.ParseError as e:
        return {"ok": False, "error": str(e)[:110]}
    return {"ok": True, "calls": len(calls), "names": [c.name or "?" for c in calls][:6]}


def measure(cases: list[ZshCase] | None = None, world: World | None = None) -> list[dict]:
    cases = cases if cases is not None else CASES
    own = world is None
    world = world or World()
    try:
        results = []
        for case in cases:
            gate = world.gate()
            reason = gate.bash(case.command)
            real = world.real(case.command)
            results.append(
                {
                    "name": case.name,
                    "command": case.command,
                    "what": case.what,
                    "old": "deny" if reason else "allow",
                    "old_reason": (reason or "")[:140],
                    "bash": shfmt_result(case.command, "bash"),
                    "zsh": shfmt_result(case.command, "zsh"),
                    "real": real,
                    "real_cc": (cc := world.real(case.command, "cc")),
                    "hole": reason is None and bool(real.get("reads")),
                    "hole_cc": reason is None and bool(cc.get("reads")),
                }
            )
        return results
    finally:
        if own:
            world.close()


def table(results: list[dict]) -> str:
    def parse(r: dict) -> str:
        return f"ok:{r['calls']}" if r["ok"] else "ERR"

    def did(real: dict) -> str:
        return "-" if not real.get("available") else ("READS" if real["reads"] else ("runs code" if real["runs"] else "no read"))

    lines = [f"{'case':32} {'old':5} {'bash':6} {'zsh':6} {'zsh -f':10} {'claude-code':11}", "-" * 78]
    for r in results:
        lines.append(
            f"{r['name']:32} {r['old']:5} {parse(r['bash']):6} {parse(r['zsh']):6} {did(r['real']):10} {did(r['real_cc']):11}"
            + ("  <== OLD ALLOWS A READ" if r["hole"] or r["hole_cc"] else "")
        )
    return "\n".join(lines)


def main() -> None:
    results = measure()
    print(table(results))
    holes = [r for r in results if r["hole"]]
    print(f"\n{len(results)} cases; the old gate allows {len(holes)} that really read the dummy sensitive file:")
    for r in holes:
        print(f"  {r['name']}: {r['command']!r}")
    if "--json" in sys.argv:
        Path(sys.argv[sys.argv.index("--json") + 1]).write_text(
            json.dumps(results, indent=1, ensure_ascii=False), encoding="utf-8"
        )


if __name__ == "__main__":
    main()
