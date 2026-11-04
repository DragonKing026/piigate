"""Matrix: shapes of an array assignment x ways to use the array (issue 340, round 7).

The rule it checks: an element put into an array NEVER disappears — every use of the name, in any form and with any
operator, is judged for ALL the elements ever assigned (a superset), and the written text stays too. The condition is
the one that matters for the gate: when the OLD gate denies a line and a real shell reads the dummy sensitive file,
the AST gate denies it too. `python3 -I tests/shell_matrix.py` prints the counts."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
sys.path.insert(0, str(HERE))

G = "../S*/p*"  # a glob that reaches the dummy sensitive file
V = "../Sensitive-data/people.csv"  # the same, spelled out

SHAPES = [
    f"a=(zzz {G})", f"a=({G})", f"a=(zzz {V})", f"a=({V})", f"declare -a a=(zzz {G})", f"a=(); a+=({G})", f"a=(zzz); a+=({G})",
    f"declare a; a+=({G})", f"declare -a a; a+=({G})", f"unset a; a+=({G})", f"typeset a; a+=({G})", f"local a; a+=({G})",
    f"export a; a+=({G})", f"readonly a=({G})", f"declare -x a=({G})", f"declare -g a=({G})", f"f() {{ a+=({G}); }}; a=(); f",
    f"a=(); for i in 1; do a+=({G}); done", f"a=(); while :; do a+=({G}); break; done", f"a=(x); a[1]={G}", f"a=(x); a[1]={V}",
    "a=(zzz); a+=($(echo x))", f"a[0]=zzz; a[1]={G}", f"a=(zzz); a+=({V})", f"declare -A a; a+=([k]={G})",
    "declare -a files; files+=(../S*/*.csv); a=(\"${files[@]}\")",
]

USES = [
    "cat ${a[@]}", 'cat "${a[@]}"', "cat ${a[@]:1}", 'cat "${a[@]:1}"', "cat ${a[@]:0}", "cat ${a[@]/zzz/}", "cat ${a[@]#zzz}",
    "cat ${a[@]%zzz}", "cat ${a[@]:-d}", "cat ${a[@]:+${a[@]}}", "cat ${a[*]}", 'cat "${a[*]}"', "cat ${a[1]}", "cat ${a[-1]}",
    "cat ${a[@]^^}", "cat ${a[@],,}", "cat ${a[@]@Q}", "for f in ${a[@]:1}; do cat $f; done", 'for f in "${a[@]:1}"; do cat "$f"; done',
    'set -- "${a[@]}"; cat $@', "set -- ${a[@]:1}; cat $1", "printf '%s\\n' \"${a[@]}\" | xargs cat", "cat ${a[@]:1:1}",
    "cat ${a[@]:1:5}", "cat ${a:1}", "cat $a", "cat ${a[0]}${a[1]}", "cat ${a[@]}${a[@]}", "cat ${a[k]}", "cat ${!a[@]}", "cat ${#a[@]}",
]


def cases() -> list[tuple[str, str]]:
    out = []
    for i, shape in enumerate(SHAPES):
        for j, use in enumerate(USES):
            out.append((f"s{i}_u{j}", f"{shape}; {use}"))
    return out


def run() -> dict:
    """Decides every case with the old gate, the AST gate (both grammars) and real shells; returns the counts and the failures."""
    import shell_zsh_cases as zc
    from piigate import gate, shell_gate

    world = zc.World()
    counts = {"cases": 0, "real_reads": 0, "old_denies_and_real_reads": 0, "ast_denies_when_old_denies_and_real_reads": 0,
              "old_allows_and_real_reads": 0, "ast_denies_when_old_allows_and_real_reads": 0}
    failures: list[str] = []
    try:
        for name, command in cases():
            world.reset()
            old_gate = world.gate()
            old_denies = gate.Gate.bash(old_gate, command, True) is not None
            reads = any(world.real(command, m).get("reads") for m in ("f", "bash"))
            denied = []
            for d in ("bash", "zsh"):
                g = shell_gate.AstGate(old_gate.cfg, old_gate.cwd, d)
                denied.append(g.bash(command, True) is not None)
            counts["cases"] += 1
            if reads:
                counts["real_reads"] += 1
                key = "old_denies" if old_denies else "old_allows"
                counts[key + "_and_real_reads"] += 1
                if all(denied):
                    counts[f"ast_denies_when_{key}_and_real_reads"] += 1
                if old_denies and not all(denied):
                    failures.append(f"{name}: {command}")
    finally:
        world.close()
    counts["failures"] = failures
    return counts


if __name__ == "__main__":
    result = run()
    print({k: v for k, v in result.items() if k != "failures"})
    for f in result["failures"]:
        print("OLD DENIES, A REAL SHELL READS, THE AST GATE ALLOWS:", f)
