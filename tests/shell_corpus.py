"""Corpus of Bash commands taken from the gate tests, with the decision each test expects (PROTOTYPE, issue 340).

`extract()` reads tests/test_filter.py WITHOUT importing it (ast only) and returns every command that a test hands to
`Gate.bash(...)` / `Gate.decision("Bash", {"command": ...})` / `self.denial("Bash", ...)`:

    Case(command, expected, test, line, templated)

`expected` is "allow" (the test asserts None / False), "deny" (asserts not None / True) or "unknown" (no assertion
directly around the call). `templated` is True when the command is an f-string: its `{placeholders}` are replaced with
`/PH/<name>` so the shell structure is still parsed (the real paths differ).

Run `python3 -I tests/shell_corpus.py` for the parsing measurement (how many commands shell.parse handles, how fast).
"""

from __future__ import annotations

import ast
import re
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))

ASSERT_ALLOW = {"assertIsNone", "assertFalse"}
ASSERT_DENY = {"assertIsNotNone", "assertTrue"}


@dataclass(frozen=True)
class Case:
    command: str
    expected: str  # allow | deny | unknown
    test: str
    line: int
    templated: bool = False


class _Unresolved(Exception):
    pass


def _render(node: ast.AST, fn: ast.AST, parents: dict, env: dict[str, list[str]]) -> tuple[list[str], bool]:
    """All string values the expression can take (loop variables expand to every element) and whether it is templated."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value], False
    if isinstance(node, ast.JoinedStr):
        out = ""
        for part in node.values:
            if isinstance(part, ast.Constant):
                out += str(part.value)
            elif isinstance(part, ast.FormattedValue):
                out += "/PH/" + re.sub(r"\W+", "_", ast.unparse(part.value))[:30].strip("_")
        return [out], True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, lt = _render(node.left, fn, parents, env)
        right, rt = _render(node.right, fn, parents, env)
        return [a + b for a in left for b in right], lt or rt
    if isinstance(node, ast.Name):
        if node.id in env:
            return env[node.id], False
        raise _Unresolved(node.id)
    raise _Unresolved(type(node).__name__)


def _strings(node: ast.AST, fn: ast.AST, parents: dict) -> list[tuple[str, bool]]:
    try:
        values, templated = _render(node, fn, parents, {})
        return [(v, templated) for v in values]
    except _Unresolved:
        return []


def _iter_values(iterable: ast.AST, fn: ast.AST, assigned: dict[str, ast.AST]) -> list[tuple[ast.AST, bool | None]]:
    """Elements of a loop iterable: (element node, expected-denial from a dict value or None)."""
    if isinstance(iterable, ast.Name) and iterable.id in assigned:
        return _iter_values(assigned[iterable.id], fn, assigned)
    if isinstance(iterable, ast.Call) and isinstance(iterable.func, ast.Attribute) and iterable.func.attr == "items":
        target = iterable.func.value
        if isinstance(target, ast.Name) and target.id in assigned:
            iterable = assigned[target.id]
    if isinstance(iterable, ast.Dict):
        out = []
        for k, v in zip(iterable.keys, iterable.values, strict=True):
            deny = v.value if isinstance(v, ast.Constant) and isinstance(v.value, bool) else None
            out.append((k, deny))
        return out
    if isinstance(iterable, (ast.Tuple, ast.List, ast.Set)):
        return [(e, None) for e in iterable.elts]
    return []


def _expected(call: ast.Call, parents: dict) -> str:
    node: ast.AST = call
    while node in parents:
        node = parents[node]
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr in ASSERT_ALLOW:
                return "allow"
            if attr in ASSERT_DENY:
                return "deny"
            if attr == "assertIn":
                return "deny"
        if isinstance(node, ast.FunctionDef):
            break
    return "unknown"


def _is_bash_call(node: ast.Call) -> ast.AST | None:
    f = node.func
    if isinstance(f, ast.Attribute) and f.attr == "bash" and len(node.args) == 1:
        return node.args[0]
    if isinstance(f, ast.Name) and f.id == "bash" and len(node.args) == 1:
        return node.args[0]
    if isinstance(f, ast.Attribute) and f.attr in ("decision", "denial") and len(node.args) == 2:
        a, b = node.args
        if isinstance(a, ast.Constant) and a.value == "Bash" and isinstance(b, ast.Dict):
            for k, v in zip(b.keys, b.values, strict=True):
                if isinstance(k, ast.Constant) and k.value == "command":
                    return v
    return None


def extract(path: Path | None = None) -> list[Case]:
    path = path or HERE / "test_filter.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    cases: list[Case] = []
    for fn in ast.walk(tree):
        if not isinstance(fn, ast.FunctionDef) or not fn.name.startswith("test_"):
            continue
        assigned: dict[str, ast.AST] = {}
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                assigned[n.targets[0].id] = n.value
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call):
                continue
            arg = _is_bash_call(call)
            if arg is None:
                continue
            expected = _expected(call, parents)
            candidates: list[tuple[ast.AST, str]] = []
            if isinstance(arg, ast.Name):
                # the loop variable: every element of the enclosing `for`; else a plain assignment
                node: ast.AST = call
                loop = None
                while node in parents:
                    node = parents[node]
                    if isinstance(node, ast.For) and (
                        (isinstance(node.target, ast.Name) and node.target.id == arg.id)
                        or (
                            isinstance(node.target, ast.Tuple)
                            and any(isinstance(e, ast.Name) and e.id == arg.id for e in node.target.elts)
                        )
                    ):
                        loop = node
                        break
                if loop is not None:
                    for element, deny in _iter_values(loop.iter, fn, assigned):
                        exp = expected
                        if deny is not None:
                            exp = "deny" if deny else "allow"
                        candidates.append((element, exp))
                elif arg.id in assigned:
                    candidates.append((assigned[arg.id], expected))
            else:
                candidates.append((arg, expected))
            for element, exp in candidates:
                for text, templated in _strings(element, fn, parents):
                    cases.append(Case(text, exp, fn.name, getattr(element, "lineno", call.lineno), templated))
    seen: set[tuple[str, str]] = set()
    unique = []
    for c in cases:
        key = (c.command, c.expected)
        if key not in seen:
            seen.add(key)
            unique.append(c)
    return unique


def measure(cases: list[Case]) -> dict:
    from piigate import shell

    ok: list[tuple[Case, list, float]] = []
    failed: list[tuple[Case, str, float]] = []
    for c in cases:
        start = time.perf_counter()
        try:
            calls = shell.parse(c.command, cwd="/w")
        except shell.ParseError as e:
            failed.append((c, str(e), (time.perf_counter() - start) * 1000))
            continue
        ok.append((c, calls, (time.perf_counter() - start) * 1000))
    times = sorted(t for _, _, t in ok)
    node_types: Counter = Counter()
    for c, _, _ in ok:
        stack = [shell.ast(c.command)]
        while stack:
            n = stack.pop()
            if isinstance(n, dict):
                if "Type" in n:
                    node_types[n["Type"]] += 1
                stack.extend(n.values())
            elif isinstance(n, list):
                stack.extend(n)
    info = Counter()
    for c, calls, _ in ok:
        words = [w for call in calls for w in call.argv]
        info["with quoted word"] += any(w.quoting != "none" for w in words)
        info["with heredoc"] += any(r.heredoc for call in calls for r in call.redirects)
        info["with redirection"] += any(call.redirects for call in calls)
        info["with substitution"] += any(call.substitutions for call in calls)
        info["with cwd set > 1"] += any(len(call.cwds) > 1 for call in calls)
        info["with pipe to shell"] += any(call.pipe_to_shell or call.stdin_interpreter for call in calls)
        info["with -c / eval script"] += any(call.origin in ("-c", "eval") for call in calls)
        info["with glob word"] += any("glob" in w.kinds for w in words)
        info["opaque code"] += any(call.opaque_code for call in calls)
    return {
        "total": len(cases),
        "parsed": len(ok),
        "failed": failed,
        "median_ms": statistics.median(times) if times else 0.0,
        "p95_ms": times[int(len(times) * 0.95) - 1] if times else 0.0,
        "mean_ms": statistics.fmean(times) if times else 0.0,
        "sum_ms": sum(times),
        "node_types": node_types,
        "info": info,
        "calls": sum(len(calls) for _, calls, _ in ok),
    }


def main() -> None:
    cases = extract()
    by_exp = Counter(c.expected for c in cases)
    print(
        f"commands: {len(cases)}  (allow {by_exp['allow']}, deny {by_exp['deny']}, unknown {by_exp['unknown']}; "
        f"templated {sum(c.templated for c in cases)})"
    )
    m = measure(cases)
    print(f"parsed {m['parsed']}/{m['total']}, simple commands found {m['calls']}")
    print(
        f"time per command incl. shfmt start: median {m['median_ms']:.1f} ms, p95 {m['p95_ms']:.1f} ms, "
        f"mean {m['mean_ms']:.1f} ms, total {m['sum_ms']:.0f} ms"
    )
    print("errors:")
    for c, message, _ in m["failed"]:
        print(f"  [{c.test}:{c.line}] {message}  <- {c.command[:70]!r}")
    print("structure available:")
    for k, v in sorted(m["info"].items()):
        print(f"  {k}: {v}")
    print("AST node types seen:", ", ".join(f"{k} {v}" for k, v in m["node_types"].most_common()))


if __name__ == "__main__":
    main()
