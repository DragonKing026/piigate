"""Shadow comparison of the Bash gate and its syntax-tree twin (issue 340). Nothing here changes a decision.

Run: ulimit -v 4000000; timeout 600 python3 -I tests/shadow_compare.py [--json FILE] [--examples N]

1. The tests of tests/test_filter.py run with `Gate.bash` wrapped: every REAL call (command, files, cwd, configuration,
   fixtures as the test made them) is decided by `Gate` (the result goes back to the test unchanged) and, at once, by
   `AstGate` on the same configuration — for the `bash` and the `zsh` dialect. Calls made inside a hook subprocess
   (`hook("gate", …)`) do not pass the wrapper: the tool wraps the test's `hook()` function, takes the command from its
   input and decides it in this process with the configuration the hook would load.
2. Commands of tests/shell_corpus.py that no test call produced (non-templated ones; a templated command has no real
   paths) are decided with the configuration of `TestGate` (strict, cwd = the plugin directory).
3. The zsh cases of tests/shell_zsh_cases.py are decided in their throw-away world.

Category per command: same-allow, same-deny, OLD-DENY-NEW-ALLOW (a security risk), OLD-ALLOW-NEW-DENY (a new false
alarm), parse-error (AstGate refuses: shfmt cannot read the line — counted apart), adapter-error (a bug of the adapter).
Also the heuristic-by-heuristic comparison and the time of both gates. All data are synthetic (the tests').
"""

from __future__ import annotations

import io
import json
import os
import re
import statistics
import sys
import time
import unittest
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
sys.path.insert(0, str(HERE))

DIALECTS = ("bash", "zsh")
OPERATOR_LIKE = re.compile(r"[;&|()<>\n\x00]+|\d?[<>]+&?\d?|&>>?|<<-?")


def category(old: str | None, new: str | None, parse_error: str, adapter_error: str) -> str:
    if adapter_error:
        return "adapter-error"
    if parse_error:
        return "parse-error"
    if old is None and new is None:
        return "same-allow"
    if old is not None and new is not None:
        return "same-deny"
    return "OLD-DENY-NEW-ALLOW" if old is not None else "OLD-ALLOW-NEW-DENY"


class Recorder:
    def __init__(self, gate_module, shell_gate_module):
        self.gate = gate_module
        self.ast_cls = shell_gate_module.AstGate
        self.original = gate_module.Gate.bash
        self.records: list[dict] = []
        self.seen: dict[tuple, dict] = {}
        self.heuristics: dict[str, dict] = defaultdict(lambda: {"compared": 0, "differ": 0, "examples": []})
        self.times_old: list[float] = []
        self.times_new: dict[str, list[float]] = {d: [] for d in DIALECTS}
        self.test = ""
        self.hook_skipped = 0
        self.heuristic_seen: set[tuple] = set()

    # -- the wrapper
    def install(self) -> None:
        recorder = self

        def bash(gate_self, command, files=True):
            if isinstance(gate_self, recorder.ast_cls):
                return recorder.original(gate_self, command, files)
            start = time.perf_counter()
            result = recorder.original(gate_self, command, files)
            recorder.times_old.append((time.perf_counter() - start) * 1000)
            recorder.record(gate_self, command, files, result, "call")
            return result

        self.gate.Gate.bash = bash

    def uninstall(self) -> None:
        self.gate.Gate.bash = self.original

    # -- one command
    def new_decisions(self, cfg: dict, cwd: str, command: str, files: bool) -> dict[str, dict]:
        out = {}
        for dialect in DIALECTS:
            g = self.ast_cls(cfg, cwd, dialect)
            start = time.perf_counter()
            reason = g.bash(command, files)  # never raises: an unexpected exception is a denial with `internal_error`
            adapter_error = g.internal_error
            self.times_new[dialect].append((time.perf_counter() - start) * 1000)
            out[dialect] = {"reason": reason, "parse_error": g.parse_error, "adapter_error": adapter_error, "gate": g}
        return out

    def record(self, old_gate, command: str, files: bool, old_reason, source: str, expected: str | None = None) -> None:
        cfg, cwd = old_gate.cfg, old_gate.cwd
        key = (command, files, cwd, old_reason is None, source == "hook", config_key(cfg))
        if key in self.seen:
            self.seen[key]["count"] += 1
            return
        new = self.new_decisions(cfg, cwd, command, files)
        entry = {
            "command": command,
            "files": files,
            "cwd": cwd,
            "test": self.test,
            "source": source,
            "count": 1,
            "expected": expected,
            "old": "allow" if old_reason is None else "deny",
            "old_reason": (old_reason or "")[:200],
        }
        for d in DIALECTS:
            n = new[d]
            entry[d] = {
                "decision": "allow" if n["reason"] is None else "deny",
                "reason": (n["reason"] or "")[:200],
                "category": category(old_reason, n["reason"], n["parse_error"], n["adapter_error"]),
                "parse_error": n["parse_error"],
                "adapter_error": n["adapter_error"],
            }
        self.seen[key] = entry
        self.records.append(entry)
        self.compare_heuristics(old_gate, new["bash"]["gate"], command)

    # -- hook subprocess calls
    def record_hook(self, data: dict, env: dict | None, result) -> None:
        if data.get("tool_name") != "Bash" or data.get("hook_event_name") != "PreToolUse":
            return
        from piigate import config

        command = (data.get("tool_input") or {}).get("command") or ""
        cwd = data.get("cwd", "")
        saved = {k: os.environ.get(k) for k in (env or {})}
        os.environ.update(env or {})
        try:
            cfg = config.load(cwd or None)
            g = self.gate.Gate(cfg, cwd)
            reason = self.original(g, command, True)
        except Exception:  # the test broke the configuration on purpose (test_bad_config): the hook denied, nothing to compare
            self.hook_skipped += 1
            return
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        hook_denied = bool(result and result.get("hookSpecificOutput", {}).get("permissionDecision") == "deny")
        self.record(g, command, True, reason, "hook")
        if hook_denied != (reason is not None):
            self.seen[(command, True, g.cwd, reason is None, True, config_key(cfg))]["hook_mismatch"] = True

    # -- heuristics, one by one
    def note(self, name: str, differ: bool, example: dict) -> None:
        h = self.heuristics[name]
        h["compared"] += 1
        if differ:
            h["differ"] += 1
            if len(h["examples"]) < 6:
                h["examples"].append(example)

    def compare_heuristics(self, old, new, command: str) -> None:
        key = (command, old.cwd)
        if key in self.heuristic_seen:
            return
        self.heuristic_seen.add(key)
        G = self.gate.Gate
        parsed = new._cache.get(command)
        if parsed is None:
            return  # the tree could not be parsed: nothing to compare
        old_tokens = G._tokens(command)

        def words(tokens):
            return sorted(str(t) for t in tokens if not OPERATOR_LIKE.fullmatch(str(t)))

        if old_tokens is None:
            self.note("_tokens", True, {"command": command[:120], "old": None, "new": words(parsed.tokens)[:12]})
            return
        a, b = words(old_tokens), words(parsed.tokens)
        self.note("_tokens (words)", a != b, {"command": command[:120], "old_only": sorted(set(a) - set(b))[:6], "new_only": sorted(set(b) - set(a))[:6]})
        # quoting flags of the words both sides have
        qa = sorted((str(t), getattr(t, "quote", "")) for t in old_tokens if getattr(t, "quote", ""))
        qb = sorted((str(t), getattr(t, "quote", "")) for t in parsed.tokens if getattr(t, "quote", ""))
        self.note("QuotedToken.quote", qa != qb, {"command": command[:120], "old": qa[:5], "new": qb[:5]})

        def stages(tokens):
            return [[str(t) for t in s if not OPERATOR_LIKE.fullmatch(str(t))] for s in G._stages_loose(tokens)]

        sa, sb = [s for s in stages(old_tokens) if s], [s for s in stages(parsed.tokens) if s]
        self.note("_stages_loose", sa != sb, {"command": command[:120], "old": sa[:4], "new": sb[:4]})
        # directories
        old_dirs = G._stage_dirs(old, command, old_tokens)
        new_dirs = new._stage_dirs(command, parsed.tokens)
        ua = sorted({d for ds in old_dirs for d in ds})
        ub = sorted({d for ds in new_dirs for d in ds})
        self.note("_stage_dirs (union of directories)", ua != ub, {"command": command[:120], "old": ua[:5], "new": ub[:5]})
        if len(old_dirs) == len(new_dirs):
            per = [sorted(x) != sorted(y) for x, y in zip(old_dirs, new_dirs)]
            self.note("_stage_dirs (per stage, same stage count)", any(per), {"command": command[:120], "old": old_dirs[:4], "new": new_dirs[:4]})
        # substitutions: how many the shell runs
        old_subs = G._substitutions(command)
        direct = sum(1 for c in shell_toplevel(parsed.calls) for s in c.substitutions if s.origin in ("$(", "`", "<(", ">("))
        self.note("_substitutions (count)", len(old_subs) != direct, {"command": command[:120], "old": [x[:40] for x in old_subs[:4]], "new": direct})
        # heredocs
        if "<<" in command:
            text = G._strip_file_heredocs(command)
            old_stripped = text != command
            new_stripped = any(b.stripped for b in parsed.bodies)
            self.note("_strip_file_heredocs (a body dropped)", old_stripped != new_stripped, {"command": command[:120], "old": old_stripped, "new": new_stripped})
            old_lit = old._heredoc_text(text)[1]
            new_lit = new._heredoc_text(parsed.view)[1]
            self.note("_heredoc_text (literal words)", old_lit != new_lit, {"command": command[:120], "old": sorted(old_lit)[:5], "new": sorted(new_lit)[:5]})
        # programs run
        names = {"piigate"}
        old_inv = old._invocations(command, names)
        new_inv = new._invocations(command, names)
        self.note(
            "_invocations(piigate)",
            [None if x is None else list(map(str, x)) for x in old_inv] != [None if x is None else list(map(str, x)) for x in new_inv],
            {"command": command[:120], "old": old_inv[:3], "new": new_inv[:3]},
        )


def config_key(cfg: dict) -> str:
    """The configuration is part of what a decision depends on: the same line under another one is another record."""
    import hashlib

    return hashlib.sha256(json.dumps(cfg, sort_keys=True, default=str).encode()).hexdigest()[:12]


def shell_toplevel(calls):
    from piigate import shell

    return shell._toplevel(calls)


def stat(times: list[float]) -> dict:
    if not times:
        return {"n": 0}
    s = sorted(times)
    return {"n": len(s), "median_ms": round(statistics.median(s), 2), "p95_ms": round(s[int(len(s) * 0.95) - 1], 2), "max_ms": round(s[-1], 2)}


def main() -> None:
    args = sys.argv[1:]
    out_path = args[args.index("--json") + 1] if "--json" in args else None
    n_examples = int(args[args.index("--examples") + 1]) if "--examples" in args else 40

    import test_filter  # noqa: E402  (sets the test environment on import)
    from piigate import gate, shell_gate

    rec = Recorder(gate, shell_gate)
    rec.install()
    real_hook = test_filter.hook

    class Names(unittest.TextTestResult):
        def startTest(self, test):
            rec.test = test.id().split(".", 1)[-1]
            super().startTest(test)

    def hook(mode, data, env=None):
        result = real_hook(mode, data, env)
        if mode == "gate":
            rec.test = rec.test or "hook"
            rec.record_hook(data, env, result)
        return result

    test_filter.hook = hook
    suite = unittest.defaultTestLoader.loadTestsFromModule(test_filter)
    stream = io.StringIO()
    run = unittest.TextTestRunner(stream=stream, verbosity=0, resultclass=Names).run(suite)
    test_filter.hook = real_hook
    tests_summary = {"ran": run.testsRun, "failures": len(run.failures), "errors": len(run.errors), "skipped": len(run.skipped),
        "problems": [f"{t.id().split('.', 1)[-1]}: {tb.strip().splitlines()[-1][:160]}" for t, tb in run.errors + run.failures]}
    from_calls = len(rec.records)

    # corpus commands that no test call produced
    import shell_corpus

    cases = shell_corpus.extract()
    caught = {r["command"] for r in rec.records}
    expected_of: dict[str, set[str]] = defaultdict(set)
    for c in cases:
        expected_of[c.command].add(c.expected)
    templated_skipped = 0
    added = 0
    base = gate.Gate(test_filter.STRICT, str(test_filter.ROOT))
    for c in cases:
        if c.command in caught:
            continue
        if c.templated:
            templated_skipped += 1
            continue
        rec.test = f"corpus:{c.test}:{c.line}"
        result = rec.original(base, c.command, True)
        rec.record(base, c.command, True, result, "corpus", c.expected)
        added += 1
    rec.uninstall()
    for r in rec.records:  # the expectation of a test, when the command is a corpus command
        if r["expected"] is None:
            exp = expected_of.get(r["command"])
            if exp and len(exp) == 1:
                r["expected"] = next(iter(exp))

    # zsh cases
    import shell_zsh_cases

    world = shell_zsh_cases.World()
    zsh_rows = []
    try:
        for case in shell_zsh_cases.CASES:
            world.reset()
            g = world.gate()
            old_reason = rec.original(g, case.command, True)
            row = {"name": case.name, "command": case.command, "what": case.what, "old": "allow" if old_reason is None else "deny"}
            real = world.real(case.command)
            real_cc = world.real(case.command, "cc")
            row["signals"] = {m: r["signal"] for m, r in (("f", real), ("cc", real_cc)) if r.get("signal")}
            row["real_reads"] = bool(real.get("reads"))
            row["real_cc_reads"] = bool(real_cc.get("reads"))
            row["real_runs_code"] = bool(real.get("runs"))
            for d in DIALECTS:
                n = rec.new_decisions(g.cfg, g.cwd, case.command, True)[d]
                row[d] = {
                    "decision": "allow" if n["reason"] is None else "deny",
                    "category": category(old_reason, n["reason"], n["parse_error"], n["adapter_error"]),
                    "parse_error": n["parse_error"],
                }
            reads = row["real_reads"] or row["real_cc_reads"]
            row["old_hole"] = old_reason is None and reads
            for d in DIALECTS:
                row[d]["new_hole"] = row[d]["decision"] == "allow" and reads
            zsh_rows.append(row)
    finally:
        world.close()

    import shell_adversarial

    world2 = shell_zsh_cases.World()
    try:
        adv_rows = shell_adversarial.measure(world2)
    finally:
        world2.close()
    adversarial = {
        "cases": len(adv_rows),
        "categories": {d: dict(Counter(r[d]["category"] for r in adv_rows)) for d in DIALECTS},
        "real_reads_and_old_allows": [r["name"] for r in adv_rows if r["old_hole"]],
        "real_reads_and_new_allows": {
            d: [{"name": r["name"], "section": r["section"], "why": r["known"] or "UNEXPLAINED"} for r in shell_adversarial.holes(adv_rows, d)]
            for d in DIALECTS
        },
        "unexplained": {d: [r["name"] for r in shell_adversarial.unexplained(adv_rows, d)] for d in DIALECTS},
        "benign_new_denies": {
            d: [r["command"][:90] for r in adv_rows if r["section"] == "B" and r["old"] == "allow" and r[d]["decision"] == "deny"]
            for d in DIALECTS
        },
        "benign_cases": sum(r["section"] == "B" for r in adv_rows),
        "piigate_expectation_broken": [
            r["name"] for r in adv_rows if r["expect"] and any(r[d]["decision"] != r["expect"] for d in DIALECTS)
        ],
        "old_deny_new_allow": [r["name"] for r in adv_rows if any(r[d]["category"] == "OLD-DENY-NEW-ALLOW" for d in DIALECTS)],
        "old_deny_new_allow_real_read": [
            r["name"] for r in adv_rows if r["real_any"] and any(r[d]["category"] == "OLD-DENY-NEW-ALLOW" for d in DIALECTS)
        ],
        "old_deny_new_allow_no_read": [
            r["name"] for r in adv_rows if not r["real_any"] and any(r[d]["category"] == "OLD-DENY-NEW-ALLOW" for d in DIALECTS)
        ],
        "rows": adv_rows,
    }
    report = {
        "tests": tests_summary,
        "adversarial": adversarial,
        "commands": {"from_test_calls": from_calls, "added_from_corpus": added, "corpus_templated_skipped": templated_skipped, "total": len(rec.records)},
        "calls_total": sum(r["count"] for r in rec.records),
        "by_source": dict(Counter(r["source"] for r in rec.records)),
        "hook_calls_skipped_broken_config": rec.hook_skipped,
        "hook_mismatch": [r["command"][:100] for r in rec.records if r.get("hook_mismatch")],
        "categories": {d: dict(Counter(r[d]["category"] for r in rec.records)) for d in DIALECTS},
        "expected": {},
        "heuristics": {k: v for k, v in sorted(rec.heuristics.items())},
        "time": {"Gate.bash": stat(rec.times_old), **{f"AstGate.bash[{d}]": stat(rec.times_new[d]) for d in DIALECTS}},
        "discrepancies": {d: [r for r in rec.records if r[d]["category"] not in ("same-allow", "same-deny")] for d in DIALECTS},
        "zsh_cases": zsh_rows,
        "records": rec.records,
    }
    for d in DIALECTS:
        known = [r for r in rec.records if r["expected"] in ("allow", "deny")]
        report["expected"][d] = {
            "with_expectation": len(known),
            "old_disagrees": sum(r["old"] != r["expected"] for r in known),
            "new_disagrees": sum(r[d]["decision"] != r["expected"] for r in known if r[d]["category"] != "parse-error"),
            "new_parse_error": sum(r[d]["category"] == "parse-error" for r in known),
        }
    if out_path:
        Path(out_path).write_text(json.dumps(report, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    print_report(report, n_examples)
    if any(r["signals"] for r in report["adversarial"]["rows"]) or any(r.get("signals") for r in report["zsh_cases"]):
        sys.exit(1)


def print_report(report: dict, n_examples: int) -> None:
    print("tests:", report["tests"])
    print("commands:", report["commands"], "| calls:", report["calls_total"], "| by source:", report["by_source"])
    if report["hook_mismatch"]:
        print("hook result differs from the in-process gate for:", report["hook_mismatch"])
    cats = ["same-allow", "same-deny", "OLD-DENY-NEW-ALLOW", "OLD-ALLOW-NEW-DENY", "parse-error", "adapter-error"]
    print(f"\n{'category':22}" + "".join(f"{d:>8}" for d in DIALECTS))
    for c in cats:
        print(f"{c:22}" + "".join(f"{report['categories'][d].get(c, 0):>8}" for d in DIALECTS))
    print("\nagainst the expectation of the test:")
    for d in DIALECTS:
        print(" ", d, report["expected"][d])
    print("\ntime:", json.dumps(report["time"]))
    print("\nheuristics (differing / compared):")
    for k, v in report["heuristics"].items():
        print(f"  {k:46} {v['differ']:>4} / {v['compared']}")
    for d in DIALECTS:
        print(f"\ndiscrepancies [{d}] (first {n_examples}):")
        for r in report["discrepancies"][d][:n_examples]:
            print(f"  [{r[d]['category']}] {r['test']}: {r['command'][:110]!r}")
            print(f"      old: {r['old']} {r['old_reason'][:80]!r} | new: {r[d]['decision']} {(r[d]['parse_error'] or r[d]['adapter_error'] or r[d]['reason'])[:80]!r} | expected {r['expected']}")
    bad = [r["name"] for r in report["adversarial"]["rows"] if r["signals"]] + [
        r["name"] for r in report["zsh_cases"] if r.get("signals")
    ]
    if bad:
        print("MEASUREMENT FAILED: a real shell died of a signal in", bad)
    adv = report["adversarial"]
    print(f"\nadversarial corpus: {adv['cases']} cases; categories:", adv["categories"])
    print("  a real shell reads and the OLD gate allows:", adv["real_reads_and_old_allows"])
    for d in DIALECTS:
        print(f"  a real shell reads and the AST gate ({d}) allows:")
        for h in adv["real_reads_and_new_allows"][d]:
            print(f"    {h['section']} {h['name']}: {h['why']}")
    for d in DIALECTS:
        print(f"  benign lines (B) the old gate allows and the AST gate denies [{d}] ({len(adv['benign_new_denies'][d])}/{adv['benign_cases']}):")
        for c in adv["benign_new_denies"][d]:
            print("    ", repr(c))
    print(
        f"  OLD-DENY-NEW-ALLOW with a real read: {len(adv['old_deny_new_allow_real_read'])} {adv['old_deny_new_allow_real_read']}; "
        f"without: {len(adv['old_deny_new_allow_no_read'])} {adv['old_deny_new_allow_no_read']}"
    )
    print("  OLD-DENY-NEW-ALLOW:", adv["old_deny_new_allow"], "| piigate expectation broken:", adv["piigate_expectation_broken"])
    print("\nzsh cases: old / bash-AST / zsh-AST / real zsh -f / real Claude Code shell")
    for row in report["zsh_cases"]:
        mark = "  <== OLD ALLOWS A READ" if row["old_hole"] else ""
        mark += "  <== bash-AST allows" if row["bash"]["new_hole"] else ""
        mark += "  <== zsh-AST allows" if row["zsh"]["new_hole"] else ""
        print(f"  {row['name']:32} {row['old']:5} {row['bash']['category']:20} {row['zsh']['category']:20} f={row['real_reads']!s:5} cc={row['real_cc_reads']!s:5}{mark}")


if __name__ == "__main__":
    main()
