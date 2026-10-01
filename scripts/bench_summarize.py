#!/usr/bin/env python3
"""Summarise the `BENCH …` lines of saved on-target benchmark logs (SHA-34, SHA-65).

The `*_bench` tests in benches/<board>-mldsa/tests/{kat,lms}.rs log one line per case:

  BENCH board=nrf52840 set=ML-DSA-44 src=wycheproof tc=147 msg_len=11 expect_valid=true
        ok=true cycles=… us=… peak_stack=… saturated=false

(on one line, usually behind a defmt timestamp / level prefix). Save the `probe-rs` output
of each run as docs/bench-logs/<board>-run{1,2,3}.txt (docs/benchmarks.md).

Usage:
  python3 scripts/bench_summarize.py LOG [LOG ...]
      Prints one markdown results row per (board, set): the headline case is the
      shortest-message Wycheproof valid case, or for a set without Wycheproof cases
      (LMS/HSS) the shortest-message valid case; also the slowest case and the deepest
      stack.
  python3 scripts/bench_summarize.py --check-consistency 0.05 LOG1 LOG2 LOG3
      Checks that every case appears in every log and that its cycles and peak_stack
      vary by at most the given fraction (max / min - 1) across the logs. Exits 1 if not.

Exits 1 on a log with no BENCH lines, a failed case (ok=false) or a saturated watermark.
Standard library only.
"""

import argparse
import re
import sys
from pathlib import Path

BENCH_RE = re.compile(r"BENCH((?:\s+\w+=\S+)+)")
FIELD_RE = re.compile(r"(\w+)=(\S+)")
INT_FIELDS = ("tc", "msg_len", "cycles", "us", "peak_stack")
REQUIRED = ("board", "set", "src", "tc", "msg_len", "expect_valid", "ok", "cycles", "peak_stack", "saturated")


def parse_log(path):
    """Returns {(board, set, src, tc): record} for the BENCH lines of one log."""
    records = {}
    for lineno, line in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        m = BENCH_RE.search(line)
        if not m:
            continue
        rec = dict(FIELD_RE.findall(m.group(1)))
        missing = [f for f in REQUIRED if f not in rec]
        if missing:
            raise ValueError(f"{path}:{lineno}: BENCH line lacks {', '.join(missing)}")
        for f in INT_FIELDS:
            if f in rec:
                rec[f] = int(rec[f])
        for f in ("expect_valid", "ok", "saturated"):
            rec[f] = rec[f] == "true"
        if not rec["ok"]:
            raise ValueError(f"{path}:{lineno}: case {rec['set']} {rec['src']} tc={rec['tc']} failed its KAT")
        if rec["saturated"]:
            raise ValueError(f"{path}:{lineno}: case tc={rec['tc']} saturated the painted stack")
        records[(rec["board"], rec["set"], rec["src"], rec["tc"])] = rec
    if not records:
        raise ValueError(f"{path}: no BENCH lines")
    return records


def summary_rows(records):
    groups = {}
    for (board, pset, _src, _tc), rec in records.items():
        groups.setdefault((board, pset), []).append(rec)
    rows = []
    for (board, pset), recs in sorted(groups.items()):
        # Headline: the shortest-message Wycheproof valid case (ML-DSA, SHA-34); a set
        # without Wycheproof cases (LMS/HSS, SHA-65) uses its shortest-message valid case.
        valid = [r for r in recs if r["expect_valid"]]
        candidates = [r for r in valid if r["src"] == "wycheproof"] or valid
        if not candidates:
            raise ValueError(f"{board} {pset}: no valid case for the headline")
        head = min(candidates, key=lambda r: (r["msg_len"], r["tc"]))
        slowest = max(recs, key=lambda r: r["cycles"])
        deepest = max(r["peak_stack"] for r in recs)
        rows.append(
            f"| {board} | {pset} | {head['cycles']} (tc {head['tc']}, {head['msg_len']} B msg) "
            f"| {head.get('us', 0) / 1000:.2f} ms | {head['peak_stack']} B | {deepest} B "
            f"| {slowest['cycles']} (tc {slowest['tc']}, {slowest['msg_len']} B msg) | {len(recs)} |"
        )
    return rows


def check_consistency(runs, tolerance):
    problems = []
    keys = set(runs[0])
    for i, run in enumerate(runs[1:], 2):
        if set(run) != keys:
            problems.append(f"log {i} has a different set of cases than log 1")
    for key in sorted(keys, key=str):
        for field in ("cycles", "peak_stack"):
            values = [run[key][field] for run in runs if key in run]
            low, high = min(values), max(values)
            spread = (high / low - 1) if low else (0 if high == 0 else float("inf"))
            if spread > tolerance:
                problems.append(f"{' '.join(map(str, key))}: {field} {values} spread {spread:.1%} > {tolerance:.1%}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("logs", nargs="+", metavar="LOG")
    parser.add_argument("--check-consistency", type=float, metavar="FRACTION")
    args = parser.parse_args()

    try:
        runs = [parse_log(log) for log in args.logs]
    except (OSError, ValueError) as e:
        sys.exit(f"bench_summarize: {e}")

    if args.check_consistency is not None:
        if len(runs) < 2:
            sys.exit("bench_summarize: --check-consistency needs at least two logs")
        problems = check_consistency(runs, args.check_consistency)
        if problems:
            print("\n".join(problems), file=sys.stderr)
            sys.exit(f"bench_summarize: {len(problems)} consistency problem(s)")
        print(f"consistent: {len(runs[0])} cases within {args.check_consistency:.1%} across {len(runs)} logs")

    merged = {}
    for run in runs:
        merged.update(run)
    print("| Board | Set | Headline cycles | Headline time | Headline peak stack | Deepest peak stack | Slowest case cycles | Cases |")
    print("|---|---|---|---|---|---|---|---|")
    try:
        print("\n".join(summary_rows(merged)))
    except ValueError as e:
        sys.exit(f"bench_summarize: {e}")


if __name__ == "__main__":
    main()
