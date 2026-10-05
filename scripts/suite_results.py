#!/usr/bin/env python3
"""Check saved runs of the on-target test suite (SHA-47, docs/on-target-tests.md).

`probe-rs run` prints embedded-test results in libtest format, one line per test case:

  test mldsa44_kat ... ok
  test policy_matrix_from_flash ... FAILED

(possibly behind a prefix, and with a module path such as `tests::mldsa44_kat`; the last
`::` segment is the test name). Save the output of each suite run as
docs/bench-logs/<board>-suite[-mldsa]-run{1,2,3}.txt.

Usage:
  python3 scripts/suite_results.py [--expect NAMES] LOG
      Prints one `name verdict` line per test of the log. Exits 1 if a test's verdict is
      not `ok`, or a name in --expect is missing.
  python3 scripts/suite_results.py --check-identical --expect NAMES LOG1 LOG2 [LOG3 ...]
      Checks that every log has every expected test (and no log has a test the others
      lack), that every test has the same verdict in every log and that every verdict is
      `ok`. Exits 1 if not. --expect is required: without it, a test missing from every
      run would go unnoticed.

NAMES is a comma-separated list of test names. Exits 1 on a log with no test lines or a
test listed twice in one log, and 2 on a usage error. The format is the one embedded-test
0.7.2 prints through probe-rs 0.32.0; validate it against the first real board log.
Standard library only.
"""

import argparse
import re
import sys
from pathlib import Path

TEST_RE = re.compile(r"\btest (\S+) \.\.\. (\S+)")


class SuiteError(Exception):
    """A check failed; the message says which log and test."""


def parse_log(path):
    """Returns {test name: verdict} for the libtest result lines of one log."""
    results = {}
    for lineno, line in enumerate(Path(path).read_text(errors="replace").splitlines(), 1):
        match = TEST_RE.search(line)
        if not match:
            continue
        name = match.group(1).split("::")[-1]
        verdict = match.group(2)
        if name in results:
            raise SuiteError(f"{path}:{lineno}: test {name} is listed twice")
        results[name] = verdict
    if not results:
        raise SuiteError(f"{path}: no test result lines (`test <name> ... <verdict>`)")
    return results


def check(paths, expect, identical):
    """Runs the checks; returns the lines to print, raises SuiteError on a failure."""
    runs = [(path, parse_log(path)) for path in paths]
    errors = []
    names = set(expect)
    for _, results in runs:
        names.update(results)
    for path, results in runs:
        for name in sorted(names):
            verdict = results.get(name)
            if verdict is None:
                if name in expect or identical:
                    errors.append(f"{path}: test {name} is missing")
            elif verdict != "ok":
                errors.append(f"{path}: test {name} ... {verdict} (expected ok)")
    if identical:
        for name in sorted(names):
            verdicts = {str(path): results[name] for path, results in runs if name in results}
            if len(set(verdicts.values())) > 1:
                detail = ", ".join(f"{p}: {v}" for p, v in verdicts.items())
                errors.append(f"test {name} differs between runs ({detail})")
    if errors:
        raise SuiteError("\n".join(errors))
    if identical:
        return [f"identical: {len(names)} tests ok in all {len(runs)} logs"]
    return [f"{name} {runs[0][1][name]}" for name in sorted(runs[0][1])]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check-identical", action="store_true",
                        help="compare two or more runs of the same suite")
    parser.add_argument("--expect", default="",
                        help="comma-separated test names every log must contain")
    parser.add_argument("logs", nargs="+")
    args = parser.parse_args(argv)
    expect = [name for name in args.expect.split(",") if name]
    if args.check_identical and len(args.logs) < 2:
        parser.error("--check-identical needs at least two logs")
    if args.check_identical and not expect:
        parser.error("--check-identical needs --expect with the suite's test names")
    if not args.check_identical and len(args.logs) != 1:
        parser.error("give one log, or --check-identical with two or more")
    try:
        for line in check(args.logs, expect, args.check_identical):
            print(line)
    except (SuiteError, OSError) as e:
        print(f"suite_results: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
