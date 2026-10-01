#!/usr/bin/env python3
"""Check that fuzz coverage reaches every TLV-type branch and every error variant (SHA-39 TP2).

Reads the text report of `llvm-cov show` (written by `scripts/fuzz.sh coverage` to
fuzz/coverage/parse_image/coverage.txt, from `cargo fuzz coverage` over the committed
corpus) and asserts an execution count above zero on:

  * every arm of `TlvKind::of` in keelsign-verify/src/image.rs (one line per TLV kind,
    `CONST => TlvKind::Variant`): every TLV-type branch of the parser;
  * every line of fuzz/src/lib.rs with a `// cov:` marker: the arms of the harness's
    `cov` functions, one per TlvKind, per ParseError variant, and Error::Parse and
    Error::TlvAreaTooLarge from Image::read_from.

Usage:
  python3 scripts/fuzz_coverage_check.py fuzz/coverage/parse_image/coverage.txt
  python3 scripts/fuzz_coverage_check.py --self-test

Standard library only.
"""

import argparse
import re
import sys

IMAGE_RS = "keelsign-verify/src/image.rs"
LIB_RS = "fuzz/src/lib.rs"
TLV_KIND_ARMS = 19
# The cov markers fuzz/src/lib.rs must carry: 19 TlvKind arms, 8 ParseError variants,
# Error::Parse and Error::TlvAreaTooLarge.
REQUIRED_MARKERS = 29
ERROR_MARKERS = [
    "ParseError::BadMagic",
    "ParseError::Truncated",
    "ParseError::HeaderTooSmall",
    "ParseError::SizeOverflow",
    "ParseError::BadTlvInfoMagic",
    "ParseError::ProtectedSizeMismatch",
    "ParseError::LengthMismatch",
    "ParseError::PqSignatureTooLong",
    "Error::Parse",
    "Error::TlvAreaTooLarge",
]

# `  487|  1.23k|    IMAGE_TLV_KEYHASH => TlvKind::KeyHash,` (count empty on non-code lines).
LINE = re.compile(r"^\s*(\d+)\|\s*([0-9.]+[kMGTE]?)?\|(.*)$")
MARKER = re.compile(r"=>.*//\s*cov:\s*(\S+)")
TLV_ARM = re.compile(r"=>\s*TlvKind::")


def parse_count(text):
    """An llvm-cov count (`0`, `12`, `1.23k`, `4.5M`) as a number, or None (no code)."""
    if not text:
        return None
    scale = {"k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "E": 1e18}
    if text[-1] in scale:
        return float(text[:-1]) * scale[text[-1]]
    return float(text)


def show(count):
    """A count for the output: `116`, `1500`, or `no code` (None)."""
    return "no code" if count is None else f"{count:g}"


def files(report):
    """{source path: [(line number, count or None, code)]} of an llvm-cov text report."""
    out, current = {}, None
    for raw in report.splitlines():
        m = LINE.match(raw)
        if m:
            if current is not None:
                out[current].append((int(m.group(1)), parse_count(m.group(2)), m.group(3)))
        elif raw.endswith(":") and not raw[:1].isspace() and "|" not in raw:
            current = raw[:-1]
            out[current] = []
    return out


def find(sources, suffix):
    matches = [path for path in sources if path.replace("\\", "/").endswith(suffix)]
    if len(matches) != 1:
        return None
    return sources[matches[0]]


def check(report):
    """(ok lines, problems) for an llvm-cov text report."""
    sources = files(report)
    ok, problems = [], []

    image = find(sources, IMAGE_RS)
    if image is None:
        problems.append(f"{IMAGE_RS}: not in the report (exactly once)")
    else:
        start = next((i for i, (_, _, code) in enumerate(image) if "pub fn of(tlv_type: u16) -> TlvKind" in code), None)
        if start is None:
            problems.append(f"{IMAGE_RS}: no `pub fn of(tlv_type: u16) -> TlvKind`")
        else:
            arms = []
            for number, count, code in image[start + 1 :]:
                if code.strip() == "}" and code.startswith("    }") and not code.startswith("        "):
                    break
                if TLV_ARM.search(code):
                    arms.append((number, count, code.strip()))
            if len(arms) != TLV_KIND_ARMS:
                problems.append(f"{IMAGE_RS}: TlvKind::of has {len(arms)} arms, expected {TLV_KIND_ARMS}")
            for number, count, code in arms:
                line = f"{IMAGE_RS}:{number}  {code}  count {show(count)}"
                (ok if count else problems).append(line)

    lib = find(sources, LIB_RS)
    if lib is None:
        problems.append(f"{LIB_RS}: not in the report (exactly once)")
    else:
        markers = [(number, count, MARKER.search(code).group(1)) for number, count, code in lib if MARKER.search(code)]
        names = [name for _, _, name in markers]
        if len(markers) != REQUIRED_MARKERS:
            problems.append(f"{LIB_RS}: {len(markers)} cov markers, expected {REQUIRED_MARKERS}")
        for name in ERROR_MARKERS:
            if name not in names:
                problems.append(f"{LIB_RS}: no cov marker {name}")
        for number, count, name in markers:
            line = f"{LIB_RS}:{number}  cov: {name}  count {show(count)}"
            (ok if count else problems).append(line)
    return ok, problems


def self_test():
    """The checker on hand-written reports: a fully covered one passes; a zero count, a
    missing arm or a missing file fails."""
    assert parse_count("") is None
    assert parse_count("0") == 0
    assert parse_count("12") == 12
    assert parse_count("1.50k") == 1500
    assert parse_count("2M") == 2e6

    kinds = [
        "KeyHash", "PubKey", "Sha256", "Sha384", "Sha512", "Rsa2048Pss", "EcdsaSig", "Rsa3072Pss",
        "Ed25519", "SigPure", "Dependency", "SecCnt", "BootRecord", "KeelsignKeyId", "MlDsa44Sig",
        "MlDsa65Sig", "LmsHssSig",
    ]

    def report(image_counts, lib_counts, with_lib=True):
        lines = ["/repo/keelsign-verify/src/image.rs:", "  486|      |    /// The kind of TLV type `tlv_type`.",
                 "  487|   10|    pub fn of(tlv_type: u16) -> TlvKind {", "  488|   10|        match tlv_type {"]
        n = 489
        arms = [f"C{i} => TlvKind::{k}," for i, k in enumerate(kinds)]
        arms += ["t if KEELSIGN_TLV_RANGE.contains(&t) => TlvKind::KeelsignReserved(t),", "t => TlvKind::Unknown(t),"]
        for arm, count in zip(arms, image_counts):
            lines.append(f"{n:>5}|{count:>6}|            {arm}")
            n += 1
        lines += [f"{n:>5}|      |        }}", f"{n + 1:>5}|   10|    }}", f"{n + 2:>5}|      |}}",
                  f"{n + 3:>5}|     0|fn other() -> TlvKind {{ X => TlvKind::KeyHash }}"]
        if with_lib:
            lines.append("/repo/fuzz/src/lib.rs:")
            markers = [f"TlvKind::{k}" for k in kinds + ["KeelsignReserved", "Unknown"]] + ERROR_MARKERS
            lines.append("    1|      |//! a doc line about the `// cov:` markers")
            for i, (name, count) in enumerate(zip(markers, lib_counts)):
                lines.append(f"{i + 2:>5}|{count:>6}|            X{i} => {i}, // cov: {name}")
        return "\n".join(lines) + "\n"

    full = report(["3"] * 19, ["1.2k"] * 29)
    ok, problems = check(full)
    assert not problems and len(ok) == 19 + 29, problems

    zero_arm = report(["3"] * 18 + ["0"], ["1"] * 29)
    _, problems = check(zero_arm)
    assert len(problems) == 1 and "TlvKind::Unknown" in problems[0], problems

    zero_marker = report(["3"] * 19, ["1"] * 28 + ["0"])
    _, problems = check(zero_marker)
    assert len(problems) == 1 and "Error::TlvAreaTooLarge" in problems[0], problems

    missing_arm = report(["3"] * 18, ["1"] * 29)
    _, problems = check(missing_arm)
    assert any("18 arms" in p for p in problems), problems

    missing_marker = report(["3"] * 19, ["1"] * 28)
    _, problems = check(missing_marker)
    assert any("28 cov markers" in p for p in problems) and any("no cov marker Error::TlvAreaTooLarge" in p for p in problems), problems

    no_code = report(["3"] * 18 + [""], ["1"] * 29)
    _, problems = check(no_code)
    assert len(problems) == 1 and "no code" in problems[0], problems

    no_lib = report(["3"] * 19, [], with_lib=False)
    _, problems = check(no_lib)
    assert any("fuzz/src/lib.rs: not in the report" in p for p in problems), problems

    print("fuzz_coverage_check self-test: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("report", nargs="?", help="llvm-cov show text output")
    parser.add_argument("--self-test", action="store_true", help="test the checker itself")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if not args.report:
        parser.error("give the coverage report, or --self-test")
    with open(args.report, encoding="utf-8") as f:
        ok, problems = check(f.read())
    for line in ok:
        print(f"ok    {line}")
    for line in problems:
        print(f"MISS  {line}")
    if problems:
        sys.exit(f"fuzz coverage: {len(problems)} problem(s); every TLV-type branch and error variant must be reached")
    print(f"fuzz coverage: all {TLV_KIND_ARMS} TlvKind::of arms and {REQUIRED_MARKERS} cov markers reached")


if __name__ == "__main__":
    main()
