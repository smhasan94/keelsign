#!/usr/bin/env python3
"""Regenerate the ML-DSA known-answer fixtures in benches/mldsa-kat/fixtures/.

Downloads pinned upstream test vectors, checks their sha256, and writes the binary
fixtures read by the `mldsa-kat` crate plus MANIFEST.json. Never edit the fixtures by
hand; rerun this script instead (CLAUDE.md).

Sources:
  * NIST ACVP-Server, ML-DSA-sigVer-FIPS204 internalProjection.json: the groups with
    signatureInterface=external and preHash=pure (15 cases per parameter set).
  * C2SP Wycheproof, testvectors_v1/mldsa_{44,65}_verify_test.json: every case.

Outputs (per parameter set 44 and 65):
  * mldsa{44,65}-host.bin: every selected case (host KATs).
  * mldsa{44,65}-target.bin: all ACVP valid cases, the first invalid ACVP case for each
    distinct ACVP `reason`, and the Wycheproof advisory regression cases (on-target KATs).

Binary format (little-endian):
  header: b"KSMD", u16 param set (44 or 65), u16 case count
  per case: u32 tc_id, u8 source (0 = ACVP, 1 = Wycheproof), u8 expect_valid (0/1),
            u16 ctx_len, u32 msg_len, u16 pk_len, u16 sig_len,
            then ctx, msg, pk, sig bytes.

Usage:
  python3 scripts/gen_mldsa_vectors.py            # write the fixtures
  python3 scripts/gen_mldsa_vectors.py --check    # regenerate into a temp dir and diff

Standard library only.
"""

import argparse
import hashlib
import json
import struct
import sys
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "benches" / "mldsa-kat" / "fixtures"

MAGIC = b"KSMD"
SOURCE_ACVP = 0
SOURCE_WYCHEPROOF = 1

SOURCES = {
    "acvp": {
        "repo": "https://github.com/usnistgov/ACVP-Server",
        "tag": "v1.1.0.43",
        "commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
        "path": "gen-val/json-files/ML-DSA-sigVer-FIPS204/internalProjection.json",
        "sha256": "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
        "bytes": 4533178,
    },
    "wycheproof44": {
        "repo": "https://github.com/C2SP/wycheproof",
        "commit": "3fa63dd0344abb611f1fb1d77e119938603ea230",
        "path": "testvectors_v1/mldsa_44_verify_test.json",
        "sha256": "0ca1b5df4575263e29b31fae7569a3da41df9a3b6fee56720a992d0cd1153b68",
    },
    "wycheproof65": {
        "repo": "https://github.com/C2SP/wycheproof",
        "commit": "3fa63dd0344abb611f1fb1d77e119938603ea230",
        "path": "testvectors_v1/mldsa_65_verify_test.json",
        "sha256": "49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02",
    },
}

# Wycheproof regression cases for the ml-dsa advisories (CLAUDE.md pin):
#   CVE-2026-24850 / GHSA-5x2r-hc65-25f9: repeated hint indices accepted.
#   GHSA-h37v-hp6w-2pp8: use_hint off by two when r0 == 0.
ADVISORY_CASES = {
    44: {
        18: ("invalid", "signature with a repeated hint"),
        147: ("valid", "signature that calls use_hint(1, 0)"),
        148: ("invalid", "invalid signature that calls use_hint(1, 0)"),
    },
    65: {
        19: ("invalid", "signature with a repeated hint"),
        161: ("valid", "signature that calls use_hint(1, 0)"),
        162: ("invalid", "invalid signature that calls use_hint(1, 0)"),
    },
}

EXPECTED_COUNTS = {
    44: {"acvp": 15, "wycheproof": 180},
    65: {"acvp": 15, "wycheproof": 210},
}


def raw_url(source):
    owner_repo = source["repo"].removeprefix("https://github.com/")
    return f"https://raw.githubusercontent.com/{owner_repo}/{source['commit']}/{source['path']}"


def fetch(name):
    source = SOURCES[name]
    url = raw_url(source)
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != source["sha256"]:
        sys.exit(f"sha256 mismatch for {url}: got {digest}, expected {source['sha256']}")
    return data


def encode_case(tc_id, source, expect_valid, ctx, msg, pk, sig):
    header = struct.pack(
        "<IBBHIHH", tc_id, source, 1 if expect_valid else 0, len(ctx), len(msg), len(pk), len(sig)
    )
    return header + ctx + msg + pk + sig


def acvp_cases(acvp, param_set):
    groups = [
        g
        for g in acvp["testGroups"]
        if g["parameterSet"] == f"ML-DSA-{param_set}"
        and g["signatureInterface"] == "external"
        and g["preHash"] == "pure"
    ]
    if len(groups) != 1:
        sys.exit(f"expected one external/pure ACVP group for ML-DSA-{param_set}, got {len(groups)}")
    cases = []
    for t in sorted(groups[0]["tests"], key=lambda t: t["tcId"]):
        cases.append(
            {
                "tc_id": t["tcId"],
                "source": SOURCE_ACVP,
                "valid": bool(t["testPassed"]),
                "reason": t["reason"],
                "ctx": bytes.fromhex(t.get("context", "")),
                "msg": bytes.fromhex(t["message"]),
                "pk": bytes.fromhex(t["pk"]),
                "sig": bytes.fromhex(t["signature"]),
            }
        )
    return cases


def wycheproof_cases(wycheproof):
    cases = []
    for group in wycheproof["testGroups"]:
        pk = bytes.fromhex(group["publicKey"])
        for t in group["tests"]:
            if t["result"] not in ("valid", "invalid"):
                sys.exit(f"Wycheproof tcId {t['tcId']}: unexpected result {t['result']!r}")
            cases.append(
                {
                    "tc_id": t["tcId"],
                    "source": SOURCE_WYCHEPROOF,
                    "valid": t["result"] == "valid",
                    "comment": t["comment"],
                    "ctx": bytes.fromhex(t.get("ctx", "")),
                    "msg": bytes.fromhex(t["msg"]),
                    "pk": pk,
                    "sig": bytes.fromhex(t["sig"]),
                }
            )
    cases.sort(key=lambda c: c["tc_id"])
    return cases


def target_subset(param_set, acvp, wycheproof):
    selected = [c for c in acvp if c["valid"]]
    seen_reasons = set()
    for c in acvp:
        if not c["valid"] and c["reason"] not in seen_reasons:
            seen_reasons.add(c["reason"])
            selected.append(c)
    selected.sort(key=lambda c: c["tc_id"])
    by_id = {c["tc_id"]: c for c in wycheproof}
    for tc_id, (result, comment) in sorted(ADVISORY_CASES[param_set].items()):
        case = by_id.get(tc_id)
        if case is None or case["comment"] != comment or case["valid"] != (result == "valid"):
            sys.exit(f"Wycheproof ML-DSA-{param_set} tcId {tc_id} is not the advisory case {comment!r}")
        selected.append(case)
    return selected


def encode_fixture(param_set, cases):
    out = bytearray(MAGIC + struct.pack("<HH", param_set, len(cases)))
    for c in cases:
        out += encode_case(c["tc_id"], c["source"], c["valid"], c["ctx"], c["msg"], c["pk"], c["sig"])
    return bytes(out)


def case_ids(cases):
    return [
        {"source": "acvp" if c["source"] == SOURCE_ACVP else "wycheproof", "tc_id": c["tc_id"], "valid": c["valid"]}
        for c in cases
    ]


def generate(out_dir):
    acvp = json.loads(fetch("acvp"))
    wycheproof = {44: json.loads(fetch("wycheproof44")), 65: json.loads(fetch("wycheproof65"))}

    manifest = {
        "generator": "scripts/gen_mldsa_vectors.py",
        "format": "KSMD v1: see the module docstring of scripts/gen_mldsa_vectors.py",
        "sources": {
            name: {**source, "url": raw_url(source)} for name, source in sorted(SOURCES.items())
        },
        "outputs": {},
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    for param_set in (44, 65):
        acvp_set = acvp_cases(acvp, param_set)
        wp_set = wycheproof_cases(wycheproof[param_set])
        expected = EXPECTED_COUNTS[param_set]
        if len(acvp_set) != expected["acvp"] or len(wp_set) != expected["wycheproof"]:
            sys.exit(
                f"ML-DSA-{param_set}: got {len(acvp_set)} ACVP / {len(wp_set)} Wycheproof cases, "
                f"expected {expected['acvp']} / {expected['wycheproof']}"
            )
        sets = {
            "host": acvp_set + wp_set,
            "target": target_subset(param_set, acvp_set, wp_set),
        }
        for kind, cases in sets.items():
            name = f"mldsa{param_set}-{kind}.bin"
            data = encode_fixture(param_set, cases)
            (out_dir / name).write_bytes(data)
            manifest["outputs"][name] = {
                "param_set": param_set,
                "count": len(cases),
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "cases": case_ids(cases),
            }

    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def check():
    names = ["MANIFEST.json"] + [f"mldsa{p}-{k}.bin" for p in (44, 65) for k in ("host", "target")]
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        generate(tmp_dir)
        differ = [n for n in names if (tmp_dir / n).read_bytes() != (FIXTURE_DIR / n).read_bytes()]
    if differ:
        sys.exit(f"fixtures differ from a fresh regeneration: {', '.join(differ)}")
    print("fixtures match a fresh regeneration")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="regenerate into a temp dir and diff")
    args = parser.parse_args()
    if args.check:
        check()
    else:
        generate(FIXTURE_DIR)
        print(f"wrote fixtures to {FIXTURE_DIR.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
