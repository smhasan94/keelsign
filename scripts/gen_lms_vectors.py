#!/usr/bin/env python3
"""Regenerate the LMS/HSS known-answer fixtures in benches/lms-kat/fixtures/.

Downloads pinned sources, checks their sha256, and writes the binary fixtures read by
the `lms-kat` crate plus MANIFEST.json. Never edit the fixtures by hand; rerun this script
instead (CLAUDE.md).

Sources:
  * RFC 8554 (text), Appendix F: Test Case 1 (HSS L=2, both levels LMS_SHA256_M32_H5 /
    LMOTS_SHA256_N32_W8) and Test Case 2 (L=2, top LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4,
    bottom LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8).
  * NIST ACVP-Server LMS sigVer, revisions SP800-208 and 1.0, internalProjection.json:
    every case (2 groups x 4 cases each: LMS_SHA256_M24_H5 / LMOTS_SHA256_N24_W1 and
    LMS_SHA256_M24_H10 / LMOTS_SHA256_N24_W2). These are single LMS trees; they are
    wrapped as HSS with one level (key u32str(1) || LMS key, signature u32str(0) || LMS
    signature, RFC 8554 section 6).
  * hsslms 0.1.3 (PyPI sdist), an independent pure-Python RFC 8554 / SP 800-208 signer.
    Only src/hsslms/{utils,lmots,lms,hss}.py are extracted into a temporary package with
    an empty __init__.py and imported from there; nothing is pip-installed. Its random
    source (`token_bytes` in lmots and lms) is replaced by a per-case SHA-256 counter
    DRBG so the output is deterministic. No NIST vectors exist for SHA-256/192 with W8 or
    for HSS with more than one level, so these cases are the accepted-set evidence for
    SHA-256/192 and HSS/W8 besides RFC 8554 Test Case 1.

Signed cases (all over one fixed 32-byte message):
  * M32/W8: H5 L1, H5+H5 L2, H10 L1, H5+H10 L2; M24/W8: H5 L1, H5+H5 L2, H10 L1.
  * Rotation keys A and B (M32/W8 H5 L1, two seeds).
  * Outside the keelsign device policies: M32/W4 H5 L1, M24/W2 H5 L1, HSS L=3 (M32/W8 H5 x 3).

Derived negatives (from RFC 8554 Test Case 1): last byte flipped, C of the bottom
LM-OTS signature flipped, bottom and top q flipped, truncated at every 97th byte, one
trailing byte, and the key patched to L = 3. From hsslms case 302 (M32/W8 H5+H5, L=2):
the bottom-level q set to exactly 2^h (RFC 8554 Algorithm 6a step 2i), and only the
bottom-level LM-OTS typecode inside the signature changed from LMOTS_SHA256_N32_W8 to
LMOTS_SHA256_N24_W8 (step 2c). The signature is parsed with the lengths of the public key
it is checked against, never with its own typecodes, so that case keeps every length,
passes the parameter gate (which covers public keys only) and reaches the typecode check;
the typecode bytes are not hashed, so without the check it would verify.

Outputs:
  * lms-host.bin: every case (host KATs).
  * lms-target.bin: the on-target subset (TARGET_IDS).

Binary format "KSLM v2" (little-endian lengths):
  header:   b"KSLM", u16 version (2), u16 case count
  per case: u16 id, u8 source (0 = rfc8554, 1 = acvp, 2 = hsslms),
            u8 expect_default, u8 expect_cnsa_2_0, u8 expect_rfc_all_sets,
            u16 pk_len, u16 sig_len, u16 msg_len, then pk, sig and msg bytes.
  Expectation codes: 0 SignatureInvalid, 1 Ok, 2 UnsupportedParameterSet,
            3 MalformedSignature, 4 InvalidPublicKey. One expectation per policy:
            `expect_default` is the result of keelsign_verify::verify_pq (policy
            ParameterPolicy::keelsign_default: W8, at most two HSS levels);
            `expect_cnsa_2_0` the result of the strict device path
            verify_pq_with(&DefaultBackend::cnsa_2_0(), ...) (ParameterPolicy::cnsa_2_0:
            the same W8 pairs, single tree only, L = 1); `expect_rfc_all_sets` the result
            of lms::verify_with_policy with ParameterPolicy::rfc_8554_all_sets.
  Version 1 had two expectations (`expect_default`, now `expect_default`, and
  `expect_rfc_all_sets`); version 2 adds `expect_cnsa_2_0` and changes no pk, sig or msg.

The strict expectation is derived by one rule, not written per case:
  expect_cnsa_2_0 = expect_default if L(pk) == 1 else UnsupportedParameterSet
where L(pk) is the first u32 of the HSS public key. Why: the verifier applies the policy
to the public key before it reads the signature (typecode pair, then 1 <= L <= max_levels,
then the key length), and the two device policies differ only in max_levels (2 and 1).
So for an L = 1 key every check is the same under both, and a key with L != 1 (every key
here holds L and both typecodes, 12 bytes or more; the script checks that) is
UnsupportedParameterSet under cnsa_2_0 whatever its signature holds: a key with L = 0 or
L > 2 is already UnsupportedParameterSet under the default, and every L = 2 key is refused
by the level check. That includes the negatives derived from RFC 8554 Test Case 1
(401-406, 5xx), whose key has L = 2, and 407/408 (hsslms case 302, L = 2).

Case IDs: 1-2 RFC 8554 Test Case 1-2; 100 + tcId ACVP SP800-208; 200 + tcId ACVP 1.0;
3xx hsslms-signed; 401-406 derived from TC1, 407-408 derived from hsslms case 302; 500 + k TC1 truncated to 97 * k bytes.

Usage:
  python3 scripts/gen_lms_vectors.py            # write the fixtures
  python3 scripts/gen_lms_vectors.py --check    # regenerate into a temp dir and diff

Standard library only.
"""

import argparse
import hashlib
import importlib
import io
import json
import re
import struct
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "benches" / "lms-kat" / "fixtures"

MAGIC = b"KSLM"
VERSION = 2

SOURCE_RFC8554 = 0
SOURCE_ACVP = 1
SOURCE_HSSLMS = 2
SOURCE_NAMES = {SOURCE_RFC8554: "rfc8554", SOURCE_ACVP: "acvp", SOURCE_HSSLMS: "hsslms"}

INVALID = 0
OK = 1
UNSUPPORTED = 2
MALFORMED = 3
INVALID_PUBLIC_KEY = 4
EXPECT_NAMES = {
    INVALID: "SignatureInvalid",
    OK: "Ok",
    UNSUPPORTED: "UnsupportedParameterSet",
    MALFORMED: "MalformedSignature",
    INVALID_PUBLIC_KEY: "InvalidPublicKey",
}

SOURCES = {
    "rfc8554": {
        "url": "https://www.rfc-editor.org/rfc/rfc8554.txt",
        "sha256": "d5bfdbd457dfe7bc5f67cc1f62482999c2f55bf8033f2af56da323f2ffc2c055",
    },
    "acvp_sp800_208": {
        "repo": "https://github.com/usnistgov/ACVP-Server",
        "commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
        "path": "gen-val/json-files/LMS-sigVer-SP800-208/internalProjection.json",
        "sha256": "015bb30cb60d4fb24bc69d0cb074965c5fd10d1c70b01d09a5914d4947e2dedf",
    },
    "acvp_lms_1_0": {
        "repo": "https://github.com/usnistgov/ACVP-Server",
        "commit": "975de31eb83d87039ec88934fdc47d8c312b892d",
        "path": "gen-val/json-files/LMS-sigVer-1.0/internalProjection.json",
        "sha256": "298bf08f3dab576483b731dc58a4feab18b93e1e741bc6192133285962cf77dd",
    },
    "hsslms": {
        "package": "hsslms==0.1.3",
        "url": "https://files.pythonhosted.org/packages/d4/d2/"
        "f3976dbdb80d05c1eba6e2de8005c04c962a71611a0975d0bf379a0d8853/hsslms-0.1.3.tar.gz",
        "sha256": "8d0a1f2bbc5f10f53f6abb394247bf185976088fbbb698a7f8c14031e97a4be5",
        "files": ["src/hsslms/utils.py", "src/hsslms/lmots.py", "src/hsslms/lms.py", "src/hsslms/hss.py"],
    },
}

# The fixed message every hsslms case signs: 32 bytes, like an image digest.
MESSAGE = hashlib.sha256(b"keelsign SHA-65 LMS/HSS fixture message").digest()

# On-target subset: TC1, TC2, one ACVP M24 case, M32 L2, M24 L1 and L2, rotation A and B,
# one tampered and one trailing-byte case, W4 and L=3, q = 2^h and the LM-OTS typecode
# mismatch.
TARGET_IDS = [1, 2, 106, 302, 311, 312, 321, 322, 331, 333, 401, 405, 407, 408]

TRUNCATION_STEP = 97


def raw_url(source):
    if "url" in source:
        return source["url"]
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


def u32(value):
    return value.to_bytes(4, "big")


# ---- RFC 8554 Appendix F -------------------------------------------------------------


def parse_rfc_test_cases(text):
    """Returns {1: {"pk", "msg", "sig"}, 2: {...}} from RFC 8554 Appendix F."""
    start = text.index("Appendix F.  Test Cases")
    end = text.index("\nAcknowledgements", start)
    appendix = text[start:end]
    blocks = {}
    current = None
    for line in appendix.splitlines():
        header = re.match(r"^   Test Case (\d) (Public Key|Message|Signature|Private Key)\s*$", line)
        if header:
            current = (int(header.group(1)), header.group(2))
            blocks[current] = bytearray()
            continue
        # Page headers and footers.
        if line.startswith("RFC 8554") or line.startswith("McGrew, et al."):
            continue
        if current is None or current[1] == "Private Key":
            continue
        body = line.split("|", 1)[0].split("#", 1)[0]
        tokens = body.split()
        if not tokens:
            continue
        # A value is the last token, lowercase hex; any tokens before it are its label
        # (`levels`, `LMS type`, `C`, `y[3]`, `path[0]`, ...), never hex themselves.
        *label, value = tokens
        if re.fullmatch(r"(?:[0-9a-f]{2})+", value) and not any(re.fullmatch(r"[0-9a-f]+", t) for t in label):
            blocks[current] += bytes.fromhex(value)
    cases = {}
    for number in (1, 2):
        cases[number] = {
            "pk": bytes(blocks[(number, "Public Key")]),
            "msg": bytes(blocks[(number, "Message")]),
            "sig": bytes(blocks[(number, "Signature")]),
        }
    # Structure: TC1 L=2 of M32_H5/W8 (LMS signature 4 + 4 + 32 * 35 + 4 + 32 * 5 = 1292
    # bytes); TC2 top M32_H10/W4 (4 + 4 + 32 * 68 + 4 + 32 * 10 = 2508), bottom M32_H5/W8.
    expected = {1: (60, 4 + 1292 + 56 + 1292), 2: (60, 4 + 2508 + 56 + 1292)}
    for number, (pk_len, sig_len) in expected.items():
        case = cases[number]
        if len(case["pk"]) != pk_len or len(case["sig"]) != sig_len:
            sys.exit(
                f"RFC 8554 Test Case {number}: parsed pk {len(case['pk'])} B / sig {len(case['sig'])} B, "
                f"expected {pk_len} / {sig_len}"
            )
    if not cases[1]["msg"].startswith(b"The powers not delegated") or not cases[2]["msg"].startswith(
        b"The enumeration"
    ):
        sys.exit("RFC 8554 test messages did not parse")
    return cases


# ---- ACVP -----------------------------------------------------------------------------


def acvp_cases(data, id_base, expected_groups):
    doc = json.loads(data)
    groups = doc["testGroups"]
    modes = [(g["lmsMode"], g["lmOtsMode"]) for g in groups]
    if modes != expected_groups:
        sys.exit(f"ACVP groups {modes}, expected {expected_groups}")
    cases = []
    for g in groups:
        lms_pk = bytes.fromhex(g["publicKey"])
        for t in sorted(g["tests"], key=lambda t: t["tcId"]):
            valid = bool(t["testPassed"])
            cases.append(
                {
                    "id": id_base + t["tcId"],
                    "source": SOURCE_ACVP,
                    "label": f"acvp {doc['revision']} tg{g['tgId']} tc{t['tcId']} {g['lmsMode']}/{g['lmOtsMode']}: {t['reason']}",
                    # W1 / W2 are outside the keelsign device policies; the RFC policy accepts them,
                    # and every modification keeps the lengths (typecode, q, message or
                    # signature bytes), so invalid cases are SignatureInvalid.
                    "expect_default": UNSUPPORTED,
                    "expect_rfc": OK if valid else INVALID,
                    "pk": u32(1) + lms_pk,
                    "sig": u32(0) + bytes.fromhex(t["signature"]),
                    "msg": bytes.fromhex(t["message"]),
                }
            )
    return cases


# ---- hsslms ---------------------------------------------------------------------------


class Drbg:
    """SHA-256 counter DRBG standing in for `secrets.token_bytes` (test fixtures only)."""

    def __init__(self, label):
        self.key = hashlib.sha256(b"keelsign-lms-fixtures:" + label.encode()).digest()
        self.counter = 0

    def __call__(self, n):
        out = b""
        while len(out) < n:
            out += hashlib.sha256(self.key + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        return out[:n]


def vendor_hsslms(sdist, tmp_dir):
    """Extracts the four signer modules into tmp_dir/hsslms and imports them."""
    package = tmp_dir / "hsslms"
    package.mkdir()
    (package / "__init__.py").write_text("")
    prefix = "hsslms-0.1.3/"
    with tarfile.open(fileobj=io.BytesIO(sdist), mode="r:gz") as tar:
        for rel in SOURCES["hsslms"]["files"]:
            member = tar.getmember(prefix + rel)
            data = tar.extractfile(member).read()
            (package / Path(rel).name).write_bytes(data)
    sys.path.insert(0, str(tmp_dir))
    modules = {name: importlib.import_module(f"hsslms.{name}") for name in ("utils", "lmots", "lms", "hss")}
    return modules


def hsslms_sign(hsslms, label, lms_names, ots_name, message):
    utils, hss = hsslms["utils"], hsslms["hss"]
    drbg = Drbg(label)
    hsslms["lmots"].token_bytes = drbg
    hsslms["lms"].token_bytes = drbg
    lms_types = [utils.LMS_ALGORITHM_TYPE[name] for name in lms_names]
    ots_type = utils.LMOTS_ALGORITHM_TYPE[ots_name]
    priv = hss.HSS_Priv(lms_types, ots_type, num_cores=1)
    pk = bytes(priv.gen_pub().get_pubkey())
    sig = bytes(priv.sign(message))
    return pk, sig


# id, label, LMS parameter sets per level, LM-OTS set, expect_default, expect_rfc_all_sets.
SIGNED = [
    (301, "m32w8-h5-l1", ["LMS_SHA256_M32_H5"], "LMOTS_SHA256_N32_W8", OK, OK),
    (302, "m32w8-h5h5-l2", ["LMS_SHA256_M32_H5", "LMS_SHA256_M32_H5"], "LMOTS_SHA256_N32_W8", OK, OK),
    (303, "m32w8-h10-l1", ["LMS_SHA256_M32_H10"], "LMOTS_SHA256_N32_W8", OK, OK),
    (304, "m32w8-h5h10-l2", ["LMS_SHA256_M32_H5", "LMS_SHA256_M32_H10"], "LMOTS_SHA256_N32_W8", OK, OK),
    (311, "m24w8-h5-l1", ["LMS_SHA256_M24_H5"], "LMOTS_SHA256_N24_W8", OK, OK),
    (312, "m24w8-h5h5-l2", ["LMS_SHA256_M24_H5", "LMS_SHA256_M24_H5"], "LMOTS_SHA256_N24_W8", OK, OK),
    (313, "m24w8-h10-l1", ["LMS_SHA256_M24_H10"], "LMOTS_SHA256_N24_W8", OK, OK),
    (321, "rotation-a", ["LMS_SHA256_M32_H5"], "LMOTS_SHA256_N32_W8", OK, OK),
    (322, "rotation-b", ["LMS_SHA256_M32_H5"], "LMOTS_SHA256_N32_W8", OK, OK),
    (331, "m32w4-h5-l1", ["LMS_SHA256_M32_H5"], "LMOTS_SHA256_N32_W4", UNSUPPORTED, OK),
    (332, "m24w2-h5-l1", ["LMS_SHA256_M24_H5"], "LMOTS_SHA256_N24_W2", UNSUPPORTED, OK),
    (
        333,
        "m32w8-h5h5h5-l3",
        ["LMS_SHA256_M32_H5", "LMS_SHA256_M32_H5", "LMS_SHA256_M32_H5"],
        "LMOTS_SHA256_N32_W8",
        UNSUPPORTED,
        OK,
    ),
]


def hsslms_cases(hsslms):
    cases = []
    for case_id, label, lms_names, ots_name, expect_default, expect_rfc in SIGNED:
        pk, sig = hsslms_sign(hsslms, label, lms_names, ots_name, MESSAGE)
        cases.append(
            {
                "id": case_id,
                "source": SOURCE_HSSLMS,
                "label": f"hsslms {label}: {'+'.join(lms_names)} / {ots_name}",
                "expect_default": expect_default,
                "expect_rfc": expect_rfc,
                "pk": pk,
                "sig": sig,
                "msg": MESSAGE,
            }
        )
    return cases


# ---- Derived negatives ----------------------------------------------------------------


def flip(data, offset, mask=0x01):
    out = bytearray(data)
    out[offset] ^= mask
    return bytes(out)


def derived_negatives(tc1):
    pk, sig, msg = tc1["pk"], tc1["sig"], tc1["msg"]
    # TC1 layout: Nspk (4) | level-0 LMS signature (1292) | level-1 public key (56) |
    # level-1 LMS signature (1292). An LMS signature is q (4) | LM-OTS type (4) | C (32) |
    # y (34 * 32) | LMS type (4) | path (5 * 32).
    top_q = 4
    bottom = 4 + 1292 + 56
    bottom_c = bottom + 4 + 4

    def case(case_id, label, expect_default, expect_rfc, pk=pk, sig=sig):
        return {
            "id": case_id,
            "source": SOURCE_RFC8554,
            "label": f"rfc8554 TC1 {label}",
            "expect_default": expect_default,
            "expect_rfc": expect_rfc,
            "pk": pk,
            "sig": sig,
            "msg": msg,
        }

    cases = [
        case(401, "last byte flipped", INVALID, INVALID, sig=flip(sig, len(sig) - 1)),
        case(402, "bottom C flipped", INVALID, INVALID, sig=flip(sig, bottom_c)),
        case(403, "bottom q flipped (wrong leaf index)", INVALID, INVALID, sig=flip(sig, bottom + 3)),
        case(404, "top q flipped (wrong tree index)", INVALID, INVALID, sig=flip(sig, top_q + 3)),
        case(405, "one trailing byte", MALFORMED, MALFORMED, sig=sig + b"\x00"),
        # L = 3 in the key: outside the keelsign default policy (at most 2 levels); under the RFC
        # policy Nspk + 1 != L.
        case(406, "key patched to L = 3", UNSUPPORTED, MALFORMED, pk=u32(3) + pk[4:]),
    ]
    for k, cut in enumerate(range(0, len(sig), TRUNCATION_STEP)):
        cases.append(case(500 + k, f"truncated to {cut} bytes", MALFORMED, MALFORMED, sig=sig[:cut]))
    return cases


def hsslms_derived_negatives(base):
    """Negatives derived from hsslms case 302 (M32/W8 H5+H5, L=2)."""
    pk, sig = base["pk"], base["sig"]
    # Layout: Nspk (4) | level-0 LMS signature (1292) | level-1 public key (56) |
    # level-1 LMS signature (1292): q (4) | LM-OTS type (4) | C | y | LMS type | path.
    if base["id"] != 302 or len(pk) != 60 or len(sig) != 4 + 1292 + 56 + 1292:
        sys.exit("hsslms case 302 does not have the expected M32/W8 H5+H5 layout")
    bottom_q = 4 + 1292 + 56
    bottom_ots = bottom_q + 4
    h = 5
    if sig[bottom_ots : bottom_ots + 4] != u32(0x04):
        sys.exit("hsslms case 302: bottom LM-OTS typecode is not LMOTS_SHA256_N32_W8")

    def patch(offset, value):
        out = bytearray(sig)
        out[offset : offset + 4] = u32(value)
        return bytes(out)

    def case(case_id, label, new_sig):
        return {
            "id": case_id,
            "source": SOURCE_HSSLMS,
            "label": f"hsslms m32w8-h5h5-l2 {label}",
            "expect_default": INVALID,
            "expect_rfc": INVALID,
            "pk": pk,
            "sig": new_sig,
            "msg": base["msg"],
        }

    return [
        case(407, "bottom q = 2^h (step 2i)", patch(bottom_q, 1 << h)),
        # LMOTS_SHA256_N24_W8 is a valid W8 code of the other hash size: every length is
        # still taken from the public key, so only the step 2c typecode check rejects it.
        case(408, "bottom LM-OTS typecode in signature N32_W8 -> N24_W8 (step 2c)", patch(bottom_ots, 0x08)),
    ]


# ---- Cross-check with the independent signer's verifier -------------------------------


def hsslms_verdict(hsslms, case):
    try:
        hsslms["hss"].HSS_Pub(case["pk"]).verify(case["msg"], case["sig"])
        return True
    except Exception:  # hsslms raises INVALID, ValueError or IndexError on bad input
        return False


def cross_check(hsslms, cases):
    """hsslms.HSS_Pub.verify must agree with every RFC-policy expectation that is Ok or
    SignatureInvalid (it accepts any number of levels and every W)."""
    for case in cases:
        verdict = hsslms_verdict(hsslms, case)
        if verdict != (case["expect_rfc"] == OK):
            sys.exit(f"hsslms verify disagrees with case {case['id']} ({case['label']}): {verdict}")


# ---- Strict CNSA 2.0 expectation ------------------------------------------------------


def hss_levels(pk):
    """L, the first u32 of an HSS public key (RFC 8554 section 6.1)."""
    return int.from_bytes(pk[:4], "big")


def strict_expectation(case):
    """The cnsa_2_0 expectation: the default one for an L = 1 key, else
    UnsupportedParameterSet (see the module docstring for why)."""
    return case["expect_default"] if hss_levels(case["pk"]) == 1 else UNSUPPORTED


def check_expectations(cases):
    """Self-checks of the three expectation columns."""
    for c in cases:
        if len(c["pk"]) < 12:
            sys.exit(f"case {c['id']}: the strict rule needs L and both typecodes in the key")
        for key in ("expect_default", "expect_cnsa_2_0", "expect_rfc"):
            if c[key] not in EXPECT_NAMES:
                sys.exit(f"case {c['id']}: {key} = {c[key]} is not an expectation code")
        if c["expect_default"] == OK and hss_levels(c["pk"]) == 2 and c["expect_cnsa_2_0"] != UNSUPPORTED:
            sys.exit(f"case {c['id']}: a valid L = 2 case must be UnsupportedParameterSet under cnsa_2_0")
    for pk_len, name in ((60, "SHA-256"), (52, "SHA-256/192")):
        if not any(
            hss_levels(c["pk"]) == 1 and len(c["pk"]) == pk_len and c["expect_cnsa_2_0"] == OK for c in cases
        ):
            sys.exit(f"no L = 1 {name} case is Ok under cnsa_2_0")


# ---- Output ---------------------------------------------------------------------------


def encode_fixture(cases):
    out = bytearray(MAGIC + struct.pack("<HH", VERSION, len(cases)))
    for c in cases:
        out += struct.pack(
            "<HBBBBHHH",
            c["id"],
            c["source"],
            c["expect_default"],
            c["expect_cnsa_2_0"],
            c["expect_rfc"],
            len(c["pk"]),
            len(c["sig"]),
            len(c["msg"]),
        )
        out += c["pk"] + c["sig"] + c["msg"]
    return bytes(out)


def manifest_cases(cases):
    return [
        {
            "id": c["id"],
            "label": c["label"],
            "source": SOURCE_NAMES[c["source"]],
            "expect_default": EXPECT_NAMES[c["expect_default"]],
            "expect_cnsa_2_0": EXPECT_NAMES[c["expect_cnsa_2_0"]],
            "expect_rfc_all_sets": EXPECT_NAMES[c["expect_rfc"]],
        }
        for c in cases
    ]


def generate(out_dir):
    rfc = parse_rfc_test_cases(fetch("rfc8554").decode("ascii"))
    acvp = acvp_cases(
        fetch("acvp_sp800_208"),
        100,
        [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"), ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2")],
    ) + acvp_cases(
        fetch("acvp_lms_1_0"),
        200,
        [("LMS_SHA256_M24_H5", "LMOTS_SHA256_N24_W1"), ("LMS_SHA256_M24_H10", "LMOTS_SHA256_N24_W2")],
    )
    if len(acvp) != 16:
        sys.exit(f"expected 16 ACVP cases, got {len(acvp)}")

    rfc_cases = [
        {
            "id": 1,
            "source": SOURCE_RFC8554,
            "label": "rfc8554 Test Case 1: HSS L=2, M32_H5/W8 + M32_H5/W8",
            "expect_default": OK,
            "expect_rfc": OK,
            **rfc[1],
        },
        {
            "id": 2,
            "source": SOURCE_RFC8554,
            "label": "rfc8554 Test Case 2: HSS L=2, M32_H10/W4 + M32_H5/W8",
            "expect_default": UNSUPPORTED,
            "expect_rfc": OK,
            **rfc[2],
        },
    ]

    with tempfile.TemporaryDirectory() as tmp:
        hsslms = vendor_hsslms(fetch("hsslms"), Path(tmp))
        signed = hsslms_cases(hsslms)
        signed_by_id = {c["id"]: c for c in signed}
        cases = rfc_cases + acvp + signed + derived_negatives(rfc[1]) + hsslms_derived_negatives(signed_by_id[302])
        cross_check(hsslms, cases)

    for c in cases:
        c["expect_cnsa_2_0"] = strict_expectation(c)
    check_expectations(cases)

    ids = [c["id"] for c in cases]
    if len(ids) != len(set(ids)):
        sys.exit("duplicate case IDs")
    by_id = {c["id"]: c for c in cases}
    sets = {"lms-host.bin": cases, "lms-target.bin": [by_id[i] for i in TARGET_IDS]}

    manifest = {
        "generator": "scripts/gen_lms_vectors.py",
        "format": "KSLM v2: see the module docstring of scripts/gen_lms_vectors.py",
        "policies": {
            "expect_default": "keelsign_verify::verify_pq (ParameterPolicy::keelsign_default)",
            "expect_cnsa_2_0": "verify_pq_with(&DefaultBackend::cnsa_2_0(), ...) (ParameterPolicy::cnsa_2_0, L = 1 only)",
            "expect_rfc_all_sets": "lms::verify_with_policy(&ParameterPolicy::rfc_8554_all_sets(), ...)",
        },
        "message_hex": MESSAGE.hex(),
        "sources": {name: {**source, "url": raw_url(source)} for name, source in sorted(SOURCES.items())},
        "outputs": {},
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, selected in sets.items():
        data = encode_fixture(selected)
        (out_dir / name).write_bytes(data)
        manifest["outputs"][name] = {
            "version": VERSION,
            "count": len(selected),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "cases": manifest_cases(selected),
        }
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {name: len(selected) for name, selected in sets.items()}


def check():
    names = ["MANIFEST.json", "lms-host.bin", "lms-target.bin"]
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
        counts = generate(FIXTURE_DIR)
        print(f"wrote fixtures to {FIXTURE_DIR.relative_to(REPO_ROOT)}: {counts}")


if __name__ == "__main__":
    main()
