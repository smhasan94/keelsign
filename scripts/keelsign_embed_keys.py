#!/usr/bin/env python3
"""Generate keelsign_mcuboot_keys.c, the key table of keelsign's MCUboot hook (SHA-62).

Usage:
    keelsign_embed_keys.py --policy pq_only|hybrid --out FILE [--raw ALG:HEX ...] [KEYFILE ...]

Each KEYFILE is a public key as `keelsign pubkey` writes it: a SubjectPublicKeyInfo in
PEM ("-----BEGIN PUBLIC KEY-----") or DER, either an HSS/LMS key (RFC 8708,
id-alg-hss-lms-hashsig 1.2.840.113549.1.9.16.3.17) or an Ed25519 key (RFC 8410,
1.3.101.112). --raw ALG:HEX gives a raw key instead (ALG `lms` or `ed25519`; for
example MANIFEST.json's public_key_hex). ML-DSA keys are refused: ML-DSA verify needs
98-158 KB of stack, more than a bootloader has (docs/mcuboot.md).

Writes a C file defining, for mcuboot/include/keelsign_mcuboot.h:

    const keelsign_key_t keelsign_mcuboot_keys[];      /* --raw keys, then KEYFILEs */
    const size_t keelsign_mcuboot_n_keys;
    const keelsign_policy_t keelsign_mcuboot_policy;   /* KEELSIGN_POLICY_PQ_ONLY or _HYBRID */

Rules (checked here so a wrong key set never builds): 1 to 8 LMS/HSS keys (rotation);
pq_only takes no Ed25519 key; hybrid takes 1 to 8 Ed25519 keys; no key twice; an
LMS/HSS key is 52 or 60 bytes (HSS public key with its level count L = 1 or 2),
an Ed25519 key 32 bytes. The output depends only on the key bytes, their order and
the policy (sources are named by file name), so it is reproducible.

Standard library only.
"""

import argparse
import base64
import sys
from pathlib import Path

OID_HSS_LMS = bytes.fromhex("2a864886f70d0109100311")  # 1.2.840.113549.1.9.16.3.17
OID_ED25519 = bytes.fromhex("2b6570")  # 1.3.101.112
OID_MLDSA = (bytes.fromhex("608648016503040311"), bytes.fromhex("608648016503040312"))
MAX_KEYS = 8
POLICIES = {"pq_only": "KEELSIGN_POLICY_PQ_ONLY", "hybrid": "KEELSIGN_POLICY_HYBRID"}
ALGS = {"lms": "KEELSIGN_ALG_LMS_HSS", "ed25519": "KEELSIGN_ALG_ED25519"}


def fail(message):
    sys.exit(f"keelsign_embed_keys: {message}")


def der_item(data, at, source):
    """(tag, content start, content end) of the DER item at `at`."""
    if at + 2 > len(data):
        fail(f"{source}: truncated DER")
    tag, length = data[at], data[at + 1]
    at += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 3 or at + n > len(data):
            fail(f"{source}: bad DER length")
        length = int.from_bytes(data[at : at + n], "big")
        at += n
    if at + length > len(data):
        fail(f"{source}: truncated DER")
    return tag, at, at + length


def spki_key(der, source):
    """(alg, raw key) of a SubjectPublicKeyInfo."""
    tag, start, end = der_item(der, 0, source)
    if tag != 0x30 or end != len(der):
        fail(f"{source}: not a SubjectPublicKeyInfo")
    tag, alg_start, alg_end = der_item(der, start, source)
    if tag != 0x30:
        fail(f"{source}: no AlgorithmIdentifier")
    tag, oid_start, oid_end = der_item(der, alg_start, source)
    if tag != 0x06:
        fail(f"{source}: no algorithm OID")
    oid = der[oid_start:oid_end]
    tag, bits_start, bits_end = der_item(der, alg_end, source)
    if tag != 0x03 or bits_end != end or bits_start >= bits_end or der[bits_start] != 0:
        fail(f"{source}: bad subjectPublicKey BIT STRING")
    bits = der[bits_start + 1 : bits_end]
    if oid == OID_HSS_LMS:
        # RFC 8708: the BIT STRING holds HSS-LMS-HashSig-PublicKey, an OCTET STRING.
        tag, key_start, key_end = der_item(bits, 0, source)
        if tag != 0x04 or key_end != len(bits):
            fail(f"{source}: HSS/LMS key is not an OCTET STRING")
        return "lms", bits[key_start:key_end]
    if oid == OID_ED25519:
        return "ed25519", bits
    if oid in OID_MLDSA:
        fail(f"{source}: ML-DSA keys are not supported in the MCUboot hook (stack; docs/mcuboot.md)")
    fail(f"{source}: unsupported key algorithm OID {oid.hex()}")


def read_keyfile(path):
    data = path.read_bytes()
    text = data.decode("ascii", errors="replace")
    if "-----BEGIN PUBLIC KEY-----" in text:
        body = text.split("-----BEGIN PUBLIC KEY-----", 1)[1].split("-----END PUBLIC KEY-----", 1)[0]
        try:
            data = base64.b64decode("".join(body.split()), validate=True)
        except ValueError:
            fail(f"{path.name}: bad PEM")
    elif "-----BEGIN" in text:
        fail(f"{path.name}: not a public key PEM (use `keelsign pubkey --key ...`)")
    return spki_key(data, path.name)


def parse_raw(arg):
    alg, sep, hexkey = arg.partition(":")
    if not sep or alg not in ALGS:
        fail(f"--raw {arg}: expected ALG:HEX with ALG one of {', '.join(sorted(ALGS))}")
    try:
        return alg, bytes.fromhex(hexkey)
    except ValueError:
        fail(f"--raw {arg}: bad hex")


def check(keys, policy):
    lms = [k for a, k, _ in keys if a == "lms"]
    ed = [k for a, k, _ in keys if a == "ed25519"]
    for alg, key, source in keys:
        if alg == "lms" and len(key) not in (52, 60):
            fail(f"{source}: an HSS/LMS public key is 52 or 60 bytes, not {len(key)}")
        if alg == "lms" and int.from_bytes(key[:4], "big") not in (1, 2):
            fail(f"{source}: HSS level count {int.from_bytes(key[:4], 'big')} (keelsign verifies L = 1 or 2)")
        if alg == "ed25519" and len(key) != 32:
            fail(f"{source}: an Ed25519 public key is 32 bytes, not {len(key)}")
    if not 1 <= len(lms) <= MAX_KEYS:
        fail(f"{len(lms)} HSS/LMS keys: give 1 to {MAX_KEYS}")
    if policy == "pq_only" and ed:
        fail("--policy pq_only takes no Ed25519 key (use --policy hybrid)")
    if policy == "hybrid" and not 1 <= len(ed) <= MAX_KEYS:
        fail(f"--policy hybrid needs 1 to {MAX_KEYS} Ed25519 keys, got {len(ed)}")
    if len(set(lms)) != len(lms) or len(set(ed)) != len(ed):
        fail("the same key is given twice")


def render(keys, policy):
    out = [
        "/*",
        " * keelsign MCUboot hook key table. GENERATED by scripts/keelsign_embed_keys.py; DO NOT EDIT.",
        " * Sources: " + ", ".join(source for _, _, source in keys),
        " *",
        " * SPDX-License-Identifier: MIT OR Apache-2.0",
        " */",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        '#include "keelsign.h"',
        '#include "keelsign_mcuboot.h"',
        "",
    ]
    for i, (alg, key, _) in enumerate(keys):
        out.append(f"/* {alg}, {len(key)} bytes */")
        out.append(f"static const uint8_t keelsign_mcuboot_key_{i}[{len(key)}] = {{")
        for row in range(0, len(key), 12):
            out.append("    " + " ".join(f"0x{b:02x}," for b in key[row : row + 12]))
        out.append("};")
        out.append("")
    out.append("const keelsign_key_t keelsign_mcuboot_keys[] = {")
    for i, (alg, _, _) in enumerate(keys):
        out.append(f"    {{{ALGS[alg]}, keelsign_mcuboot_key_{i}, sizeof keelsign_mcuboot_key_{i}}},")
    out.append("};")
    out.append("")
    out.append(f"const size_t keelsign_mcuboot_n_keys = {len(keys)};")
    out.append("")
    out.append(f"const keelsign_policy_t keelsign_mcuboot_policy = {POLICIES[policy]};")
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--policy", choices=sorted(POLICIES), required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--raw", action="append", default=[], metavar="ALG:HEX")
    ap.add_argument("keyfiles", nargs="*", type=Path)
    args = ap.parse_args()
    keys = []
    for arg in args.raw:
        alg, key = parse_raw(arg)
        keys.append((alg, key, f"raw {alg}"))
    for path in args.keyfiles:
        alg, key = read_keyfile(path)
        keys.append((alg, key, path.name))
    check(keys, args.policy)
    text = render(keys, args.policy)
    if not args.out.exists() or args.out.read_text() != text:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)


if __name__ == "__main__":
    main()
