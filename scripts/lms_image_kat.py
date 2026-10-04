#!/usr/bin/env python3
"""Pack keelsign-signed LMS/HSS images into a KSLM v2 fixture for the on-target check.

The on-target check of SHA-67 TP3 (docs/signing.md, "On-target check") verifies images
signed by `keelsign sign` with an LMS/HSS key on the boards, through the same runner as
the SHA-65 KATs (benches/lms-kat). This script turns the images into that runner's
fixture format, KSLM v2 (benches/lms-kat/src/lib.rs):

  header:   b"KSLM", u16 version (2), u16 case count
  per case: u16 id, u8 source, u8 expect_default, u8 expect_cnsa_2_0,
            u8 expect_rfc_all_sets, u16 pk_len, u16 sig_len, u16 msg_len, pk, sig, msg

For each image:
  * msg is the image digest M: SHA-256 over the header, body and protected TLV area
    (docs/image-format.md); the LMS/HSS message is M itself;
  * sig is the value of the single KEELSIGN_LMS_HSS_SIG TLV (0x4BA3);
  * pk is the HSS public key from the --pub SubjectPublicKeyInfo (RFC 8708: the BIT STRING
    holds the DER OCTET STRING of the key), and the image's KEELSIGN_KEY_ID TLV (0x4BA0)
    must equal SHA-256(pk)[:16];
  * every case is expected to verify (Ok) under keelsign-verify's default policy and the
    RFC 8554 policy, and under CNSA 2.0 when the key has one level (L = 2 is
    UnsupportedParameterSet there);
  * case IDs are 700, 701, ... in the order given; the source byte is 2, the slot for
    signatures made by a signer other than the verifier under test.

Usage:
  python3 scripts/lms_image_kat.py --pub lms.pub.pem --out lms-leaves.bin \\
      leaf-0.bin leaf-1.bin leaf-1023.bin

Standard library only; offline.
"""

import argparse
import base64
import hashlib
import struct
import sys
from pathlib import Path

MCUBOOT_MAGIC = 0x96F3B83D
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908
TLV_KEELSIGN_KEY_ID = 0x4BA0
TLV_LMS_HSS_SIG = 0x4BA3
# id-alg-hss-lms-hashsig, 1.2.840.113549.1.9.16.3.17, as a DER OBJECT IDENTIFIER.
OID_HSS_LMS_HASHSIG = bytes.fromhex("060b2a864886f70d0109100311")
FIRST_CASE_ID = 700
SOURCE_OTHER_SIGNER = 2
EXPECT_OK = 1
EXPECT_UNSUPPORTED = 2


def fail(message):
    sys.exit(f"lms_image_kat.py: {message}")


def der_item(data, offset):
    """(tag, content, next offset) of the DER item at offset."""
    if offset + 2 > len(data):
        fail("truncated DER")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 2 or offset + count > len(data):
            fail("unsupported DER length")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if offset + length > len(data):
        fail("truncated DER")
    return tag, data[offset : offset + length], offset + length


def hss_public_key(path):
    """The HSS public key of an RFC 8708 SubjectPublicKeyInfo file (PEM or DER)."""
    data = Path(path).read_bytes()
    if b"-----BEGIN PUBLIC KEY-----" in data:
        text = data.decode("ascii")
        body = text.split("-----BEGIN PUBLIC KEY-----", 1)[1].split("-----END PUBLIC KEY-----", 1)[0]
        data = base64.b64decode("".join(body.split()))
    tag, spki, _ = der_item(data, 0)
    if tag != 0x30:
        fail(f"{path}: not a SubjectPublicKeyInfo")
    tag, algorithm, offset = der_item(spki, 0)
    if tag != 0x30 or algorithm != OID_HSS_LMS_HASHSIG:
        fail(f"{path}: not an id-alg-hss-lms-hashsig public key with parameters absent")
    tag, bits, _ = der_item(spki, offset)
    if tag != 0x03 or not bits or bits[0] != 0:
        fail(f"{path}: malformed subjectPublicKey")
    tag, key, end = der_item(bits, 1)
    if tag != 0x04 or end != len(bits) or len(key) not in (52, 60):
        fail(f"{path}: the subjectPublicKey is not the DER OCTET STRING of an HSS key")
    return key


def image_case(path, pk):
    """(msg, sig) of a keelsign-signed MCUboot image."""
    data = Path(path).read_bytes()
    if len(data) < 32:
        fail(f"{path}: too short for an MCUboot header")
    magic, _load, hdr_size, protect_size, img_size, _flags = struct.unpack_from("<IIHHII", data, 0)
    if magic != MCUBOOT_MAGIC:
        fail(f"{path}: not an MCUboot image")
    hashed_end = hdr_size + img_size + protect_size
    if hashed_end + 4 > len(data):
        fail(f"{path}: truncated")
    if protect_size:
        prot_magic, = struct.unpack_from("<H", data, hdr_size + img_size)
        if prot_magic != TLV_PROT_INFO_MAGIC:
            fail(f"{path}: bad protected TLV info magic")
    msg = hashlib.sha256(data[:hashed_end]).digest()
    info_magic, tlv_tot = struct.unpack_from("<HH", data, hashed_end)
    if info_magic != TLV_INFO_MAGIC or hashed_end + tlv_tot > len(data):
        fail(f"{path}: bad unprotected TLV area")
    tlvs = {}
    offset = hashed_end + 4
    while offset < hashed_end + tlv_tot:
        tlv_type, tlv_len = struct.unpack_from("<HH", data, offset)
        value = data[offset + 4 : offset + 4 + tlv_len]
        tlvs.setdefault(tlv_type, []).append(value)
        offset += 4 + tlv_len
    sigs = tlvs.get(TLV_LMS_HSS_SIG, [])
    key_ids = tlvs.get(TLV_KEELSIGN_KEY_ID, [])
    if len(sigs) != 1 or len(key_ids) != 1:
        fail(f"{path}: needs exactly one LMS/HSS signature TLV and one key-ID TLV")
    if key_ids[0] != hashlib.sha256(pk).digest()[:16]:
        fail(f"{path}: its key ID is not SHA-256 of the --pub key; signed with another key?")
    return msg, sigs[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--pub", required=True, help="the key's public key (keelsign pubkey)")
    parser.add_argument("--out", required=True, help="the KSLM v2 fixture to write")
    parser.add_argument("images", nargs="+", help="images signed by keelsign sign")
    args = parser.parse_args()

    pk = hss_public_key(args.pub)
    levels = int.from_bytes(pk[:4], "big")
    expect_cnsa = EXPECT_OK if levels == 1 else EXPECT_UNSUPPORTED
    cases = []
    for index, image in enumerate(args.images):
        msg, sig = image_case(image, pk)
        cases.append(
            struct.pack(
                "<HBBBBHHH",
                FIRST_CASE_ID + index,
                SOURCE_OTHER_SIGNER,
                EXPECT_OK,
                expect_cnsa,
                EXPECT_OK,
                len(pk),
                len(sig),
                len(msg),
            )
            + pk
            + sig
            + msg
        )
    fixture = b"KSLM" + struct.pack("<HH", 2, len(cases)) + b"".join(cases)
    Path(args.out).write_bytes(fixture)
    print(f"wrote {len(cases)} cases ({len(fixture)} bytes) to {args.out}")


if __name__ == "__main__":
    main()
