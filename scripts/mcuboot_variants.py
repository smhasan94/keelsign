#!/usr/bin/env python3
"""Bad variants of the keelsign_hello application for the on-board checks (SHA-62).

Usage:
    mcuboot_variants.py [--keelsign CLI] BUILD_DIR

From BUILD_DIR/keelsign_hello/zephyr/zephyr.signed.keelsign.{bin,hex} (a
`scripts/zephyr_sample_ci.sh build`) writes, into BUILD_DIR/variants/:

  tampered.bin / .hex   one byte of the image body flipped (header size + 16), all
                        signatures left as they were: keelsign must reject it with
                        status 70 (KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH),
                        docs/mcuboot.md#p2-tampered-image-rejected-needs-hardware
  wrong-key.bin / .hex  the keelsign signature replaced by one from a fresh LMS/HSS key
                        the bootloader does not trust (`keelsign sign --replace`, key
                        variants/other.pem): status 15 (KEELSIGN_ERR_KEY_NOT_TRUSTED),
                        docs/mcuboot.md#p3-wrong-key-rejected-needs-hardware
  bad-ecdsa.bin / .hex  the last byte of imgtool's ECDSA signature (TLV 0x22) flipped:
                        keelsign's signature still verifies (it does not cover the
                        unprotected TLVs), MCUboot's own ECDSA check must reject it,
                        docs/mcuboot.md#p4-classical-fallback-needs-hardware

The .hex files are at the address of the signed .hex (slot 0), ready for
`probe-rs download --binary-format hex`. CLI is the keelsign host CLI (default: the one
the sysbuild build made, BUILD_DIR/keelsign-cargo-host/release/keelsign). Prints one
line per file. Standard library only.
"""

import argparse
import struct
import subprocess
import sys
from pathlib import Path


def hex_base(path):
    """The lowest address of an Intel HEX file (types 00, 02 and 04 records)."""
    upper = 0
    lowest = None
    for line in Path(path).read_text().split():
        raw = bytes.fromhex(line[1:])
        count, offset, rtype = raw[0], struct.unpack(">H", raw[1:3])[0], raw[3]
        data = raw[4 : 4 + count]
        if rtype == 0x00:
            addr = upper + offset
            lowest = addr if lowest is None else min(lowest, addr)
        elif rtype == 0x02:
            upper = struct.unpack(">H", data)[0] << 4
        elif rtype == 0x04:
            upper = struct.unpack(">H", data)[0] << 16
        elif rtype == 0x01:
            break
    if lowest is None:
        sys.exit(f"mcuboot_variants: {path} has no data")
    return lowest


def record(rtype, offset, data):
    body = bytes([len(data)]) + struct.pack(">H", offset) + bytes([rtype]) + data
    return ":" + (body + bytes([(-sum(body)) & 0xFF])).hex().upper()


def write_hex(path, base, data):
    """`data` at `base` as Intel HEX (type 04 extended linear addresses)."""
    lines = []
    upper = None
    for at in range(0, len(data), 16):
        addr = base + at
        if addr >> 16 != upper:
            upper = addr >> 16
            lines.append(record(0x04, 0, struct.pack(">H", upper)))
        lines.append(record(0x00, addr & 0xFFFF, data[at : at + 16]))
    lines.append(record(0x01, 0, b""))
    Path(path).write_text("\n".join(lines) + "\n")


def tlv_value_span(image, wanted):
    """(start, end) of the value of the unprotected TLV of type `wanted`."""
    hdr_size, protect_size = struct.unpack_from("<HH", image, 8)
    (img_size,) = struct.unpack_from("<I", image, 12)
    at = hdr_size + img_size + protect_size
    magic, total = struct.unpack_from("<HH", image, at)
    if magic != 0x6907:
        sys.exit(f"mcuboot_variants: no unprotected TLV area at {at:#x}")
    end = at + total
    at += 4
    while at + 4 <= end:
        typ, length = struct.unpack_from("<HH", image, at)
        if typ == wanted:
            return at + 4, at + 4 + length
        at += 4 + length
    sys.exit(f"mcuboot_variants: no TLV {wanted:#06x}")


def run(*cmd):
    subprocess.run([str(c) for c in cmd], check=True, stdout=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--keelsign", type=Path, help="keelsign CLI")
    ap.add_argument("build", type=Path)
    args = ap.parse_args()
    zephyr = args.build / "keelsign_hello" / "zephyr"
    signed = zephyr / "zephyr.signed.keelsign.bin"
    cli = args.keelsign or args.build / "keelsign-cargo-host" / "release" / "keelsign"
    if not signed.is_file():
        sys.exit(f"mcuboot_variants: {signed} not found; run scripts/zephyr_sample_ci.sh build first")
    base = hex_base(zephyr / "zephyr.signed.keelsign.hex")
    image = signed.read_bytes()
    out = args.build / "variants"
    out.mkdir(exist_ok=True)

    (hdr_size,) = struct.unpack_from("<H", image, 8)
    tampered = bytearray(image)
    tampered[hdr_size + 16] ^= 0x01
    (out / "tampered.bin").write_bytes(tampered)
    write_hex(out / "tampered.hex", base, bytes(tampered))

    other = out / "other.pem"
    if not other.exists():
        run(cli, "keygen", "--alg", "lms-sha256-m32-h10", "--out", other)
    run(cli, "sign", "--replace", "--force", "--key", other, signed, out / "wrong-key.bin")
    write_hex(out / "wrong-key.hex", base, (out / "wrong-key.bin").read_bytes())

    _start, ecdsa_end = tlv_value_span(image, 0x22)
    bad_ecdsa = bytearray(image)
    bad_ecdsa[ecdsa_end - 1] ^= 0x01
    (out / "bad-ecdsa.bin").write_bytes(bad_ecdsa)
    write_hex(out / "bad-ecdsa.hex", base, bytes(bad_ecdsa))

    for name in ("tampered.bin", "tampered.hex", "wrong-key.bin", "wrong-key.hex", "bad-ecdsa.bin", "bad-ecdsa.hex"):
        print(f"{out / name} (slot 0 at {base:#x})")


if __name__ == "__main__":
    main()
