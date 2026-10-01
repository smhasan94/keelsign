#!/usr/bin/env python3
"""Regenerate the parse_image fuzz seed corpus in fuzz/corpus/parse_image/.

The seeds are:
  * fixture-<name>.bin: a copy of every image under tests/fixtures/images/ (its
    subdirectory joined with '-'), except the files in EXCLUDED. These are the images
    gen_image_fixtures.py writes; their expected parse result comes from that MANIFEST.
  * synth-<name>.bin: small images built here, so that the committed corpus reaches every
    TLV kind and every error variant the harness sorts outcomes into (fuzz/src/lib.rs,
    `cov`): one image with a TLV of every kind, one per ParseError variant, one valid
    image whose TLV areas are larger than the 4 KiB read_from buffer
    (Error::TlvAreaTooLarge), and one with empty TLV areas.

fuzz/corpus/MANIFEST.json (outside the input directory, so libFuzzer never reads it)
records every seed's source, sha256, size, expected Image::parse result and expected
Image::read_from result with a 4096-byte TLV buffer, in Rust Debug notation; the
keelsign-fuzz tests check them. The seeds are not minimised.

Usage:
  python3 scripts/gen_fuzz_corpus.py            # write the seeds and MANIFEST.json
  python3 scripts/gen_fuzz_corpus.py --check    # regenerate into a temp dir and diff

Offline; standard library only. Never edit the corpus by hand; rerun this script
(CLAUDE.md). Write mode removes stale fixture-*/synth-* seeds and leaves any other file
in the directory (inputs libFuzzer added, gitignored) alone.
"""

import argparse
import hashlib
import json
import struct
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
IMAGES = REPO_ROOT / "tests" / "fixtures" / "images"
IMAGES_MANIFEST = IMAGES / "MANIFEST.json"
CORPUS_ROOT = REPO_ROOT / "fuzz" / "corpus"
SEED_DIR = "parse_image"

EXCLUDED = {
    "mcuboot-ed25519-200k.bin": "205 KB, over the fuzzer's -max_len=8192; its header and "
    "TLV areas are those of mcuboot-ed25519.bin with a larger body",
    "policy-matrix.bin": "not an image: the SHA-46 on-target index of the policy matrix",
}

# The TLV buffer size the harness checks Image::read_from with (fuzz/src/lib.rs).
SMALL_TLV_BUF = 4096

IMAGE_MAGIC = 0x96F3B83D
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908
MAX_PQ_SIGNATURE_LEN = 3924

# Every TlvKind (keelsign-verify/src/image.rs, TlvKind::of): (type, value length).
KEYHASH, PUBKEY, SHA256, SHA384, SHA512 = 0x01, 0x02, 0x10, 0x11, 0x12
RSA2048_PSS, ECDSA_SIG, RSA3072_PSS, ED25519, SIG_PURE = 0x20, 0x22, 0x23, 0x24, 0x25
DEPENDENCY, SEC_CNT, BOOT_RECORD = 0x40, 0x50, 0x60
KEELSIGN_KEY_ID, MLDSA44_SIG, MLDSA65_SIG, LMS_HSS_SIG = 0x4BA0, 0x4BA1, 0x4BA2, 0x4BA3
KEELSIGN_RESERVED, UNKNOWN = 0x4BA4, 0x7F00


def header(hdr_size, protect_tlv_size, img_size):
    """A 32-byte image header: load address 0x1000, flags 0, version 1.2.3+4."""
    return struct.pack("<IIHHII", IMAGE_MAGIC, 0x1000, hdr_size, protect_tlv_size, img_size, 0) + bytes(
        [1, 2, 3, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    )


def value(tlv_type, length):
    """A deterministic TLV value."""
    return bytes((tlv_type * 7 + i) & 0xFF for i in range(length))


def area(magic, tlvs):
    body = b"".join(struct.pack("<HH", t, len(v)) + v for t, v in tlvs)
    return struct.pack("<HH", magic, 4 + len(body)) + body


def synth(protected, unprotected):
    """A 32-byte header, a 4-byte body and the given TLV areas (as image.rs's synth())."""
    prot = area(TLV_PROT_INFO_MAGIC, protected) if protected is not None else b""
    return header(32, len(prot), 4) + bytes([0xAA, 0xBB, 0xCC, 0xDD]) + prot + area(TLV_INFO_MAGIC, unprotected)


def put_u16(data, at, v):
    data[at : at + 2] = struct.pack("<H", v)


def put_u32(data, at, v):
    data[at : at + 4] = struct.pack("<I", v)


def error_seed(variant):
    """One input per ParseError variant, as image.rs's
    every_parse_error_variant_is_reachable_and_distinct builds them."""
    d = bytearray(synth([(SEC_CNT, bytes([7, 0, 0, 0]))], [(SHA256, bytes(32))]))
    if variant == "BadMagic":
        d[3] = 0x97
    elif variant == "Truncated":
        d.pop()
    elif variant == "HeaderTooSmall":
        put_u16(d, 8, 31)
    elif variant == "SizeOverflow":
        put_u32(d, 12, 0xFFFFFFFF)
    elif variant == "BadTlvInfoMagic":
        put_u16(d, 36, TLV_INFO_MAGIC)
    elif variant == "ProtectedSizeMismatch":
        put_u16(d, 38, 13)
    elif variant == "LengthMismatch":
        put_u16(d, 50, 3)
    elif variant == "PqSignatureTooLong":
        d = bytearray(synth(None, [(LMS_HSS_SIG, bytes(MAX_PQ_SIGNATURE_LEN + 1))]))
    else:
        raise ValueError(variant)
    return bytes(d)


ERROR_SEEDS = [
    ("bad-magic", "BadMagic", "header magic changed"),
    ("truncated", "Truncated", "last byte of the unprotected area removed"),
    ("header-too-small", "HeaderTooSmall", "hdr_size 31"),
    ("size-overflow", "SizeOverflow", "img_size 0xFFFFFFFF"),
    ("bad-tlv-info-magic", "BadTlvInfoMagic", "protected area with the unprotected magic"),
    ("protected-size-mismatch", "ProtectedSizeMismatch", "protected tlv_tot 13, header 12"),
    ("length-mismatch", "LengthMismatch", "unprotected tlv_tot 3"),
    ("pq-signature-too-long", "PqSignatureTooLong", "LMS/HSS signature TLV of 3925 bytes"),
]


def synth_seeds():
    """(name, bytes, description, expect_parse, expect_read_from_4k) of every synth seed."""
    every_kind_protected = [(SEC_CNT, value(SEC_CNT, 4)), (DEPENDENCY, value(DEPENDENCY, 12)), (BOOT_RECORD, value(BOOT_RECORD, 8))]
    every_kind_unprotected = [
        (KEYHASH, value(KEYHASH, 32)),
        (PUBKEY, value(PUBKEY, 32)),
        (SHA256, value(SHA256, 32)),
        (SHA384, value(SHA384, 48)),
        (SHA512, value(SHA512, 64)),
        (RSA2048_PSS, value(RSA2048_PSS, 256)),
        (ECDSA_SIG, value(ECDSA_SIG, 72)),
        (RSA3072_PSS, value(RSA3072_PSS, 384)),
        (ED25519, value(ED25519, 64)),
        (SIG_PURE, value(SIG_PURE, 1)),
        (KEELSIGN_KEY_ID, value(KEELSIGN_KEY_ID, 16)),
        (MLDSA44_SIG, value(MLDSA44_SIG, 64)),
        (MLDSA65_SIG, value(MLDSA65_SIG, 64)),
        (LMS_HSS_SIG, value(LMS_HSS_SIG, 64)),
        (KEELSIGN_RESERVED, value(KEELSIGN_RESERVED, 4)),
        (UNKNOWN, value(UNKNOWN, 4)),
    ]
    seeds = [
        (
            "synth-every-tlv-kind.bin",
            synth(every_kind_protected, every_kind_unprotected),
            "a TLV of every TlvKind: SEC_CNT, DEPENDENCY, BOOT_RECORD protected; the rest "
            "unprotected (PQ signatures of 64 bytes, reserved 0x4ba4, unknown 0x7f00)",
            "Ok",
            "Ok",
        )
    ]
    for name, variant, how in ERROR_SEEDS:
        seeds.append((f"synth-error-{name}.bin", error_seed(variant), f"ParseError::{variant}: {how}", variant, f"Parse({variant})"))
    seeds.append(
        (
            "synth-tlv-area-too-large.bin",
            synth(None, [(SHA256, value(SHA256, 32)), (UNKNOWN + 1, value(UNKNOWN + 1, 4200))]),
            "valid; 4244 bytes of TLV areas, more than the 4096-byte read_from buffer",
            "Ok",
            "TlvAreaTooLarge",
        )
    )
    seeds.append(("synth-empty-tlv-areas.bin", synth([], []), "valid; both TLV areas empty (tlv_tot 4)", "Ok", "Ok"))
    return seeds


def tlv_areas_len(data):
    """protect_tlv_size + max(unprotected tlv_tot, 4) of a valid image."""
    hdr_size, prot, img_size = struct.unpack_from("<HHI", data, 8)
    hashed = hdr_size + img_size + prot
    (tlv_tot,) = struct.unpack_from("<H", data, hashed + 2)
    return prot + max(tlv_tot, 4)


def fixture_seeds():
    """(name, bytes, source, expect_parse, expect_read_from_4k) of every fixture seed."""
    outputs = json.loads(IMAGES_MANIFEST.read_text())["outputs"]
    seeds = []
    for path in sorted(IMAGES.rglob("*.bin")):
        rel = path.relative_to(IMAGES).as_posix()
        if rel in EXCLUDED:
            continue
        entry = outputs.get(rel)
        if entry is None or "expect_parse" not in entry:
            sys.exit(f"{rel}: not in {IMAGES_MANIFEST.relative_to(REPO_ROOT)} with expect_parse; add it to EXCLUDED or the manifest")
        data = path.read_bytes()
        expect = entry["expect_parse"]
        if expect == "Ok":
            read_4k = "TlvAreaTooLarge" if tlv_areas_len(data) > SMALL_TLV_BUF else "Ok"
        elif expect in ("BadMagic", "HeaderTooSmall"):
            # Header errors: read_from reports them before reading anything else.
            read_4k = f"Parse({expect})"
        else:
            sys.exit(f"{rel}: expect_parse {expect}: work out its read_from result and extend this script")
        source = (IMAGES / rel).relative_to(REPO_ROOT).as_posix()
        seeds.append(("fixture-" + rel.replace("/", "-"), data, source, expect, read_4k))
    return seeds


def generate(out_root):
    """Write the seeds and MANIFEST.json under out_root (a fuzz/corpus directory)."""
    seed_dir = out_root / SEED_DIR
    seed_dir.mkdir(parents=True, exist_ok=True)
    seeds = fixture_seeds() + [(n, d, f"synth: {desc}", p, r) for n, d, desc, p, r in synth_seeds()]
    names = {name for name, *_ in seeds}
    if len(names) != len(seeds):
        sys.exit("duplicate seed names")
    for old in seed_dir.iterdir():
        if old.name.startswith(("fixture-", "synth-")) and old.name not in names:
            old.unlink()
    manifest = {
        "excluded": {f"tests/fixtures/images/{k}": v for k, v in EXCLUDED.items()},
        "format": "seed inputs of the parse_image fuzz target (fuzz/fuzz_targets/parse_image.rs); "
        "expect_parse is Image::parse, expect_read_from_4k is Image::read_from with a 4096-byte "
        "TLV buffer, in Rust Debug notation",
        "generator": "scripts/gen_fuzz_corpus.py",
        "seeds": {},
    }
    for name, data, source, expect_parse, read_4k in seeds:
        (seed_dir / name).write_bytes(data)
        manifest["seeds"][name] = {
            "bytes": len(data),
            "expect_parse": expect_parse,
            "expect_read_from_4k": read_4k,
            "sha256": hashlib.sha256(data).hexdigest(),
            "source": source,
        }
    (out_root / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return seeds


def seed_files(root):
    """The generator's seeds in root/parse_image. Anything else there is ignored: a bare
    `cargo fuzz run parse_image` (docs/fuzzing.md, AC1) writes the inputs it finds into
    that directory under 40-hex-digit names, and they are gitignored."""
    return {p.name: p.read_bytes() for p in (root / SEED_DIR).glob("*.bin") if p.name.startswith(("fixture-", "synth-"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="regenerate into a temp dir and diff")
    args = parser.parse_args()
    if not args.check:
        seeds = generate(CORPUS_ROOT)
        total = sum(len(d) for _, d, *_ in seeds)
        print(f"wrote {len(seeds)} seeds ({total} bytes) to {(CORPUS_ROOT / SEED_DIR).relative_to(REPO_ROOT)}")
        return
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        generate(fresh)
        problems = []
        want, have = seed_files(fresh), seed_files(CORPUS_ROOT)
        for name in sorted(want.keys() - have.keys()):
            problems.append(f"missing seed {name}")
        for name in sorted(have.keys() - want.keys()):
            problems.append(f"stale seed {name}")
        for name in sorted(want.keys() & have.keys()):
            if want[name] != have[name]:
                problems.append(f"seed {name} differs")
        committed = CORPUS_ROOT / "MANIFEST.json"
        if not committed.exists() or committed.read_text() != (fresh / "MANIFEST.json").read_text():
            problems.append("fuzz/corpus/MANIFEST.json differs")
        if problems:
            print("\n".join(problems), file=sys.stderr)
            sys.exit("fuzz corpus does not match a fresh regeneration; run python3 scripts/gen_fuzz_corpus.py")
        print(f"{len(want)} seeds: fuzz corpus matches a fresh regeneration")


if __name__ == "__main__":
    main()
