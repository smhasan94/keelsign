#!/usr/bin/env python3
"""Regenerate the keelsign sample MCUboot images in tests/fixtures/images/.

Every image is a real MCUboot image made by the pinned imgtool (header, optional
protected TLVs, the SHA256 TLV and, for the hybrid image, the Ed25519 KEYHASH + ED25519
pair), to which this script appends the keelsign TLVs in the unprotected TLV area and
fixes up `it_tlv_tot`. The format is specified in docs/image-format.md. Never edit the
fixtures by hand; rerun this script instead (CLAUDE.md).

Tool prerequisite: imgtool 2.4.0 (PyPI `imgtool==2.4.0`), found with `--imgtool PATH` or
on PATH. Install it into a virtual environment, for example:

  python3 -m venv .venv-imgtool && .venv-imgtool/bin/pip install imgtool==2.4.0
  python3 scripts/gen_image_fixtures.py --imgtool .venv-imgtool/bin/imgtool

The script itself uses the standard library only. The resolved imgtool and cryptography
versions are recorded in MANIFEST.json.

LMS/HSS signatures come from the independent signer hsslms 0.1.3, vendored at run time
by scripts/gen_lms_vectors.py (pinned sdist sha256, nothing pip-installed) with its
random source replaced by a per-key SHA-256 counter DRBG, so every run is deterministic.
Each LMS/HSS image has its own key and uses leaf 0 of it once.

The Ed25519 key in keys/ed25519-test-key.pem is a TEST KEY derived from a fixed public
seed (anyone can recompute it); it must never sign a real image.

Images (all: header size 0x200, version 1.2.3+4, the same 1,536-byte body):
  * keelsign-lms-m32-h5.bin: LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1.
  * keelsign-hss2-m32-h5h5.bin: HSS L=2, both levels M32_H5 / N32_W8.
  * keelsign-lms-protected-tlvs.bin: as the first, plus protected SEC_CNT and a vendor
    TLV 0x10A0, so the digest covers a protected TLV area.
  * keelsign-hybrid-ed25519-lms.bin: imgtool Ed25519 (KEYHASH + ED25519 over the same
    digest) plus the keelsign key ID and an LMS M32_H5 signature.
  * keelsign-mldsa44.bin, keelsign-mldsa65.bin: length-correct ML-DSA filler signatures
    (2,420 and 3,309 bytes) and filler public keys: they select and walk correctly but
    do not verify (`verifiable: false`) until a real ML-DSA signer is pinned.
  * keelsign-dual-pq-invalid.bin: one key ID and two PQ signature TLVs (LMS, then
    ML-DSA-44 filler); must fail with MultiplePqSignatures.

The keelsign TLV IDs are read from keelsign-verify/src/tlv.rs.

Usage:
  python3 scripts/gen_image_fixtures.py [--imgtool PATH]           # write the fixtures
  python3 scripts/gen_image_fixtures.py --check [--imgtool PATH]   # verify them

`--check` decodes every committed image and re-encodes it byte-identically, runs
`imgtool verify` on it, then regenerates everything into a temp dir and diffs it with the
committed files. The tool versions recorded in MANIFEST.json are not part of the diff
(Ed25519 signatures are deterministic, so the images do not depend on them); a
difference is reported as a note.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "images"
TLV_RS = REPO_ROOT / "keelsign-verify" / "src" / "tlv.rs"

IMGTOOL_VERSION = "2.4.0"

IMAGE_MAGIC = 0x96F3B83D
IMAGE_HEADER_SIZE = 32
TLV_INFO_MAGIC = 0x6907
TLV_PROT_INFO_MAGIC = 0x6908

# MCUboot TLV types (boot/bootutil/include/bootutil/image.h).
TLV_KEYHASH = 0x01
TLV_SHA256 = 0x10
TLV_ED25519 = 0x24
TLV_SEC_CNT = 0x50

HEADER_SIZE = 0x200
SLOT_SIZE = 0x20000
VERSION = "1.2.3+4"
ALIGN = "4"
BODY_LEN = 1536
SECURITY_COUNTER = 7
PROTECTED_VENDOR_TLV = 0x10A0
PROTECTED_VENDOR_VALUE = b"keelsign-protected-vendor-tlv"

MLDSA44_PK_LEN, MLDSA44_SIG_LEN = 1312, 2420
MLDSA65_PK_LEN, MLDSA65_SIG_LEN = 1952, 3309

# PKCS #8 / SubjectPublicKeyInfo prefixes for Ed25519 (RFC 8410).
ED25519_PKCS8_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ED25519_SEED = hashlib.sha256(b"keelsign SHA-37 Ed25519 TEST KEY - never use for real images").digest()

KEY_PEM = "keys/ed25519-test-key.pem"
KEY_SPKI = "keys/ed25519-test-key.spki.der"

# name, description, PQ signatures ("lms:<label>" / "mldsa44" / "mldsa65"), LMS parameter
# sets per level, protected extras, Ed25519, expected verify_pq result.
LMS_M32_H5 = ["LMS_SHA256_M32_H5"]
IMAGES = [
    ("keelsign-lms-m32-h5.bin", "LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1",
     ["lms"], LMS_M32_H5, False, False, "Ok"),
    ("keelsign-hss2-m32-h5h5.bin", "HSS L=2, both levels LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8",
     ["lms"], LMS_M32_H5 * 2, False, False, "Ok"),
    ("keelsign-lms-protected-tlvs.bin",
     "LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1, with protected SEC_CNT and vendor TLV 0x10A0",
     ["lms"], LMS_M32_H5, True, False, "Ok"),
    ("keelsign-hybrid-ed25519-lms.bin",
     "hybrid: imgtool Ed25519 (KEYHASH + ED25519) plus LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1",
     ["lms"], LMS_M32_H5, False, True, "Ok"),
    ("keelsign-mldsa44.bin", "ML-DSA-44 filler signature and public key (length-correct, does not verify)",
     ["mldsa44"], None, False, False, "UnsupportedAlgorithm"),
    ("keelsign-mldsa65.bin", "ML-DSA-65 filler signature and public key (length-correct, does not verify)",
     ["mldsa65"], None, False, False, "UnsupportedAlgorithm"),
    ("keelsign-dual-pq-invalid.bin",
     "invalid: one key ID and two PQ signature TLVs (LMS M32_H5, then ML-DSA-44 filler)",
     ["lms", "mldsa44"], LMS_M32_H5, False, False, "MultiplePqSignatures"),
]


def load_lms_generator():
    sys.dont_write_bytecode = True  # no scripts/__pycache__ from importing the sibling script
    spec = importlib.util.spec_from_file_location("gen_lms_vectors", REPO_ROOT / "scripts" / "gen_lms_vectors.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def keelsign_tlv_ids():
    text = TLV_RS.read_text()
    ids = {name: int(value, 16) for name, value in re.findall(r"pub const (TLV_\w+): u16 = (0x[0-9A-Fa-f]+);", text)}
    expected = {"TLV_KEELSIGN_KEY_ID", "TLV_MLDSA44_SIG", "TLV_MLDSA65_SIG", "TLV_LMS_HSS_SIG"}
    if set(ids) != expected:
        sys.exit(f"{TLV_RS}: expected TLV constants {sorted(expected)}, found {sorted(ids)}")
    key_id_len = re.search(r"pub const KEY_ID_LEN: usize = (\d+);", text)
    if not key_id_len:
        sys.exit(f"{TLV_RS}: no KEY_ID_LEN")
    return ids, int(key_id_len.group(1))


# ---- imgtool ---------------------------------------------------------------------------


def find_imgtool(path):
    if path:
        tool = Path(path)
        if not tool.is_file():
            sys.exit(f"--imgtool {path}: no such file")
        return str(tool)
    found = shutil.which("imgtool")
    if not found:
        sys.exit(
            f"imgtool not found on PATH. Install imgtool=={IMGTOOL_VERSION} into a virtual environment "
            f"(python3 -m venv .venv-imgtool && .venv-imgtool/bin/pip install imgtool=={IMGTOOL_VERSION}) "
            "and pass --imgtool .venv-imgtool/bin/imgtool"
        )
    return found


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stdout}{result.stderr}")
    return result.stdout


def tool_versions(imgtool):
    version = run([imgtool, "version"]).strip()
    if version != IMGTOOL_VERSION:
        sys.exit(f"{imgtool} is imgtool {version}; the fixtures need imgtool=={IMGTOOL_VERSION}")
    # The console script's interpreter is the environment imgtool is installed in.
    shebang = Path(imgtool).read_text(errors="replace").splitlines()[0]
    if not shebang.startswith("#!"):
        sys.exit(f"{imgtool}: cannot find its Python interpreter (no shebang)")
    python = shebang[2:].strip().split()[0]
    cryptography = run([python, "-c", "import cryptography; print(cryptography.__version__)"]).strip()
    return {"imgtool": version, "cryptography": cryptography, "imgtool_requirement": f"imgtool=={IMGTOOL_VERSION}"}


def imgtool_sign(imgtool, tmp, name, body, protected, ed25519_key):
    raw = tmp / f"{name}.body"
    out = tmp / f"{name}.signed.bin"
    raw.write_bytes(body)
    cmd = [imgtool, "sign", "--header-size", hex(HEADER_SIZE), "--pad-header", "--align", ALIGN,
           "--version", VERSION, "--slot-size", hex(SLOT_SIZE)]
    if protected:
        cmd += ["--security-counter", str(SECURITY_COUNTER),
                "--custom-tlv", hex(PROTECTED_VENDOR_TLV), "0x" + PROTECTED_VENDOR_VALUE.hex()]
    if ed25519_key:
        cmd += ["--key", str(ed25519_key), "--public-key-format", "hash"]
    run(cmd + [str(raw), str(out)])
    return out.read_bytes()


def imgtool_verify(imgtool, image_path, key):
    cmd = [imgtool, "verify"]
    if key:
        cmd += ["--key", str(key)]
    out = run(cmd + [str(image_path)])
    if "Image was correctly validated" not in out:
        sys.exit(f"imgtool verify {image_path}: {out}")


# ---- MCUboot image codec -------------------------------------------------------------


def decode_tlvs(data, magic):
    info_magic, tot = struct.unpack_from("<HH", data, 0)
    if info_magic != magic:
        raise ValueError(f"TLV info magic {info_magic:#06x}, expected {magic:#06x}")
    if tot > len(data):
        raise ValueError("TLV area overruns the image")
    tlvs, off = [], 4
    while off < tot:
        if off + 4 > tot:
            raise ValueError("truncated TLV header")
        kind, length = struct.unpack_from("<HH", data, off)
        off += 4
        if off + length > tot:
            raise ValueError(f"TLV {kind:#06x} overruns its area")
        tlvs.append((kind, bytes(data[off:off + length])))
        off += length
    return tlvs, tot


def encode_tlvs(tlvs, magic):
    body = b"".join(struct.pack("<HH", kind, len(value)) + value for kind, value in tlvs)
    return struct.pack("<HH", magic, 4 + len(body)) + body


def decode_image(data):
    magic, load_addr, hdr_size, prot_size, img_size, flags = struct.unpack_from("<IIHHII", data, 0)
    if magic != IMAGE_MAGIC:
        raise ValueError(f"image magic {magic:#010x}")
    tlv_off = hdr_size + img_size
    protected = None
    if prot_size:
        protected, tot = decode_tlvs(data[tlv_off:], TLV_PROT_INFO_MAGIC)
        if tot != prot_size:
            raise ValueError(f"ih_protect_tlv_size {prot_size} != protected it_tlv_tot {tot}")
    unprotected, tot = decode_tlvs(data[tlv_off + prot_size:], TLV_INFO_MAGIC)
    end = tlv_off + prot_size + tot
    if end != len(data):
        raise ValueError(f"{len(data) - end} trailing bytes after the TLV area")
    return {
        "head": bytes(data[:tlv_off]),
        "hdr_size": hdr_size,
        "img_size": img_size,
        "prot_size": prot_size,
        "protected": protected,
        "unprotected": unprotected,
    }


def encode_image(image):
    out = image["head"]
    if image["protected"] is not None:
        out += encode_tlvs(image["protected"], TLV_PROT_INFO_MAGIC)
    return out + encode_tlvs(image["unprotected"], TLV_INFO_MAGIC)


def digest_of(data, image):
    """M: SHA-256 over header, body and the protected TLV area (info header included)."""
    return hashlib.sha256(data[: image["hdr_size"] + image["img_size"] + image["prot_size"]]).digest()


# ---- Keys and signatures ---------------------------------------------------------------


def write_ed25519_key(out_dir):
    der = ED25519_PKCS8_PREFIX + ED25519_SEED
    lines = base64.b64encode(der).decode()
    pem = (
        "# TEST KEY - keelsign image fixtures only (scripts/gen_image_fixtures.py).\n"
        "# Derived from a fixed public seed: anyone can recompute it. NEVER sign a real image with it.\n"
        f"-----BEGIN PRIVATE KEY-----\n{lines}\n-----END PRIVATE KEY-----\n"
    )
    path = out_dir / KEY_PEM
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pem)
    return path


def filler(lms, label, n):
    return lms.Drbg("image-fixture-filler:" + label)(n)


def generate(out_dir, imgtool):
    lms = load_lms_generator()
    ids, key_id_len = keelsign_tlv_ids()
    tools = tool_versions(imgtool)
    body = lms.Drbg("image-fixture-body")(BODY_LEN)

    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = write_ed25519_key(out_dir)
    spki = run_bytes([imgtool, "getpub", "--key", str(key_path), "--encoding", "raw"])
    if len(spki) != len(ED25519_SPKI_PREFIX) + 32 or not spki.startswith(ED25519_SPKI_PREFIX):
        sys.exit(f"imgtool getpub returned an unexpected Ed25519 SubjectPublicKeyInfo ({len(spki)} bytes)")
    (out_dir / KEY_SPKI).write_bytes(spki)
    keyhash = hashlib.sha256(spki).digest()

    manifest = {
        "generator": "scripts/gen_image_fixtures.py",
        "format": "MCUboot image (docs/design.md) with keelsign TLVs in the unprotected area: docs/image-format.md",
        "tools": tools,
        "sources": {"hsslms": {**lms.SOURCES["hsslms"], "url": lms.raw_url(lms.SOURCES["hsslms"])}},
        "tlv_ids": {name: f"{value:#06x}" for name, value in sorted(ids.items())},
        "image": {
            "header_size": HEADER_SIZE,
            "version": VERSION,
            "align": int(ALIGN),
            "body_len": BODY_LEN,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        },
        "keys": {
            KEY_PEM: {
                "note": "TEST KEY from a fixed public seed; never use for real images",
                "sha256": hashlib.sha256((out_dir / KEY_PEM).read_bytes()).hexdigest(),
            },
            KEY_SPKI: {
                "note": "DER SubjectPublicKeyInfo of the Ed25519 test key; SHA-256 of it is the KEYHASH TLV",
                "keyhash_hex": keyhash.hex(),
                "sha256": hashlib.sha256(spki).hexdigest(),
            },
        },
        "outputs": {},
    }

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        hsslms = lms.vendor_hsslms(lms.fetch("hsslms"), tmp)
        for name, description, pq, lms_levels, protected, ed25519, expect in IMAGES:
            stem = name.removesuffix(".bin")
            signed = imgtool_sign(imgtool, tmp, stem, body, protected, key_path if ed25519 else None)
            image = decode_image(signed)
            if encode_image(image) != signed:
                sys.exit(f"{name}: imgtool output does not round-trip through the codec")
            m = digest_of(signed, image)
            sha_tlvs = [v for k, v in image["unprotected"] if k == TLV_SHA256]
            if sha_tlvs != [m]:
                sys.exit(f"{name}: the SHA256 TLV is not SHA-256(header || body || protected TLVs)")

            # The PQ signatures and the key ID (of the first signature's public key).
            signatures, public_key, algorithm = [], None, None
            for kind in pq:
                if kind == "lms":
                    ots = "LMOTS_SHA256_N32_W8"
                    pk, sig = lms.hsslms_sign(hsslms, "image:" + stem, lms_levels, ots, m)
                    if not lms.hsslms_verdict(hsslms, {"pk": pk, "msg": m, "sig": sig}):
                        sys.exit(f"{name}: hsslms does not verify its own signature")
                    signatures.append((ids["TLV_LMS_HSS_SIG"], sig))
                    this = (pk, "LmsHss")
                else:
                    pk_len, sig_len, tlv = {
                        "mldsa44": (MLDSA44_PK_LEN, MLDSA44_SIG_LEN, "TLV_MLDSA44_SIG"),
                        "mldsa65": (MLDSA65_PK_LEN, MLDSA65_SIG_LEN, "TLV_MLDSA65_SIG"),
                    }[kind]
                    pk = filler(lms, f"{stem}:{kind}:pk", pk_len)
                    signatures.append((ids[tlv], filler(lms, f"{stem}:{kind}:sig", sig_len)))
                    this = (pk, {"mldsa44": "MlDsa44", "mldsa65": "MlDsa65"}[kind])
                if public_key is None:
                    public_key, algorithm = this
            key_id = hashlib.sha256(public_key).digest()[:key_id_len]

            image["unprotected"] = image["unprotected"] + [(ids["TLV_KEELSIGN_KEY_ID"], key_id)] + signatures
            data = encode_image(image)
            if decode_image(data)["unprotected"] != image["unprotected"] or digest_of(data, image) != m:
                sys.exit(f"{name}: appending the keelsign TLVs changed the image")
            (out_dir / name).write_bytes(data)
            imgtool_verify(imgtool, out_dir / name, key_path if ed25519 else None)

            if ed25519:
                kinds = [k for k, _ in image["unprotected"]]
                if kinds.count(TLV_KEYHASH) != 1 or kinds.count(TLV_ED25519) != 1:
                    sys.exit(f"{name}: expected exactly one KEYHASH and one ED25519 TLV")
                if dict(image["unprotected"])[TLV_KEYHASH] != keyhash:
                    sys.exit(f"{name}: KEYHASH is not SHA-256 of the test key's SubjectPublicKeyInfo")

            manifest["outputs"][name] = {
                "description": description,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "algorithm": algorithm,
                "verifiable": all(kind == "lms" for kind in pq),
                "expect_verify_pq": expect,
                "ed25519": ed25519,
                "digest_hex": m.hex(),
                "key_id_hex": key_id.hex(),
                "public_key_hex": public_key.hex(),
                "signature_lens": " ".join(str(len(sig)) for _, sig in signatures),
                "protected_tlvs": " ".join(f"{k:#06x}" for k, _ in image["protected"] or []),
                "unprotected_tlvs": " ".join(f"{k:#06x}" for k, _ in image["unprotected"]),
            }

    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def run_bytes(cmd):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.decode(errors='replace')}")
    return result.stdout


def committed_files():
    return ["MANIFEST.json", KEY_PEM, KEY_SPKI] + [name for name, *_ in IMAGES]


def without_tools(manifest_text):
    manifest = json.loads(manifest_text)
    tools = manifest.pop("tools", None)
    return manifest, tools


def check(imgtool):
    # 1. Every committed image decodes and re-encodes byte-identically, and imgtool
    #    accepts it (hash, and the Ed25519 signature for the hybrid image).
    for name, *_, ed25519, _expect in IMAGES:
        data = (FIXTURE_DIR / name).read_bytes()
        try:
            image = decode_image(data)
        except ValueError as e:
            sys.exit(f"{name}: does not decode: {e}")
        if encode_image(image) != data:
            sys.exit(f"{name}: decode + re-encode is not byte-identical")
        imgtool_verify(imgtool, FIXTURE_DIR / name, FIXTURE_DIR / KEY_PEM if ed25519 else None)
    # 2. A fresh regeneration matches the committed files.
    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        generate(tmp_dir, imgtool)
        differ = []
        for rel in committed_files():
            fresh, committed = (tmp_dir / rel).read_bytes(), (FIXTURE_DIR / rel).read_bytes()
            if rel == "MANIFEST.json":
                fresh_m, fresh_tools = without_tools(fresh)
                committed_m, committed_tools = without_tools(committed)
                if fresh_m != committed_m:
                    differ.append(rel)
                elif fresh_tools != committed_tools:
                    print(f"note: tool versions differ from MANIFEST.json: {fresh_tools} vs {committed_tools}")
            elif fresh != committed:
                differ.append(rel)
    if differ:
        sys.exit(f"fixtures differ from a fresh regeneration: {', '.join(differ)}")
    print(f"{len(IMAGES)} images decode and re-encode byte-identically and pass imgtool verify")
    print("fixtures match a fresh regeneration")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="round-trip, imgtool verify, regenerate and diff")
    parser.add_argument("--imgtool", metavar="PATH", help=f"imgtool {IMGTOOL_VERSION} executable (default: from PATH)")
    args = parser.parse_args()
    imgtool = find_imgtool(args.imgtool)
    if args.check:
        check(imgtool)
    else:
        manifest = generate(FIXTURE_DIR, imgtool)
        sizes = {name: entry["bytes"] for name, entry in manifest["outputs"].items()}
        print(f"wrote fixtures to {FIXTURE_DIR.relative_to(REPO_ROOT)}: {sizes}")


if __name__ == "__main__":
    main()
