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

Golden MCUboot images (SHA-35), plain imgtool output with no keelsign TLVs, for the
keelsign-verify image parser. All are signed with `--public-key-format hash`, security
counter 7, a dependency on image 1 version 1.2.3+4 and a boot record (sw_type `app`), so
they carry SEC_CNT, BOOT_RECORD and DEPENDENCY (protected) and SHA256, KEYHASH and a
signature TLV (unprotected):
  * mcuboot-rsa2048.bin: RSA-2048 PSS (keys/rsa2048-test-key.pem).
  * mcuboot-ecdsa-p256.bin: ECDSA P-256 (keys/ecdsa-p256-test-key.pem).
  * mcuboot-ed25519.bin: Ed25519 (keys/ed25519-test-key.pem).
  * mcuboot-ed25519-padded.bin: as mcuboot-ed25519.bin, padded to a 0x2000-byte slot
    with the boot trailer (`--pad`): the bytes after the TLV area are not TLVs.
  * rejected/mcuboot-ed25519-bigendian.bin: as mcuboot-ed25519.bin, but big-endian
    (`-e big`); keelsign supports little-endian images only, so the parser rejects it
    (`expect_parse: BadMagic`).

The RSA-2048 and ECDSA P-256 keys are TEST KEYS derived deterministically from fixed
public seeds (a SHA-256 counter DRBG: Miller-Rabin primes for RSA, a scalar for ECDSA);
anyone can recompute them. They are serialised by a helper run under imgtool's own
Python interpreter (which has `cryptography`); this script itself stays stdlib-only.

RSA-PSS and ECDSA signatures are randomised, so they are made once (`imgtool sign
--sig-out`) and committed as base64 under sigs/. Every later run rebuilds the images
from them with `imgtool sign --fix-sig sigs/NAME.sig --fix-sig-pubkey KEY`, which is
byte-identical. `--resign` signs afresh (needed only when the keys, the body or the
imgtool arguments change) and rewrites sigs/.

The keelsign TLV IDs are read from keelsign-verify/src/tlv.rs.

Usage:
  python3 scripts/gen_image_fixtures.py [--imgtool PATH] [--resign]  # write the fixtures
  python3 scripts/gen_image_fixtures.py --check [--imgtool PATH]     # verify them

`--check` decodes every committed image and re-encodes it byte-identically, runs
`imgtool verify` on every little-endian image (with its key where it has one), compares
`imgtool dumpinfo`'s TLV listing of every little-endian golden image with MANIFEST.json,
then regenerates everything into a temp dir (with the committed signatures) and diffs it
with the committed files. The tool versions recorded in MANIFEST.json are not part of the diff
(Ed25519 signatures are deterministic, so the images do not depend on them); a
difference is reported as a note.
"""

import argparse
import base64
import hashlib
import importlib.util
import json
import math
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

# MCUboot TLV types (boot/bootutil/include/bootutil/image.h:99-121 @ a8ffd2c).
TLV_KEYHASH = 0x01
TLV_SHA256 = 0x10
TLV_RSA2048_PSS = 0x20
TLV_ECDSA_SIG = 0x22
TLV_ED25519 = 0x24
TLV_DEPENDENCY = 0x40
TLV_SEC_CNT = 0x50
TLV_BOOT_RECORD = 0x60

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

# ---- Golden MCUboot images (SHA-35) ----------------------------------------------------

RSA_KEY_PEM = "keys/rsa2048-test-key.pem"
ECDSA_KEY_PEM = "keys/ecdsa-p256-test-key.pem"
RSA_SEED_LABEL = "golden-rsa2048-test-key"
ECDSA_SEED_LABEL = "golden-ecdsa-p256-test-key"
RSA_BITS, RSA_E = 2048, 65537
# NIST P-256 group order (SEC 2 v2, section 2.4.2).
P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

GOLDEN_DEPENDENCY = "(1,1.2.3+4)"
GOLDEN_BOOT_RECORD = "app"
PADDED_SLOT_SIZE = 0x2000

# key name -> (committed key file, signature TLV type, fixed signature file or None).
GOLDEN_KEYS = {
    "rsa2048": (RSA_KEY_PEM, TLV_RSA2048_PSS, "sigs/mcuboot-rsa2048.sig"),
    "ecdsa-p256": (ECDSA_KEY_PEM, TLV_ECDSA_SIG, "sigs/mcuboot-ecdsa-p256.sig"),
    "ed25519": (KEY_PEM, TLV_ED25519, None),
}

# name, description, key, padded, endian, expected parse result.
GOLDEN = [
    ("mcuboot-rsa2048.bin", "imgtool RSA-2048 PSS, SEC_CNT, BOOT_RECORD and DEPENDENCY",
     "rsa2048", False, "little", "Ok"),
    ("mcuboot-ecdsa-p256.bin", "imgtool ECDSA P-256, SEC_CNT, BOOT_RECORD and DEPENDENCY",
     "ecdsa-p256", False, "little", "Ok"),
    ("mcuboot-ed25519.bin", "imgtool Ed25519, SEC_CNT, BOOT_RECORD and DEPENDENCY",
     "ed25519", False, "little", "Ok"),
    ("mcuboot-ed25519-padded.bin",
     "as mcuboot-ed25519.bin, padded to a 0x2000-byte slot with the boot trailer (--pad)",
     "ed25519", True, "little", "Ok"),
    ("rejected/mcuboot-ed25519-bigendian.bin",
     "as mcuboot-ed25519.bin but big-endian (-e big): unsupported, the parser rejects it",
     "ed25519", False, "big", "BadMagic"),
]

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


def imgtool_python(imgtool):
    """The console script's interpreter: the environment imgtool is installed in."""
    shebang = Path(imgtool).read_text(errors="replace").splitlines()[0]
    if not shebang.startswith("#!"):
        sys.exit(f"{imgtool}: cannot find its Python interpreter (no shebang)")
    return shebang[2:].strip().split()[0]


def tool_versions(imgtool):
    version = run([imgtool, "version"]).strip()
    if version != IMGTOOL_VERSION:
        sys.exit(f"{imgtool} is imgtool {version}; the fixtures need imgtool=={IMGTOOL_VERSION}")
    python = imgtool_python(imgtool)
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


def imgtool_sign_golden(imgtool, tmp, stem, body, key, padded, endian, fix_sig=None, sig_out=None):
    """imgtool sign with the golden-image options: signed with `key`, or with the fixed
    signature `fix_sig` made by `key` earlier."""
    raw = tmp / f"{stem}.body"
    out = tmp / f"{stem}.signed.bin"
    raw.write_bytes(body)
    cmd = [imgtool, "sign", "--header-size", hex(HEADER_SIZE), "--pad-header", "--align", ALIGN,
           "--version", VERSION, "--slot-size", hex(PADDED_SLOT_SIZE if padded else SLOT_SIZE),
           "--security-counter", str(SECURITY_COUNTER), "--dependencies", GOLDEN_DEPENDENCY,
           "--boot-record", GOLDEN_BOOT_RECORD, "--public-key-format", "hash", "--endian", endian]
    if padded:
        cmd += ["--pad"]
    if fix_sig:
        cmd += ["--fix-sig", str(fix_sig), "--fix-sig-pubkey", str(key)]
    else:
        cmd += ["--key", str(key)]
    if sig_out:
        cmd += ["--sig-out", str(sig_out)]
    run(cmd + [str(raw), str(out)])
    return out.read_bytes()


def dumpinfo_tlvs(imgtool, image_path):
    """imgtool dumpinfo's TLV listing: {"protected": [(type, len)], "unprotected": [...]}."""
    out = run([imgtool, "dumpinfo", str(image_path)])
    areas, area = {"protected": [], "unprotected": []}, None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("#### Protected TLV area"):
            area = "protected"
        elif line.startswith("#### TLV area"):
            area = "unprotected"
        elif line.startswith("####"):
            area = None
        elif area and line.startswith("type:"):
            kind = int(re.search(r"\((0x[0-9a-fA-F]+)\)", line).group(1), 16)
            areas[area].append([kind, None])
        elif area and line.startswith("len:"):
            areas[area][-1][1] = int(line.split()[1], 16)
    return {k: [tuple(t) for t in v] for k, v in areas.items()}


def imgtool_verify(imgtool, image_path, key):
    cmd = [imgtool, "verify"]
    if key:
        cmd += ["--key", str(key)]
    out = run(cmd + [str(image_path)])
    if "Image was correctly validated" not in out:
        sys.exit(f"imgtool verify {image_path}: {out}")


# ---- MCUboot image codec -------------------------------------------------------------


def decode_tlvs(data, magic, e="<"):
    info_magic, tot = struct.unpack_from(e + "HH", data, 0)
    if info_magic != magic:
        raise ValueError(f"TLV info magic {info_magic:#06x}, expected {magic:#06x}")
    if tot > len(data):
        raise ValueError("TLV area overruns the image")
    tlvs, off = [], 4
    while off < tot:
        if off + 4 > tot:
            raise ValueError("truncated TLV header")
        kind, length = struct.unpack_from(e + "HH", data, off)
        off += 4
        if off + length > tot:
            raise ValueError(f"TLV {kind:#06x} overruns its area")
        tlvs.append((kind, bytes(data[off:off + length])))
        off += length
    return tlvs, tot


def encode_tlvs(tlvs, magic, e="<"):
    body = b"".join(struct.pack(e + "HH", kind, len(value)) + value for kind, value in tlvs)
    return struct.pack(e + "HH", magic, 4 + len(body)) + body


def decode_image(data, endian="little", allow_trailing=False):
    """Decodes an MCUboot image. `allow_trailing` keeps bytes after the TLV area (a padded
    slot's trailer) as `trailer`; `endian` "big" decodes an imgtool `-e big` image."""
    e = "<" if endian == "little" else ">"
    magic, load_addr, hdr_size, prot_size, img_size, flags = struct.unpack_from(e + "IIHHII", data, 0)
    if magic != IMAGE_MAGIC:
        raise ValueError(f"image magic {magic:#010x}")
    major, minor, revision, build = struct.unpack_from(e + "BBHI", data, 20)
    tlv_off = hdr_size + img_size
    protected = None
    if prot_size:
        protected, tot = decode_tlvs(data[tlv_off:], TLV_PROT_INFO_MAGIC, e)
        if tot != prot_size:
            raise ValueError(f"ih_protect_tlv_size {prot_size} != protected it_tlv_tot {tot}")
    unprotected, tot = decode_tlvs(data[tlv_off + prot_size:], TLV_INFO_MAGIC, e)
    end = tlv_off + prot_size + tot
    if end != len(data) and not allow_trailing:
        raise ValueError(f"{len(data) - end} trailing bytes after the TLV area")
    return {
        "e": e,
        "head": bytes(data[:tlv_off]),
        "hdr_size": hdr_size,
        "img_size": img_size,
        "prot_size": prot_size,
        "flags": flags,
        "version": f"{major}.{minor}.{revision}+{build}",
        "protected": protected,
        "unprotected": unprotected,
        "tlv_end": end,
        "trailer": bytes(data[end:]),
    }


def encode_image(image):
    e = image.get("e", "<")
    out = image["head"]
    if image["protected"] is not None:
        out += encode_tlvs(image["protected"], TLV_PROT_INFO_MAGIC, e)
    return out + encode_tlvs(image["unprotected"], TLV_INFO_MAGIC, e) + image.get("trailer", b"")


def digest_of(data, image):
    """M: SHA-256 over header, body and the protected TLV area (info header included)."""
    return hashlib.sha256(data[: image["hdr_size"] + image["img_size"] + image["prot_size"]]).digest()


def layout_fields(image):
    """The manifest's header fields and per-area TLV lengths of a decoded image."""
    return {
        "header": {
            "hdr_size": image["hdr_size"],
            "protect_tlv_size": image["prot_size"],
            "img_size": image["img_size"],
            "flags": image["flags"],
            "version": image["version"],
        },
        "protected_tlv_lens": " ".join(str(len(v)) for _, v in image["protected"] or []),
        "unprotected_tlv_lens": " ".join(str(len(v)) for _, v in image["unprotected"]),
        "tlv_end": image["tlv_end"],
    }


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


# Serialises a key from its numbers as unencrypted PKCS #8 PEM. Runs under imgtool's
# interpreter, which has `cryptography`; reads JSON on stdin.
KEY_HELPER = """
import json, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
req = json.load(sys.stdin)
if req["kind"] == "rsa":
    p, q, e, d = (int(req[k]) for k in ("p", "q", "e", "d"))
    key = rsa.RSAPrivateNumbers(
        p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q), rsa.rsa_crt_iqmp(p, q),
        rsa.RSAPublicNumbers(e, p * q)).private_key()
else:
    key = ec.derive_private_key(int(req["scalar"]), ec.SECP256R1())
sys.stdout.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()).decode())
"""

SMALL_PRIMES = [n for n in range(3, 2000, 2) if all(n % d for d in range(3, math.isqrt(n) + 1, 2))]


def is_probable_prime(n, drbg, rounds=40):
    """Miller-Rabin with DRBG-chosen bases, after trial division."""
    for small in SMALL_PRIMES:
        if n % small == 0:
            return n == small
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    width = (n.bit_length() + 7) // 8
    for _ in range(rounds):
        a = 2 + int.from_bytes(drbg(width), "big") % (n - 3)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def derive_prime(drbg, bits, e):
    """The first DRBG candidate (top two and low bit set) that is prime with gcd(p-1, e) = 1."""
    while True:
        c = int.from_bytes(drbg(bits // 8), "big") | (3 << (bits - 2)) | 1
        if math.gcd(c - 1, e) == 1 and is_probable_prime(c, drbg):
            return c


def test_key_numbers(lms, kind):
    """The numbers of the RSA-2048 or ECDSA P-256 test key, derived from a fixed seed."""
    if kind == "rsa2048":
        drbg = lms.Drbg(RSA_SEED_LABEL)
        p = derive_prime(drbg, RSA_BITS // 2, RSA_E)
        q = derive_prime(drbg, RSA_BITS // 2, RSA_E)
        if p == q or (p * q).bit_length() != RSA_BITS:
            sys.exit("RSA test key derivation produced an unusable pair of primes")
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        return {"kind": "rsa", "p": str(p), "q": str(q), "e": str(RSA_E), "d": str(pow(RSA_E, -1, lam))}
    # A scalar in [1, n - 1].
    scalar = 1 + int.from_bytes(lms.Drbg(ECDSA_SEED_LABEL)(40), "big") % (P256_ORDER - 1)
    return {"kind": "ec", "scalar": str(scalar)}


def write_test_key(lms, python, kind, path):
    numbers = json.dumps(test_key_numbers(lms, kind))
    result = subprocess.run([python, "-c", KEY_HELPER], input=numbers, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"key helper failed for {kind}:\n{result.stderr}")
    label = {"rsa2048": "RSA-2048", "ecdsa-p256": "ECDSA P-256"}[kind]
    pem = (
        f"# TEST KEY - {label}, keelsign image fixtures only (scripts/gen_image_fixtures.py).\n"
        "# Derived from a fixed public seed: anyone can recompute it. NEVER sign a real image with it.\n"
        + result.stdout
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(pem)


def generate(out_dir, imgtool, resign=False):
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
                "expect_parse": "Ok",
                "imgtool_verify": True,
                **layout_fields(decode_image(data)),
            }

        generate_golden(out_dir, imgtool, lms, tmp, body, manifest, resign)

    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def generate_golden(out_dir, imgtool, lms, tmp, body, manifest, resign):
    """The golden MCUboot images (SHA-35): their keys, fixed signatures and manifest entries."""
    python = imgtool_python(imgtool)
    for kind, rel, label in [("rsa2048", RSA_KEY_PEM, "RSA-2048"), ("ecdsa-p256", ECDSA_KEY_PEM, "ECDSA P-256")]:
        write_test_key(lms, python, kind, out_dir / rel)
    public = {}
    for kind, (rel, _, _) in GOLDEN_KEYS.items():
        # What imgtool hashes into KEYHASH: PKCS #1 RSAPublicKey DER for RSA
        # (imgtool/keys/rsa.py get_public_bytes), SubjectPublicKeyInfo DER for ECDSA and Ed25519.
        public[kind] = run_bytes([imgtool, "getpub", "--key", str(out_dir / rel), "--encoding", "raw"])
        if kind != "ed25519":
            manifest["keys"][rel] = {
                "note": "TEST KEY derived from a fixed public seed; never use for real images",
                "sha256": hashlib.sha256((out_dir / rel).read_bytes()).hexdigest(),
                "public_der_hex": public[kind].hex(),
                "keyhash_hex": hashlib.sha256(public[kind]).hexdigest(),
            }
    manifest["signatures"] = {}

    for name, description, kind, padded, endian, expect in GOLDEN:
        stem = Path(name).name.removesuffix(".bin")
        key_rel, sig_tlv, sig_rel = GOLDEN_KEYS[kind]
        key = out_dir / key_rel
        if sig_rel is None:
            signed = imgtool_sign_golden(imgtool, tmp, stem, body, key, padded, endian)
        else:
            if resign:
                fresh = tmp / f"{stem}.sig"
                signed = imgtool_sign_golden(imgtool, tmp, stem, body, key, padded, endian, sig_out=fresh)
                sig_text = fresh.read_bytes()
            else:
                committed = FIXTURE_DIR / sig_rel
                if not committed.is_file():
                    sys.exit(f"{committed.relative_to(REPO_ROOT)} is missing: rerun with --resign")
                sig_text = committed.read_bytes()
                fixed = tmp / f"{stem}.fixed.sig"
                fixed.write_bytes(sig_text)
                signed = imgtool_sign_golden(imgtool, tmp, stem, body, key, padded, endian, fix_sig=fixed)
            (out_dir / sig_rel).parent.mkdir(parents=True, exist_ok=True)
            (out_dir / sig_rel).write_bytes(sig_text)
            manifest["signatures"][sig_rel] = {
                "note": f"base64 {kind} signature of {name} (imgtool sign --sig-out); reused with --fix-sig",
                "image": name,
                "decoded_bytes": len(base64.b64decode(sig_text)),
                "sha256": hashlib.sha256(sig_text).hexdigest(),
            }

        image = decode_image(signed, endian=endian, allow_trailing=padded)
        if encode_image(image) != signed:
            sys.exit(f"{name}: imgtool output does not round-trip through the codec")
        if padded != (len(image["trailer"]) > 0) or (padded and len(signed) != PADDED_SLOT_SIZE):
            sys.exit(f"{name}: unexpected bytes after the TLV area")
        m = digest_of(signed, image)
        # imgtool 2.4.0 writes a predefined TLV type as `u8 type, u8 0` whatever the
        # endianness (imgtool/image.py TLV.add, struct `BBH`), so a big-endian image's
        # TLV types read byte-swapped; they are recorded as MCUboot type values.
        def mcuboot_type(k):
            return k if endian == "little" else ((k & 0xFF) << 8) | (k >> 8)
        prot = [mcuboot_type(k) for k, _ in image["protected"] or []]
        unprot = [mcuboot_type(k) for k, _ in image["unprotected"]]
        image["unprotected"] = [(mcuboot_type(k), v) for k, v in image["unprotected"]]
        if prot != [TLV_SEC_CNT, TLV_BOOT_RECORD, TLV_DEPENDENCY] or unprot != [TLV_SHA256, TLV_KEYHASH, sig_tlv]:
            sys.exit(f"{name}: unexpected TLVs {prot} / {unprot}")
        values = dict(image["unprotected"])
        if values[TLV_SHA256] != m:
            sys.exit(f"{name}: the SHA256 TLV is not SHA-256(header || body || protected TLVs)")
        if values[TLV_KEYHASH] != hashlib.sha256(public[kind]).digest():
            sys.exit(f"{name}: KEYHASH is not SHA-256 of the key's public bytes")
        path = out_dir / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(signed)
        little = endian == "little"
        if little:
            imgtool_verify(imgtool, path, key)

        manifest["outputs"][name] = {
            "description": description,
            "bytes": len(signed),
            "sha256": hashlib.sha256(signed).hexdigest(),
            "endian": endian,
            "key": key_rel,
            "signature_tlv": f"{sig_tlv:#06x}",
            "signature_len": len(values[sig_tlv]),
            "keyhash_hex": values[TLV_KEYHASH].hex(),
            "digest_hex": m.hex(),
            "expect_parse": expect,
            "imgtool_verify": little,
            "protected_tlvs": " ".join(f"{k:#06x}" for k in prot),
            "unprotected_tlvs": " ".join(f"{k:#06x}" for k in unprot),
            **layout_fields(image),
        }


def run_bytes(cmd):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.decode(errors='replace')}")
    return result.stdout


def committed_files():
    sigs = [sig for _, _, sig in GOLDEN_KEYS.values() if sig]
    return (["MANIFEST.json", KEY_PEM, KEY_SPKI, RSA_KEY_PEM, ECDSA_KEY_PEM] + sigs
            + [name for name, *_ in IMAGES] + [name for name, *_ in GOLDEN])


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
    # 1b. The golden images too, and every little-endian one passes `imgtool verify --key`
    #     and has the TLV listing (type and length, per area) in `imgtool dumpinfo` that
    #     MANIFEST.json records. imgtool dumpinfo cannot read big-endian images.
    manifest = json.loads((FIXTURE_DIR / "MANIFEST.json").read_text())
    for name, _description, kind, padded, endian, _expect in GOLDEN:
        path = FIXTURE_DIR / name
        data = path.read_bytes()
        try:
            image = decode_image(data, endian=endian, allow_trailing=padded)
        except ValueError as e:
            sys.exit(f"{name}: does not decode: {e}")
        if encode_image(image) != data:
            sys.exit(f"{name}: decode + re-encode is not byte-identical")
        if endian != "little":
            continue
        imgtool_verify(imgtool, path, FIXTURE_DIR / GOLDEN_KEYS[kind][0])
        entry = manifest["outputs"][name]
        expected = {}
        for area in ("protected", "unprotected"):
            kinds = [int(k, 16) for k in entry[f"{area}_tlvs"].split()]
            lens = [int(n) for n in entry[f"{area}_tlv_lens"].split()]
            expected[area] = list(zip(kinds, lens))
        listed = dumpinfo_tlvs(imgtool, path)
        if listed != expected:
            sys.exit(f"{name}: imgtool dumpinfo lists {listed}, MANIFEST.json {expected}")
    # 2. A fresh regeneration (with the committed signatures) matches the committed files.
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
    little = sum(1 for *_, endian, _expect in GOLDEN if endian == "little")
    print(f"{len(IMAGES) + len(GOLDEN)} images decode and re-encode byte-identically and "
          f"{len(IMAGES) + little} little-endian ones pass imgtool verify")
    print(f"imgtool dumpinfo TLV listings match MANIFEST.json for {little} golden images")
    print("fixtures match a fresh regeneration")


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--check", action="store_true", help="round-trip, imgtool verify, regenerate and diff")
    parser.add_argument("--imgtool", metavar="PATH", help=f"imgtool {IMGTOOL_VERSION} executable (default: from PATH)")
    parser.add_argument("--resign", action="store_true",
                        help="sign the RSA and ECDSA golden images afresh and rewrite sigs/ (instead of --fix-sig)")
    args = parser.parse_args()
    imgtool = find_imgtool(args.imgtool)
    if args.check:
        if args.resign:
            sys.exit("--check always uses the committed signatures; drop --resign")
        check(imgtool)
    else:
        manifest = generate(FIXTURE_DIR, imgtool, resign=args.resign)
        sizes = {name: entry["bytes"] for name, entry in manifest["outputs"].items()}
        print(f"wrote fixtures to {FIXTURE_DIR.relative_to(REPO_ROOT)}: {sizes}")


if __name__ == "__main__":
    main()
