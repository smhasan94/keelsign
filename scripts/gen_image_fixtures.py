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

The script itself uses the standard library only. It downloads the hsslms sdist and the
dilithium-py wheel (both pinned by sha256). The resolved imgtool and cryptography
versions are recorded in MANIFEST.json.

LMS/HSS signatures come from the independent signer hsslms 0.1.3, vendored at run time
by scripts/gen_lms_vectors.py (pinned sdist sha256, nothing pip-installed) with its
random source replaced by a per-key SHA-256 counter DRBG, so every run is deterministic.
Each LMS/HSS image has its own key and uses leaf 0 of it once.

ML-DSA signatures (SHA-44) come from the independent signer dilithium-py 1.4.0, vendored
at run time from its pinned wheel (sha256 in SOURCES, nothing pip-installed), signing
pure ML-DSA (FIPS 204 ML-DSA.Sign) over M with the context b"keelsign-mcuboot-image-v1"
in the deterministic variant (rnd = 0), and verifying each signature it makes. Two TEST
KEYS, one per parameter set, are derived from fixed public seeds (MLDSA_TEST_KEYS) and
shared by every image of that set; keelsign-verify/tests/mldsa_images.rs checks every
committed key and signature byte-for-byte against RustCrypto ml-dsa's deterministic
signer from the same seed.

The Ed25519 key in keys/ed25519-test-key.pem is a TEST KEY derived from a fixed public
seed (anyone can recompute it); it must never sign a real image.

Images (all: header size 0x200, version 1.2.3+4, the same 1,536-byte body):
  * keelsign-lms-m32-h5.bin: LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1.
  * keelsign-hss2-m32-h5h5.bin: HSS L=2, both levels M32_H5 / N32_W8.
  * keelsign-lms-protected-tlvs.bin: as the first, plus protected SEC_CNT and a vendor
    TLV 0x10A0, so the digest covers a protected TLV area.
  * keelsign-hybrid-ed25519-lms.bin: imgtool Ed25519 (KEYHASH + ED25519 over the same
    digest) plus the keelsign key ID and an LMS M32_H5 signature.
  * keelsign-mldsa44.bin, keelsign-mldsa65.bin: ML-DSA-44 / ML-DSA-65 signatures
    (2,420 and 3,309 bytes) under the ML-DSA test keys (SHA-44).
  * keelsign-mldsa44-protected-tlvs.bin, keelsign-mldsa65-protected-tlvs.bin (SHA-44):
    as the two above, plus protected SEC_CNT and vendor TLV 0x10A0, so their M differs
    (the source of the "signature from another image" mutations).
  * keelsign-dual-pq-invalid.bin: one key ID and two PQ signature TLVs (LMS, then
    ML-DSA-44); must fail with MultiplePqSignatures.
  * keelsign-hybrid-ed25519-mldsa44.bin (SHA-46): imgtool Ed25519 plus an ML-DSA-44
    half.
  * keelsign-hybrid-protected-tlvs.bin (SHA-46): the hybrid layout with protected
    SEC_CNT 7 and vendor TLV 0x10A0.
  * keelsign-hybrid-reserved-tlv-protected.bin (SHA-46): the hybrid layout plus imgtool
    `--custom-tlv 0x4ba0 <16 bytes>`, a keelsign-block TLV in the protected area (inside
    M; both signatures are valid over that M); verify rejects it.
  * keelsign-hybrid-ed25519-hss2.bin (SHA-69): imgtool Ed25519 plus an HSS L=2
    signature, both levels M32_H5 / N32_W8 (the source of the HSS-2 hybrid mutations).

Policy mutations (SHA-46): deterministic edits of keelsign-hybrid-ed25519-lms.bin (and
one of keelsign-hybrid-protected-tlvs.bin) as regenerated in the same run, listed in
MUTATIONS with what they change. SHA-44 adds the ML-DSA mutations (tampered body and
protected TLV, with and without the SHA256 TLV recomputed, tampered, malformed and
truncated signatures, an untrusted key ID, a signature from another image, and the PQ
half stripped from the ML-DSA hybrid image). SHA-69 adds four edits of
keelsign-hybrid-ed25519-hss2.bin (Ed25519 tampered, the bottom and the top HSS level
tampered, the HSS signature removed). They are not re-signed: imgtool would reject most of
them (`imgtool_verify: false`), and the manifest records `derived_from` and `mutation`.
The key fields are copied from the base so tests can build its trusted key.

Policy expectations (SHA-46): every output's MANIFEST.json entry has a `policy` object,
the verdict of `keelsign_verify::verify` under each policy (`classical_only`,
`pq_only`, `hybrid`), with `DefaultBackend::new()`, the image's own PQ key (if any) and
the Ed25519 test key trusted, and the `ed25519` and `ml-dsa` features on. Where the
verdict differs without the `ml-dsa` feature (SHA-44: every cell whose PQ half reaches
the ML-DSA backend becomes UnsupportedAlgorithm), the entry also has a
`policy_without_ml_dsa` object (all three cells). The strings are the table
POLICY_CODES; docs/policy.md's matrix, keelsign-verify/tests/policy_matrix.rs and
benches/policy-kat are checked against them.

policy-matrix.bin ("KSPM v2", little-endian) is the index benches/policy-kat runs on
the boards: b"KSPM", u16 version (2), u16 count, then per case u8 name_len, name (UTF-8,
the manifest name), u8 pq_alg (0 none, 1 MlDsa44, 2 MlDsa65, 3 LmsHss), u16 pk_len,
the PQ public key, three u8 expectation codes with the `ml-dsa` feature on and three
with it off (ClassicalOnly, PqOnly, Hybrid each): the index of the verdict string in
POLICY_CODES. It holds every output with
`in_policy_matrix_bin: true` (all but the 200 KB image), sorted by name, and no image
bytes.

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
  * mcuboot-ed25519-200k.bin (SHA-42): as mcuboot-ed25519.bin, but with its own
    204,800-byte body (DRBG label `image-fixture-body-200k`) in a 0x40000-byte slot, for
    the chunked image digest on the host and from flash on the boards.

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
import io
import json
import math
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
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

# The FIPS 204 context string of every keelsign ML-DSA signature (keelsign-verify
# src/tlv.rs MLDSA_CONTEXT; checked against it in keelsign_tlv_ids()).
MLDSA_CONTEXT = b"keelsign-mcuboot-image-v1"

# The independent ML-DSA signer (SHA-44): extracted from the pinned wheel into a temp dir
# and imported; nothing is installed.
DILITHIUM_SOURCE = {
    "package": "dilithium-py==1.4.0",
    "url": "https://files.pythonhosted.org/packages/68/92/"
    "3e242ff1e2d9e459c599caef9127708b1f92606f38a9031a4b45549b427c/dilithium_py-1.4.0-py3-none-any.whl",
    "sha256": "dda3ae43e6e3d212ae1fe1b30d5b6dffe5e25a1f389d1fea26faad4afdc33ff8",
    "files": [
        "dilithium_py/__init__.py",
        "dilithium_py/ml_dsa/__init__.py",
        "dilithium_py/ml_dsa/ml_dsa.py",
        "dilithium_py/ml_dsa/default_parameters.py",
        "dilithium_py/ml_dsa/hash_ml_dsa.py",
        "dilithium_py/modules/__init__.py",
        "dilithium_py/modules/modules.py",
        "dilithium_py/modules/modules_generic.py",
        "dilithium_py/polynomials/__init__.py",
        "dilithium_py/polynomials/polynomials.py",
        "dilithium_py/polynomials/polynomials_generic.py",
        "dilithium_py/shake/shake_wrapper.py",
        "dilithium_py/utilities/__init__.py",
        "dilithium_py/utilities/utils.py",
    ],
}

# The ML-DSA TEST KEYS (SHA-44): the FIPS 204 seed xi of each is SHA-256 of a fixed public
# label, so anyone can recompute them. They must never sign a real image.
MLDSA_TEST_KEYS = {
    "mldsa44": "keelsign-image-fixture-mldsa44-test-key",
    "mldsa65": "keelsign-image-fixture-mldsa65-test-key",
}
MLDSA_ALGORITHMS = {"mldsa44": "MlDsa44", "mldsa65": "MlDsa65"}

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

# Golden images with their own body instead of the shared BODY_LEN one (SHA-42):
# name -> (DRBG label of the body, body length, slot size).
GOLDEN_BODIES = {
    "mcuboot-ed25519-200k.bin": ("image-fixture-body-200k", 204_800, 0x40000),
}

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
    ("mcuboot-ed25519-200k.bin",
     "as mcuboot-ed25519.bin with a 204,800-byte body in a 0x40000-byte slot (chunked digest, SHA-42)",
     "ed25519", False, "little", "Ok"),
]

# name, description, PQ signatures ("lms:<label>" / "mldsa44" / "mldsa65"), LMS parameter
# sets per level, protected extras (SEC_CNT and the vendor TLV), Ed25519, expected
# verify_pq result.
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
    ("keelsign-mldsa44.bin", "ML-DSA-44 signature (pure, keelsign context) under the ML-DSA-44 test key",
     ["mldsa44"], None, False, False, "Ok"),
    ("keelsign-mldsa65.bin", "ML-DSA-65 signature (pure, keelsign context) under the ML-DSA-65 test key",
     ["mldsa65"], None, False, False, "Ok"),
    ("keelsign-dual-pq-invalid.bin",
     "invalid: one key ID and two PQ signature TLVs (LMS M32_H5, then ML-DSA-44)",
     ["lms", "mldsa44"], LMS_M32_H5, False, False, "MultiplePqSignatures"),
    # SHA-46 policy matrix.
    ("keelsign-hybrid-ed25519-mldsa44.bin",
     "hybrid: imgtool Ed25519 (KEYHASH + ED25519) plus an ML-DSA-44 signature under the ML-DSA-44 test key",
     ["mldsa44"], None, False, True, "Ok"),
    ("keelsign-hybrid-protected-tlvs.bin",
     "hybrid Ed25519 + LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1, with protected SEC_CNT and vendor TLV 0x10A0",
     ["lms"], LMS_M32_H5, True, True, "Ok"),
    ("keelsign-hybrid-reserved-tlv-protected.bin",
     "invalid: hybrid Ed25519 + LMS M32_H5 with a keelsign key-ID-typed TLV 0x4BA0 in the protected area (imgtool --custom-tlv)",
     ["lms"], LMS_M32_H5, False, True, "Ok"),
    # SHA-44: ML-DSA over a different M (protected TLVs), the foreign-signature source.
    ("keelsign-mldsa44-protected-tlvs.bin",
     "ML-DSA-44 under the ML-DSA-44 test key, with protected SEC_CNT and vendor TLV 0x10A0",
     ["mldsa44"], None, True, False, "Ok"),
    ("keelsign-mldsa65-protected-tlvs.bin",
     "ML-DSA-65 under the ML-DSA-65 test key, with protected SEC_CNT and vendor TLV 0x10A0",
     ["mldsa65"], None, True, False, "Ok"),
    # SHA-69: hybrid Ed25519 + HSS L=2.
    ("keelsign-hybrid-ed25519-hss2.bin",
     "hybrid: imgtool Ed25519 (KEYHASH + ED25519) plus HSS L=2, both levels LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8",
     ["lms"], LMS_M32_H5 * 2, False, True, "Ok"),
]

# Extra imgtool `--custom-tlv` TLVs (protected area) per image (SHA-46).
EXTRA_PROTECTED = {
    "keelsign-hybrid-reserved-tlv-protected.bin": [
        (0x4BA0, hashlib.sha256(b"keelsign SHA-46 reserved TLV in the protected area").digest()[:16]),
    ],
}

TLV_SHA384 = 0x11
TLV_SIG_PURE = 0x25
IMAGE_F_ENCRYPTED_AES128 = 0x04
IMAGE_F_NON_BOOTABLE = 0x10
IMAGE_F_COMPRESSED_LZMA2 = 0x400
HYBRID_BASE = "keelsign-hybrid-ed25519-lms.bin"
HYBRID_PROTECTED_BASE = "keelsign-hybrid-protected-tlvs.bin"
HYBRID_HSS2_BASE = "keelsign-hybrid-ed25519-hss2.bin"


def _tlv_index(tlvs, kind):
    found = [i for i, (k, _) in enumerate(tlvs) if k == kind]
    if len(found) != 1:
        sys.exit(f"mutation: expected exactly one TLV {kind:#06x}, found {len(found)}")
    return found[0]


def _flip_value(kind, at):
    def mutate(image):
        tlvs = image["unprotected"]
        i = _tlv_index(tlvs, kind)
        value = bytearray(tlvs[i][1])
        value[at] ^= 0x01
        tlvs[i] = (kind, bytes(value))
    return mutate


def _remove(kind):
    def mutate(image):
        tlvs = image["unprotected"]
        del tlvs[_tlv_index(tlvs, kind)]
    return mutate


def _duplicate(*kinds):
    def mutate(image):
        tlvs = image["unprotected"]
        first = _tlv_index(tlvs, kinds[0])
        run_ = tlvs[first:first + len(kinds)]
        if [k for k, _ in run_] != list(kinds):
            sys.exit(f"mutation: TLVs {kinds} are not adjacent")
        tlvs[first + len(kinds):first + len(kinds)] = run_
    return mutate


def _truncate(kind, length):
    def mutate(image):
        tlvs = image["unprotected"]
        i = _tlv_index(tlvs, kind)
        tlvs[i] = (kind, tlvs[i][1][:length])
    return mutate


def _set_flags(flag):
    def mutate(image):
        head = bytearray(image["head"])
        (flags,) = struct.unpack_from("<I", head, 16)
        struct.pack_into("<I", head, 16, flags | flag)
        image["head"] = bytes(head)
        image["flags"] = flags | flag
    return mutate


def _flip_body(image):
    head = bytearray(image["head"])
    head[image["hdr_size"]] ^= 0x01
    image["head"] = bytes(head)


def _sha384_only(image):
    data = encode_image(image)
    hashed = data[: image["hdr_size"] + image["img_size"] + image["prot_size"]]
    tlvs = image["unprotected"]
    tlvs[_tlv_index(tlvs, TLV_SHA256)] = (TLV_SHA384, hashlib.sha384(hashed).digest())


def _append_sig_pure(image):
    image["unprotected"].append((TLV_SIG_PURE, b"\x01"))


def _duplicate_protected_sec_cnt(image):
    prot = image["protected"]
    i = [k for k, _ in prot].index(TLV_SEC_CNT)
    prot.insert(i + 1, prot[i])
    size = len(encode_tlvs(prot, TLV_PROT_INFO_MAGIC))
    head = bytearray(image["head"])
    struct.pack_into("<H", head, 10, size)
    image["head"] = bytes(head)
    image["prot_size"] = size


def _flip_protected_value(kind, at):
    def mutate(image):
        tlvs = image["protected"]
        i = _tlv_index(tlvs, kind)
        value = bytearray(tlvs[i][1])
        value[at] ^= 0x01
        tlvs[i] = (kind, bytes(value))
    return mutate


def _set_last_byte(kind, byte):
    def mutate(image):
        tlvs = image["unprotected"]
        i = _tlv_index(tlvs, kind)
        value = bytearray(tlvs[i][1])
        if value[-1] == byte:
            sys.exit(f"mutation: TLV {kind:#06x} already ends in {byte:#04x}")
        value[-1] = byte
        tlvs[i] = (kind, bytes(value))
    return mutate


def _remove_all(*kinds):
    def mutate(image):
        for kind in kinds:
            _remove(kind)(image)
    return mutate


def _rehash(image):
    """Recompute the SHA256 TLV over the (mutated) header, body and protected area."""
    data = encode_image(image)
    tlvs = image["unprotected"]
    tlvs[_tlv_index(tlvs, TLV_SHA256)] = (TLV_SHA256, digest_of(data, image))


def _then(*mutations):
    def mutate(image, outputs):
        for m in mutations:
            m(image, outputs) if getattr(m, "needs_outputs", False) else m(image)
    mutate.needs_outputs = True
    return mutate


def _replace_value_from(source, kind):
    """The TLV `kind` replaced by the same TLV of `source` (a signature from another image
    under the same key, over another M)."""
    def mutate(image, outputs):
        tlvs = image["unprotected"]
        theirs = decode_image(outputs[source])["unprotected"]
        value = theirs[_tlv_index(theirs, kind)][1]
        i = _tlv_index(tlvs, kind)
        if tlvs[i][1] == value:
            sys.exit(f"mutation: {source} has the same TLV {kind:#06x}")
        tlvs[i] = (kind, value)
    mutate.needs_outputs = True
    return mutate


MLDSA44_BASE = "keelsign-mldsa44.bin"
MLDSA65_BASE = "keelsign-mldsa65.bin"
MLDSA44_PROTECTED_BASE = "keelsign-mldsa44-protected-tlvs.bin"
MLDSA65_PROTECTED_BASE = "keelsign-mldsa65-protected-tlvs.bin"
MLDSA_HYBRID_BASE = "keelsign-hybrid-ed25519-mldsa44.bin"

# name, base, mutation, description (SHA-46, SHA-44). Deterministic edits of the base
# image as regenerated in the same run; nothing is re-signed.
MUTATIONS = [
    ("keelsign-hybrid-bad-ed25519.bin", HYBRID_BASE, _flip_value(TLV_ED25519, 0),
     "ED25519 TLV value byte 0 ^= 0x01"),
    ("keelsign-hybrid-bad-pq.bin", HYBRID_BASE, _flip_value(0x4BA3, -1),
     "LMS/HSS signature TLV (0x4BA3) last byte ^= 0x01"),
    ("keelsign-hybrid-missing-pq.bin", HYBRID_BASE, _remove(0x4BA3),
     "LMS/HSS signature TLV (0x4BA3) removed"),
    ("keelsign-hybrid-missing-key-id.bin", HYBRID_BASE, _remove(0x4BA0),
     "key-ID TLV (0x4BA0) removed"),
    ("keelsign-hybrid-unpaired-ed25519.bin", HYBRID_BASE, _remove(TLV_KEYHASH),
     "KEYHASH TLV removed: the ED25519 TLV follows the SHA256 TLV"),
    ("keelsign-hybrid-keyhash-only.bin", HYBRID_BASE, _remove(TLV_ED25519),
     "ED25519 TLV removed: KEYHASH alone"),
    ("keelsign-hybrid-two-ed25519.bin", HYBRID_BASE, _duplicate(TLV_KEYHASH, TLV_ED25519),
     "the KEYHASH + ED25519 pair duplicated"),
    ("keelsign-hybrid-short-ed25519.bin", HYBRID_BASE, _truncate(TLV_ED25519, 63),
     "ED25519 TLV value truncated to 63 bytes"),
    ("keelsign-hybrid-bad-body.bin", HYBRID_BASE, _flip_body,
     "body byte 0 ^= 0x01"),
    ("keelsign-hybrid-bad-sha256.bin", HYBRID_BASE, _flip_value(TLV_SHA256, 0),
     "SHA256 TLV value byte 0 ^= 0x01"),
    ("keelsign-hybrid-no-sha256.bin", HYBRID_BASE, _remove(TLV_SHA256),
     "SHA256 TLV removed"),
    ("keelsign-hybrid-two-sha256.bin", HYBRID_BASE, _duplicate(TLV_SHA256),
     "SHA256 TLV duplicated"),
    ("keelsign-hybrid-sha384-only.bin", HYBRID_BASE, _sha384_only,
     "SHA256 TLV replaced by a SHA384 TLV (0x11) of the hashed bytes"),
    ("keelsign-hybrid-sig-pure.bin", HYBRID_BASE, _append_sig_pure,
     "SIG_PURE TLV (0x25) = 01 appended"),
    ("keelsign-hybrid-flag-encrypted.bin", HYBRID_BASE, _set_flags(IMAGE_F_ENCRYPTED_AES128),
     "ih_flags |= IMAGE_F_ENCRYPTED_AES128 (0x04)"),
    ("keelsign-hybrid-flag-compressed.bin", HYBRID_BASE, _set_flags(IMAGE_F_COMPRESSED_LZMA2),
     "ih_flags |= IMAGE_F_COMPRESSED_LZMA2 (0x400)"),
    ("keelsign-hybrid-flag-non-bootable.bin", HYBRID_BASE, _set_flags(IMAGE_F_NON_BOOTABLE),
     "ih_flags |= IMAGE_F_NON_BOOTABLE (0x10)"),
    ("keelsign-hybrid-two-sec-cnt.bin", HYBRID_PROTECTED_BASE, _duplicate_protected_sec_cnt,
     "protected SEC_CNT duplicated (ih_protect_tlv_size and it_tlv_tot re-encoded)"),
    # SHA-44: ML-DSA negatives (TP2) and the stripped hybrid (TP3).
    ("keelsign-mldsa44-bad-body.bin", MLDSA44_BASE, _flip_body,
     "body byte 0 ^= 0x01"),
    ("keelsign-mldsa44-bad-body-rehashed.bin", MLDSA44_BASE, _then(_flip_body, _rehash),
     "body byte 0 ^= 0x01, SHA256 TLV recomputed"),
    ("keelsign-mldsa44-bad-protected.bin", MLDSA44_PROTECTED_BASE, _flip_protected_value(TLV_SEC_CNT, 0),
     "protected SEC_CNT value byte 0 ^= 0x01"),
    ("keelsign-mldsa44-bad-protected-rehashed.bin", MLDSA44_PROTECTED_BASE,
     _then(_flip_protected_value(TLV_SEC_CNT, 0), _rehash),
     "protected SEC_CNT value byte 0 ^= 0x01, SHA256 TLV recomputed"),
    ("keelsign-mldsa44-bad-sig.bin", MLDSA44_BASE, _flip_value(0x4BA1, 0),
     "ML-DSA-44 signature TLV (0x4BA1) byte 0 (c~) ^= 0x01"),
    ("keelsign-mldsa44-bad-hint.bin", MLDSA44_BASE, _set_last_byte(0x4BA1, 0xFF),
     "ML-DSA-44 signature TLV (0x4BA1) last byte := 0xFF (hint count > omega)"),
    ("keelsign-mldsa44-short-sig.bin", MLDSA44_BASE, _truncate(0x4BA1, MLDSA44_SIG_LEN - 1),
     "ML-DSA-44 signature TLV (0x4BA1) truncated to 2,419 bytes"),
    ("keelsign-mldsa44-bad-key-id.bin", MLDSA44_BASE, _flip_value(0x4BA0, 0),
     "key-ID TLV (0x4BA0) byte 0 ^= 0x01"),
    ("keelsign-mldsa44-foreign-sig.bin", MLDSA44_BASE, _replace_value_from(MLDSA44_PROTECTED_BASE, 0x4BA1),
     f"ML-DSA-44 signature TLV (0x4BA1) replaced by the one of {MLDSA44_PROTECTED_BASE} (same key, other M)"),
    ("keelsign-mldsa65-bad-body-rehashed.bin", MLDSA65_BASE, _then(_flip_body, _rehash),
     "body byte 0 ^= 0x01, SHA256 TLV recomputed"),
    ("keelsign-mldsa65-bad-protected-rehashed.bin", MLDSA65_PROTECTED_BASE,
     _then(_flip_protected_value(TLV_SEC_CNT, 0), _rehash),
     "protected SEC_CNT value byte 0 ^= 0x01, SHA256 TLV recomputed"),
    ("keelsign-mldsa65-bad-sig.bin", MLDSA65_BASE, _flip_value(0x4BA2, 0),
     "ML-DSA-65 signature TLV (0x4BA2) byte 0 (c~) ^= 0x01"),
    ("keelsign-mldsa65-bad-hint.bin", MLDSA65_BASE, _set_last_byte(0x4BA2, 0xFF),
     "ML-DSA-65 signature TLV (0x4BA2) last byte := 0xFF (hint count > omega)"),
    ("keelsign-mldsa65-short-sig.bin", MLDSA65_BASE, _truncate(0x4BA2, MLDSA65_SIG_LEN - 1),
     "ML-DSA-65 signature TLV (0x4BA2) truncated to 3,308 bytes"),
    ("keelsign-mldsa65-foreign-sig.bin", MLDSA65_BASE, _replace_value_from(MLDSA65_PROTECTED_BASE, 0x4BA2),
     f"ML-DSA-65 signature TLV (0x4BA2) replaced by the one of {MLDSA65_PROTECTED_BASE} (same key, other M)"),
    ("keelsign-hybrid-mldsa44-missing-pq.bin", MLDSA_HYBRID_BASE, _remove(0x4BA1),
     "ML-DSA-44 signature TLV (0x4BA1) removed"),
    ("keelsign-hybrid-mldsa44-stripped-pq.bin", MLDSA_HYBRID_BASE, _remove_all(0x4BA0, 0x4BA1),
     "key-ID TLV (0x4BA0) and ML-DSA-44 signature TLV (0x4BA1) removed: a plain imgtool Ed25519 image"),
    # SHA-69: either half of the hybrid Ed25519 + HSS L=2 image tampered or missing. The
    # HSS signature is u32 Nspk | level-0 LMS signature (u32 q | u32 ots_type | C | y ...)
    # | pub[1] | level-1 LMS signature, so value byte 12 is C[0] of the level-0 LM-OTS
    # signature (the top level) and the last byte is in the level-1 (bottom) path.
    ("keelsign-hybrid-hss2-bad-ed25519.bin", HYBRID_HSS2_BASE, _flip_value(TLV_ED25519, 0),
     "ED25519 TLV value byte 0 ^= 0x01"),
    ("keelsign-hybrid-hss2-bad-pq.bin", HYBRID_HSS2_BASE, _flip_value(0x4BA3, -1),
     "LMS/HSS signature TLV (0x4BA3) last byte (bottom-level path) ^= 0x01"),
    ("keelsign-hybrid-hss2-bad-top-level.bin", HYBRID_HSS2_BASE, _flip_value(0x4BA3, 12),
     "LMS/HSS signature TLV (0x4BA3) byte 12 (level-0 LM-OTS C[0]) ^= 0x01"),
    ("keelsign-hybrid-hss2-missing-pq.bin", HYBRID_HSS2_BASE, _remove(0x4BA3),
     "LMS/HSS signature TLV (0x4BA3) removed"),
]

# The verdict strings of the policy matrix, numbered: the expectation codes of
# policy-matrix.bin (mirrored by benches/policy-kat's `Expect`). A string is
# `Ok`, a flat `keelsign_verify::Error` variant, or a wrapped one as Rust's Debug prints
# it, except that a TLV type is printed as 0x%04X.
POLICY_CODES = [
    "Ok",
    "Parse(BadMagic)",
    "MissingPqSignature",
    "MissingKeyId",
    "MultiplePqSignatures",
    "SignatureInvalid",
    "UnsupportedAlgorithm(MlDsa44)",
    "UnsupportedAlgorithm(MlDsa65)",
    "Ed25519(Missing)",
    "Ed25519(Multiple)",
    "Ed25519(Unpaired)",
    "Ed25519(InvalidSignatureLength)",
    "Ed25519(SignatureInvalid)",
    "Image(Encrypted)",
    "Image(Compressed)",
    "Image(NonBootable)",
    "Image(KeelsignTlvProtected(0x4BA0))",
    "Image(SigPure)",
    "Image(MissingSha256Tlv)",
    "Image(MultipleSha256Tlvs)",
    "Image(MultipleSecurityCounters)",
    "Image(DigestMismatch)",
    # SHA-44 (appended, so the codes above keep their numbers).
    "MalformedSignature",
    "KeyNotTrusted",
]

POLICIES = ("classical_only", "pq_only", "hybrid")


def _cells(classical_only, pq_only, hybrid):
    return {"classical_only": classical_only, "pq_only": pq_only, "hybrid": hybrid}


def _all(verdict):
    return _cells(verdict, verdict, verdict)


# An Ed25519-only golden passes the classical half under Hybrid (its pair is valid), so
# the PQ half decides.
_ED_ONLY_GOLDEN = _cells("Ok", "MissingPqSignature", "MissingPqSignature")
_OTHER_GOLDEN = _cells("Ed25519(Missing)", "MissingPqSignature", "Ed25519(Missing)")
_PQ_ONLY_LMS = _cells("Ed25519(Missing)", "Ok", "Ed25519(Missing)")

_PQ_ONLY_OK = _PQ_ONLY_LMS


def _pq_only(verdict):
    return _cells("Ed25519(Missing)", verdict, "Ed25519(Missing)")


# The expected verify verdicts of every output under (ClassicalOnly, PqOnly, Hybrid):
# DefaultBackend::new(), the image's own PQ key (if any) and the Ed25519 test key
# trusted, the `ed25519` and `ml-dsa` features on (the host test configuration).
POLICY = {
    "keelsign-lms-m32-h5.bin": _PQ_ONLY_LMS,
    "keelsign-hss2-m32-h5h5.bin": _PQ_ONLY_LMS,
    "keelsign-lms-protected-tlvs.bin": _PQ_ONLY_LMS,
    "keelsign-hybrid-ed25519-lms.bin": _all("Ok"),
    "keelsign-mldsa44.bin": _PQ_ONLY_OK,
    "keelsign-mldsa65.bin": _PQ_ONLY_OK,
    "keelsign-dual-pq-invalid.bin": _cells("Ed25519(Missing)", "MultiplePqSignatures",
                                           "Ed25519(Missing)"),
    "keelsign-hybrid-ed25519-mldsa44.bin": _all("Ok"),
    "keelsign-hybrid-protected-tlvs.bin": _all("Ok"),
    "keelsign-hybrid-reserved-tlv-protected.bin": _all("Image(KeelsignTlvProtected(0x4BA0))"),
    "keelsign-hybrid-bad-ed25519.bin": _cells("Ed25519(SignatureInvalid)", "Ok",
                                              "Ed25519(SignatureInvalid)"),
    "keelsign-hybrid-bad-pq.bin": _cells("Ok", "SignatureInvalid", "SignatureInvalid"),
    "keelsign-hybrid-missing-pq.bin": _cells("Ok", "MissingPqSignature", "MissingPqSignature"),
    "keelsign-hybrid-missing-key-id.bin": _cells("Ok", "MissingKeyId", "MissingKeyId"),
    "keelsign-hybrid-unpaired-ed25519.bin": _cells("Ed25519(Unpaired)", "Ok", "Ed25519(Unpaired)"),
    "keelsign-hybrid-keyhash-only.bin": _cells("Ed25519(Missing)", "Ok", "Ed25519(Missing)"),
    "keelsign-hybrid-two-ed25519.bin": _cells("Ed25519(Multiple)", "Ok", "Ed25519(Multiple)"),
    "keelsign-hybrid-short-ed25519.bin": _cells("Ed25519(InvalidSignatureLength)", "Ok",
                                                "Ed25519(InvalidSignatureLength)"),
    "keelsign-hybrid-bad-body.bin": _all("Image(DigestMismatch)"),
    "keelsign-hybrid-bad-sha256.bin": _all("Image(DigestMismatch)"),
    "keelsign-hybrid-no-sha256.bin": _all("Image(MissingSha256Tlv)"),
    "keelsign-hybrid-two-sha256.bin": _all("Image(MultipleSha256Tlvs)"),
    "keelsign-hybrid-sha384-only.bin": _all("Image(MissingSha256Tlv)"),
    "keelsign-hybrid-sig-pure.bin": _all("Image(SigPure)"),
    "keelsign-hybrid-flag-encrypted.bin": _all("Image(Encrypted)"),
    "keelsign-hybrid-flag-compressed.bin": _all("Image(Compressed)"),
    "keelsign-hybrid-flag-non-bootable.bin": _all("Image(NonBootable)"),
    "keelsign-hybrid-two-sec-cnt.bin": _all("Image(MultipleSecurityCounters)"),
    "mcuboot-rsa2048.bin": _OTHER_GOLDEN,
    "mcuboot-ecdsa-p256.bin": _OTHER_GOLDEN,
    "mcuboot-ed25519.bin": _ED_ONLY_GOLDEN,
    "mcuboot-ed25519-padded.bin": _ED_ONLY_GOLDEN,
    "rejected/mcuboot-ed25519-bigendian.bin": _all("Parse(BadMagic)"),
    "mcuboot-ed25519-200k.bin": _ED_ONLY_GOLDEN,
    # SHA-44.
    "keelsign-mldsa44-protected-tlvs.bin": _PQ_ONLY_OK,
    "keelsign-mldsa65-protected-tlvs.bin": _PQ_ONLY_OK,
    "keelsign-mldsa44-bad-body.bin": _all("Image(DigestMismatch)"),
    "keelsign-mldsa44-bad-body-rehashed.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa44-bad-protected.bin": _all("Image(DigestMismatch)"),
    "keelsign-mldsa44-bad-protected-rehashed.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa44-bad-sig.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa44-bad-hint.bin": _pq_only("MalformedSignature"),
    "keelsign-mldsa44-short-sig.bin": _pq_only("MalformedSignature"),
    "keelsign-mldsa44-bad-key-id.bin": _pq_only("KeyNotTrusted"),
    "keelsign-mldsa44-foreign-sig.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa65-bad-body-rehashed.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa65-bad-protected-rehashed.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa65-bad-sig.bin": _pq_only("SignatureInvalid"),
    "keelsign-mldsa65-bad-hint.bin": _pq_only("MalformedSignature"),
    "keelsign-mldsa65-short-sig.bin": _pq_only("MalformedSignature"),
    "keelsign-mldsa65-foreign-sig.bin": _pq_only("SignatureInvalid"),
    "keelsign-hybrid-mldsa44-missing-pq.bin": _cells("Ok", "MissingPqSignature", "MissingPqSignature"),
    "keelsign-hybrid-mldsa44-stripped-pq.bin": _cells("Ok", "MissingPqSignature", "MissingPqSignature"),
    # SHA-69.
    "keelsign-hybrid-ed25519-hss2.bin": _all("Ok"),
    "keelsign-hybrid-hss2-bad-ed25519.bin": _cells("Ed25519(SignatureInvalid)", "Ok",
                                                   "Ed25519(SignatureInvalid)"),
    "keelsign-hybrid-hss2-bad-pq.bin": _cells("Ok", "SignatureInvalid", "SignatureInvalid"),
    "keelsign-hybrid-hss2-bad-top-level.bin": _cells("Ok", "SignatureInvalid", "SignatureInvalid"),
    "keelsign-hybrid-hss2-missing-pq.bin": _cells("Ok", "MissingPqSignature", "MissingPqSignature"),
}

_UA44 = "UnsupportedAlgorithm(MlDsa44)"
_UA65 = "UnsupportedAlgorithm(MlDsa65)"

# The cells that differ without the `ml-dsa` feature (SHA-44): the dispatcher answers
# UnsupportedAlgorithm before any backend runs, so every cell whose PQ half reaches the
# ML-DSA backend changes; every other cell is the same as in POLICY. Checked against that
# rule by check_policy_without_ml_dsa().
POLICY_WITHOUT_ML_DSA = {
    "keelsign-mldsa44.bin": _pq_only(_UA44),
    "keelsign-mldsa65.bin": _pq_only(_UA65),
    "keelsign-mldsa44-protected-tlvs.bin": _pq_only(_UA44),
    "keelsign-mldsa65-protected-tlvs.bin": _pq_only(_UA65),
    "keelsign-hybrid-ed25519-mldsa44.bin": _cells("Ok", _UA44, _UA44),
    "keelsign-mldsa44-bad-body-rehashed.bin": _pq_only(_UA44),
    "keelsign-mldsa44-bad-protected-rehashed.bin": _pq_only(_UA44),
    "keelsign-mldsa44-bad-sig.bin": _pq_only(_UA44),
    "keelsign-mldsa44-bad-hint.bin": _pq_only(_UA44),
    "keelsign-mldsa44-short-sig.bin": _pq_only(_UA44),
    "keelsign-mldsa44-foreign-sig.bin": _pq_only(_UA44),
    "keelsign-mldsa65-bad-body-rehashed.bin": _pq_only(_UA65),
    "keelsign-mldsa65-bad-protected-rehashed.bin": _pq_only(_UA65),
    "keelsign-mldsa65-bad-sig.bin": _pq_only(_UA65),
    "keelsign-mldsa65-bad-hint.bin": _pq_only(_UA65),
    "keelsign-mldsa65-short-sig.bin": _pq_only(_UA65),
    "keelsign-mldsa65-foreign-sig.bin": _pq_only(_UA65),
}

# The verdicts only the ML-DSA backend gives (with the dispatcher's checks passed).
ML_DSA_BACKEND_VERDICTS = {"Ok", "SignatureInvalid", "MalformedSignature"}

# Outputs left out of policy-matrix.bin (the on-target index): the 200 KB image, which
# the SHA-42 board test already reads from flash.
NOT_IN_POLICY_MATRIX_BIN = {"mcuboot-ed25519-200k.bin"}
POLICY_MATRIX_BIN = "policy-matrix.bin"
PQ_ALG_CODES = {None: 0, "MlDsa44": 1, "MlDsa65": 2, "LmsHss": 3}


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
    context = re.search(r'pub const MLDSA_CONTEXT: &\[u8\] = b"([^"]*)";', text)
    if not context or context.group(1).encode() != MLDSA_CONTEXT:
        sys.exit(f"{TLV_RS}: MLDSA_CONTEXT is not {MLDSA_CONTEXT!r}")
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


def imgtool_sign(imgtool, tmp, name, body, protected, ed25519_key, extra_protected=()):
    raw = tmp / f"{name}.body"
    out = tmp / f"{name}.signed.bin"
    raw.write_bytes(body)
    cmd = [imgtool, "sign", "--header-size", hex(HEADER_SIZE), "--pad-header", "--align", ALIGN,
           "--version", VERSION, "--slot-size", hex(SLOT_SIZE)]
    if protected:
        cmd += ["--security-counter", str(SECURITY_COUNTER),
                "--custom-tlv", hex(PROTECTED_VENDOR_TLV), "0x" + PROTECTED_VENDOR_VALUE.hex()]
    for tag, value in extra_protected:
        cmd += ["--custom-tlv", hex(tag), "0x" + value.hex()]
    if ed25519_key:
        cmd += ["--key", str(ed25519_key), "--public-key-format", "hash"]
    run(cmd + [str(raw), str(out)])
    return out.read_bytes()


def imgtool_sign_golden(imgtool, tmp, stem, body, key, padded, endian, fix_sig=None, sig_out=None,
                        slot_size=None):
    """imgtool sign with the golden-image options: signed with `key`, or with the fixed
    signature `fix_sig` made by `key` earlier."""
    raw = tmp / f"{stem}.body"
    out = tmp / f"{stem}.signed.bin"
    raw.write_bytes(body)
    if slot_size is None:
        slot_size = PADDED_SLOT_SIZE if padded else SLOT_SIZE
    cmd = [imgtool, "sign", "--header-size", hex(HEADER_SIZE), "--pad-header", "--align", ALIGN,
           "--version", VERSION, "--slot-size", hex(slot_size),
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


def fetch_dilithium():
    url = DILITHIUM_SOURCE["url"]
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != DILITHIUM_SOURCE["sha256"]:
        sys.exit(f"sha256 mismatch for {url}: got {digest}, expected {DILITHIUM_SOURCE['sha256']}")
    return data


def vendor_dilithium(wheel, tmp_dir):
    """Extracts the ML-DSA modules of the dilithium-py wheel into tmp_dir/dilithium-py and
    imports them (the optional `xoflib` is not needed: hashlib SHAKE gives the same output)."""
    root = tmp_dir / "dilithium-py"
    with zipfile.ZipFile(io.BytesIO(wheel)) as wheel_zip:
        for rel in DILITHIUM_SOURCE["files"]:
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(wheel_zip.read(rel))
    sys.path.insert(0, str(root))
    module = importlib.import_module("dilithium_py.ml_dsa")
    return {"mldsa44": module.ML_DSA_44, "mldsa65": module.ML_DSA_65}


def mldsa_test_key(dilithium, kind):
    """(seed, public key, secret key) of the ML-DSA test key of `kind`."""
    seed = hashlib.sha256(MLDSA_TEST_KEYS[kind].encode()).digest()
    pk, sk = dilithium[kind].key_derive(seed)
    return seed, pk, sk


def mldsa_sign(dilithium, kind, m):
    """(public key, signature) of the ML-DSA test key of `kind` over `m`: pure ML-DSA
    (FIPS 204 ML-DSA.Sign, deterministic variant) with MLDSA_CONTEXT, self-verified."""
    _seed, pk, sk = mldsa_test_key(dilithium, kind)
    sig = dilithium[kind].sign(sk, m, ctx=MLDSA_CONTEXT, deterministic=True)
    pk_len, sig_len = {"mldsa44": (MLDSA44_PK_LEN, MLDSA44_SIG_LEN),
                       "mldsa65": (MLDSA65_PK_LEN, MLDSA65_SIG_LEN)}[kind]
    if (len(pk), len(sig)) != (pk_len, sig_len):
        sys.exit(f"dilithium-py {kind}: unexpected lengths {len(pk)} / {len(sig)}")
    if not dilithium[kind].verify(pk, m, sig, ctx=MLDSA_CONTEXT):
        sys.exit(f"dilithium-py does not verify its own {kind} signature")
    if dilithium[kind].verify(pk, m, sig, ctx=b""):
        sys.exit(f"dilithium-py {kind}: the signature verifies without the context")
    return pk, sig


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
        "sources": {
            "hsslms": {**lms.SOURCES["hsslms"], "url": lms.raw_url(lms.SOURCES["hsslms"])},
            "dilithium-py": dict(DILITHIUM_SOURCE),
        },
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

    outputs = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        hsslms = lms.vendor_hsslms(lms.fetch("hsslms"), tmp)
        dilithium = vendor_dilithium(fetch_dilithium(), tmp)
        for kind, label in MLDSA_TEST_KEYS.items():
            seed, pk, _sk = mldsa_test_key(dilithium, kind)
            manifest["keys"][f"mldsa-test-key:{kind}"] = {
                "note": "TEST KEY from a fixed public seed; never use for real images",
                "algorithm": MLDSA_ALGORITHMS[kind],
                "seed_label": label,
                "seed_hex": seed.hex(),
                "public_key_hex": pk.hex(),
                "sha256": hashlib.sha256(pk).hexdigest(),
                "key_id_hex": hashlib.sha256(pk).digest()[:key_id_len].hex(),
            }
        for name, description, pq, lms_levels, protected, ed25519, expect in IMAGES:
            stem = name.removesuffix(".bin")
            signed = imgtool_sign(imgtool, tmp, stem, body, protected, key_path if ed25519 else None,
                                  EXTRA_PROTECTED.get(name, ()))
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
                    tlv = {"mldsa44": "TLV_MLDSA44_SIG", "mldsa65": "TLV_MLDSA65_SIG"}[kind]
                    pk, sig = mldsa_sign(dilithium, kind, m)
                    signatures.append((ids[tlv], sig))
                    this = (pk, MLDSA_ALGORITHMS[kind])
                if public_key is None:
                    public_key, algorithm = this
            key_id = hashlib.sha256(public_key).digest()[:key_id_len]

            image["unprotected"] = image["unprotected"] + [(ids["TLV_KEELSIGN_KEY_ID"], key_id)] + signatures
            data = encode_image(image)
            if decode_image(data)["unprotected"] != image["unprotected"] or digest_of(data, image) != m:
                sys.exit(f"{name}: appending the keelsign TLVs changed the image")
            (out_dir / name).write_bytes(data)
            outputs[name] = data
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
                "verifiable": True,
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

        generate_mutations(out_dir, outputs, manifest)
        generate_golden(out_dir, imgtool, lms, tmp, body, manifest, resign)

    add_policy(out_dir, manifest)
    (out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def generate_mutations(out_dir, outputs, manifest):
    """The SHA-46 / SHA-44 policy mutations, from the bytes written in this run."""
    for name, base, mutate, description in MUTATIONS:
        image = decode_image(outputs[base])
        if getattr(mutate, "needs_outputs", False):
            mutate(image, outputs)
        else:
            mutate(image)
        data = encode_image(image)
        decoded = decode_image(data)
        if data == outputs[base]:
            sys.exit(f"{name}: the mutation changed nothing")
        (out_dir / name).write_bytes(data)
        outputs[name] = data
        base_entry = manifest["outputs"][base]
        manifest["outputs"][name] = {
            "description": f"mutation of {base}: {description}",
            "derived_from": base,
            "mutation": description,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "algorithm": base_entry["algorithm"],
            "public_key_hex": base_entry["public_key_hex"],
            "key_id_hex": base_entry["key_id_hex"],
            "ed25519": base_entry["ed25519"],
            "digest_hex": digest_of(data, decoded).hex(),
            "protected_tlvs": " ".join(f"{k:#06x}" for k, _ in decoded["protected"] or []),
            "unprotected_tlvs": " ".join(f"{k:#06x}" for k, _ in decoded["unprotected"]),
            "expect_parse": "Ok",
            "imgtool_verify": False,
            **layout_fields(decoded),
        }


def check_policy_without_ml_dsa(outputs):
    """POLICY_WITHOUT_ML_DSA follows the rule: without the `ml-dsa` feature, a cell
    differs exactly when its policy needs the PQ half, the image's PQ key is ML-DSA and the
    verdict with the feature comes from the ML-DSA backend; it is then
    UnsupportedAlgorithm(<that algorithm>)."""
    for name, entry in sorted(outputs.items()):
        on = POLICY[name]
        algorithm = entry.get("algorithm")
        derived = {}
        for p in POLICIES:
            reaches = (p != "classical_only" and algorithm in ("MlDsa44", "MlDsa65")
                       and on[p] in ML_DSA_BACKEND_VERDICTS)
            derived[p] = f"UnsupportedAlgorithm({algorithm})" if reaches else on[p]
        listed = POLICY_WITHOUT_ML_DSA.get(name)
        if (listed if listed is not None else on) != derived:
            sys.exit(f"{name}: POLICY_WITHOUT_ML_DSA {listed} does not follow the rule ({derived})")
        if listed is not None and listed == on:
            sys.exit(f"{name}: POLICY_WITHOUT_ML_DSA lists cells equal to POLICY")


def add_policy(out_dir, manifest):
    """The `policy` (and `policy_without_ml_dsa`) cells of every output and
    policy-matrix.bin (SHA-46, SHA-44)."""
    outputs = manifest["outputs"]
    if set(POLICY) != set(outputs):
        sys.exit(f"POLICY and the outputs differ: {sorted(set(POLICY) ^ set(outputs))}")
    if not set(POLICY_WITHOUT_ML_DSA) <= set(outputs):
        sys.exit(f"POLICY_WITHOUT_ML_DSA names unknown outputs: {sorted(set(POLICY_WITHOUT_ML_DSA) - set(outputs))}")
    check_policy_without_ml_dsa(outputs)
    # The ML-DSA test key is the same in every image of its set.
    for kind, algorithm in MLDSA_ALGORITHMS.items():
        key = manifest["keys"][f"mldsa-test-key:{kind}"]["public_key_hex"]
        for name, entry in outputs.items():
            if entry.get("algorithm") == algorithm and entry.get("public_key_hex") != key:
                sys.exit(f"{name}: its {algorithm} key is not the {kind} test key")
    cases = []
    for name, entry in sorted(outputs.items()):
        for table in (POLICY, POLICY_WITHOUT_ML_DSA):
            cells = table.get(name)
            if cells is not None and (tuple(cells) != POLICIES or any(v not in POLICY_CODES for v in cells.values())):
                sys.exit(f"{name}: bad policy cells {cells}")
        entry["policy"] = dict(POLICY[name])
        if name in POLICY_WITHOUT_ML_DSA:
            entry["policy_without_ml_dsa"] = dict(POLICY_WITHOUT_ML_DSA[name])
        entry["in_policy_matrix_bin"] = name not in NOT_IN_POLICY_MATRIX_BIN
        if entry["in_policy_matrix_bin"]:
            cases.append((name, entry))
    index = bytearray(b"KSPM" + struct.pack("<HH", 2, len(cases)))
    for name, entry in cases:
        raw_name = name.encode()
        pk = bytes.fromhex(entry.get("public_key_hex", ""))
        index += struct.pack("<B", len(raw_name)) + raw_name
        index += struct.pack("<BH", PQ_ALG_CODES[entry.get("algorithm")], len(pk)) + pk
        index += bytes(POLICY_CODES.index(entry["policy"][p]) for p in POLICIES)
        index += bytes(POLICY_CODES.index(off_cells(entry)[p]) for p in POLICIES)
    # Self-check: the index decodes back to the manifest.
    if decode_policy_matrix(bytes(index)) != expected_index(cases):
        sys.exit("policy-matrix.bin does not decode back to the manifest")
    (out_dir / POLICY_MATRIX_BIN).write_bytes(bytes(index))
    manifest["policy_matrix"] = {
        POLICY_MATRIX_BIN: {
            "note": "KSPM v2 index of the policy matrix for benches/policy-kat (no image bytes): "
                    "per case the cells with the ml-dsa feature on, then off",
            "bytes": len(index),
            "sha256": hashlib.sha256(index).hexdigest(),
            "count": len(cases),
            "version": 2,
        },
        "codes": {str(i): verdict for i, verdict in enumerate(POLICY_CODES)},
        "policies": list(POLICIES),
    }


def off_cells(entry):
    """The cells of an output without the `ml-dsa` feature."""
    return entry.get("policy_without_ml_dsa", entry["policy"])


def expected_index(cases):
    return [
        (name, entry.get("algorithm"), entry.get("public_key_hex", ""),
         [entry["policy"][p] for p in POLICIES], [off_cells(entry)[p] for p in POLICIES])
        for name, entry in cases
    ]


def decode_policy_matrix(data):
    """[(name, algorithm, public key hex, [verdict per policy, ml-dsa on],
    [verdict per policy, ml-dsa off])] of a KSPM v2 index."""
    if data[:4] != b"KSPM":
        raise ValueError("not a KSPM index")
    version, count = struct.unpack_from("<HH", data, 4)
    if version != 2:
        raise ValueError(f"KSPM version {version}")
    algorithms = {v: k for k, v in PQ_ALG_CODES.items()}
    off, cases = 8, []
    for _ in range(count):
        n = data[off]
        name = data[off + 1:off + 1 + n].decode()
        off += 1 + n
        alg, pk_len = struct.unpack_from("<BH", data, off)
        off += 3
        pk = data[off:off + pk_len]
        off += pk_len
        on = data[off:off + 3]
        off_codes = data[off + 3:off + 6]
        off += 6
        cases.append((name, algorithms[alg], pk.hex(), [POLICY_CODES[c] for c in on],
                      [POLICY_CODES[c] for c in off_codes]))
    if off != len(data):
        raise ValueError("trailing bytes in the KSPM index")
    return cases


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
        own_body = GOLDEN_BODIES.get(name)
        if sig_rel is None:
            if own_body:
                label, body_len, slot_size = own_body
                signed = imgtool_sign_golden(imgtool, tmp, stem, lms.Drbg(label)(body_len), key, padded,
                                             endian, slot_size=slot_size)
            else:
                signed = imgtool_sign_golden(imgtool, tmp, stem, body, key, padded, endian)
        elif own_body:
            sys.exit(f"{name}: an own body needs a deterministic (Ed25519) signature")
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
        if own_body:
            label, body_len, slot_size = own_body
            manifest["outputs"][name].update({
                "body_drbg_label": label,
                "body_len": body_len,
                "slot_size": slot_size,
            })


def run_bytes(cmd):
    result = subprocess.run(cmd, capture_output=True)
    if result.returncode != 0:
        sys.exit(f"command failed ({result.returncode}): {' '.join(cmd)}\n{result.stderr.decode(errors='replace')}")
    return result.stdout


def committed_files():
    sigs = [sig for _, _, sig in GOLDEN_KEYS.values() if sig]
    return (["MANIFEST.json", KEY_PEM, KEY_SPKI, RSA_KEY_PEM, ECDSA_KEY_PEM] + sigs
            + [name for name, *_ in IMAGES] + [name for name, *_ in GOLDEN]
            + [name for name, *_ in MUTATIONS] + [POLICY_MATRIX_BIN])


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
    # 1c. The SHA-46 mutations decode and re-encode byte-identically (they are not
    #     imgtool-verifiable by design), and policy-matrix.bin decodes to MANIFEST.json.
    for name, *_ in MUTATIONS:
        data = (FIXTURE_DIR / name).read_bytes()
        try:
            image = decode_image(data)
        except ValueError as e:
            sys.exit(f"{name}: does not decode: {e}")
        if encode_image(image) != data:
            sys.exit(f"{name}: decode + re-encode is not byte-identical")
    indexed = decode_policy_matrix((FIXTURE_DIR / POLICY_MATRIX_BIN).read_bytes())
    expected = expected_index(
        [(name, entry) for name, entry in sorted(manifest["outputs"].items()) if entry["in_policy_matrix_bin"]])
    if indexed != expected:
        sys.exit(f"{POLICY_MATRIX_BIN} does not match the MANIFEST.json policy cells")
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
    print(f"{len(IMAGES) + len(GOLDEN) + len(MUTATIONS)} images decode and re-encode byte-identically and "
          f"{len(IMAGES) + little} little-endian signed ones pass imgtool verify")
    print(f"{POLICY_MATRIX_BIN} ({len(indexed)} cases) matches the MANIFEST.json policy cells")
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
