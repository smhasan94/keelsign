# keelsign image format (SHA-37)

keelsign keeps MCUboot's image format: an MCUboot header, the image body, an optional
protected TLV area and the unprotected TLV area, exactly as `imgtool` writes them. It adds
a key-ID TLV and one post-quantum (PQ) signature TLV to the unprotected TLV area. This
document fixes those TLVs, what the PQ signature covers, how keys are identified, how the
Ed25519 hybrid is laid out, the sizes, and how all of it fits MCUboot's TLV rules.

The constants live in [`keelsign-verify/src/tlv.rs`](../keelsign-verify/src/tlv.rs).
MCUboot sources are cited as `path:lines` at MCUboot commit `a8ffd2c`
(`a8ffd2c312910cc648219bcb29e04260f7857492`, v2.5.0-rc1) unless another repository is
named; see [References](#references).

The words MUST, MUST NOT and SHOULD are used as in RFC 2119.

## TLV table

keelsign owns the TLV block `0x4BA0`–`0x4BAF` (`KEELSIGN_TLV_RANGE`). All keelsign TLVs
are little-endian MCUboot TLVs (`u16 type`, `u16 len`, value) in the **unprotected** TLV
area.

| ID | Constant | Length (bytes) | Encoding | Area |
|---|---|---|---|---|
| `0x4BA0` | `TLV_KEELSIGN_KEY_ID` | 16 (`KEY_ID_LEN`) | SHA-256 of the raw public key, first 16 bytes ([Key ID](#key-id)) | unprotected |
| `0x4BA1` | `TLV_MLDSA44_SIG` | 2,420 | ML-DSA-44 signature (FIPS 204), pure ML-DSA over `M` with context `MLDSA_CONTEXT` | unprotected |
| `0x4BA2` | `TLV_MLDSA65_SIG` | 3,309 | ML-DSA-65 signature (FIPS 204), pure ML-DSA over `M` with context `MLDSA_CONTEXT` | unprotected |
| `0x4BA3` | `TLV_LMS_HSS_SIG` | per parameter set ([Sizes](#sizes)) | HSS signature (RFC 8554 §6.2, SP 800-208) over `M`; a single LMS tree is HSS with `L = 1` | unprotected |
| `0x4BA4`–`0x4BAF` | reserved | — | reserved for keelsign; not emitted | — |

Rules:

- Signers emit exactly one `0x4BA0` and exactly one PQ signature TLV (`0x4BA1`, `0x4BA2`
  or `0x4BA3`), after every MCUboot TLV: key ID first, then the signature.
- Verifiers MUST ignore TLV types they do not know, in both areas, including the reserved
  `0x4BA4`–`0x4BAF`. A future keelsign TLV with verification meaning gets a new ID from
  the reserved block and a new version of this document.
- A second key-ID TLV fails with `Error::MultipleKeyIds` and a second PQ signature TLV
  with `Error::MultiplePqSignatures`: the verifier fails closed rather than picking one.

Why this block: MCUboot reserves `xxA0`–`xxFF` of every upper byte `xx` for vendors
(`boot/bootutil/include/bootutil/image.h:137-146`). keelsign first used `0x00A0`–`0x00A3`,
but nRF Connect SDK already uses `0x00A0` for its installer image
(nrfconnect/sdk-mcuboot `boot/zephyr/firmware_loader_bm.c:23`) and `0x00A1` as the default
PERIPHCONF TLV (nrfconnect/sdk-nrf `sysbuild/Kconfig.mcuboot:364-367`,
`modules/mcuboot/Kconfig:155-157`). The whole `0x00xx` vendor block is the one every
vendor picks first, so keelsign moved to `0x4B` ("K"). No use of `0x4BA0`–`0x4BAF` was
found in MCUboot or sdk-mcuboot at the cited commits, nor by GitHub code search in
sdk-nrf.

## Signing mode

The PQ signature is over the 32-byte **image digest `M`**:

```text
M = SHA-256( image header || image body || protected TLV area )
```

The protected TLV area is included with its TLV info header (magic `0x6908`) when
`ih_protect_tlv_size != 0`, and absent otherwise. These are the bytes and the value of
MCUboot's own `IMAGE_TLV_SHA256` (`0x10`): MCUboot hashes `ih_hdr_size + ih_img_size +
ih_protect_tlv_size` bytes (`boot/bootutil/src/bootutil_img_hash.c:122-135`;
`docs/design.md:159-164` and `:1349-1351`).

- **ML-DSA-44/65:** pure ML-DSA (FIPS 204 `ML-DSA.Sign` / `ML-DSA.Verify`) with message
  `M` and context string `MLDSA_CONTEXT` ([ML-DSA context](#ml-dsa-context)). Never
  HashML-DSA.
- **LMS/HSS:** HSS (RFC 8554 §6) with message `M`.
- The same `M` is signed by the Ed25519 half of a hybrid image ([Hybrid layout](#hybrid-layout)).

The verifier computes `M` itself while hashing the image in chunks (SHA-42), and also
requires the `IMAGE_TLV_SHA256` TLV to be present and equal to `M` (SHA-46). Images
carrying `IMAGE_TLV_SIG_PURE` (`0x25`, `image.h:109`), MCUboot's "signature over the image,
not its digest" mode, are rejected.

### Rationale

- **It is MCUboot's model.** MCUboot's signatures are over the image hash
  (`image.h:90-98`); `bootutil_img_validate` passes the 32-byte hash to
  `bootutil_verify_sig(hash, sizeof(hash), …)` (`boot/bootutil/src/image_validate.c:413-414`),
  and the Ed25519 verifier requires `mlen == 32` outside pure mode
  (`boot/bootutil/src/image_ed25519.c:100-106`). keelsign's PQ signature and the Ed25519
  signature are checked against the same `M`, computed once.
- **One hash pass, fixed-size message.** The device streams the image through SHA-256
  once, in chunks, without a heap. ML-DSA's message representative μ and every LMS/HSS
  message hash are then computed over 32 bytes, so no streaming signature interface is
  needed. Signing the whole image instead would force one (and a second hash pass).
- **FIPS 204 does not constrain `M`.** ML-DSA signs any byte string; signing a digest of
  the image is a protocol choice, not HashML-DSA. NIST has confirmed that computing μ
  outside the signing module is permitted ("FAQ – FIPS 204 – Computing mu", March 2025),
  which is the same property: the signer only needs `M`.
- **Not HashML-DSA.** HashML-DSA is not allowed in CNSA 2.0 (CNSA 2.0 FAQ v2.1) and
  draft-connolly-cfrg-ml-dsa-security-considerations-02 §3.2.5 discourages it
  (verification ambiguity, hash-algorithm confusion); pure ML-DSA over `M` avoids both.
- **Applies to both families.** The same `M` is the message for ML-DSA and LMS/HSS, so
  the parser, the hashing and the dispatch are identical for every algorithm.
- **Protected TLVs are covered.** Everything MCUboot authenticates (header, body,
  protected TLVs such as the security counter) is covered by the PQ signature too.

## Key ID

```text
key ID = SHA-256( raw public key )[0..16]
```

"Raw public key" is exactly the byte string held in the device's trusted key set
(`TrustedKey::public_key`), and the ID is computed by `keelsign_verify::key_id_of`:

- ML-DSA-44/65: the FIPS 204 public-key encoding (1,312 / 1,952 bytes).
- LMS/HSS: the HSS public key `u32 L || LMS public key` (RFC 8554 §6.1; 52 bytes for
  m = 24, 60 bytes for m = 32).

The key ID only selects a trusted key: it is public, travels unprotected, and a wrong or
swapped ID selects either no key (`Error::KeyNotTrusted`) or another trusted key whose
signature check then fails. 16 bytes make an accidental collision among a device's few
trusted keys negligible, and `TrustedKeys::new` refuses duplicate IDs anyway.

The Ed25519 key of a hybrid image is identified by MCUboot's own `IMAGE_TLV_KEYHASH`
(`0x01`): SHA-256 of the DER SubjectPublicKeyInfo, which is what imgtool embeds and
hashes (`scripts/imgtool/keys/ed25519.py:32-36`). MCUboot compares only the first
`keyhash_len` bytes of it (`boot/bootutil/src/bootutil_find_key.c:56-80`); keelsign-verify
requires all 32.

## Hybrid layout

A hybrid image carries a complete MCUboot Ed25519 signature and one keelsign PQ
signature, both over the same `M`. The unprotected TLV area is, in order:

| # | TLV | Written by |
|---|---|---|
| 1 | `IMAGE_TLV_SHA256` (`0x10`), `M` | imgtool |
| 2 | `IMAGE_TLV_KEYHASH` (`0x01`), 32 bytes | imgtool |
| 3 | `IMAGE_TLV_ED25519` (`0x24`), 64 bytes | imgtool |
| 4 | `TLV_KEELSIGN_KEY_ID` (`0x4BA0`), 16 bytes | keelsign |
| 5 | one PQ signature TLV (`0x4BA1`, `0x4BA2` or `0x4BA3`) | keelsign |

- Exactly one KEYHASH + ED25519 pair, KEYHASH immediately before ED25519: MCUboot picks
  the key from the KEYHASH TLV and ignores a signature TLV that no KEYHASH precedes
  (`image_validate.c:364-403`, reset after each signature at `:433`).
- MCUboot TLVs first, then the keelsign TLVs, so `imgtool sign` output is kept byte for
  byte and keelsign only appends (and fixes up `it_tlv_tot`).
- A PQ-only image has rows 1, 4 and 5.
- The hybrid policy (both must verify) is SHA-46.

## One PQ signature per image

An image carries exactly one PQ signature TLV; more than one is
`Error::MultiplePqSignatures`.

- **No choice to get wrong.** With one signature there is no "which one counts" rule for
  a verifier to implement differently, and no downgrade by stripping one of several.
- **Rotation without multiple signatures.** Key rotation is handled by the trusted key
  set, which holds several keys during a rotation (SHA-171): the image names its key by
  ID. Migrating to another algorithm is a re-sign with the new key once devices trust it.
- **Size.** One PQ signature already takes most of a 4 KiB page ([Sizes](#sizes)); two
  would not fit the budget.

## Sizes

PQ and key-ID TLV values in keelsign's v0.1 signing profile (ML-DSA-44/65; LMS/HSS with
LM-OTS W8, m ∈ {24, 32}, tree heights H10 and H20, one or two HSS levels). An HSS
signature with W8 is `4 + L·(4 + (4 + n + p·n) + 4 + h·m) + (L − 1)·(24 + m)` bytes with
n = m and p = 34 (n = 32) or 26 (n = 24) (RFC 8554 §4.5, §5.4, §6.2; SP 800-208 Table 4).

| Item | Parameters | Levels | Bytes |
|---|---|---|---|
| Key ID | SHA-256 truncated | — | 16 |
| ML-DSA-44 | FIPS 204 | — | 2,420 |
| ML-DSA-65 | FIPS 204 | — | 3,309 |
| LMS/HSS | M32 H10 | 1 | 1,456 |
| LMS/HSS | M32 H20 | 1 | 1,776 |
| LMS/HSS | M32 H10+H10 | 2 | 2,964 |
| LMS/HSS | M32 H20+H20 | 2 | 3,604 |
| LMS/HSS | M24 H10 | 1 | 904 |
| LMS/HSS | M24 H20 | 1 | 1,144 |
| LMS/HSS | M24 H10+H10 | 2 | 1,852 |
| LMS/HSS | M24 H20+H20 | 2 | 2,332 |

`MAX_PQ_SIGNATURE_LEN = 3,604` bytes (HSS-2, M32, H20+H20) is the largest of these. It is
a budget, not a verifier limit: the verifier accepts H5, H15 and H25 too (for example
HSS-2 M32 H25+H25 is 3,924 bytes), which are outside the v0.1 profile and must be budgeted
separately.

Worst-case unprotected TLV area of a v0.1 hybrid image:

| Part | Bytes |
|---|---|
| TLV info header | 4 |
| SHA256 TLV (4 + 32) | 36 |
| KEYHASH TLV (4 + 32) | 36 |
| ED25519 TLV (4 + 64) | 68 |
| Key-ID TLV (4 + 16) | 20 |
| PQ signature TLV (4 + `MAX_PQ_SIGNATURE_LEN`) | 3,608 |
| Total | 3,772 |

**Budget rule:** reserve one 4 KiB flash page after the image body for the TLV areas
(protected and unprotected). The worst case above leaves 324 bytes for protected TLVs.
Per-board slot and partition numbers are SHA-58.

## ML-DSA context

```text
MLDSA_CONTEXT = b"keelsign-mcuboot-image-v1"   (25 bytes)
```

Every keelsign ML-DSA signature uses this FIPS 204 context string (at most 255 bytes).
draft-connolly-cfrg-ml-dsa-security-considerations-02 §2.2.2 recommends a fixed context
string per protocol use: it separates keelsign image signatures from any other signature
made with the same ML-DSA key. The ML-DSA backend (SHA-44) passes it to
`verify_with_context`; a new image-format version would get a new context string.

## Accepted LMS parameter sets and CNSA 2.0

keelsign-verify accepts HSS keys and signatures with LM-OTS W8, SHA-256 (m = n = 32) or
SHA-256/192 (m = n = 24), tree heights H5–H25, the same hash at every level, and at most
two levels. Today this policy is `keelsign_verify::lms::ParameterPolicy::cnsa_2_0()`, and
`lms::verify` / `DefaultBackend` use it.

CNSA 2.0 (CNSA 2.0 FAQ v2.1, December 2024) allows LMS and XMSS for firmware and software
signing only, and only the single-tree variants: HSS and XMSS^MT are not approved for
national security systems (NSS). An HSS key with two levels is therefore not CNSA 2.0
compliant, so the name `cnsa_2_0()` for a policy that accepts `L = 2` is inaccurate.
**Planned split** (a separate follow-up ticket; the code does not change in SHA-37):

| Policy | Levels | LM-OTS | Hash | Use |
|---|---|---|---|---|
| `cnsa_2_0()` | `L = 1` only | W8 | SHA-256 or SHA-256/192 | NSS deployments that must follow CNSA 2.0 |
| `keelsign_default()` | `L ≤ 2` | W8 | SHA-256 or SHA-256/192 | the device default (`lms::verify`, `DefaultBackend`) |

**Deviation from CNSA 2.0:** the device default accepts two-level HSS, which CNSA 2.0 does
not approve for NSS; two levels let one long-lived top-level key certify many short-lived
signing trees. NSS deployments must sign with a single LMS tree (`L = 1`) and verify with
the strict `cnsa_2_0()` policy. Note also that CNSA 2.0's ML-DSA parameter set is
ML-DSA-87; keelsign's ML-DSA-44/65 are not CNSA 2.0 algorithms (ML-DSA-87 is out of scope,
see [Out of scope](#out-of-scope)).

## MCUboot compatibility

- **Stock MCUboot ignores keelsign TLVs.** `bootutil_img_validate` walks every TLV and
  acts only on the types it was built for; its `switch` has no `default`, so other types
  are skipped (`image_validate.c:306-551`). A hybrid image therefore boots on an
  unmodified Ed25519 MCUboot, which checks the SHA256, KEYHASH and ED25519 TLVs.
- **Unprotected, not protected.** The PQ signature cannot be inside the area it signs,
  and the key ID follows MCUboot's KEYHASH, which is also unprotected. `imgtool sign
  --custom-tlv` accepts vendor types `0x00a0`–`0xfffe` (`scripts/imgtool/image.py:103-104`,
  `:141-147`) but only places them in the protected area (`docs/imgtool.md:175-180`), so
  keelsign appends its TLVs to imgtool's output itself.
- **TLV allow list (SHA-62).** With `MCUBOOT_USE_TLV_ALLOW_LIST`, MCUboot rejects every
  unprotected TLV not in `allowed_unprot_tlvs` (`image_validate.c:164-194`, `:318-338`;
  `docs/design.md:170-176`). Zephyr's `CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST` defaults to `y`
  (`boot/zephyr/Kconfig:1327-1337`, mapped in
  `boot/zephyr/include/mcuboot_config/mcuboot_config.h:155-156`), and the Mynewt, Mbed,
  Cypress and Espressif ports define it unconditionally. A keelsign-enabled MCUboot build
  (SHA-62) MUST either add `0x4BA0`–`0x4BA3` to the allow list or disable it. A stock
  Zephyr MCUboot with the default allow list **rejects** keelsign images.
- **SHA256 TLV is mandatory.** MCUboot requires the hash TLV and compares it
  (`image_validate.c:341-362`, `:553-557`); keelsign requires it too (SHA-46).
- **Not adopted: MCUboot PR #2707.** That PR (open, head `1d9ea7a`) adds native LMS support with its own
  `IMAGE_TLV_LMS` (`0x26`) in MCUboot's space. keelsign keeps its vendor TLVs; a
  compatibility mode is tracked as a follow-up.

## MCUboot compatibility checklist

Each row was checked against the cited source at the stated commit.

- [x] `0x4BA0`–`0x4BAF` are in MCUboot's vendor-reserved space `xxA0`–`xxFF` and are not
  `IMAGE_TLV_ANY` (`0xffff`): `boot/bootutil/include/bootutil/image.h:137-147` @ `a8ffd2c`.
- [x] No MCUboot-defined TLV type is in `0x4BA0`–`0x4BAF` (every defined type is below
  `0xA0`): `boot/bootutil/include/bootutil/image.h:99-136` @ `a8ffd2c`.
- [x] imgtool accepts `0x4BA0`–`0x4BAF` as custom TLVs (range `0x00a0`–`0xfffe`), in the
  protected area only: `scripts/imgtool/image.py:103-104`, `:141-147` and
  `docs/imgtool.md:175-180` @ `a8ffd2c`.
- [x] TLV info magics are `0x6907` (unprotected) and `0x6908` (protected), and a TLV is
  `u16 type, u16 len`: `scripts/imgtool/image.py:98-101`, `:148` @ `a8ffd2c`.
- [x] Unknown TLV types are skipped during validation (the `switch` has no `default`):
  `boot/bootutil/src/image_validate.c:306-551` @ `a8ffd2c`.
- [x] With `MCUBOOT_USE_TLV_ALLOW_LIST`, unknown unprotected TLVs fail validation:
  `boot/bootutil/src/image_validate.c:164-194`, `:318-338` @ `a8ffd2c`.
- [x] Zephyr enables the allow list by default: `boot/zephyr/Kconfig:1327-1337` and
  `boot/zephyr/include/mcuboot_config/mcuboot_config.h:155-156` @ `a8ffd2c`.
- [x] The image hash covers header, body and the protected TLV area with its info header:
  `boot/bootutil/src/bootutil_img_hash.c:122-135` and `docs/design.md:159-164`,
  `:1349-1351` @ `a8ffd2c`.
- [x] The SHA256 TLV must be present and equal to the computed hash:
  `boot/bootutil/src/image_validate.c:341-362`, `:553-557` @ `a8ffd2c`.
- [x] Signatures are verified over the 32-byte hash, and Ed25519 requires `mlen == 32`
  outside pure mode: `boot/bootutil/src/image_validate.c:413-414` and
  `boot/bootutil/src/image_ed25519.c:100-106` @ `a8ffd2c`.
- [x] The KEYHASH TLV must precede its signature TLV; the key is reset after each
  signature: `boot/bootutil/src/image_validate.c:364-403`, `:433` @ `a8ffd2c`.
- [x] KEYHASH is SHA-256 of the DER SubjectPublicKeyInfo and is compared over
  `keyhash_len` bytes: `scripts/imgtool/keys/ed25519.py:32-36` and
  `boot/bootutil/src/bootutil_find_key.c:56-80` @ `a8ffd2c`.
- [x] An Ed25519 signature TLV is exactly 64 bytes:
  `boot/bootutil/src/image_validate.c:87-90` @ `a8ffd2c`.
- [x] `IMAGE_TLV_SIG_PURE` (`0x25`) marks a signature over the image instead of the hash:
  `boot/bootutil/include/bootutil/image.h:109-111` and
  `boot/bootutil/src/image_validate.c:273-284` @ `a8ffd2c`.
- [x] nRF Connect SDK uses `0x00A0` and `0x00A1`, which ruled out keelsign's first IDs:
  nrfconnect/sdk-mcuboot `boot/zephyr/firmware_loader_bm.c:23` @ `2b21b8b`, and
  nrfconnect/sdk-nrf `sysbuild/Kconfig.mcuboot:364-367`, `modules/mcuboot/Kconfig:155-157`
  @ `8270993`.

## Out of scope

- A format-version TLV: the format is versioned by this document and by `MLDSA_CONTEXT`.
- A policy TLV (for example "hybrid required"): policy is device configuration, never
  taken from the image.
- An algorithm or parameter-set TLV: the algorithm is the signature TLV's type and the
  LMS/HSS parameter set is the trusted public key's.
- ML-DSA-87 and SLH-DSA.
- MCUboot PR #2707's `IMAGE_TLV_LMS` (`0x26`) compatibility mode (follow-up).
- The image parser (SHA-35), digest computation (SHA-42), hybrid policy and Ed25519
  verification (SHA-46), the ML-DSA backend (SHA-44), the CLI (SHA-49, SHA-51),
  per-board partition numbers (SHA-58) and the MCUboot allow-list glue (SHA-62).
- The `cnsa_2_0()` / `keelsign_default()` policy split in code (follow-up ticket).

## Sample images

`tests/fixtures/images/` holds sample images generated by
[`scripts/gen_image_fixtures.py`](../scripts/gen_image_fixtures.py): imgtool 2.4.0 output
(header, protected TLVs, SHA256 TLV and, for the hybrid image, the Ed25519 KEYHASH and
ED25519 TLVs, made with a committed Ed25519 **test key** from a fixed public seed) plus the
keelsign TLVs, with LMS/HSS signatures from the pinned independent signer hsslms 0.1.3.
`MANIFEST.json` records every file's size and SHA-256 and the imgtool and cryptography
versions. `keelsign-verify/tests/image_fixtures.rs` walks and verifies them.

Tool prerequisite for regenerating (not for testing): `imgtool==2.4.0` in a virtual
environment, passed with `--imgtool PATH` or found on `PATH`.

```sh
python3 -m venv .venv-imgtool && .venv-imgtool/bin/pip install imgtool==2.4.0
python3 scripts/gen_image_fixtures.py --imgtool .venv-imgtool/bin/imgtool
python3 scripts/gen_image_fixtures.py --check --imgtool .venv-imgtool/bin/imgtool
```

## References

- MCUboot, commit `a8ffd2c312910cc648219bcb29e04260f7857492` (v2.5.0-rc1),
  <https://github.com/mcu-tools/mcuboot/tree/a8ffd2c312910cc648219bcb29e04260f7857492>.
- MCUboot PR #2707 (native LMS, `IMAGE_TLV_LMS` `0x26`),
  <https://github.com/mcu-tools/mcuboot/pull/2707>.
- imgtool 2.4.0 (PyPI), <https://pypi.org/project/imgtool/2.4.0/>.
- nrfconnect/sdk-mcuboot, commit `2b21b8b1bd3e93b0538dd50768dab71b8836ac25`,
  <https://github.com/nrfconnect/sdk-mcuboot/blob/2b21b8b1bd3e93b0538dd50768dab71b8836ac25/boot/zephyr/firmware_loader_bm.c#L23>.
- nrfconnect/sdk-nrf, commit `8270993e2405c973d083a8d04713bd5b9b38fc09`,
  <https://github.com/nrfconnect/sdk-nrf/blob/8270993e2405c973d083a8d04713bd5b9b38fc09/sysbuild/Kconfig.mcuboot#L364-L367>.
- NIST FIPS 204, Module-Lattice-Based Digital Signature Standard, August 2024,
  <https://doi.org/10.6028/NIST.FIPS.204>.
- NIST, "FAQ – FIPS 204 – Computing mu", March 2025,
  <https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/faq/fips204-sec6-03192025.pdf>.
- D. Connolly, draft-connolly-cfrg-ml-dsa-security-considerations-02, March 2026,
  §2.2.2 (context strings), §3.2.4 (external μ), §3.2.5 (HashML-DSA),
  <https://datatracker.ietf.org/doc/draft-connolly-cfrg-ml-dsa-security-considerations/02/>.
- NSA, Commercial National Security Algorithm Suite 2.0 FAQ, version 2.1, December 2024,
  <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>.
- RFC 8554, Leighton-Micali Hash-Based Signatures, <https://www.rfc-editor.org/rfc/rfc8554>.
- NIST SP 800-208, Recommendation for Stateful Hash-Based Signature Schemes,
  <https://doi.org/10.6028/NIST.SP.800-208>.
