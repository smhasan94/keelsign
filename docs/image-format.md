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
- That order is a signer rule only. Verifiers MUST NOT depend on the relative order of
  the keelsign TLVs, nor on their position among the MCUboot TLVs.
- **Byte order.** keelsign supports only little-endian images: the image header fields,
  both TLV info headers and every TLV header are little-endian, and a verifier rejects
  anything else. imgtool can write big-endian images (`imgtool sign -e/--endian big`,
  `scripts/imgtool/main.py:439-440`; the same option in imgtool 2.4.0); keelsign does not
  support them.
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
ih_protect_tlv_size` bytes (sizes at `boot/bootutil/src/bootutil_img_hash.c:122-135`,
hashing from `bootutil_sha_init` to `bootutil_sha_finish` at `:137-210`;
`docs/design.md:159-164` and `:1349-1351`).

The verifier MUST reject, rather than hash anyway, an image whose protected area is
malformed: `ih_protect_tlv_size != 0` with a TLV info magic other than `0x6908`, or a
protected info header whose `it_tlv_tot != ih_protect_tlv_size`. MCUboot's TLV iterator
rejects both too (`boot/bootutil/src/tlv.c:66-77`). SHA-35's parser rejects both
(`BadTlvInfoMagic`, `ProtectedSizeMismatch`), and SHA-42's `image_digest` hashes only an
`Image` that parsed, so a malformed protected area is never hashed.

- **ML-DSA-44/65:** pure ML-DSA (FIPS 204 `ML-DSA.Sign` / `ML-DSA.Verify`) with message
  `M` and context string `MLDSA_CONTEXT` ([ML-DSA context](#ml-dsa-context)). Never
  HashML-DSA.
- **LMS/HSS:** HSS (RFC 8554 §6) with message `M`.
- The same `M` is signed by the Ed25519 half of a hybrid image ([Hybrid layout](#hybrid-layout)).

The verifier computes `M` itself while hashing the image in chunks (SHA-42:
`keelsign_verify::image_digest`, which hashes the 32 header bytes it parsed, streams the
body from the slot through a caller-sized buffer and, since SHA-46, hashes the protected
TLV area from the copy it parsed too), and also requires the `IMAGE_TLV_SHA256` TLV to be
present and equal to `M`. Every `IMAGE_TLV_SHA256` (`0x10`) present MUST equal `M`, and a
keelsign verifier rejects an image carrying more than one. Images hashed with SHA-384 or
SHA-512 (`IMAGE_TLV_SHA384` `0x11` / `IMAGE_TLV_SHA512` `0x12`, `image.h:102-103`, no
`0x10`) are unsupported in v0.1 and rejected. SHA-35 exposes these TLVs, SHA-42 computes
`M`, and these rules are enforced by `keelsign_verify::verify` (SHA-46; see
[docs/policy.md](policy.md)), which the policy-matrix sample images exercise
(`Image(MissingSha256Tlv)`, `Image(MultipleSha256Tlvs)`, `Image(DigestMismatch)`). Images
carrying `IMAGE_TLV_SIG_PURE` (`0x25`, `image.h:109`), MCUboot's "signature over the
image, not its digest" mode, are rejected (`Image(SigPure)`).

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
- **Not HashML-DSA.** NSA's CNSA 2.0 FAQ v2.1 says NSA "anticipates there will be no
  need for HashML-DSA in NSS" ([CNSA 2.0](#accepted-lms-parameter-sets-and-cnsa-20)), and
  draft-connolly-cfrg-ml-dsa-security-considerations-02 §3.2.5 discourages it
  (verification ambiguity, hash-algorithm confusion); pure ML-DSA over `M` avoids both.
- **Applies to both families.** The same `M` is the message for ML-DSA and LMS/HSS, so
  the parser, the hashing and the dispatch are identical for every algorithm.
- **Protected TLVs are covered.** Everything MCUboot authenticates (header, body,
  protected TLVs such as the security counter) is covered by the PQ signature too.
- **Collision assumption.** Signing `M` caps image binding at SHA-256 collision
  resistance (128 bits), below ML-DSA-65's category-3 target; this is MCUboot's own
  assumption for every signature it verifies.

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

A PQ signature TLV whose type differs from the selected key's algorithm (for example an
`0x4BA1` ML-DSA-44 signature naming an LMS/HSS key) is rejected with
`Error::KeyAlgorithmMismatch`; it is never re-interpreted as another algorithm.

The Ed25519 key of a hybrid image is identified by MCUboot's own `IMAGE_TLV_KEYHASH`
(`0x01`): SHA-256 of the DER SubjectPublicKeyInfo, which is what imgtool embeds and
hashes (`scripts/imgtool/keys/ed25519.py:32-36`). MCUboot compares only the first
`keyhash_len` bytes of it (`boot/bootutil/src/bootutil_find_key.c:56-80`); keelsign-verify
requires all 32. A device trusts an Ed25519 key as `keelsign_verify::Ed25519Key` (the raw
32-byte key) in the same `TrustedKeys` set as its PQ keys
(`TrustedKeys::with_ed25519`), which looks it up by `keelsign_verify::keyhash_of`, the
SHA-256 of the RFC 8410 SubjectPublicKeyInfo prefix and the key.

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
- "Exactly one pair" is a verifier rule too: under `Policy::Hybrid` and
  `Policy::ClassicalOnly`, `keelsign_verify::verify` (SHA-46) rejects an image with zero
  KEYHASH + ED25519 pairs (`Ed25519(Missing)`), with more than one (`Ed25519(Multiple)`)
  or with an ED25519 TLV that no KEYHASH immediately precedes (`Ed25519(Unpaired)`). MCUboot's own semantics differ: it
  verifies every signature whose KEYHASH names a known key, each result overwriting the
  last (`image_validate.c:413-414`, taken at `:562-564`), and skips a signature that
  follows an unknown KEYHASH (`:396-403`). This is the one intentional difference between
  the two validators.
- MCUboot TLVs first, then the keelsign TLVs, so `imgtool sign` output is kept byte for
  byte and keelsign only appends (and fixes up `it_tlv_tot`).
- A PQ-only image has rows 1, 4 and 5.
- The hybrid policy (both must verify) is enforced by `keelsign_verify::verify` under
  `Policy::Hybrid` (SHA-46; see [docs/policy.md](policy.md)), with the Ed25519 half
  checked by `ed25519-dalek`'s `verify_strict` behind the `ed25519` feature.

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

PQ and key-ID TLV values for ML-DSA-44/65 and for LMS/HSS with LM-OTS W8, m ∈ {24, 32},
tree heights H10, H20 and H25 and one or two HSS levels. An HSS signature with W8 is
`4 + L·(4 + (4 + n + p·n) + 4 + h·m) + (L − 1)·(24 + m)` bytes with n = m and p = 34
(n = 32) or 26 (n = 24) (RFC 8554 §4.5, §5.4, §6.2; SP 800-208 Table 4).

| Item | Parameters | Levels | Bytes |
|---|---|---|---|
| Key ID | SHA-256 truncated | — | 16 |
| ML-DSA-44 | FIPS 204 | — | 2,420 |
| ML-DSA-65 | FIPS 204 | — | 3,309 |
| LMS/HSS | M32 H10 | 1 | 1,456 |
| LMS/HSS | M32 H20 | 1 | 1,776 |
| LMS/HSS | M32 H25 | 1 | 1,936 |
| LMS/HSS | M32 H10+H10 | 2 | 2,964 |
| LMS/HSS | M32 H20+H20 | 2 | 3,604 |
| LMS/HSS | M32 H25+H25 | 2 | 3,924 |
| LMS/HSS | M24 H10 | 1 | 904 |
| LMS/HSS | M24 H20 | 1 | 1,144 |
| LMS/HSS | M24 H25 | 1 | 1,264 |
| LMS/HSS | M24 H10+H10 | 2 | 1,852 |
| LMS/HSS | M24 H20+H20 | 2 | 2,332 |
| LMS/HSS | M24 H25+H25 | 2 | 2,572 |

`MAX_PQ_SIGNATURE_LEN = 3,924` bytes (HSS-2, M32, H25+H25) is the largest PQ signature
TLV value the verifier accepts ([Accepted LMS parameter sets](#accepted-lms-parameter-sets-and-cnsa-20):
H5–H25, at most two levels under the default policy, one under `cnsa_2_0()`; every
mixed-height two-level signature is smaller). The
parser (SHA-35) enforces it as a hard parse bound on the PQ signature TLV length.

Worst-case unprotected TLV area of a hybrid image:

| Part | Bytes |
|---|---|
| TLV info header | 4 |
| SHA256 TLV (4 + 32) | 36 |
| KEYHASH TLV (4 + 32) | 36 |
| ED25519 TLV (4 + 64) | 68 |
| Key-ID TLV (4 + 16) | 20 |
| PQ signature TLV (4 + `MAX_PQ_SIGNATURE_LEN`) | 3,928 |
| Total | 4,092 |

**Budget rule:** reserve one 4 KiB flash page after the image body for the TLV areas
(protected and unprotected). The worst case above leaves 4 bytes for protected TLVs:
room for the protected TLV info header and nothing else, so an image with the largest PQ
signature and any protected TLV (a security counter, for example) needs more than one
page.

The TLV areas count against the slot's usable size, which is the slot minus MCUboot's
trailer: MCUboot rejects an image whose TLV area ends beyond `bootutil_max_image_size`
(`boot/bootutil/src/bootutil_misc.c:355`, checked at `image_validate.c:300`). Per-board
slot and partition numbers are SHA-58.

## ML-DSA context

```text
MLDSA_CONTEXT = b"keelsign-mcuboot-image-v1"   (25 bytes)
```

Every keelsign ML-DSA signature uses this FIPS 204 context string (at most 255 bytes).
draft-connolly-cfrg-ml-dsa-security-considerations-02 §2.2.2 recommends a fixed context
string per protocol use: it separates keelsign image signatures from any other signature
made with the same ML-DSA key. `keelsign_verify::mldsa` (SHA-44, the `ml-dsa` feature)
passes it to `verify_with_context`; a new image-format version would get a new context
string.

## Accepted LMS parameter sets and CNSA 2.0

**The only CNSA 2.0-compliant keelsign configuration is single-tree LMS (`L = 1`) verified
under `ParameterPolicy::cnsa_2_0()` (`DefaultBackend::cnsa_2_0()` with `verify_pq_with`).
ML-DSA-44 and ML-DSA-65 are never CNSA 2.0 algorithms: CNSA 2.0 uses ML-DSA-87.**

keelsign-verify has two device policies for LMS/HSS (`keelsign_verify::lms::ParameterPolicy`,
SHA-240). Both accept LM-OTS W8 with SHA-256 (m = n = 32) or SHA-256/192 (m = n = 24),
tree heights H5–H25 and the same hash at every level; they differ only in the number of
HSS levels:

| Policy | Levels | LM-OTS | Hash | Entry points | Use |
|---|---|---|---|---|---|
| `keelsign_default()` | `L ≤ 2` | W8 | SHA-256 or SHA-256/192 | `lms::verify`, `DefaultBackend::new()`, `verify_pq` | the device default |
| `cnsa_2_0()` | `L = 1` only | W8 | SHA-256 or SHA-256/192 | `DefaultBackend::cnsa_2_0()` via `verify_pq_with` | NSS deployments that must follow CNSA 2.0 |
| `rfc_8554_all_sets()` | `L ≤ 8` | W1–W8 | SHA-256 or SHA-256/192 | none on a device (`lms::verify_with_policy` in host tests) | checking published vectors outside the device policies |

An integrator selects the strict policy in code, at the call site:
`verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, image.unprotected().pairs(), &digest)`.
There is no Cargo feature for it, and `DefaultBackend` has no constructor for
`rfc_8554_all_sets()`. Under `cnsa_2_0()` an HSS public key with `L ≥ 2` is
`UnsupportedParameterSet` before its signature is read. A single LMS tree is an HSS key
with `L = 1`: RFC 8554 §6 says "HSS allows L=1, in which case the HSS public key and
signature formats are essentially the LMS public key and signature formats, prepended by
a fixed field", and "In the specific case of L=1, the format of an HSS signature is
u32str(0) || sig[0]". So keelsign's HSS-framed `L = 1` key and signature are single-tree
LMS; what CNSA 2.0 forbids is `L ≥ 2`.

Sources:

- **ML-DSA-87 is CNSA 2.0's ML-DSA** (NSA-authored IETF drafts, checked for this
  document): draft-jenkins-cnsa2-pkix-profile-05 (M. Jenkins, NSA-CCSS, July 2026) §4:
  "The signature applied to all CNSA Suite certificates and CRLs MUST be made with a
  ML-DSA-87 signing key."; draft-guthrie-cnsa2-ipsec-profile-04 (R. Guthrie, NSA-CCSS,
  July 2026) §3: "NSA has selected two: ML-DSA-87 [FIPS204] for signing and ML-KEM-1024
  [FIPS203] for key establishment."
- **HashML-DSA.** NSA announced CNSA 2.0 FAQ v2.1 on the NIST pqc-forum ("Updates to the
  CNSA 2.0 FAQ", Morgan B. Stern, NSA Cybersecurity, 13 January 2025); a reply in that
  thread (J. Mattsson, 14 January 2025) quotes the FAQ's sentence: "Because HashML-DSA
  does not offer any functionality not already offered by the CNSA hash functions
  combined in a standard way with ML-DSA-87, and because standard ML-DSA-87 is expected to
  be widely supported, NSA anticipates there will be no need for HashML-DSA in NSS."
  The FAQ itself (next item) carries this sentence verbatim. keelsign never uses
  HashML-DSA ([Signing mode](#signing-mode)).
- **Single-tree LMS/XMSS only.** NSA, *The Commercial National Security Algorithm Suite
  2.0 and Quantum Computing FAQ* (CNSA 2.0 FAQ v2.1, U/OO/194427-22, PP-24-4014,
  December 2024), read from the Wayback Machine snapshot of 23 December 2025,
  <https://web.archive.org/web/20251223232129/https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>
  (sha256 and size in [References](#references); the direct media.defense.gov URL
  returned HTTP 403 on 2026-09-30). Its question on page 6 of 21 of the archived PDF,
  "Q: Can I use HSS or XMSSMT from NIST SP 800-208?", is answered: "From NIST SP 800-208,
  NSA has only approved LMS and XMSS for use in NSS. The multi-tree algorithms HSS and
  XMSSMT are not allowed." [XMSS^MT; the superscript is lost in the text extraction.] So
  an HSS key with two levels is not CNSA 2.0 compliant.
- **LMS parameters.** The FAQ's algorithm table (page 3 of the archived PDF) lists LMS (NIST SP 800-208) for
  "digitally signing firmware and software" with "All parameters approved for all
  classification levels. LMS SHA-256/192 is recommended.", and its hash-based-signature
  answer names the "preferred parameter set is Section 4.2, LMS with SHA-256/192". Both
  device policies accept both hash sizes, each with W8 only; NSA's preferred hash is
  SHA-256/192 (M24).

**Deviation from CNSA 2.0:** the device default `keelsign_default()` (`lms::verify`,
`DefaultBackend::new()`, `verify_pq`) accepts two-level HSS (`L ≤ 2`), which the CNSA 2.0
FAQ v2.1 says is not allowed in NSS. Two levels let one long-lived top-level key certify
many short-lived signing trees, and `MAX_PQ_SIGNATURE_LEN` is sized for them. NSS
deployments must sign with a single LMS tree (`L = 1`) and verify with
`DefaultBackend::cnsa_2_0()` through `verify_pq_with`. ML-DSA images, hybrid or not, are
outside CNSA 2.0 whatever the policy (ML-DSA-87 is out of scope, see
[Out of scope](#out-of-scope)).

## MCUboot compatibility

- **Stock MCUboot ignores keelsign TLVs.** `bootutil_img_validate` walks every TLV and
  acts only on the types it was built for; its `switch` has no `default`, so other types
  are skipped (`image_validate.c:306-551`). A hybrid image therefore boots on an
  unmodified Ed25519 MCUboot, which checks the SHA256, KEYHASH and ED25519 TLVs, when the
  TLV allow list is disabled or extended (Zephyr enables it by default; see below).
- **No PQ guarantee on stock MCUboot.** Because a stock MCUboot ignores the keelsign PQ
  TLVs, a hybrid image whose PQ signature is stripped or garbage still boots there. The
  PQ guarantee exists only in a keelsign-enabled bootloader.
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
  Cypress, Espressif and NuttX ports define it unconditionally (NuttX:
  `boot/nuttx/include/mcuboot_config/mcuboot_config.h:138`). A keelsign-enabled MCUboot build
  (SHA-62) MUST either add `0x4BA0`–`0x4BA3` to the allow list or disable it. A stock
  Zephyr MCUboot with the default allow list **rejects** keelsign images.
- **SHA256 TLV is mandatory.** MCUboot requires the hash TLV and compares it
  (`image_validate.c:341-362`, `:553-557`); `keelsign_verify::verify` requires exactly
  one, equal to `M`, under every policy (SHA-46, `Image(MissingSha256Tlv)`,
  `Image(MultipleSha256Tlvs)`, `Image(DigestMismatch)`).
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
  `boot/bootutil/src/bootutil_img_hash.c:122-135`, `:137-210` and `docs/design.md:159-164`,
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
  `boot/bootutil/src/image_validate.c:273-284`, `:425-431` @ `a8ffd2c`.
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
- The image parser (SHA-35), digest computation (SHA-42), per-board partition numbers
  (SHA-58) and the MCUboot allow-list glue (SHA-62); the verify policies (SHA-46) are in
  [docs/policy.md](policy.md) and the CLI's `verify` command in
  [docs/verify.md](verify.md).

## Sample images

`tests/fixtures/images/` holds sample images generated by
[`scripts/gen_image_fixtures.py`](../scripts/gen_image_fixtures.py): imgtool 2.4.0 output
(header, protected TLVs, SHA256 TLV and, for the hybrid image, the Ed25519 KEYHASH and
ED25519 TLVs, made with a committed Ed25519 **test key** from a fixed public seed) plus the
keelsign TLVs, with LMS/HSS signatures from the pinned independent signer hsslms 0.1.3
and ML-DSA signatures (SHA-44) from the pinned independent signer dilithium-py 1.4.0
(pure ML-DSA over `M` with `MLDSA_CONTEXT`, the FIPS 204 deterministic variant). The
ML-DSA signatures are made with two **test keys**, one per parameter set, whose seeds are
SHA-256 of fixed public labels; `MANIFEST.json` `keys` records each seed and public key
(`mldsa-test-key:mldsa44`, `mldsa-test-key:mldsa65`), and
`keelsign-verify/tests/mldsa_images.rs` checks every committed ML-DSA key and signature
byte for byte against RustCrypto `ml-dsa`'s deterministic signer from the same seed.
`MANIFEST.json` records every file's size and SHA-256 and the imgtool and cryptography
versions. `keelsign-verify/tests/image_fixtures.rs` parses them with
`keelsign_verify::image` and verifies them.

The policy matrix (SHA-46, [docs/policy.md](policy.md)) adds three signed images and
eighteen deterministic mutations, all written by the same script:

| File | Notes |
|---|---|
| `keelsign-hybrid-ed25519-mldsa44.bin` | imgtool Ed25519 plus an ML-DSA-44 half under the ML-DSA-44 test key |
| `keelsign-hybrid-protected-tlvs.bin` | the hybrid layout with protected `SEC_CNT` 7 and vendor TLV `0x10A0` |
| `keelsign-hybrid-reserved-tlv-protected.bin` | the hybrid layout plus a `0x4BA0` TLV in the protected area (`imgtool sign --custom-tlv`); rejected |
| `keelsign-hybrid-*.bin` (18 more) | mutations of `keelsign-hybrid-ed25519-lms.bin` (one of `keelsign-hybrid-protected-tlvs.bin`), not re-signed; `MANIFEST.json` records `derived_from` and `mutation` |
| `policy-matrix.bin` | the "KSPM v2" index of the matrix (names, PQ keys, expected verdicts with the `ml-dsa` feature on and off; no image bytes) that `benches/policy-kat` runs on the host and the boards |

The ML-DSA verifier (SHA-44) adds two signed images and seventeen mutations:

| File | Notes |
|---|---|
| `keelsign-mldsa44.bin`, `keelsign-mldsa65.bin` | ML-DSA-44 / ML-DSA-65 under the test keys (re-signed in SHA-44; before, length-correct fillers) |
| `keelsign-mldsa44-protected-tlvs.bin`, `keelsign-mldsa65-protected-tlvs.bin` | the same with protected `SEC_CNT` 7 and vendor TLV `0x10A0`, so their `M` differs: the source of the "signature from another image" mutations |
| `keelsign-mldsa{44,65}-*.bin` (15) | mutations: body and protected TLV tampered (with and without the SHA256 TLV recomputed), signature `c̃` flipped, hint count over ω, signature truncated, key ID flipped, signature taken from the `-protected-tlvs` image |
| `keelsign-hybrid-mldsa44-missing-pq.bin`, `keelsign-hybrid-mldsa44-stripped-pq.bin` | `keelsign-hybrid-ed25519-mldsa44.bin` without its `0x4BA1` TLV, and without `0x4BA0` and `0x4BA1` |

The hybrid Ed25519 + LMS work on the device (SHA-69) adds one signed image and four
mutations:

| File | Notes |
|---|---|
| `keelsign-hybrid-ed25519-hss2.bin` | imgtool Ed25519 plus an HSS L=2 signature (2,644 bytes), both levels `LMS_SHA256_M32_H5` / `LMOTS_SHA256_N32_W8`, under its own key |
| `keelsign-hybrid-hss2-bad-ed25519.bin`, `keelsign-hybrid-hss2-bad-pq.bin`, `keelsign-hybrid-hss2-bad-top-level.bin`, `keelsign-hybrid-hss2-missing-pq.bin` | mutations of it: `ED25519` byte 0 flipped, the last `0x4BA3` byte (bottom-level path) flipped, `0x4BA3` byte 12 (`C[0]` of the top level's one-time signature) flipped, `0x4BA3` removed |

Every image's `MANIFEST.json` entry carries a `policy` object, its expected verdict under
`classical_only`, `pq_only` and `hybrid`; docs/policy.md's matrix table,
`keelsign-verify/tests/policy_matrix.rs` and `policy-matrix.bin` are checked against it.
Where the verdict differs without the `ml-dsa` feature, the entry also has a
`policy_without_ml_dsa` object ([docs/policy.md](policy.md#the-ml-dsa-feature)).

The same directory holds golden MCUboot images for the image parser (SHA-35): plain
imgtool 2.4.0 output, no keelsign TLVs, each with a security counter (7), a dependency
(image 1, version 1.2.3+4) and a boot record, so they carry the protected `SEC_CNT`,
`BOOT_RECORD` and `DEPENDENCY` TLVs and the unprotected `SHA256`, `KEYHASH` and signature
TLVs:

| File | Signature | Notes |
|---|---|---|
| `mcuboot-rsa2048.bin` | RSA-2048 PSS (`0x20`) | key `keys/rsa2048-test-key.pem` |
| `mcuboot-ecdsa-p256.bin` | ECDSA P-256 (`0x22`) | key `keys/ecdsa-p256-test-key.pem` |
| `mcuboot-ed25519.bin` | Ed25519 (`0x24`) | key `keys/ed25519-test-key.pem` |
| `mcuboot-ed25519-padded.bin` | Ed25519 (`0x24`) | padded to a `0x2000`-byte slot with the boot trailer (`--pad`); bytes after the TLV area are allowed |
| `rejected/mcuboot-ed25519-bigendian.bin` | Ed25519 (`0x24`) | big-endian (`-e big`); rejected with `BadMagic` |
| `mcuboot-ed25519-200k.bin` | Ed25519 (`0x24`) | own 204,800-byte body in a `0x40000`-byte slot (SHA-42): the chunked digest on the host and from flash on the boards |

The RSA-2048 and ECDSA P-256 keys are **test keys** derived deterministically from fixed
public seeds, like the Ed25519 one; every committed key file starts with `# TEST KEY`.
RSA-PSS and ECDSA signatures are randomised, so the script signs once (`imgtool sign
--sig-out`), commits the base64 signatures under `sigs/`, and rebuilds the images from
them with `imgtool sign --fix-sig sigs/NAME.sig --fix-sig-pubkey KEY`, byte for byte.
`--resign` signs afresh and rewrites `sigs/` (needed only when the keys, the body or the
imgtool options change). For each golden image `MANIFEST.json` records the header fields,
the TLV types and lengths per area, `M` (`digest_hex`), `tlv_end`, the expected parse
result (`expect_parse`) and whether `imgtool verify` applies (little-endian only).

Tool prerequisite for regenerating (not for testing): `imgtool==2.4.0` in a virtual
environment, passed with `--imgtool PATH` or found on `PATH`. The script downloads the
hsslms sdist and the dilithium-py wheel (both pinned by SHA-256, extracted into a
temporary directory, never installed), so regenerating and `--check` need network access.

```sh
python3 -m venv .venv-imgtool && .venv-imgtool/bin/pip install imgtool==2.4.0
python3 scripts/gen_image_fixtures.py --imgtool .venv-imgtool/bin/imgtool
python3 scripts/gen_image_fixtures.py --check --imgtool .venv-imgtool/bin/imgtool
```

`--check` also runs `imgtool verify --key` on every little-endian image and compares the
TLV listing of `imgtool dumpinfo` with `MANIFEST.json` for each little-endian golden image.

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
- NSA, The Commercial National Security Algorithm Suite 2.0 and Quantum Computing FAQ,
  version 2.1 (U/OO/194427-22, PP-24-4014), December 2024. Read from the Wayback Machine
  snapshot `20251223232129`,
  <https://web.archive.org/web/20251223232129/https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>
  (441,742 bytes, 21 pages, sha256
  `ca447adb27af022f6bcca70873ef3404a7db0758fa0626fe9cd994451d86f5e0`). The direct URL,
  <https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF>,
  returned HTTP 403 on 2026-09-30.
- M. Jenkins (NSA), draft-jenkins-cnsa2-pkix-profile-05, July 2026, §4,
  <https://datatracker.ietf.org/doc/draft-jenkins-cnsa2-pkix-profile/05/>.
- R. Guthrie (NSA), draft-guthrie-cnsa2-ipsec-profile-04, July 2026, §3,
  <https://datatracker.ietf.org/doc/draft-guthrie-cnsa2-ipsec-profile/04/>.
- M. B. Stern (NSA), "Updates to the CNSA 2.0 FAQ", NIST pqc-forum, 13 January 2025,
  <https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/sS47RFCdJ74>.
- RFC 8554, Leighton-Micali Hash-Based Signatures, §6 (HSS with `L = 1`),
  <https://www.rfc-editor.org/rfc/rfc8554>.
- NIST SP 800-208, Recommendation for Stateful Hash-Based Signature Schemes,
  <https://doi.org/10.6028/NIST.SP.800-208>.
