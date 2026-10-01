# Verify policies (SHA-46)

`keelsign_verify::verify` is the single entry point a bootloader calls: it reads an image
from a slot, enforces the image rules, computes the image digest `M` and verifies the
halves the device's `Policy` requires against its trusted keys, then returns a
`VerifiedImage` for the caller's anti-rollback check. This document specifies the
policies, the key sets, the image rules and their precedence, and the full policy × image
matrix, which is checked cell by cell against the code. The image format itself (TLV IDs,
signing mode, hybrid layout) is [docs/image-format.md](image-format.md).

```rust,ignore
use keelsign_verify::{DEFAULT_CHUNK_LEN, Ed25519Key, Policy, TrustedKeys, verify};

let keys = TrustedKeys::<1, 1>::with_ed25519(&[lms_key], &[Ed25519Key { public_key: &ed25519_pk }])?;
let mut tlv_buf = [0u8; 4096];
let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
let verified = verify(&mut slot_reader, &keys, Policy::Hybrid, &mut tlv_buf, &mut chunk)?;
// Anti-rollback is the caller's: verified.version, verified.security_counter.
```

`verify_with(backend, ..)` is the same with any `Backend` for the post-quantum half, for
example `DefaultBackend::cnsa_2_0()` (single-tree LMS only). No heap: the caller supplies
the TLV buffer and the digest chunk.

## Policies

`Policy` has three values and no default: a device must choose one, and an unset policy
can never silently mean "accept".

| Policy | Ed25519 half | Post-quantum half | Ignores |
|---|---|---|---|
| `ClassicalOnly` | required | not checked | the keelsign TLVs (transition mode for fleets not yet verifying PQ signatures) |
| `PqOnly` | not checked | required | a KEYHASH + ED25519 pair, whatever it holds |
| `Hybrid` | required | required | nothing |

Both halves are over the same `M`. One hybrid image therefore serves fleets under all
three policies. The image rules apply under every policy. `Policy::requires_ed25519()`
and `Policy::requires_pq()` say which halves a policy checks.

## Key sets

A device's trusted keys are one `TrustedKeys<'a, N, E>` set:

- up to `N` post-quantum keys (`TrustedKey`: algorithm and raw public key), found by the
  16-byte key ID (`key_id_of`, SHA-256 of the raw key, truncated) that the image carries
  in `TLV_KEELSIGN_KEY_ID`;
- up to `E` Ed25519 keys (`Ed25519Key`: the raw 32-byte key), found by MCUboot's
  KEYHASH (`keyhash_of`: SHA-256 of the RFC 8410 SubjectPublicKeyInfo, all 32 bytes).

`E` defaults to 0, so `TrustedKeys::<N>::new(&pq)` is a post-quantum-only set; a hybrid
device writes `TrustedKeys::<N, E>::with_ed25519(&pq, &ed25519)`. More keys than `N` or
`E` is `KeySetError::Capacity`; two Ed25519 keys with the same KEYHASH are
`KeySetError::DuplicateKeyId`. Empty sets fail closed: with no Ed25519 key, every policy
that checks the Ed25519 half ends in `Ed25519(KeyNotTrusted)` for an image whose Ed25519
half is otherwise well-formed; with no PQ key, every policy that checks the PQ half ends
in `KeyNotTrusted` for an image whose PQ half is otherwise well-formed (an image without
a PQ signature is `MissingPqSignature` first, see [Error precedence](#error-precedence)).

Under `Hybrid` the two halves are not bound to the same signer: any trusted Ed25519 key
plus any trusted PQ key passes, which suits the algorithm-break threat model; a deployment
with several signers should keep one key of each kind per trusted signer set.

There is no PQ-algorithm policy ("accept only LMS"): the trusted key set is the policy.
A device that trusts only an LMS key accepts only LMS signatures. A separate algorithm
policy is a follow-up if a deployment needs one.

## The `ed25519` feature

The Ed25519 half needs the `ed25519` feature of `keelsign-verify` (off by default), which
pulls in `ed25519-dalek` `=3.0.0` without default features (`no_std`, no heap) and checks
signatures with `verify_strict`. Without the feature, `ClassicalOnly` and `Hybrid` fail
closed with `Ed25519(NotEnabled)` before anything is read, and `PqOnly` is unaffected (a
`PqOnly` bootloader carries no curve code). `keelsign_verify::ed25519::is_enabled()` says
which build is running. The flash cost is measured in
[docs/benchmarks.md](benchmarks.md#hybrid-verify-entry-point-sha-46); the deepest static
stack chain of a hybrid verify is about 12.8 KB, of which roughly 8 KB is Ed25519 (its
NAF lookup tables and frames), see the same
[section](benchmarks.md#hybrid-verify-entry-point-sha-46).

## The `ml-dsa` feature

ML-DSA-44 and ML-DSA-65 signatures need the `ml-dsa` feature of `keelsign-verify` (off by
default, SHA-44), which pulls in `ml-dsa` `=0.1.1` without default features (`no_std`,
no heap, no `alloc`/`getrandom`/`pkcs8`) and checks each signature with
`keelsign_verify::mldsa::verify`: pure FIPS 204 `ML-DSA.Verify` over `M` with the context
`MLDSA_CONTEXT` ([docs/image-format.md](image-format.md#ml-dsa-context)), never
HashML-DSA. `keelsign_verify::mldsa::is_enabled()` and `Algorithm::is_enabled` say which
build is running.

- **Without the feature**, the dispatcher answers `UnsupportedAlgorithm(MlDsa44)` or
  `UnsupportedAlgorithm(MlDsa65)` after the key lookup and before any backend runs, under
  every backend. Only the cells whose post-quantum half reaches the ML-DSA backend change;
  image rules, the Ed25519 half and the key lookup (`KeyNotTrusted`) still come first.
  These are the cells without the feature (the manifest's `policy_without_ml_dsa`; every
  other cell is as in the [Policy matrix](#policy-matrix)):

| Image | ClassicalOnly | PqOnly | Hybrid |
|---|---|---|---|
| `keelsign-hybrid-ed25519-mldsa44.bin` | `Ok` | `UnsupportedAlgorithm(MlDsa44)` | `UnsupportedAlgorithm(MlDsa44)` |
| `keelsign-mldsa44-bad-body-rehashed.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44-bad-hint.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44-bad-protected-rehashed.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44-bad-sig.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44-foreign-sig.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44-protected-tlvs.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44-short-sig.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa44.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa44)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-bad-body-rehashed.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-bad-hint.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-bad-protected-rehashed.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-bad-sig.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-foreign-sig.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-protected-tlvs.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65-short-sig.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |
| `keelsign-mldsa65.bin` | `Ed25519(Missing)` | `UnsupportedAlgorithm(MlDsa65)` | `Ed25519(Missing)` |

- **`DefaultBackend::new()`** verifies ML-DSA-44/65 (`DefaultBackend::allows_ml_dsa()` is
  `true`). **`DefaultBackend::cnsa_2_0()` refuses ML-DSA** with `UnsupportedParameterSet`
  (`allows_ml_dsa()` is `false`): ML-DSA-44 and ML-DSA-65 are never CNSA 2.0 algorithms
  ([docs/image-format.md](image-format.md)), so the strict backend accepts single-tree LMS
  only.
- **Error mapping** of the ML-DSA backend (the backend slot of step 10 in
  [Error precedence](#error-precedence)):

  | Failure | Variant |
  |---|---|
  | public key not 1,312 / 1,952 bytes (only through `Backend::verify` called directly; `TrustedKeys::new` already refuses it) | `InvalidPublicKey` |
  | signature not 2,420 / 3,309 bytes (truncated or trailing bytes) | `MalformedSignature` |
  | signature does not decode: malformed hint encoding, or `‖z‖∞ ≥ γ1 − β` (the FIPS 204 norm bound, which `ml-dsa` checks while decoding) | `MalformedSignature` |
  | the verification equation fails (wrong key, message or context, tampered `c̃` or `z`) | `SignatureInvalid` |
  | key ID not in the set / of the wrong length / for another algorithm | `KeyNotTrusted` / `InvalidKeyId` / `KeyAlgorithmMismatch` (dispatcher) |
  | body or protected TLV tampered | `Image(DigestMismatch)`, before any signature; with the SHA256 TLV recomputed, `SignatureInvalid` |

- **What the signature covers.** An ML-DSA signature covers `M` only, like MCUboot's own
  signatures: the unprotected TLV area is outside it. Moving a signature to another image
  with the same `M` (same header, body and protected TLVs) therefore verifies by design;
  a signature taken from an image with a different `M` is `SignatureInvalid`
  (`keelsign-mldsa44-foreign-sig.bin`, `keelsign-mldsa65-foreign-sig.bin`).
- **Stack.** The verify runs on the stack: about 98 KB (ML-DSA-44) and 158 KB (ML-DSA-65) on stable
  for the verify frame alone, far over the 32 KB device budget. See
  [docs/benchmarks.md](benchmarks.md#ml-dsa-verify-sha-44); SHA-169 owns a low-stack
  verify.

## Image rules

These rules hold under every policy (`Error::Image(ImageError::…)`). MCUboot sources are
cited at commit `a8ffd2c`.

- **Flags.** `IMAGE_F_ENCRYPTED_AES128` / `IMAGE_F_ENCRYPTED_AES256` is `Encrypted` and
  any `IMAGE_F_COMPRESSED_*` flag is `Compressed` (MCUboot's `IS_ENCRYPTED` /
  `IS_COMPRESSED`, `image.h:191-198`): the digest of such an image is not over what
  boots, and keelsign does not support them yet. `IMAGE_F_NON_BOOTABLE` is `NonBootable`
  (MCUboot refuses to boot it, `bootutil_public.c:787`). `IMAGE_F_PIC`,
  `IMAGE_F_RAM_LOAD`, `IMAGE_F_ROM_FIXED` and unknown bits are accepted, as by MCUboot.
- **keelsign TLVs are unprotected-only.** Any TLV of the keelsign block
  `0x4BA0..=0x4BAF` in the protected area, an assigned or a reserved ID, is
  `KeelsignTlvProtected(type)`: the signer broke the format (a PQ signature there is
  inside `M` and can never sign `M`; reserved IDs are never emitted).
- **No pure signatures.** A `SIG_PURE` TLV (`0x25`) in either area is `SigPure`: the
  signature would be over the image itself, not `M`.
- **Exactly one SHA256 TLV.** `IMAGE_TLV_SHA256` (`0x10`) TLVs are counted over both
  areas: none is `MissingSha256Tlv` (this covers SHA-384- and SHA-512-only images), more
  than one `MultipleSha256Tlvs`, a length other than 32 `InvalidSha256Tlv`. MCUboot
  requires the hash TLV and rejects any that does not match (`image_validate.c:341-362`);
  a protected `0x10` is inside `M` and can never equal it.
- **Security counter.** `SEC_CNT` (`0x50`) is read from the protected area only, as
  MCUboot reads it with `prot = true`: more than one protected `SEC_CNT` is
  `MultipleSecurityCounters`, a length other than 4 `InvalidSecurityCounter`; none means
  `security_counter = None`. An unprotected `SEC_CNT` is ignored.
- **Digest.** `M` computed over the slot must equal the SHA256 TLV, or the image is
  `DigestMismatch` (it changed after it was hashed).

The halves:

- **Ed25519 (classical) half**, over the unprotected area: exactly one ED25519 TLV
  (`Ed25519(Missing)`, `Ed25519(Multiple)`), at most one KEYHASH TLV
  (`Ed25519(Multiple)`), KEYHASH immediately before ED25519 (`Ed25519(Unpaired)`;
  MCUboot pairs them the same way, `image_validate.c:364-403`, resetting the key after
  each signature at `:433`), a 32-byte KEYHASH (`Ed25519(InvalidKeyHash)`), a 64-byte
  signature (`Ed25519(InvalidSignatureLength)`, `image_validate.c:87-90`), a trusted key
  with that KEYHASH (`Ed25519(KeyNotTrusted)`), a public key that decodes
  (`Ed25519(InvalidPublicKey)`), and a signature over `M` that passes `verify_strict`
  (`Ed25519(SignatureInvalid)`).
- **Post-quantum half**, over the unprotected area: `verify_pq_with`, exactly one key-ID
  TLV and one PQ signature TLV, a trusted key of the signature's algorithm, the
  algorithm compiled in, then the backend (docs/image-format.md, Key ID and One PQ
  signature per image).

## Error precedence

When an image has several faults, the first check in this order decides the error
(`policy::tests::error_precedence_is_documented_order` proves it):

1. `Ed25519(NotEnabled)` if the policy checks the Ed25519 half and the `ed25519` feature is
   off, before any read.
2. `Image::read_from`: `Parse(_)`, `Read(_)`, `TlvAreaTooLarge`.
3. Header flags: `Image(Encrypted)`, then `Image(Compressed)`, then `Image(NonBootable)`.
4. The first keelsign-block TLV in the protected area: `Image(KeelsignTlvProtected(_))`.
5. A `SIG_PURE` TLV in either area: `Image(SigPure)`.
6. SHA256 TLVs over both areas: `Image(MissingSha256Tlv)`, `Image(MultipleSha256Tlvs)`,
   `Image(InvalidSha256Tlv)`.
7. Protected `SEC_CNT` TLVs: `Image(MultipleSecurityCounters)`,
   `Image(InvalidSecurityCounter)`.
8. `image_digest` (`Read(_)`, `ChunkBufferEmpty`), then `Image(DigestMismatch)`.
9. The Ed25519 half, if the policy checks it: `Ed25519(Missing)`, `Ed25519(Multiple)`,
   `Ed25519(Unpaired)`, `Ed25519(InvalidKeyHash)`, `Ed25519(InvalidSignatureLength)`,
   `Ed25519(KeyNotTrusted)`, `Ed25519(InvalidPublicKey)`, `Ed25519(SignatureInvalid)`.
10. The post-quantum half, if the policy checks it: `MultipleKeyIds` or
    `MultiplePqSignatures` (whichever comes first in TLV order), `MissingPqSignature`,
    `MissingKeyId`, `InvalidKeyId`, `KeyNotTrusted`, `KeyAlgorithmMismatch`,
    `UnsupportedAlgorithm(_)`, then the backend's `UnsupportedParameterSet`,
    `MalformedSignature`, `InvalidPublicKey` or `SignatureInvalid`.
11. `Ok(VerifiedImage)`.

The Ed25519 half is checked before the post-quantum half under `Hybrid`: it is MCUboot's
native structure and the cheaper check. Errors of the Ed25519 half are always wrapped in
`Error::Ed25519` and image rules in `Error::Image`, so an error names the half (or the
rule) that failed; the flat variants are the post-quantum half and the read.

## Policy matrix

Every image in `tests/fixtures/images/` (generated by `scripts/gen_image_fixtures.py`)
under every policy, with `DefaultBackend::new()`, the image's own PQ key (if it has one)
and the Ed25519 test key trusted, and the `ed25519` and `ml-dsa` features on. A cell is `Ok` or the
error, as Rust's `Debug` prints it (a TLV type as `0x%04X`). The cells are the `policy`
objects of `MANIFEST.json`; `keelsign-verify/tests/policy_matrix.rs` runs every cell
(also from a NOR flash), `benches/policy-kat` runs the cells of `policy-matrix.bin` on the
host and on both boards, and a repo check keeps this table equal to the manifest.

The cells are those with the `ml-dsa` feature on as well (the host test configuration).
Without it, the cells whose post-quantum half reaches the ML-DSA backend are
`UnsupportedAlgorithm` instead (SHA-44): the table in
[The ml-dsa feature](#the-ml-dsa-feature) lists them, and the manifest records them as
`policy_without_ml_dsa`. An Ed25519-only MCUboot image passes the Ed25519 half under
`Hybrid`, so the post-quantum half decides (`MissingPqSignature`).

| Image | ClassicalOnly | PqOnly | Hybrid | Notes |
|---|---|---|---|---|
| `keelsign-dual-pq-invalid.bin` | `Ed25519(Missing)` | `MultiplePqSignatures` | `Ed25519(Missing)` | invalid: one key ID and two PQ signature TLVs (LMS M32_H5, then ML-DSA-44) |
| `keelsign-hss2-m32-h5h5.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | HSS L=2, both levels LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8 |
| `keelsign-hybrid-bad-body.bin` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: body byte 0 ^= 0x01 |
| `keelsign-hybrid-bad-ed25519.bin` | `Ed25519(SignatureInvalid)` | `Ok` | `Ed25519(SignatureInvalid)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: ED25519 TLV value byte 0 ^= 0x01 |
| `keelsign-hybrid-bad-pq.bin` | `Ok` | `SignatureInvalid` | `SignatureInvalid` | mutation of `keelsign-hybrid-ed25519-lms.bin`: LMS/HSS signature TLV (0x4BA3) last byte ^= 0x01 |
| `keelsign-hybrid-bad-sha256.bin` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: SHA256 TLV value byte 0 ^= 0x01 |
| `keelsign-hybrid-ed25519-lms.bin` | `Ok` | `Ok` | `Ok` | hybrid: imgtool Ed25519 (KEYHASH + ED25519) plus LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1 |
| `keelsign-hybrid-ed25519-mldsa44.bin` | `Ok` | `Ok` | `Ok` | hybrid: imgtool Ed25519 (KEYHASH + ED25519) plus an ML-DSA-44 signature under the ML-DSA-44 test key (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-hybrid-flag-compressed.bin` | `Image(Compressed)` | `Image(Compressed)` | `Image(Compressed)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: `IMAGE_F_COMPRESSED_LZMA2` (0x400) set in `ih_flags` |
| `keelsign-hybrid-flag-encrypted.bin` | `Image(Encrypted)` | `Image(Encrypted)` | `Image(Encrypted)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: `IMAGE_F_ENCRYPTED_AES128` (0x04) set in `ih_flags` |
| `keelsign-hybrid-flag-non-bootable.bin` | `Image(NonBootable)` | `Image(NonBootable)` | `Image(NonBootable)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: `IMAGE_F_NON_BOOTABLE` (0x10) set in `ih_flags` |
| `keelsign-hybrid-keyhash-only.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: ED25519 TLV removed: KEYHASH alone |
| `keelsign-hybrid-missing-key-id.bin` | `Ok` | `MissingKeyId` | `MissingKeyId` | mutation of `keelsign-hybrid-ed25519-lms.bin`: key-ID TLV (0x4BA0) removed |
| `keelsign-hybrid-missing-pq.bin` | `Ok` | `MissingPqSignature` | `MissingPqSignature` | mutation of `keelsign-hybrid-ed25519-lms.bin`: LMS/HSS signature TLV (0x4BA3) removed |
| `keelsign-hybrid-mldsa44-missing-pq.bin` | `Ok` | `MissingPqSignature` | `MissingPqSignature` | mutation of `keelsign-hybrid-ed25519-mldsa44.bin`: ML-DSA-44 signature TLV (0x4BA1) removed |
| `keelsign-hybrid-mldsa44-stripped-pq.bin` | `Ok` | `MissingPqSignature` | `MissingPqSignature` | mutation of `keelsign-hybrid-ed25519-mldsa44.bin`: key-ID TLV (0x4BA0) and ML-DSA-44 signature TLV (0x4BA1) removed: a plain imgtool Ed25519 image |
| `keelsign-hybrid-no-sha256.bin` | `Image(MissingSha256Tlv)` | `Image(MissingSha256Tlv)` | `Image(MissingSha256Tlv)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: SHA256 TLV removed |
| `keelsign-hybrid-protected-tlvs.bin` | `Ok` | `Ok` | `Ok` | hybrid Ed25519 + LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1, with protected SEC_CNT and vendor TLV 0x10A0 |
| `keelsign-hybrid-reserved-tlv-protected.bin` | `Image(KeelsignTlvProtected(0x4BA0))` | `Image(KeelsignTlvProtected(0x4BA0))` | `Image(KeelsignTlvProtected(0x4BA0))` | invalid: hybrid Ed25519 + LMS M32_H5 with a keelsign key-ID-typed TLV 0x4BA0 in the protected area (imgtool --custom-tlv) |
| `keelsign-hybrid-sha384-only.bin` | `Image(MissingSha256Tlv)` | `Image(MissingSha256Tlv)` | `Image(MissingSha256Tlv)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: SHA256 TLV replaced by a SHA384 TLV (0x11) of the hashed bytes |
| `keelsign-hybrid-short-ed25519.bin` | `Ed25519(InvalidSignatureLength)` | `Ok` | `Ed25519(InvalidSignatureLength)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: ED25519 TLV value truncated to 63 bytes |
| `keelsign-hybrid-sig-pure.bin` | `Image(SigPure)` | `Image(SigPure)` | `Image(SigPure)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: SIG_PURE TLV (0x25) = 01 appended |
| `keelsign-hybrid-two-ed25519.bin` | `Ed25519(Multiple)` | `Ok` | `Ed25519(Multiple)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: the KEYHASH + ED25519 pair duplicated |
| `keelsign-hybrid-two-sec-cnt.bin` | `Image(MultipleSecurityCounters)` | `Image(MultipleSecurityCounters)` | `Image(MultipleSecurityCounters)` | mutation of `keelsign-hybrid-protected-tlvs.bin`: protected SEC_CNT duplicated (ih_protect_tlv_size and it_tlv_tot re-encoded) |
| `keelsign-hybrid-two-sha256.bin` | `Image(MultipleSha256Tlvs)` | `Image(MultipleSha256Tlvs)` | `Image(MultipleSha256Tlvs)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: SHA256 TLV duplicated |
| `keelsign-hybrid-unpaired-ed25519.bin` | `Ed25519(Unpaired)` | `Ok` | `Ed25519(Unpaired)` | mutation of `keelsign-hybrid-ed25519-lms.bin`: KEYHASH TLV removed: the ED25519 TLV follows the SHA256 TLV |
| `keelsign-lms-m32-h5.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1 |
| `keelsign-lms-protected-tlvs.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | LMS_SHA256_M32_H5 / LMOTS_SHA256_N32_W8, HSS L=1, with protected SEC_CNT and vendor TLV 0x10A0 |
| `keelsign-mldsa44-bad-body-rehashed.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44.bin`: body byte 0 ^= 0x01, SHA256 TLV recomputed (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44-bad-body.bin` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | mutation of `keelsign-mldsa44.bin`: body byte 0 ^= 0x01 |
| `keelsign-mldsa44-bad-hint.bin` | `Ed25519(Missing)` | `MalformedSignature` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44.bin`: ML-DSA-44 signature TLV (0x4BA1) last byte := 0xFF (hint count > omega) (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44-bad-key-id.bin` | `Ed25519(Missing)` | `KeyNotTrusted` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44.bin`: key-ID TLV (0x4BA0) byte 0 ^= 0x01 |
| `keelsign-mldsa44-bad-protected-rehashed.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44-protected-tlvs.bin`: protected SEC_CNT value byte 0 ^= 0x01, SHA256 TLV recomputed (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44-bad-protected.bin` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | `Image(DigestMismatch)` | mutation of `keelsign-mldsa44-protected-tlvs.bin`: protected SEC_CNT value byte 0 ^= 0x01 |
| `keelsign-mldsa44-bad-sig.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44.bin`: ML-DSA-44 signature TLV (0x4BA1) byte 0 (c~) ^= 0x01 (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44-foreign-sig.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44.bin`: ML-DSA-44 signature TLV (0x4BA1) replaced by the one of keelsign-mldsa44-protected-tlvs.bin (same key, other M) (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44-protected-tlvs.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | ML-DSA-44 under the ML-DSA-44 test key, with protected SEC_CNT and vendor TLV 0x10A0 (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44-short-sig.bin` | `Ed25519(Missing)` | `MalformedSignature` | `Ed25519(Missing)` | mutation of `keelsign-mldsa44.bin`: ML-DSA-44 signature TLV (0x4BA1) truncated to 2,419 bytes (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa44.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | ML-DSA-44 signature (pure, keelsign context) under the ML-DSA-44 test key (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-bad-body-rehashed.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa65.bin`: body byte 0 ^= 0x01, SHA256 TLV recomputed (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-bad-hint.bin` | `Ed25519(Missing)` | `MalformedSignature` | `Ed25519(Missing)` | mutation of `keelsign-mldsa65.bin`: ML-DSA-65 signature TLV (0x4BA2) last byte := 0xFF (hint count > omega) (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-bad-protected-rehashed.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa65-protected-tlvs.bin`: protected SEC_CNT value byte 0 ^= 0x01, SHA256 TLV recomputed (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-bad-sig.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa65.bin`: ML-DSA-65 signature TLV (0x4BA2) byte 0 (c~) ^= 0x01 (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-foreign-sig.bin` | `Ed25519(Missing)` | `SignatureInvalid` | `Ed25519(Missing)` | mutation of `keelsign-mldsa65.bin`: ML-DSA-65 signature TLV (0x4BA2) replaced by the one of keelsign-mldsa65-protected-tlvs.bin (same key, other M) (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-protected-tlvs.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | ML-DSA-65 under the ML-DSA-65 test key, with protected SEC_CNT and vendor TLV 0x10A0 (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65-short-sig.bin` | `Ed25519(Missing)` | `MalformedSignature` | `Ed25519(Missing)` | mutation of `keelsign-mldsa65.bin`: ML-DSA-65 signature TLV (0x4BA2) truncated to 3,308 bytes (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `keelsign-mldsa65.bin` | `Ed25519(Missing)` | `Ok` | `Ed25519(Missing)` | ML-DSA-65 signature (pure, keelsign context) under the ML-DSA-65 test key (without `ml-dsa`: see [The ml-dsa feature](#the-ml-dsa-feature)) |
| `mcuboot-ecdsa-p256.bin` | `Ed25519(Missing)` | `MissingPqSignature` | `Ed25519(Missing)` | imgtool ECDSA P-256, SEC_CNT, BOOT_RECORD and DEPENDENCY |
| `mcuboot-ed25519-200k.bin` | `Ok` | `MissingPqSignature` | `MissingPqSignature` | as mcuboot-ed25519.bin with a 204,800-byte body in a 0x40000-byte slot (chunked digest, SHA-42) (not in `policy-matrix.bin`) |
| `mcuboot-ed25519-padded.bin` | `Ok` | `MissingPqSignature` | `MissingPqSignature` | as mcuboot-ed25519.bin, padded to a 0x2000-byte slot with the boot trailer (--pad) |
| `mcuboot-ed25519.bin` | `Ok` | `MissingPqSignature` | `MissingPqSignature` | imgtool Ed25519, SEC_CNT, BOOT_RECORD and DEPENDENCY |
| `mcuboot-rsa2048.bin` | `Ed25519(Missing)` | `MissingPqSignature` | `Ed25519(Missing)` | imgtool RSA-2048 PSS, SEC_CNT, BOOT_RECORD and DEPENDENCY |
| `rejected/mcuboot-ed25519-bigendian.bin` | `Parse(BadMagic)` | `Parse(BadMagic)` | `Parse(BadMagic)` | as mcuboot-ed25519.bin but big-endian (-e big): unsupported, the parser rejects it |

## VerifiedImage and anti-rollback

`verify` returns a `VerifiedImage` (`#[non_exhaustive]`; only `verify` / `verify_with`
make one):

| Field | Meaning |
|---|---|
| `policy` | the policy it passed |
| `version` | `ImageVersion` from the header, `major.minor.revision+build_num` |
| `security_counter` | the protected `SEC_CNT` value, `None` without one (an unprotected one is ignored) |
| `digest` | `M`, 32 bytes (for logging or attestation) |
| `image_len` | header, body and both TLV areas (`Image::tlv_end`) |
| `pq_key` | the trusted PQ key that verified it, when the policy checks the PQ half |
| `ed25519_key` | the trusted Ed25519 key that verified it, when the policy checks the Ed25519 half |

Anti-rollback stays with the caller, which knows what it has stored. `ImageVersion` has no
`Ord`; pick one of the two comparators so that the `build_num` decision is explicit:

- `ImageVersion::cmp_ignoring_build_num`: `(major, minor, revision)`, MCUboot's default
  `boot_version_cmp`;
- `ImageVersion::cmp_with_build_num`: then `build_num`, as MCUboot built with
  `MCUBOOT_VERSION_CMP_USE_BUILD_NUMBER`.

Compare `security_counter` with the device's stored counter where hardware rollback
protection is used (MCUboot's `MCUBOOT_HW_ROLLBACK_PROT`); only a protected `SEC_CNT` is
reported, because only the protected area is covered by the signatures.

## TOCTOU

`verify` reads the header and both TLV areas once (`Image::read_from`) and hashes the
header and the protected TLV area from that parsed copy; only the body is streamed from
the slot again (`image_digest`). So the version and the security counter that
`VerifiedImage` reports are exactly the bytes that were hashed and signed: a second read
of the protected area cannot differ from the copy the rules inspected. An attacker who can
change the flash between the two reads can still change the body, which changes `M` and
fails the SHA256 TLV comparison or the signatures; changing the body after `verify`
returns is outside the verifier's reach (as in MCUboot, executing the verified bytes is
the bootloader's concern).

## Differences from MCUboot

- **One pair, fail closed.** MCUboot verifies every signature whose KEYHASH names a known
  key and lets the last result win, and skips a signature no KEYHASH precedes;
  `verify` requires exactly one KEYHASH + ED25519 pair and rejects an unpaired ED25519 TLV
  (`Ed25519(Multiple)`, `Ed25519(Unpaired)`).
- **`verify_strict`.** `ed25519-dalek`'s `verify_strict` also rejects small-order keys and
  non-canonical `R`, which MCUboot's cofactorless verifier accepts. It only ever rejects
  more than MCUboot; imgtool's signatures are canonical (both sample Ed25519 images pass).
- **All 32 KEYHASH bytes.** MCUboot compares `keyhash_len` bytes
  (`bootutil_find_key.c:56-80`); keelsign compares all 32.
- **keelsign TLVs in the protected area** are rejected; MCUboot has no such TLVs.
- **Encrypted and compressed images** are rejected (not yet supported).
