# keelsign-verify

**Status: pre-release, API unstable.** `verify` is the single entry point: it reads an
MCUboot image from a slot (`ImageReader`, for `&[u8]` and any `embedded-storage` NOR
flash through `NorFlashReader`), enforces the image rules, hashes the image in chunks
(peak RAM bounded by the caller's chunk buffer, 256 bytes by default) and verifies the
halves the device's `Policy` requires (`ClassicalOnly`, `PqOnly` or `Hybrid`) against a
`TrustedKeys` set, returning a `VerifiedImage` (version, security counter, digest) for
the caller's anti-rollback check; every failure is a typed error. Underneath are the
MCUboot image header and TLV-area parser (`image`, panic-free on any input), the
post-quantum signature dispatch, the built-in LMS/HSS verifier (RFC 8554, SP 800-208;
SHA-256 and SHA-256/192 with W8, up to two HSS levels by default, or single-tree only
under the strict CNSA 2.0 policy (`DefaultBackend::cnsa_2_0()`, through `verify_with`))
and the Ed25519 half of hybrid images (MCUboot's KEYHASH + ED25519 pair, `ed25519-dalek`
`verify_strict`). The image format (keelsign TLV IDs `0x4BA0`–`0x4BA3`, the signing
mode, key IDs and the hybrid Ed25519 layout) is specified in
[docs/image-format.md](https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md)
and the policies in
[docs/policy.md](https://github.com/smhasan94/keelsign/blob/main/docs/policy.md). The
ML-DSA-44/65 verifier (FIPS 204, pure ML-DSA with the keelsign context, through
`ml-dsa` `=0.1.1` with no heap) comes with the `ml-dsa` feature; without it ML-DSA
signatures fail closed with `UnsupportedAlgorithm`, and the strict
`DefaultBackend::cnsa_2_0()` refuses ML-DSA in any build. ML-DSA verify needs about
98 KB (ML-DSA-44) / 158 KB (ML-DSA-65) of stack on stable, far over a 32 KB device budget
([docs/benchmarks.md](https://github.com/smhasan94/keelsign/blob/main/docs/benchmarks.md#ml-dsa-verify-sha-44));
a low-stack verify is planned. Both features are off by default: `ed25519` (needed for
`ClassicalOnly` and `Hybrid`, which otherwise fail closed) and `ml-dsa`.

`keelsign-verify` will be the `no_std`, heap-free on-device verifier of the keelsign
post-quantum firmware signing kit: it parses the MCUboot header and TLV area, hashes
the image in chunks and verifies ML-DSA-44/65 and LMS/HSS signatures, optionally
hybrid with Ed25519.

Repository: <https://github.com/smhasan94/keelsign>

## Example

Verify a slot under `Policy::PqOnly` against one trusted LMS/HSS key, then run the
caller's anti-rollback check. These are the visible lines of the crate-level doctest
(`src/lib.rs`, `# Example`), which runs in the repository's `cargo test` with the test
fixture `tests/fixtures/images/keelsign-lms-protected-tlvs.bin` and its public key; the
fixture is not in the published crate. On a device, read the slot through a
`NorFlashReader` over the board's flash; with the `ed25519` feature,
`TrustedKeys::with_ed25519` and `Policy::Hybrid` add the Ed25519 half
([docs/policy.md](https://github.com/smhasan94/keelsign/blob/main/docs/policy.md)).

```rust
use core::cmp::Ordering;
use keelsign_verify::image::ImageVersion;
use keelsign_verify::{Algorithm, DEFAULT_CHUNK_LEN, Policy, TrustedKey, TrustedKeys, verify};

// The device's trusted LMS/HSS public key (raw HSS encoding), typically in flash.
let lms_key = TrustedKey { algorithm: Algorithm::LmsHss, public_key: &lms_public_key };
let keys = TrustedKeys::<1>::new(&[lms_key])?;

// The candidate image. A `&[u8]` reads it here; on a device, use a `NorFlashReader`.
let mut slot: &[u8] = image;
let mut tlv_buf = [0u8; 4096];
let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
let verified = verify(&mut slot, &keys, Policy::PqOnly, &mut tlv_buf, &mut chunk)?;

// Anti-rollback is the caller's: refuse a downgrade or a lower security counter.
let running = ImageVersion { major: 1, minor: 2, revision: 0, build_num: 0 };
let stored_counter = 7;
let downgrade = verified.version.cmp_ignoring_build_num(&running) == Ordering::Less;
let rolled_back = verified.security_counter.unwrap_or(0) < stored_counter;
assert!(!downgrade && !rolled_back, "refuse the update");
```

## Licence

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
