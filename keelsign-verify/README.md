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
ML-DSA backend comes in a later release. Both features are off by default: `ed25519`
(needed for `ClassicalOnly` and `Hybrid`, which otherwise fail closed) and `ml-dsa`.

`keelsign-verify` will be the `no_std`, heap-free on-device verifier of the keelsign
post-quantum firmware signing kit: it parses the MCUboot header and TLV area, hashes
the image in chunks and verifies ML-DSA-44/65 and LMS/HSS signatures, optionally
hybrid with Ed25519.

Repository: <https://github.com/smhasan94/keelsign>

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
