# keelsign-verify

**Status: pre-release, API unstable.** Not yet usable to verify images. The current
code holds the trusted-key set (lookup by key ID) and the post-quantum signature
dispatch to a pluggable backend, with typed errors. The keelsign TLV IDs are
provisional. The ML-DSA and LMS/HSS backends, TLV-area parsing and image hashing come
in later releases. The `ml-dsa` feature is off by default.

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
