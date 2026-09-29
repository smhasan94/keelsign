# keelsign-verify

**Status: placeholder / name reservation.** This `0.0.1` release has no
functionality. Do not depend on it.

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
