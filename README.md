# keelsign

Post-quantum firmware signing kit. Sign firmware on the host with ML-DSA or LMS/HSS
(optionally hybrid with Ed25519) and verify it on the device, keeping MCUboot's image
format so MCUboot and embassy-boot users keep their existing update pipeline.

**Status: placeholder / name reservation.** The published `0.0.1` crates contain no
functionality.

## Crates

| Crate | Kind | Purpose |
|---|---|---|
| `keelsign` | host CLI | `keygen` / `sign` / `verify` / `inspect` MCUboot-format images |
| `keelsign-verify` | `no_std`, no heap | Parses header + TLV area, hashes image in chunks, verifies ML-DSA-44/65 and LMS/HSS, hybrid with Ed25519; typed errors |
| `keelsign-embassy` (planned) | `no_std` | Adapter for embassy-boot |
| `keelsign-ffi` (planned) | staticlib | C ABI + cbindgen header for MCUboot's `MCUBOOT_USE_CUSTOM_CRYPTO` hook (`libkeelsign`) |

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
