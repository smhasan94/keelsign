# keelsign

Post-quantum firmware signing kit. Sign firmware on the host with LMS/HSS or ML-DSA
(optionally hybrid with Ed25519) and verify it on the device, keeping MCUboot's image
format so MCUboot and embassy-boot users keep their existing update pipeline.

**Status: placeholder / name reservation on crates.io.** The published `0.0.1` crates
contain no functionality. The verifier described below is unreleased and its API is
unstable. The host CLI has `keygen` and `pubkey` ([docs/keys.md](docs/keys.md)),
`sign` and `inspect` ([docs/signing.md](docs/signing.md)) and `verify`
([docs/verify.md](docs/verify.md)), for ML-DSA-44/65 and stateful LMS/HSS keys
(optionally hybrid with Ed25519). The embassy-boot adapter `keelsign-embassy`
verifies the DFU slot before marking it for swap
([docs/embassy.md](docs/embassy.md)). The C static library `libkeelsign.a` and its header
([docs/ffi.md](docs/ffi.md)) are pre-release and unpublished; the MCUboot glue around them
is not written yet.

## Quickstart

Build it once: `cargo install --path keelsign --locked` (or
`cargo build --release -p keelsign` and put `target/release` on `PATH`). Then, from the
repository root, sign an imgtool-signed image with a new LMS/HSS key
(LMS_SHA256_M32_H10: 1,024 signatures) and verify it as the device would.

**LMS/HSS keys are stateful.** Every signature uses up one one-time leaf of the key, and
signing twice with the same leaf breaks the key. `keygen` writes `signing.pem.state` and
`signing.pem.journal` next to the key; `sign` records the leaf there before it signs.
Keep the three files together, sign only with keelsign on one machine, and never copy
the key elsewhere or restore it from a backup: read
[docs/keys.md, Stateful LMS keys](docs/keys.md#stateful-lms-keys) before using one for
real firmware. (`--alg ml-dsa-65` gives a stateless ML-DSA key instead.)

```sh
work="$(mktemp -d)"
cp tests/fixtures/images/mcuboot-ed25519.bin "$work/app.signed.bin"   # any imgtool-signed image
cd "$work"
keelsign keygen --alg lms-sha256-m32-h10 --out signing.pem   # also writes signing.pem.state and signing.pem.journal
keelsign pubkey --key signing.pem --out signing.pub.pem
keelsign sign --key signing.pem app.signed.bin app.keelsign.bin   # reserves leaf 0 in signing.pem.state, then signs
keelsign verify --pub signing.pub.pem app.keelsign.bin
keelsign inspect app.keelsign.bin                                 # shows the leaf index used (q: 0)
```

`verify` prints `verified:` and exits 0, or names the reason and exits non-zero (the exit
codes are in [docs/verify.md](docs/verify.md#exit-codes)). CI runs this block verbatim
with `scripts/check-quickstart.sh`, within a five-minute budget.

## What works today

`keelsign-verify` is a `no_std`, heap-free, `unsafe`-free verifier with one entry point,
`verify`. It reads an MCUboot image from a slot, through a `&[u8]` or any
`embedded-storage` NOR flash. It enforces the image rules, hashes the image in chunks
(256-byte buffer by default) and checks the signatures the device's policy requires.
It returns the image version and security counter for the caller's anti-rollback check.
Every failure is a typed error.

| Policy | Ed25519 signature | Post-quantum signature |
|---|---|---|
| `ClassicalOnly` | required | not checked (transition mode) |
| `PqOnly` | not checked | required |
| `Hybrid` | required | required |

One hybrid image serves fleets under all three policies. See
[docs/policy.md](docs/policy.md) for the rules and the full policy × image matrix.

| Signature | Enable with | Static stack frame | Flash, release (nRF52840) |
|---|---|---|---|
| LMS/HSS (RFC 8554, SP 800-208; SHA-256 and SHA-256/192, W8) | always on | 1,512 B | about 7 KB |
| Ed25519 (MCUboot's KEYHASH + ED25519 pair), as a hybrid Ed25519 + LMS verify | `ed25519` feature | about 12.8 KB for the whole verify | about 74 KB for the whole verify |
| ML-DSA-44 / ML-DSA-65 (FIPS 204) | `ml-dsa` feature | about 98 KB / 158 KB (stable build) | about 55 KB more |

ML-DSA verify needs far more stack than the 32 KB device budget. It works on the test
boards but not yet in a real bootloader; a low-stack verify is tracked separately. Under
the strict CNSA 2.0 backend, `DefaultBackend::cnsa_2_0()`, only single-tree LMS is
accepted. All figures are measured and kept current in
[docs/benchmarks.md](docs/benchmarks.md); cycle counts and measured peak stack still
need the boards.

## Crates

| Crate | Kind | Purpose |
|---|---|---|
| `keelsign` | host CLI (pre-release) | `keygen` / `pubkey` / `sign` / `inspect` / `verify` MCUboot-format images |
| `keelsign-verify` | `no_std`, no heap | Parses the header and TLV area, hashes the image in chunks, verifies LMS/HSS, Ed25519 and ML-DSA-44/65 under a policy; typed errors |
| `keelsign-embassy` (pre-release) | `no_std`, no heap | Adapter for embassy-boot: verifies the DFU image, then marks it for swap; blocking and async updaters, nRF and RP board modules |
| `keelsign-ffi` (pre-release, unpublished) | staticlib | C ABI and cbindgen header for MCUboot's `MCUBOOT_USE_CUSTOM_CRYPTO` hook (`libkeelsign`) |

## Boards

| Board | Core | Target |
|---|---|---|
| Nordic nRF52840-DK | Cortex-M4F | `thumbv7em-none-eabihf` |
| Raspberry Pi Pico 2 W (RP2350) | Cortex-M33 | `thumbv8m.main-none-eabihf` |
| ST NUCLEO-U575ZI-Q | Cortex-M33 | `thumbv8m.main-none-eabihf` |

A Raspberry Pi Debug Probe drives the Pico 2 W. See [docs/hardware.md](docs/hardware.md).

## Documentation

- [docs/image-format.md](docs/image-format.md): the image format. keelsign's TLVs in the
  MCUboot TLV area, what each signature covers, key IDs, the hybrid Ed25519 layout,
  sizes, CNSA 2.0 and MCUboot compatibility.
- [docs/policy.md](docs/policy.md): the three policies, key sets, image rules, error
  precedence, the policy matrix and anti-rollback.
- [docs/keys.md](docs/keys.md): `keelsign keygen` and `pubkey`, the key file formats
  and OIDs, passphrase encryption, key IDs and KEYHASH, and the exit codes.
- [docs/signing.md](docs/signing.md) and [docs/verify.md](docs/verify.md):
  `keelsign sign`, `inspect` and `verify`, the policies `verify` checks, public key
  files and the final exit-code table.
- [docs/ffi.md](docs/ffi.md): the C static library `libkeelsign.a`: build, header, the
  pointer contract, status codes and the C harness.
- [docs/benchmarks.md](docs/benchmarks.md): on-target known-answer tests, stack and flash
  per algorithm, and the toolchains every figure was measured with.
- [docs/embassy.md](docs/embassy.md): `keelsign-embassy` with embassy-boot. Partition
  layouts, the bootloader, the two example applications and the on-board update
  procedures.
- [docs/setup.md](docs/setup.md): toolchain, probes, flashing the example boards and
  on-target tests.
- [docs/on-target-tests.md](docs/on-target-tests.md): the on-target test suite on both
  boards, how to run it and the three-identical-runs check.
- [docs/hardware.md](docs/hardware.md) and [docs/release.md](docs/release.md): the bill
  of materials and the human-only release steps.

## Development

Stable Rust 1.91 or newer and the two embedded targets; [docs/setup.md](docs/setup.md)
has the rest. The usual checks:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p keelsign-verify --locked --features ed25519,ml-dsa
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p keelsign-verify --locked --features ed25519,ml-dsa
cargo deny --locked check   # cargo-deny 0.20.2, see docs/setup.md
```

The recorded flash and stack figures in `docs/benchmarks.md` are checked against a fresh
build. These checks need the exact compilers the doc names and both board targets:

```sh
cargo test -p repo-checks --locked --test benchmarks_doc -- --ignored recorded_
```

Test fixtures are generated by the scripts in `scripts/` and never edited by hand.

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
