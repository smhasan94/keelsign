# keelsign-embassy

embassy-boot adapter for [keelsign](https://github.com/smhasan94/keelsign): the
application verifies the post-quantum signed MCUboot image in the DFU slot with
`keelsign-verify` and only then marks it for swap. `no_std`, no heap, no `unsafe`.
**Pre-release: the API is unstable.**

```rust
static LMS_KEY: [u8; 60] = [/* the device's LMS/HSS public key */];
const CONFIG: Config<'static, 1> = Config::new(
    Policy::PqOnly,
    [TrustedKey { algorithm: Algorithm::LmsHss, public_key: &LMS_KEY }],
    [],
);
let mut aligned = AlignedBuffer([0; nrf::BLOCKING_STATE_BUF_LEN]);
let mut updater = nrf::blocking_from_linkerfile(&flash, &mut aligned.0, &CONFIG)?;
let (mut tlv_buf, mut chunk) = ([0u8; 4096], [0u8; DEFAULT_CHUNK_LEN]);
match updater.verify_and_mark_updated(&mut tlv_buf, &mut chunk) {
    Ok(image) => cortex_m::peripheral::SCB::sys_reset(), // the bootloader swaps it in
    Err(e) => defmt::error!("update not marked: {}", e), // nothing was written
}
```

`BlockingUpdater` wraps embassy-boot's blocking updater (nRF52840 NVMC); `Updater` the
async one, for one flash behind an `embassy_sync` mutex (RP2350; nRF through
`SyncFlash`). Neither offers a plain `mark_updated`.

## Keys

`Config` holds up to `N` post-quantum keys (`TrustedKey`: LMS/HSS, ML-DSA-44/65) and up
to `E` Ed25519 keys, borrowed from flash and checked once when the updater is built
(`Error::KeySet`). Images name their key by key ID; see docs/keys.md and
docs/image-format.md.

## Policy

`Policy::PqOnly`, `Policy::Hybrid` or `Policy::ClassicalOnly` (the last two need the
`ed25519` feature), as in docs/policy.md. `Config::cnsa_2_0()` accepts single-tree LMS
only. `verify_and_mark_updated_if` takes an `accept` check on the `VerifiedImage`
(version, security counter) for anti-rollback.

## Partitions

The usual embassy-boot layout: bootloader, a state page, the active slot and a DFU slot
one page larger. keelsign images keep MCUboot's 0x200-byte header, so the application is
linked at ACTIVE + 0x200 and the bootloader jumps there. The partition symbols come from
the application's `memory.x`; docs/embassy.md has both boards' tables and the bootloader.

## On reject

A rejected image (`Error::Rejected` names keelsign-verify's reason), an image the caller
does not accept (`Error::NotAccepted`) or a pending swap (`Error::BadState`) leaves the
state partition untouched: the bootloader keeps booting the current application.
Verification only reads the DFU slot; a reset at any point leaves the state Boot or Swap.

## Features

All off by default: `ed25519`, `ml-dsa` (about 98 / 158 KB of stack, see
docs/benchmarks.md), `defmt` (logs rejects and accepts), `nrf`, `rp` (board modules;
enable the chip on the HAL, e.g. `embassy-nrf/nrf52840`, `embassy-rp/rp235xa`).

Do not enable embassy-boot's `ed25519-dalek` or `ed25519-salty` features: they remove
the `mark_updated` this adapter calls after verifying.

## Limitations

The DFU flash must read single bytes blockingly (`READ_SIZE == 1`; flashes with larger
reads wait for SHA-274). `Updater` needs both partitions on one flash. The bootloader
does not verify again before swapping.

Licensed under either of Apache-2.0 or MIT, at your option.
