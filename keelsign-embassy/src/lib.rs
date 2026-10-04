//! embassy-boot adapter for keelsign: verify the image in the DFU slot with
//! [`keelsign_verify`] before marking it for swap.
//!
//! **Pre-release: the API is unstable.**
//!
//! An application that received an update into embassy-boot's DFU partition calls
//! [`BlockingUpdater::verify_and_mark_updated`] instead of embassy-boot's own
//! `mark_updated`. The adapter reads the MCUboot-format image from the DFU slot, verifies
//! it under the device's [`Policy`] and trusted keys ([`Config`]), and only if that
//! succeeds writes the swap magic to the state partition. A rejected image leaves the
//! state partition untouched, so the bootloader keeps booting the current application,
//! and the error names the reason ([`Error::Rejected`] wraps the
//! [`keelsign_verify::Error`] variant).
//!
//! # Building blocks
//!
//! - [`Config`]: the policy, the trusted post-quantum and Ed25519 keys and the backend;
//!   constructible in a `const`.
//! - [`BlockingUpdater`]: wraps embassy-boot's `BlockingFirmwareUpdater` over a
//!   [`FirmwareUpdaterConfig`] (nRF52840: the NVMC is blocking).
//! - [`Updater`]: the async updater over one flash behind an `embassy_sync` mutex
//!   ([`Layout`] names the partitions). Verification reads the DFU slot with the flash's
//!   blocking reads while holding the mutex once.
//! - [`SyncFlash`]: gives a blocking-only flash (the nRF52840 NVMC) the async traits, for
//!   [`Updater`].
//! - `nrf` / `rp` (features): state-buffer lengths and type aliases per board.
//!
//! # Features
//!
//! All off by default: `ed25519` and `ml-dsa` forward to keelsign-verify, `defmt` logs
//! rejects and accepts and implements `defmt::Format` for the errors, `nrf` / `rp` add
//! the board modules.
//!
//! The firmware must not enable embassy-boot's `ed25519-dalek` or `ed25519-salty`
//! features: they remove `mark_updated`, which this adapter needs.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

mod config;
mod error;
mod sync_flash;

pub use config::Config;
pub use error::{ConfigError, Error};
pub use sync_flash::SyncFlash;

pub use embassy_boot::{AlignedBuffer, FirmwareUpdaterConfig, State};
pub use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, DefaultBackend, Ed25519Key, Policy, TrustedKey, VerifiedImage,
};
