//! The `keelsign` host CLI: key generation and key files (see `docs/keys.md`), image
//! signing and inspection (see `docs/signing.md`) and verification (see `docs/verify.md`).
//!
//! **Pre-release.** This library API is unstable; it exists for the CLI and its tests.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cli;
pub mod error;
pub mod image_file;
pub mod inspect;
pub mod keyfile;
pub mod keys;
pub mod sign;
pub mod verify;
