//! The `keelsign` host CLI: key generation and key files (see `docs/keys.md`).
//!
//! **Pre-release.** This library API is unstable; it exists for the CLI and its tests.
//! Signing, verifying and inspecting images are not written yet.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod error;
pub mod keys;
