//! `no_std`, heap-free on-device verifier for keelsign-signed MCUboot images.
//!
//! **Pre-release: the API is unstable** and the TLV IDs in [`tlv`] are provisional
//! (SHA-37). This version holds the trusted-key set and the post-quantum signature
//! dispatch; TLV-area parsing, image hashing, the ML-DSA and LMS/HSS backends and the
//! hybrid Ed25519 policy land in later releases.
//!
//! - [`TrustedKeys`] holds up to `N` borrowed public keys and finds one by key ID
//!   ([`key_id_of`]).
//! - [`verify_pq_with`] picks the single post-quantum signature TLV and the key-ID TLV
//!   out of an image's TLVs, looks up the trusted key, checks that its [`Algorithm`]
//!   matches and is compiled in, and calls a [`Backend`] to verify the signature.
//!
//! Every failure is a distinct [`Error`] variant.
//!
//! # Features
//!
//! - `ml-dsa` (off by default): enables ML-DSA-44/65. Without it, ML-DSA signatures
//!   fail with [`Error::UnsupportedAlgorithm`]. LMS/HSS is always enabled.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

mod algorithm;
mod dispatch;
mod error;
pub mod tlv;
mod trusted_keys;

pub use algorithm::Algorithm;
pub use dispatch::{Backend, SelectedSignature, select_pq_signature, verify_pq_with};
pub use error::{Error, KeySetError};
pub use trusted_keys::{KeyId, TrustedKey, TrustedKeys, key_id_of};
