//! `no_std`, heap-free on-device verifier for keelsign-signed MCUboot images.
//!
//! **Pre-release: the API is unstable.** The image format (TLV IDs, signing mode, key
//! ID, hybrid layout) is specified in [docs/image-format.md](https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md) and its constants
//! are in [`tlv`]. This version holds the MCUboot image parser, the trusted-key set, the
//! post-quantum signature dispatch and the LMS/HSS verifier; image hashing, the ML-DSA
//! backend and the hybrid Ed25519 policy land in later releases.
//!
//! - [`image`] parses and validates an MCUboot image (header, protected and unprotected
//!   TLV areas) without panicking on any input, and yields its TLVs;
//!   [`image::TlvArea::pairs`] feeds [`select_pq_signature`] and [`verify_pq`]. PQ
//!   selection MUST use the unprotected area, `image.unprotected().pairs()`: keelsign TLVs
//!   are unprotected-only (docs/image-format.md), so keelsign TLVs in the protected area
//!   are ignored for PQ selection (a PQ signature there is inside `M` and can never be a
//!   valid signature over `M`; rejecting such images is a candidate SHA-46 policy rule).
//! - [`TrustedKeys`] holds up to `N` borrowed public keys and finds one by key ID
//!   ([`key_id_of`]).
//! - [`verify_pq`] picks the single post-quantum signature TLV and the key-ID TLV out of
//!   an image's TLVs, looks up the trusted key, checks that its [`Algorithm`] matches and
//!   is compiled in, and verifies the signature with the built-in [`DefaultBackend`].
//!   [`verify_pq_with`] does the same with any [`Backend`].
//! - [`lms`] verifies LMS/HSS signatures (RFC 8554, SP 800-208) over SHA-256 and
//!   SHA-256/192 under the keelsign parameter policy.
//!
//! Every failure is a distinct [`Error`] variant.
//!
//! # Features
//!
//! - `ml-dsa` (off by default): enables ML-DSA-44/65 in the dispatcher. Without it,
//!   ML-DSA signatures fail with [`Error::UnsupportedAlgorithm`]; until SHA-44 lands,
//!   [`DefaultBackend`] also answers ML-DSA with that error when the feature is on.
//!   LMS/HSS is always enabled.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

mod algorithm;
mod backend;
mod dispatch;
mod error;
pub mod image;
pub mod lms;
pub mod tlv;
mod trusted_keys;

pub use algorithm::Algorithm;
pub use backend::{DefaultBackend, verify_pq};
pub use dispatch::{Backend, SelectedSignature, select_pq_signature, verify_pq_with};
pub use error::{Error, KeySetError};
pub use trusted_keys::{KeyId, TrustedKey, TrustedKeys, key_id_of};
