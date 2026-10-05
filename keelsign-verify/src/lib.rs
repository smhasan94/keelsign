//! `no_std`, heap-free on-device verifier for keelsign-signed MCUboot images.
//!
//! **Pre-release: the API is unstable.** The image format (TLV IDs, signing mode, key
//! ID, hybrid layout) is specified in [docs/image-format.md](https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md) and its constants
//! are in [`tlv`]; the verify policies in [docs/policy.md](https://github.com/smhasan94/keelsign/blob/main/docs/policy.md).
//!
//! # Verifying an image
//!
//! [`verify`] is the single entry point (SHA-46): it reads the image from a slot
//! ([`ImageReader`]), enforces the image rules ([`ImageError`]), computes the image digest
//! `M` and verifies the halves the device's [`Policy`] requires against a
//! [`TrustedKeys`] set, then returns a [`VerifiedImage`] (version, security counter,
//! digest, keys) for the caller's anti-rollback check:
//!
//! - [`Policy::ClassicalOnly`]: MCUboot's Ed25519 KEYHASH + ED25519 pair only;
//! - [`Policy::PqOnly`]: the keelsign post-quantum signature only;
//! - [`Policy::Hybrid`]: both, over the same `M`.
//!
//! [`verify_with`] does the same with any [`Backend`] for the post-quantum half, for
//! example [`DefaultBackend::cnsa_2_0`]. No heap: the caller passes the TLV buffer and
//! the digest chunk. Every failure is a distinct [`Error`] variant;
//! [`Error::Ed25519`] names the classical half and [`Error::Image`] an image rule.
//!
//! # Example
//!
//! Verify a slot under [`Policy::PqOnly`] against one trusted LMS/HSS key, then run the
//! caller's anti-rollback check (SHA-47; the crate README shows the same lines). The
//! hidden setup reads a repository test fixture (`keelsign-lms-protected-tlvs.bin`, which
//! carries a protected `SEC_CNT` of 7) and its public key, so this doctest runs from a
//! repository checkout, not from the published crate.
//!
//! ```
//! # let image: &[u8] =
//! #     include_bytes!("../../tests/fixtures/images/keelsign-lms-protected-tlvs.bin");
//! # let manifest = include_str!("../../tests/fixtures/images/MANIFEST.json");
//! # let entry = &manifest[manifest.find("\"keelsign-lms-protected-tlvs.bin\": {").unwrap()..];
//! # let hex = entry.split("\"public_key_hex\": \"").nth(1).unwrap();
//! # let hex = &hex[..hex.find('"').unwrap()];
//! # let lms_public_key: Vec<u8> = (0..hex.len())
//! #     .step_by(2)
//! #     .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
//! #     .collect();
//! use core::cmp::Ordering;
//! use keelsign_verify::image::ImageVersion;
//! use keelsign_verify::{Algorithm, DEFAULT_CHUNK_LEN, Policy, TrustedKey, TrustedKeys, verify};
//!
//! // The device's trusted LMS/HSS public key (raw HSS encoding), typically in flash.
//! let lms_key = TrustedKey { algorithm: Algorithm::LmsHss, public_key: &lms_public_key };
//! let keys = TrustedKeys::<1>::new(&[lms_key])?;
//!
//! // The candidate image. A `&[u8]` reads it here; on a device, use a `NorFlashReader`.
//! let mut slot: &[u8] = image;
//! let mut tlv_buf = [0u8; 4096];
//! let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
//! let verified = verify(&mut slot, &keys, Policy::PqOnly, &mut tlv_buf, &mut chunk)?;
//!
//! // Anti-rollback is the caller's: refuse a downgrade or a lower security counter.
//! let running = ImageVersion { major: 1, minor: 2, revision: 0, build_num: 0 };
//! let stored_counter = 7;
//! let downgrade = verified.version.cmp_ignoring_build_num(&running) == Ordering::Less;
//! let rolled_back = verified.security_counter.unwrap_or(0) < stored_counter;
//! assert!(!downgrade && !rolled_back, "refuse the update");
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! # Building blocks
//!
//! - [`image`] parses and validates an MCUboot image (header, protected and unprotected
//!   TLV areas) without panicking on any input, and yields its TLVs;
//!   [`image::TlvArea::pairs`] feeds [`select_pq_signature`] and [`verify_pq`]. PQ
//!   selection MUST use the unprotected area, `image.unprotected().pairs()`: keelsign TLVs
//!   are unprotected-only (docs/image-format.md), and [`verify`] rejects an image with a
//!   keelsign TLV in the protected area ([`ImageError::KeelsignTlvProtected`]).
//! - [`reader`] reads an image from a slot: [`ImageReader`], implemented for `&[u8]` and,
//!   through [`NorFlashReader`], for any `embedded-storage` NOR flash.
//!   [`image::Image::read_from`] reads and validates the header and TLV areas, and
//!   [`image_digest`] computes the image digest `M` (SHA-256 of header, body and
//!   protected TLV area; only the body is read again, the header and protected area are
//!   hashed from the parsed copy) through a caller-sized chunk buffer
//!   ([`DEFAULT_CHUNK_LEN`], 256 bytes), so peak RAM does not grow with the image.
//! - [`TrustedKeys`] holds up to `N` borrowed post-quantum public keys, found by key ID
//!   ([`key_id_of`]), and up to `E` Ed25519 keys, found by KEYHASH ([`keyhash_of`]).
//! - [`verify_pq`] picks the single post-quantum signature TLV and the key-ID TLV out of
//!   an image's TLVs, looks up the trusted key, checks that its [`Algorithm`] matches and
//!   is compiled in, and verifies the signature with the built-in
//!   [`DefaultBackend::new`]. [`verify_pq_with`] does the same with any [`Backend`].
//! - [`ed25519`] selects MCUboot's KEYHASH + ED25519 pair and verifies it
//!   (`verify_strict`).
//! - [`lms`] verifies LMS/HSS signatures (RFC 8554, SP 800-208) over SHA-256 and
//!   SHA-256/192 with LM-OTS W8, under one of two device policies:
//!   [`lms::ParameterPolicy::keelsign_default`] (up to two HSS levels; used by
//!   [`lms::verify`], [`DefaultBackend::new`], [`verify_pq`] and [`verify`]) or the strict
//!   [`lms::ParameterPolicy::cnsa_2_0`] (single-tree LMS only, `L = 1`), selected with
//!   [`verify_with`]`(&DefaultBackend::cnsa_2_0(), ..)` or
//!   [`verify_pq_with`]`(&DefaultBackend::cnsa_2_0(), keys, tlvs, message)`. Only the
//!   strict policy is CNSA 2.0-compliant (docs/image-format.md).
//! - [`mldsa`] verifies ML-DSA-44/65 signatures (FIPS 204, pure, with
//!   [`tlv::MLDSA_CONTEXT`]) with the `ml-dsa` feature.
//!
//! # Features
//!
//! Both are off by default.
//!
//! - `ed25519`: the Ed25519 half (`ed25519-dalek`, `verify_strict`). Without it,
//!   [`Policy::ClassicalOnly`] and [`Policy::Hybrid`] fail closed with
//!   [`Error::Ed25519`]`(`[`Ed25519Error::NotEnabled`]`)` before anything is read;
//!   [`Policy::PqOnly`] is unaffected.
//! - `ml-dsa`: verifies ML-DSA-44/65 signatures ([`mldsa`], SHA-44: pure FIPS 204
//!   `ML-DSA.Verify` with [`tlv::MLDSA_CONTEXT`], through `ml-dsa` with no heap) under
//!   [`DefaultBackend::new`]; [`DefaultBackend::cnsa_2_0`] refuses ML-DSA with
//!   [`Error::UnsupportedParameterSet`]. Without the feature, ML-DSA signatures fail with
//!   [`Error::UnsupportedAlgorithm`]. Its verify needs about 98 KB (ML-DSA-44) / 158 KB
//!   (ML-DSA-65) of stack, far over the 32 KB device budget: see docs/benchmarks.md,
//!   "ML-DSA verify (SHA-44)" (SHA-169 owns a low-stack verify). LMS/HSS is always
//!   enabled.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(test)]
extern crate std;

mod algorithm;
mod backend;
pub mod digest;
mod dispatch;
pub mod ed25519;
mod error;
pub mod image;
pub mod lms;
pub mod mldsa;
pub mod policy;
pub mod reader;
pub mod tlv;
mod trusted_keys;

pub use algorithm::Algorithm;
pub use backend::{DefaultBackend, verify_pq};
pub use digest::{DEFAULT_CHUNK_LEN, image_digest};
pub use dispatch::{Backend, SelectedSignature, select_pq_signature, verify_pq_with};
pub use ed25519::{Ed25519Error, Ed25519Key, KeyHash, keyhash_of};
pub use error::{Error, KeySetError};
pub use policy::{ImageError, Policy, VerifiedImage, verify, verify_with};
pub use reader::{ImageReader, NorFlashReader, ReadError};
pub use trusted_keys::{KeyId, TrustedKey, TrustedKeys, key_id_of};
