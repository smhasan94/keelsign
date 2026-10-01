//! Typed errors.

use core::fmt;

use crate::algorithm::Algorithm;
use crate::ed25519::Ed25519Error;
use crate::image::ParseError;
use crate::policy::ImageError;
use crate::reader::ReadError;

/// Why an image was rejected: it could not be read or parsed, its post-quantum
/// signature does not verify (the flat variants), its classical half does not
/// ([`Error::Ed25519`]), or it breaks an image rule ([`Error::Image`]).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The TLV area has no key-ID TLV.
    MissingKeyId,
    /// The key-ID TLV is not [`KEY_ID_LEN`](crate::tlv::KEY_ID_LEN) bytes long.
    InvalidKeyId,
    /// The TLV area has more than one key-ID TLV. Fails closed rather than picking one.
    MultipleKeyIds,
    /// The TLV area has no post-quantum signature TLV.
    MissingPqSignature,
    /// The TLV area has more than one post-quantum signature TLV. Fails closed rather
    /// than picking one.
    MultiplePqSignatures,
    /// No trusted key has the image's key ID.
    KeyNotTrusted,
    /// The trusted key with the image's key ID is for a different algorithm than the
    /// image's signature TLV.
    KeyAlgorithmMismatch,
    /// The signature's algorithm is not compiled into this build (see
    /// [`Algorithm::is_enabled`]).
    UnsupportedAlgorithm(Algorithm),
    /// The public key or signature uses a parameter set the backend does not support.
    ///
    /// The LMS/HSS backend ([`lms`](crate::lms)) returns it for a typecode pair outside its
    /// [`ParameterPolicy`](crate::lms::ParameterPolicy) at any level, or an unsupported
    /// number of HSS levels, before hashing anything.
    ///
    /// [`DefaultBackend::cnsa_2_0`](crate::DefaultBackend::cnsa_2_0) returns it for every
    /// ML-DSA-44/65 signature (never CNSA 2.0 algorithms).
    UnsupportedParameterSet,
    /// The signature is shorter or longer than its parameter sets dictate (truncated, or
    /// with trailing bytes), or its structure does not match the public key (for HSS,
    /// a level count other than the key's).
    ///
    /// For ML-DSA ([`mldsa`](crate::mldsa)) also a signature that does not decode: a
    /// malformed hint encoding, or `‖z‖∞ ≥ γ1 − β` (the FIPS 204 norm bound surfaces here
    /// because `ml-dsa` checks it while decoding).
    MalformedSignature,
    /// The trusted public key is not a valid encoding for its parameter set (for LMS/HSS,
    /// too short or not exactly `4 + 24 + m` bytes; for ML-DSA, not 1,312 / 1,952 bytes).
    InvalidPublicKey,
    /// The signature does not verify under the selected key (for ML-DSA: wrong key,
    /// message or context, or a tampered `c̃` or `z`).
    SignatureInvalid,
    /// The image does not parse ([`Image::read_from`](crate::image::Image::read_from)).
    Parse(ParseError),
    /// Reading the image from its [`ImageReader`](crate::reader::ImageReader) failed.
    Read(ReadError),
    /// The image's TLV areas fit the slot but not the buffer given to
    /// [`Image::read_from`](crate::image::Image::read_from).
    TlvAreaTooLarge,
    /// [`image_digest`](crate::digest::image_digest) was given an empty chunk buffer.
    ChunkBufferEmpty,
    /// The Ed25519 (classical) half of the image was rejected (SHA-46).
    Ed25519(Ed25519Error),
    /// The image breaks an image rule of [`verify`](crate::verify), whatever the policy
    /// (SHA-46).
    Image(ImageError),
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
    }
}

impl From<Ed25519Error> for Error {
    fn from(e: Ed25519Error) -> Self {
        Error::Ed25519(e)
    }
}

impl From<ImageError> for Error {
    fn from(e: ImageError) -> Self {
        Error::Image(e)
    }
}

impl From<ReadError> for Error {
    fn from(e: ReadError) -> Self {
        Error::Read(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingKeyId => f.write_str("no post-quantum key-ID TLV"),
            Error::InvalidKeyId => f.write_str("post-quantum key-ID TLV has the wrong length"),
            Error::MultipleKeyIds => f.write_str("more than one post-quantum key-ID TLV"),
            Error::MissingPqSignature => f.write_str("no post-quantum signature TLV"),
            Error::MultiplePqSignatures => f.write_str("more than one post-quantum signature TLV"),
            Error::KeyNotTrusted => {
                f.write_str("post-quantum key ID is not in the trusted key set")
            }
            Error::KeyAlgorithmMismatch => {
                f.write_str("trusted post-quantum key algorithm does not match the signature TLV")
            }
            Error::UnsupportedAlgorithm(alg) => {
                write!(
                    f,
                    "post-quantum algorithm {alg:?} is not enabled in this build"
                )
            }
            Error::UnsupportedParameterSet => f.write_str("unsupported post-quantum parameter set"),
            Error::MalformedSignature => f.write_str("post-quantum signature is malformed"),
            Error::InvalidPublicKey => f.write_str("post-quantum public key is malformed"),
            Error::SignatureInvalid => f.write_str("post-quantum signature is invalid"),
            Error::Parse(e) => write!(f, "image does not parse: {e}"),
            Error::Read(e) => write!(f, "image read failed: {e}"),
            Error::TlvAreaTooLarge => f.write_str("TLV areas are larger than the TLV buffer"),
            Error::ChunkBufferEmpty => f.write_str("the digest chunk buffer is empty"),
            Error::Ed25519(e) => write!(f, "Ed25519 half rejected: {e}"),
            Error::Image(e) => write!(f, "image rule broken: {e}"),
        }
    }
}

impl core::error::Error for Error {}

/// Why a trusted key set could not be built.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySetError {
    /// More post-quantum keys than the set's capacity `N`, or more Ed25519 keys than `E`.
    Capacity,
    /// Two keys have the same key ID (the same public-key bytes), or two Ed25519 keys
    /// the same KEYHASH.
    DuplicateKeyId,
    /// A public key does not have the length its algorithm requires.
    InvalidPublicKeyLength(Algorithm),
}

impl fmt::Display for KeySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeySetError::Capacity => f.write_str("more keys than the key set's capacity"),
            KeySetError::DuplicateKeyId => f.write_str("two keys have the same key ID"),
            KeySetError::InvalidPublicKeyLength(alg) => {
                write!(f, "{alg:?} public key has the wrong length")
            }
        }
    }
}

impl core::error::Error for KeySetError {}

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use std::collections::BTreeSet;
    use std::string::ToString;
    use std::vec::Vec;

    use super::*;

    /// One value of every variant. The match is exhaustive, so a new variant needs a
    /// value here.
    fn every_variant() -> Vec<Error> {
        let all = Vec::from([
            Error::MissingKeyId,
            Error::InvalidKeyId,
            Error::MultipleKeyIds,
            Error::MissingPqSignature,
            Error::MultiplePqSignatures,
            Error::KeyNotTrusted,
            Error::KeyAlgorithmMismatch,
            Error::UnsupportedAlgorithm(Algorithm::MlDsa44),
            Error::UnsupportedParameterSet,
            Error::MalformedSignature,
            Error::InvalidPublicKey,
            Error::SignatureInvalid,
            Error::Parse(ParseError::BadMagic),
            Error::Read(ReadError::Other),
            Error::TlvAreaTooLarge,
            Error::ChunkBufferEmpty,
            Error::Ed25519(Ed25519Error::SignatureInvalid),
            Error::Image(ImageError::DigestMismatch),
        ]);
        for e in &all {
            match e {
                Error::MissingKeyId
                | Error::InvalidKeyId
                | Error::MultipleKeyIds
                | Error::MissingPqSignature
                | Error::MultiplePqSignatures
                | Error::KeyNotTrusted
                | Error::KeyAlgorithmMismatch
                | Error::UnsupportedAlgorithm(_)
                | Error::UnsupportedParameterSet
                | Error::MalformedSignature
                | Error::InvalidPublicKey
                | Error::SignatureInvalid
                | Error::Parse(_)
                | Error::Read(_)
                | Error::TlvAreaTooLarge
                | Error::ChunkBufferEmpty
                | Error::Ed25519(_)
                | Error::Image(_) => {}
            }
        }
        all
    }

    #[test]
    fn every_variant_displays_distinctly() {
        let all = every_variant();
        let messages: BTreeSet<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(messages.len(), all.len(), "Display strings are distinct");
        // The post-quantum half's variants name it in the message (AC2), as the classical
        // half and the image rules do below.
        for e in &all {
            if !matches!(
                e,
                Error::Parse(_)
                    | Error::Read(_)
                    | Error::TlvAreaTooLarge
                    | Error::ChunkBufferEmpty
                    | Error::Ed25519(_)
                    | Error::Image(_)
            ) {
                assert!(e.to_string().contains("post-quantum"), "{e:?}: {e}");
            }
        }
        // The classical half and the image rules are named in the message.
        assert!(
            Error::Ed25519(Ed25519Error::SignatureInvalid)
                .to_string()
                .starts_with("Ed25519 half rejected: ")
        );
        assert!(
            Error::Image(ImageError::DigestMismatch)
                .to_string()
                .starts_with("image rule broken: ")
        );
        // Every Ed25519Error and ImageError variant also displays distinctly once wrapped,
        // and differs from every flat variant.
        let ed = [
            Ed25519Error::NotEnabled,
            Ed25519Error::Missing,
            Ed25519Error::Multiple,
            Ed25519Error::Unpaired,
            Ed25519Error::InvalidKeyHash,
            Ed25519Error::InvalidSignatureLength,
            Ed25519Error::KeyNotTrusted,
            Ed25519Error::InvalidPublicKey,
            Ed25519Error::SignatureInvalid,
        ];
        let image = [
            ImageError::Encrypted,
            ImageError::Compressed,
            ImageError::NonBootable,
            ImageError::KeelsignTlvProtected(0x4BA0),
            ImageError::SigPure,
            ImageError::MissingSha256Tlv,
            ImageError::MultipleSha256Tlvs,
            ImageError::InvalidSha256Tlv,
            ImageError::MultipleSecurityCounters,
            ImageError::InvalidSecurityCounter,
            ImageError::DigestMismatch,
        ];
        let wrapped: Vec<Error> = ed
            .iter()
            .map(|&e| Error::from(e))
            .chain(image.iter().map(|&e| Error::from(e)))
            .collect();
        let mut messages: BTreeSet<_> = all
            .iter()
            .filter(|e| !matches!(e, Error::Ed25519(_) | Error::Image(_)))
            .map(ToString::to_string)
            .collect();
        let flat = messages.len();
        messages.extend(wrapped.iter().map(ToString::to_string));
        assert_eq!(messages.len(), flat + ed.len() + image.len());
        assert_eq!(
            Error::from(Ed25519Error::Missing),
            Error::Ed25519(Ed25519Error::Missing)
        );
        assert_eq!(
            Error::from(ImageError::SigPure),
            Error::Image(ImageError::SigPure)
        );
    }
}
