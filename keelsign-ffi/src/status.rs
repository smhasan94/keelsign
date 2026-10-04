//! Status codes: one stable number per known `keelsign_verify` error variant, plus a
//! catch-all per group for variants added later (`KEELSIGN_ERR_*_UNKNOWN`).

use keelsign_verify::image::ParseError;
use keelsign_verify::{Ed25519Error, Error, ImageError, KeySetError, ReadError};

/// The result of a keelsign call. `KEELSIGN_OK` (0) is success; every other value is an
/// error. The numbers are stable: a code is never renumbered or reused. Treat any value
/// you do not recognise as an error.
///
/// | Range | Group |
/// |---|---|
/// | 1–4 | arguments |
/// | 5–9 | the trusted key set |
/// | 10–23 | the post-quantum half and buffers |
/// | 30–39 | image parsing |
/// | 40–49 | reading the image |
/// | 50–59 | the Ed25519 half |
/// | 60–79 | image rules |
/// | 99 | an error this ABI version does not know |
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum keelsign_status_t {
    /// Success.
    KEELSIGN_OK = 0,
    /// A pointer argument that must not be NULL is NULL.
    KEELSIGN_ERR_NULL_POINTER = 1,
    /// `len` is above `UINT32_MAX`.
    KEELSIGN_ERR_IMAGE_TOO_LARGE = 2,
    /// `policy` is not a `KEELSIGN_POLICY_*` value.
    KEELSIGN_ERR_INVALID_POLICY = 3,
    /// A key's `alg` is not a `KEELSIGN_ALG_*` value.
    KEELSIGN_ERR_INVALID_ALGORITHM = 4,
    /// More than `KEELSIGN_MAX_PQ_KEYS` post-quantum or `KEELSIGN_MAX_ED25519_KEYS`
    /// Ed25519 keys.
    KEELSIGN_ERR_TOO_MANY_KEYS = 5,
    /// Two keys have the same key ID (post-quantum) or KEYHASH (Ed25519).
    KEELSIGN_ERR_DUPLICATE_KEY = 6,
    /// A key has the wrong length for its algorithm (or is not a valid LMS/HSS key).
    KEELSIGN_ERR_KEY_LENGTH = 7,
    /// The key set was rejected for a reason this ABI version does not know.
    KEELSIGN_ERR_KEYSET_UNKNOWN = 9,
    /// No post-quantum key-ID TLV.
    KEELSIGN_ERR_MISSING_KEY_ID = 10,
    /// The post-quantum key-ID TLV has the wrong length.
    KEELSIGN_ERR_INVALID_KEY_ID = 11,
    /// More than one post-quantum key-ID TLV.
    KEELSIGN_ERR_MULTIPLE_KEY_IDS = 12,
    /// No post-quantum signature TLV.
    KEELSIGN_ERR_MISSING_PQ_SIGNATURE = 13,
    /// More than one post-quantum signature TLV.
    KEELSIGN_ERR_MULTIPLE_PQ_SIGNATURES = 14,
    /// The image's post-quantum key ID is not among the trusted keys.
    KEELSIGN_ERR_KEY_NOT_TRUSTED = 15,
    /// The trusted key's algorithm does not match the signature TLV.
    KEELSIGN_ERR_KEY_ALGORITHM_MISMATCH = 16,
    /// The image is signed with an algorithm this build does not verify (ML-DSA without
    /// the `ml-dsa` feature).
    KEELSIGN_ERR_UNSUPPORTED_ALGORITHM = 17,
    /// Unsupported post-quantum parameter set.
    KEELSIGN_ERR_UNSUPPORTED_PARAMETER_SET = 18,
    /// The post-quantum signature is malformed.
    KEELSIGN_ERR_MALFORMED_SIGNATURE = 19,
    /// The trusted post-quantum public key is malformed.
    KEELSIGN_ERR_INVALID_PUBLIC_KEY = 20,
    /// The post-quantum signature does not verify.
    KEELSIGN_ERR_SIGNATURE_INVALID = 21,
    /// The TLV areas do not fit `KEELSIGN_TLV_BUF_LEN`.
    KEELSIGN_ERR_TLV_AREA_TOO_LARGE = 22,
    /// The digest chunk buffer is empty (never returned by this library).
    KEELSIGN_ERR_CHUNK_BUFFER_EMPTY = 23,
    /// Not a little-endian MCUboot image (bad header magic).
    KEELSIGN_ERR_PARSE_BAD_MAGIC = 30,
    /// The image is truncated (also: `len` is 0).
    KEELSIGN_ERR_PARSE_TRUNCATED = 31,
    /// The header size is below 32 bytes.
    KEELSIGN_ERR_PARSE_HEADER_TOO_SMALL = 32,
    /// The image sizes overflow.
    KEELSIGN_ERR_PARSE_SIZE_OVERFLOW = 33,
    /// A TLV info header has the wrong magic.
    KEELSIGN_ERR_PARSE_BAD_TLV_INFO_MAGIC = 34,
    /// The protected TLV area size does not match the header.
    KEELSIGN_ERR_PARSE_PROTECTED_SIZE_MISMATCH = 35,
    /// A TLV length runs past its area.
    KEELSIGN_ERR_PARSE_LENGTH_MISMATCH = 36,
    /// The post-quantum signature TLV is too long.
    KEELSIGN_ERR_PARSE_PQ_SIGNATURE_TOO_LONG = 37,
    /// The image does not parse, for a reason this ABI version does not know.
    KEELSIGN_ERR_PARSE_UNKNOWN = 39,
    /// A read ran past the end of the image.
    KEELSIGN_ERR_READ_OUT_OF_BOUNDS = 40,
    /// A read was not aligned.
    KEELSIGN_ERR_READ_NOT_ALIGNED = 41,
    /// Another read error.
    KEELSIGN_ERR_READ_OTHER = 42,
    /// A read error this ABI version does not know.
    KEELSIGN_ERR_READ_UNKNOWN = 49,
    /// The policy needs the Ed25519 half and the library was built without `ed25519`.
    KEELSIGN_ERR_ED25519_NOT_ENABLED = 50,
    /// No ED25519 signature TLV.
    KEELSIGN_ERR_ED25519_MISSING = 51,
    /// More than one ED25519 or KEYHASH TLV.
    KEELSIGN_ERR_ED25519_MULTIPLE = 52,
    /// The ED25519 TLV does not follow a KEYHASH TLV.
    KEELSIGN_ERR_ED25519_UNPAIRED = 53,
    /// The KEYHASH TLV has the wrong length.
    KEELSIGN_ERR_ED25519_INVALID_KEYHASH = 54,
    /// The ED25519 TLV has the wrong length.
    KEELSIGN_ERR_ED25519_INVALID_SIGNATURE_LENGTH = 55,
    /// The KEYHASH is not among the trusted Ed25519 keys.
    KEELSIGN_ERR_ED25519_KEY_NOT_TRUSTED = 56,
    /// The trusted Ed25519 public key is malformed.
    KEELSIGN_ERR_ED25519_INVALID_PUBLIC_KEY = 57,
    /// The Ed25519 signature does not verify.
    KEELSIGN_ERR_ED25519_SIGNATURE_INVALID = 58,
    /// The Ed25519 half failed for a reason this ABI version does not know.
    KEELSIGN_ERR_ED25519_UNKNOWN = 59,
    /// Encrypted images are not supported.
    KEELSIGN_ERR_IMAGE_ENCRYPTED = 60,
    /// Compressed images are not supported.
    KEELSIGN_ERR_IMAGE_COMPRESSED = 61,
    /// The image is flagged non-bootable.
    KEELSIGN_ERR_IMAGE_NON_BOOTABLE = 62,
    /// A keelsign TLV is in the protected TLV area.
    KEELSIGN_ERR_IMAGE_KEELSIGN_TLV_PROTECTED = 63,
    /// SIG_PURE images are not supported.
    KEELSIGN_ERR_IMAGE_SIG_PURE = 64,
    /// No SHA256 TLV.
    KEELSIGN_ERR_IMAGE_MISSING_SHA256_TLV = 65,
    /// More than one SHA256 TLV.
    KEELSIGN_ERR_IMAGE_MULTIPLE_SHA256_TLVS = 66,
    /// The SHA256 TLV has the wrong length.
    KEELSIGN_ERR_IMAGE_INVALID_SHA256_TLV = 67,
    /// More than one protected security counter TLV.
    KEELSIGN_ERR_IMAGE_MULTIPLE_SECURITY_COUNTERS = 68,
    /// The protected security counter TLV has the wrong length.
    KEELSIGN_ERR_IMAGE_INVALID_SECURITY_COUNTER = 69,
    /// The SHA256 TLV does not match the image digest.
    KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH = 70,
    /// An image rule this ABI version does not know was broken.
    KEELSIGN_ERR_IMAGE_UNKNOWN = 79,
    /// An error this ABI version does not know.
    KEELSIGN_ERR_UNKNOWN = 99,
}

use keelsign_status_t::*;

/// The status code of a verifier error.
pub(crate) fn status_of(error: Error) -> keelsign_status_t {
    match error {
        Error::MissingKeyId => KEELSIGN_ERR_MISSING_KEY_ID,
        Error::InvalidKeyId => KEELSIGN_ERR_INVALID_KEY_ID,
        Error::MultipleKeyIds => KEELSIGN_ERR_MULTIPLE_KEY_IDS,
        Error::MissingPqSignature => KEELSIGN_ERR_MISSING_PQ_SIGNATURE,
        Error::MultiplePqSignatures => KEELSIGN_ERR_MULTIPLE_PQ_SIGNATURES,
        Error::KeyNotTrusted => KEELSIGN_ERR_KEY_NOT_TRUSTED,
        Error::KeyAlgorithmMismatch => KEELSIGN_ERR_KEY_ALGORITHM_MISMATCH,
        Error::UnsupportedAlgorithm(_) => KEELSIGN_ERR_UNSUPPORTED_ALGORITHM,
        Error::UnsupportedParameterSet => KEELSIGN_ERR_UNSUPPORTED_PARAMETER_SET,
        Error::MalformedSignature => KEELSIGN_ERR_MALFORMED_SIGNATURE,
        Error::InvalidPublicKey => KEELSIGN_ERR_INVALID_PUBLIC_KEY,
        Error::SignatureInvalid => KEELSIGN_ERR_SIGNATURE_INVALID,
        Error::Parse(e) => parse_status(e),
        Error::Read(e) => read_status(e),
        Error::TlvAreaTooLarge => KEELSIGN_ERR_TLV_AREA_TOO_LARGE,
        Error::ChunkBufferEmpty => KEELSIGN_ERR_CHUNK_BUFFER_EMPTY,
        Error::Ed25519(e) => ed25519_status(e),
        Error::Image(e) => image_status(e),
        _ => KEELSIGN_ERR_UNKNOWN,
    }
}

/// The status code of a rejected key set.
pub(crate) fn keyset_status(error: KeySetError) -> keelsign_status_t {
    match error {
        KeySetError::Capacity => KEELSIGN_ERR_TOO_MANY_KEYS,
        KeySetError::DuplicateKeyId => KEELSIGN_ERR_DUPLICATE_KEY,
        KeySetError::InvalidPublicKeyLength(_) => KEELSIGN_ERR_KEY_LENGTH,
        _ => KEELSIGN_ERR_KEYSET_UNKNOWN,
    }
}

fn parse_status(error: ParseError) -> keelsign_status_t {
    match error {
        ParseError::BadMagic => KEELSIGN_ERR_PARSE_BAD_MAGIC,
        ParseError::Truncated => KEELSIGN_ERR_PARSE_TRUNCATED,
        ParseError::HeaderTooSmall => KEELSIGN_ERR_PARSE_HEADER_TOO_SMALL,
        ParseError::SizeOverflow => KEELSIGN_ERR_PARSE_SIZE_OVERFLOW,
        ParseError::BadTlvInfoMagic => KEELSIGN_ERR_PARSE_BAD_TLV_INFO_MAGIC,
        ParseError::ProtectedSizeMismatch => KEELSIGN_ERR_PARSE_PROTECTED_SIZE_MISMATCH,
        ParseError::LengthMismatch => KEELSIGN_ERR_PARSE_LENGTH_MISMATCH,
        ParseError::PqSignatureTooLong => KEELSIGN_ERR_PARSE_PQ_SIGNATURE_TOO_LONG,
        _ => KEELSIGN_ERR_PARSE_UNKNOWN,
    }
}

fn read_status(error: ReadError) -> keelsign_status_t {
    match error {
        ReadError::OutOfBounds => KEELSIGN_ERR_READ_OUT_OF_BOUNDS,
        ReadError::NotAligned => KEELSIGN_ERR_READ_NOT_ALIGNED,
        ReadError::Other => KEELSIGN_ERR_READ_OTHER,
        _ => KEELSIGN_ERR_READ_UNKNOWN,
    }
}

fn ed25519_status(error: Ed25519Error) -> keelsign_status_t {
    match error {
        Ed25519Error::NotEnabled => KEELSIGN_ERR_ED25519_NOT_ENABLED,
        Ed25519Error::Missing => KEELSIGN_ERR_ED25519_MISSING,
        Ed25519Error::Multiple => KEELSIGN_ERR_ED25519_MULTIPLE,
        Ed25519Error::Unpaired => KEELSIGN_ERR_ED25519_UNPAIRED,
        Ed25519Error::InvalidKeyHash => KEELSIGN_ERR_ED25519_INVALID_KEYHASH,
        Ed25519Error::InvalidSignatureLength => KEELSIGN_ERR_ED25519_INVALID_SIGNATURE_LENGTH,
        Ed25519Error::KeyNotTrusted => KEELSIGN_ERR_ED25519_KEY_NOT_TRUSTED,
        Ed25519Error::InvalidPublicKey => KEELSIGN_ERR_ED25519_INVALID_PUBLIC_KEY,
        Ed25519Error::SignatureInvalid => KEELSIGN_ERR_ED25519_SIGNATURE_INVALID,
        _ => KEELSIGN_ERR_ED25519_UNKNOWN,
    }
}

fn image_status(error: ImageError) -> keelsign_status_t {
    match error {
        ImageError::Encrypted => KEELSIGN_ERR_IMAGE_ENCRYPTED,
        ImageError::Compressed => KEELSIGN_ERR_IMAGE_COMPRESSED,
        ImageError::NonBootable => KEELSIGN_ERR_IMAGE_NON_BOOTABLE,
        ImageError::KeelsignTlvProtected(_) => KEELSIGN_ERR_IMAGE_KEELSIGN_TLV_PROTECTED,
        ImageError::SigPure => KEELSIGN_ERR_IMAGE_SIG_PURE,
        ImageError::MissingSha256Tlv => KEELSIGN_ERR_IMAGE_MISSING_SHA256_TLV,
        ImageError::MultipleSha256Tlvs => KEELSIGN_ERR_IMAGE_MULTIPLE_SHA256_TLVS,
        ImageError::InvalidSha256Tlv => KEELSIGN_ERR_IMAGE_INVALID_SHA256_TLV,
        ImageError::MultipleSecurityCounters => KEELSIGN_ERR_IMAGE_MULTIPLE_SECURITY_COUNTERS,
        ImageError::InvalidSecurityCounter => KEELSIGN_ERR_IMAGE_INVALID_SECURITY_COUNTER,
        ImageError::DigestMismatch => KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH,
        _ => KEELSIGN_ERR_IMAGE_UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use std::collections::BTreeMap;
    use std::vec::Vec;

    use keelsign_verify::Algorithm;

    use super::*;

    /// Every variant this crate knows, as (status code, error). Each `match` below is
    /// exhaustive over the variants of keelsign-verify 0.0.1 apart from the wildcard
    /// `#[non_exhaustive]` forces, so a new upstream variant shows up here as a mapping
    /// to a catch-all and fails the test until it gets its own code.
    fn every_known_error() -> Vec<(keelsign_status_t, &'static str)> {
        let parse = [
            ParseError::BadMagic,
            ParseError::Truncated,
            ParseError::HeaderTooSmall,
            ParseError::SizeOverflow,
            ParseError::BadTlvInfoMagic,
            ParseError::ProtectedSizeMismatch,
            ParseError::LengthMismatch,
            ParseError::PqSignatureTooLong,
        ];
        let read = [
            ReadError::OutOfBounds,
            ReadError::NotAligned,
            ReadError::Other,
        ];
        let ed25519 = [
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
        let flat = [
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
            Error::TlvAreaTooLarge,
            Error::ChunkBufferEmpty,
        ];
        let keyset = [
            KeySetError::Capacity,
            KeySetError::DuplicateKeyId,
            KeySetError::InvalidPublicKeyLength(Algorithm::LmsHss),
        ];
        let mut all: Vec<(keelsign_status_t, &'static str)> = Vec::new();
        for e in flat {
            all.push((status_of(e), "Error"));
        }
        for e in parse {
            all.push((status_of(Error::Parse(e)), "ParseError"));
        }
        for e in read {
            all.push((status_of(Error::Read(e)), "ReadError"));
        }
        for e in ed25519 {
            all.push((status_of(Error::Ed25519(e)), "Ed25519Error"));
        }
        for e in image {
            all.push((status_of(Error::Image(e)), "ImageError"));
        }
        for e in keyset {
            all.push((keyset_status(e), "KeySetError"));
        }
        // 14 flat + 8 + 3 + 9 + 11 nested Error variants, 3 KeySetError variants.
        assert_eq!(all.len(), 14 + 8 + 3 + 9 + 11 + 3);
        all
    }

    /// TP1: every known error variant has its own code, none of them a catch-all, and
    /// every algorithm of `UnsupportedAlgorithm` / `InvalidPublicKeyLength` maps alike.
    #[test]
    fn every_known_error_variant_maps_to_a_distinct_status() {
        let catch_alls = [
            KEELSIGN_ERR_KEYSET_UNKNOWN,
            KEELSIGN_ERR_PARSE_UNKNOWN,
            KEELSIGN_ERR_READ_UNKNOWN,
            KEELSIGN_ERR_ED25519_UNKNOWN,
            KEELSIGN_ERR_IMAGE_UNKNOWN,
            KEELSIGN_ERR_UNKNOWN,
        ];
        let all = every_known_error();
        let mut seen: BTreeMap<keelsign_status_t, &str> = BTreeMap::new();
        for (status, group) in &all {
            assert!(
                !catch_alls.contains(status),
                "a known {group} variant maps to the catch-all {status:?}"
            );
            assert_ne!(*status, KEELSIGN_OK);
            if let Some(other) = seen.insert(*status, group) {
                panic!("{status:?} is used by a {other} and a {group} variant");
            }
        }
        assert_eq!(seen.len(), all.len());
        for alg in Algorithm::ALL.iter().copied() {
            assert_eq!(
                status_of(Error::UnsupportedAlgorithm(alg)),
                KEELSIGN_ERR_UNSUPPORTED_ALGORITHM
            );
            assert_eq!(
                keyset_status(KeySetError::InvalidPublicKeyLength(alg)),
                KEELSIGN_ERR_KEY_LENGTH
            );
        }
        assert_eq!(
            status_of(Error::Image(ImageError::KeelsignTlvProtected(0x4BA3))),
            KEELSIGN_ERR_IMAGE_KEELSIGN_TLV_PROTECTED
        );
    }

    /// The numbers are part of the ABI (docs/ffi.md, include/keelsign.h): pin each one.
    #[test]
    fn status_numbers_are_stable() {
        let table: [(keelsign_status_t, i32); 59] = [
            (KEELSIGN_OK, 0),
            (KEELSIGN_ERR_NULL_POINTER, 1),
            (KEELSIGN_ERR_IMAGE_TOO_LARGE, 2),
            (KEELSIGN_ERR_INVALID_POLICY, 3),
            (KEELSIGN_ERR_INVALID_ALGORITHM, 4),
            (KEELSIGN_ERR_TOO_MANY_KEYS, 5),
            (KEELSIGN_ERR_DUPLICATE_KEY, 6),
            (KEELSIGN_ERR_KEY_LENGTH, 7),
            (KEELSIGN_ERR_KEYSET_UNKNOWN, 9),
            (KEELSIGN_ERR_MISSING_KEY_ID, 10),
            (KEELSIGN_ERR_INVALID_KEY_ID, 11),
            (KEELSIGN_ERR_MULTIPLE_KEY_IDS, 12),
            (KEELSIGN_ERR_MISSING_PQ_SIGNATURE, 13),
            (KEELSIGN_ERR_MULTIPLE_PQ_SIGNATURES, 14),
            (KEELSIGN_ERR_KEY_NOT_TRUSTED, 15),
            (KEELSIGN_ERR_KEY_ALGORITHM_MISMATCH, 16),
            (KEELSIGN_ERR_UNSUPPORTED_ALGORITHM, 17),
            (KEELSIGN_ERR_UNSUPPORTED_PARAMETER_SET, 18),
            (KEELSIGN_ERR_MALFORMED_SIGNATURE, 19),
            (KEELSIGN_ERR_INVALID_PUBLIC_KEY, 20),
            (KEELSIGN_ERR_SIGNATURE_INVALID, 21),
            (KEELSIGN_ERR_TLV_AREA_TOO_LARGE, 22),
            (KEELSIGN_ERR_CHUNK_BUFFER_EMPTY, 23),
            (KEELSIGN_ERR_PARSE_BAD_MAGIC, 30),
            (KEELSIGN_ERR_PARSE_TRUNCATED, 31),
            (KEELSIGN_ERR_PARSE_HEADER_TOO_SMALL, 32),
            (KEELSIGN_ERR_PARSE_SIZE_OVERFLOW, 33),
            (KEELSIGN_ERR_PARSE_BAD_TLV_INFO_MAGIC, 34),
            (KEELSIGN_ERR_PARSE_PROTECTED_SIZE_MISMATCH, 35),
            (KEELSIGN_ERR_PARSE_LENGTH_MISMATCH, 36),
            (KEELSIGN_ERR_PARSE_PQ_SIGNATURE_TOO_LONG, 37),
            (KEELSIGN_ERR_PARSE_UNKNOWN, 39),
            (KEELSIGN_ERR_READ_OUT_OF_BOUNDS, 40),
            (KEELSIGN_ERR_READ_NOT_ALIGNED, 41),
            (KEELSIGN_ERR_READ_OTHER, 42),
            (KEELSIGN_ERR_READ_UNKNOWN, 49),
            (KEELSIGN_ERR_ED25519_NOT_ENABLED, 50),
            (KEELSIGN_ERR_ED25519_MISSING, 51),
            (KEELSIGN_ERR_ED25519_MULTIPLE, 52),
            (KEELSIGN_ERR_ED25519_UNPAIRED, 53),
            (KEELSIGN_ERR_ED25519_INVALID_KEYHASH, 54),
            (KEELSIGN_ERR_ED25519_INVALID_SIGNATURE_LENGTH, 55),
            (KEELSIGN_ERR_ED25519_KEY_NOT_TRUSTED, 56),
            (KEELSIGN_ERR_ED25519_INVALID_PUBLIC_KEY, 57),
            (KEELSIGN_ERR_ED25519_SIGNATURE_INVALID, 58),
            (KEELSIGN_ERR_ED25519_UNKNOWN, 59),
            (KEELSIGN_ERR_IMAGE_ENCRYPTED, 60),
            (KEELSIGN_ERR_IMAGE_COMPRESSED, 61),
            (KEELSIGN_ERR_IMAGE_NON_BOOTABLE, 62),
            (KEELSIGN_ERR_IMAGE_KEELSIGN_TLV_PROTECTED, 63),
            (KEELSIGN_ERR_IMAGE_SIG_PURE, 64),
            (KEELSIGN_ERR_IMAGE_MISSING_SHA256_TLV, 65),
            (KEELSIGN_ERR_IMAGE_MULTIPLE_SHA256_TLVS, 66),
            (KEELSIGN_ERR_IMAGE_INVALID_SHA256_TLV, 67),
            (KEELSIGN_ERR_IMAGE_MULTIPLE_SECURITY_COUNTERS, 68),
            (KEELSIGN_ERR_IMAGE_INVALID_SECURITY_COUNTER, 69),
            (KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH, 70),
            (KEELSIGN_ERR_IMAGE_UNKNOWN, 79),
            (KEELSIGN_ERR_UNKNOWN, 99),
        ];
        for (status, number) in table {
            assert_eq!(status as i32, number, "{status:?}");
        }
        assert_eq!(core::mem::size_of::<keelsign_status_t>(), 4);
        // No code is listed twice; the header check
        // (repo_checks::ffi::header_status_codes_match_the_rust_enum) ties the table to
        // the enum's variant list.
        let distinct: std::collections::BTreeSet<i32> =
            table.iter().map(|(s, _)| *s as i32).collect();
        assert_eq!(distinct.len(), table.len());
    }
}
