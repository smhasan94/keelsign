//! Typed errors.

use core::fmt;

use crate::algorithm::Algorithm;
use crate::image::ParseError;
use crate::reader::ReadError;

/// Why an image was rejected: it could not be read or parsed, or its post-quantum
/// signature does not verify.
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
    UnsupportedParameterSet,
    /// The signature is shorter or longer than its parameter sets dictate (truncated, or
    /// with trailing bytes), or its structure does not match the public key (for HSS,
    /// a level count other than the key's).
    MalformedSignature,
    /// The trusted public key is not a valid encoding for its parameter set (for LMS/HSS,
    /// too short or not exactly `4 + 24 + m` bytes).
    InvalidPublicKey,
    /// The signature does not verify under the selected key.
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
}

impl From<ParseError> for Error {
    fn from(e: ParseError) -> Self {
        Error::Parse(e)
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
            Error::MissingKeyId => f.write_str("no key-ID TLV"),
            Error::InvalidKeyId => f.write_str("key-ID TLV has the wrong length"),
            Error::MultipleKeyIds => f.write_str("more than one key-ID TLV"),
            Error::MissingPqSignature => f.write_str("no post-quantum signature TLV"),
            Error::MultiplePqSignatures => f.write_str("more than one post-quantum signature TLV"),
            Error::KeyNotTrusted => f.write_str("key ID is not in the trusted key set"),
            Error::KeyAlgorithmMismatch => {
                f.write_str("trusted key algorithm does not match the signature TLV")
            }
            Error::UnsupportedAlgorithm(alg) => {
                write!(f, "algorithm {alg:?} is not enabled in this build")
            }
            Error::UnsupportedParameterSet => f.write_str("unsupported parameter set"),
            Error::MalformedSignature => f.write_str("signature is malformed"),
            Error::InvalidPublicKey => f.write_str("public key is malformed"),
            Error::SignatureInvalid => f.write_str("signature is invalid"),
            Error::Parse(e) => write!(f, "image does not parse: {e}"),
            Error::Read(e) => write!(f, "image read failed: {e}"),
            Error::TlvAreaTooLarge => f.write_str("TLV areas are larger than the TLV buffer"),
            Error::ChunkBufferEmpty => f.write_str("the digest chunk buffer is empty"),
        }
    }
}

impl core::error::Error for Error {}

/// Why a trusted key set could not be built.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeySetError {
    /// More keys than the set's capacity `N`.
    Capacity,
    /// Two keys have the same key ID (the same public-key bytes).
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
