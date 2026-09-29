//! Typed errors.

use core::fmt;

use crate::algorithm::Algorithm;

/// Why an image's post-quantum signature was rejected.
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
    /// Reserved for the real backends (SHA-65, SHA-44); nothing in this crate returns it
    /// yet.
    UnsupportedParameterSet,
    /// The signature does not verify under the selected key.
    SignatureInvalid,
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
            Error::SignatureInvalid => f.write_str("signature is invalid"),
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
