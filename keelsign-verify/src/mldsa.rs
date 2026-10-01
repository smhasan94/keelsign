//! ML-DSA-44/65 signature verification (FIPS 204), behind the `ml-dsa` feature (SHA-44).
//!
//! keelsign signs the 32-byte image digest `M` (SHA-256 of header, body and protected TLV
//! area) as **pure** ML-DSA (`ML-DSA.Sign` / `ML-DSA.Verify`, FIPS 204 Algorithms 2 and
//! 3) with the context string [`MLDSA_CONTEXT`], never HashML-DSA
//! ([docs/image-format.md, Signing mode][spec]). [`verify`] is that check, and is what
//! [`DefaultBackend`](crate::DefaultBackend) calls; [`verify_with_context`] takes any
//! context, for known-answer tests.
//!
//! Every failure maps to one [`Error`] variant, checked in this order:
//!
//! | Failure | Variant |
//! |---|---|
//! | `algorithm` is not ML-DSA-44/65, or the `ml-dsa` feature is off | [`Error::UnsupportedAlgorithm`] |
//! | public key not 1,312 / 1,952 bytes | [`Error::InvalidPublicKey`] |
//! | signature not 2,420 / 3,309 bytes (truncated or trailing bytes) | [`Error::MalformedSignature`] |
//! | signature does not decode: malformed hint encoding, or `‖z‖∞ ≥ γ1 − β` (the FIPS 204 Algorithm 3 norm bound, which `ml-dsa` checks while decoding) | [`Error::MalformedSignature`] |
//! | the verification equation fails (wrong key, message or context, tampered `c̃` or `z`), or the context is longer than 255 bytes | [`Error::SignatureInvalid`] |
//!
//! The verify runs entirely on the stack (no heap) and needs a lot of it: about 98 KB for
//! ML-DSA-44 and 158 KB for ML-DSA-65 (stable release), far over the 32 KB device budget
//! (docs/benchmarks.md, "ML-DSA verify (SHA-44)"; SHA-169 owns a low-stack verify). Each
//! parameter set runs in its own non-inlined frame, so callers that never reach an ML-DSA
//! signature (LMS/HSS, Ed25519) do not reserve that stack.
//!
//! [spec]: https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#signing-mode

use crate::algorithm::Algorithm;
use crate::error::Error;
use crate::tlv::MLDSA_CONTEXT;

// FIPS 204 limits the context string to 255 bytes; a longer one never verifies.
const _: () = assert!(MLDSA_CONTEXT.len() <= 255);

/// Whether this build verifies ML-DSA: `cfg!(feature = "ml-dsa")`, the same answer as
/// [`Algorithm::is_enabled`] for [`Algorithm::MlDsa44`] and [`Algorithm::MlDsa65`].
pub const fn is_enabled() -> bool {
    cfg!(feature = "ml-dsa")
}

/// FIPS 204 `ML-DSA.Verify`, pure, with the keelsign context [`MLDSA_CONTEXT`]: verify
/// `signature` over `message` (the image digest `M`) under the raw FIPS 204
/// `public_key`. This is what [`DefaultBackend`](crate::DefaultBackend) calls.
///
/// It is [`verify_with_context`]`(algorithm, public_key, message, MLDSA_CONTEXT,
/// signature)`; see the [module docs](self) for the errors.
pub fn verify(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    verify_with_context(algorithm, public_key, message, MLDSA_CONTEXT, signature)
}

/// FIPS 204 `ML-DSA.Verify` (Algorithm 3), pure, with any `context` (known-answer tests;
/// keelsign images use [`verify`]).
///
/// `algorithm` must be [`Algorithm::MlDsa44`] or [`Algorithm::MlDsa65`]; anything else is
/// [`Error::UnsupportedAlgorithm`]`(algorithm)`, as is every call without the `ml-dsa`
/// feature. See the [module docs](self) for the other errors and their order.
pub fn verify_with_context(
    algorithm: Algorithm,
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    #[cfg(feature = "ml-dsa")]
    {
        match algorithm {
            Algorithm::MlDsa44 => {
                verify_param::<ml_dsa::MlDsa44>(public_key, message, context, signature)
            }
            Algorithm::MlDsa65 => {
                verify_param::<ml_dsa::MlDsa65>(public_key, message, context, signature)
            }
            Algorithm::LmsHss => Err(Error::UnsupportedAlgorithm(algorithm)),
        }
    }
    #[cfg(not(feature = "ml-dsa"))]
    {
        let _ = (public_key, message, context, signature);
        Err(Error::UnsupportedAlgorithm(algorithm))
    }
}

/// One parameter set's verify.
///
/// `#[inline(never)]` is load-bearing: inlined into [`verify_with_context`] (and on into
/// `verify_with`), the ML-DSA-65 state (about 158 KB) would become part of the caller's
/// frame and every verify, LMS/HSS included, would reserve it. Kept out of line, each
/// parameter set has its own frame (about 98 KB / 158 KB) that only an ML-DSA signature
/// reaches.
#[cfg(feature = "ml-dsa")]
#[inline(never)]
fn verify_param<P: ml_dsa::MlDsaParams>(
    public_key: &[u8],
    message: &[u8],
    context: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};

    let vk_enc =
        EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| Error::InvalidPublicKey)?;
    let sig_enc =
        EncodedSignature::<P>::try_from(signature).map_err(|_| Error::MalformedSignature)?;
    // `None` for a malformed hint encoding or for `‖z‖∞ ≥ γ1 − β`.
    let sig = Signature::<P>::decode(&sig_enc).ok_or(Error::MalformedSignature)?;
    // `false` also for a context longer than 255 bytes.
    if VerifyingKey::<P>::decode(&vk_enc).verify_with_context(message, context, &sig) {
        Ok(())
    } else {
        Err(Error::SignatureInvalid)
    }
}

#[cfg(test)]
mod tests {
    // Host test code, not no_std firmware: failing a test with a message is the point.
    #![allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )]

    use super::*;

    #[cfg(not(feature = "ml-dsa"))]
    #[test]
    fn feature_off_answers_unsupported_algorithm() {
        assert!(!is_enabled());
        for algorithm in Algorithm::ALL.iter().copied() {
            let pk = [0u8; 1952];
            let pk = &pk[..algorithm.public_key_len().unwrap_or(32)];
            for sig in [&[][..], &[0u8; 2420][..], &[0u8; 3309][..]] {
                assert_eq!(
                    verify(algorithm, pk, &[0u8; 32], sig),
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?}"
                );
                assert_eq!(
                    verify_with_context(algorithm, pk, &[0u8; 32], b"", sig),
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?}"
                );
            }
        }
    }

    #[cfg(feature = "ml-dsa")]
    mod enabled {
        use std::vec::Vec;

        use ml_dsa::{MlDsa44, MlDsa65, MlDsaParams, Seed, SigningKey};

        use super::*;

        const MSG: [u8; 32] = [0x5A; 32];

        /// A deterministic (FIPS 204, `rnd = 0`) keypair and signature over `MSG` with
        /// the keelsign context.
        fn sign<P: MlDsaParams>(seed: u8, msg: &[u8], ctx: &[u8]) -> (Vec<u8>, Vec<u8>) {
            let sk = SigningKey::<P>::from_seed(&Seed::try_from(&[seed; 32][..]).unwrap());
            let sig = sk
                .expanded_key()
                .sign_deterministic(msg, ctx)
                .unwrap()
                .encode();
            let pk = sk.expanded_key().verifying_key().encode();
            (pk.to_vec(), sig.to_vec())
        }

        fn signed(algorithm: Algorithm) -> (Vec<u8>, Vec<u8>) {
            match algorithm {
                Algorithm::MlDsa44 => sign::<MlDsa44>(44, &MSG, MLDSA_CONTEXT),
                Algorithm::MlDsa65 => sign::<MlDsa65>(65, &MSG, MLDSA_CONTEXT),
                Algorithm::LmsHss => unreachable!(),
            }
        }

        /// Byte offset of `z` (after `c̃`, λ/4 bytes) in an encoded signature.
        fn z_offset(algorithm: Algorithm) -> usize {
            match algorithm {
                Algorithm::MlDsa44 => 32,
                _ => 48,
            }
        }

        const SETS: [(Algorithm, usize); 2] =
            [(Algorithm::MlDsa44, 2420), (Algorithm::MlDsa65, 3309)];

        #[test]
        fn valid_signatures_verify() {
            assert!(is_enabled());
            for (algorithm, sig_len) in SETS {
                let (pk, sig) = signed(algorithm);
                assert_eq!(Some(pk.len()), algorithm.public_key_len());
                assert_eq!(sig.len(), sig_len);
                assert_eq!(verify(algorithm, &pk, &MSG, &sig), Ok(()), "{algorithm:?}");
                assert_eq!(
                    verify_with_context(algorithm, &pk, &MSG, MLDSA_CONTEXT, &sig),
                    Ok(()),
                    "{algorithm:?}"
                );
            }
        }

        #[test]
        fn error_mapping_per_failure() {
            for (algorithm, sig_len) in SETS {
                let (pk, sig) = signed(algorithm);
                let check = |pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8], want: Error, what| {
                    assert_eq!(
                        verify_with_context(algorithm, pk, msg, ctx, sig),
                        Err(want),
                        "{algorithm:?}: {what}"
                    );
                };

                // Public key one byte short / one byte long.
                check(
                    &pk[..pk.len() - 1],
                    &MSG,
                    MLDSA_CONTEXT,
                    &sig,
                    Error::InvalidPublicKey,
                    "pk -1",
                );
                let mut long_pk = pk.clone();
                long_pk.push(0);
                check(
                    &long_pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &sig,
                    Error::InvalidPublicKey,
                    "pk +1",
                );
                check(
                    &[],
                    &MSG,
                    MLDSA_CONTEXT,
                    &sig,
                    Error::InvalidPublicKey,
                    "pk empty",
                );

                // Signature length: empty, truncated, trailing byte.
                check(
                    &pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &[],
                    Error::MalformedSignature,
                    "sig empty",
                );
                check(
                    &pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &sig[..sig_len - 1],
                    Error::MalformedSignature,
                    "sig -1",
                );
                let mut long_sig = sig.clone();
                long_sig.push(0);
                check(
                    &pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &long_sig,
                    Error::MalformedSignature,
                    "sig +1",
                );

                // Hint encoding: the last byte is the last polynomial's cumulative hint
                // count; 0xFF exceeds ω.
                let mut bad_hint = sig.clone();
                *bad_hint.last_mut().unwrap() = 0xFF;
                check(
                    &pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &bad_hint,
                    Error::MalformedSignature,
                    "hint 0xFF",
                );

                // z out of range: the first coefficient is encoded as γ1 − z; all-zero bits
                // give z = γ1 ≥ γ1 − β, which ml-dsa refuses while decoding.
                let mut bad_z = sig.clone();
                let z = z_offset(algorithm);
                bad_z[z..z + 3].fill(0);
                check(
                    &pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &bad_z,
                    Error::MalformedSignature,
                    "z = γ1",
                );

                // The verification equation: c̃ flip, message flip, wrong context.
                let mut bad_c = sig.clone();
                bad_c[0] ^= 1;
                check(
                    &pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &bad_c,
                    Error::SignatureInvalid,
                    "c~ flip",
                );
                let mut msg = MSG;
                msg[31] ^= 0x80;
                check(
                    &pk,
                    &msg,
                    MLDSA_CONTEXT,
                    &sig,
                    Error::SignatureInvalid,
                    "message flip",
                );
                check(
                    &pk,
                    &MSG,
                    b"",
                    &sig,
                    Error::SignatureInvalid,
                    "empty context",
                );
                check(
                    &pk,
                    &MSG,
                    &[0u8; 256],
                    &sig,
                    Error::SignatureInvalid,
                    "256-byte context",
                );
                // verify() passes MLDSA_CONTEXT: a signature made with no context fails.
                let (pk2, sig2) = match algorithm {
                    Algorithm::MlDsa44 => sign::<MlDsa44>(44, &MSG, b""),
                    _ => sign::<MlDsa65>(65, &MSG, b""),
                };
                assert_eq!(pk2, pk);
                assert_eq!(
                    verify(algorithm, &pk, &MSG, &sig2),
                    Err(Error::SignatureInvalid)
                );
                assert_eq!(
                    verify_with_context(algorithm, &pk, &MSG, b"", &sig2),
                    Ok(())
                );
                // Another key.
                let (other_pk, _) = match algorithm {
                    Algorithm::MlDsa44 => sign::<MlDsa44>(1, &MSG, MLDSA_CONTEXT),
                    _ => sign::<MlDsa65>(1, &MSG, MLDSA_CONTEXT),
                };
                check(
                    &other_pk,
                    &MSG,
                    MLDSA_CONTEXT,
                    &sig,
                    Error::SignatureInvalid,
                    "other key",
                );
            }
            // Not an ML-DSA algorithm.
            assert_eq!(
                verify(Algorithm::LmsHss, &[0u8; 52], &MSG, &[0u8; 100]),
                Err(Error::UnsupportedAlgorithm(Algorithm::LmsHss))
            );
            assert_eq!(
                verify_with_context(Algorithm::LmsHss, &[], &MSG, b"", &[]),
                Err(Error::UnsupportedAlgorithm(Algorithm::LmsHss))
            );
        }

        #[test]
        fn parameter_sets_are_not_interchangeable() {
            let (pk44, sig44) = signed(Algorithm::MlDsa44);
            let (pk65, sig65) = signed(Algorithm::MlDsa65);
            // A 44 key under 65 (and the reverse) has the wrong length.
            assert_eq!(
                verify(Algorithm::MlDsa65, &pk44, &MSG, &sig65),
                Err(Error::InvalidPublicKey)
            );
            assert_eq!(
                verify(Algorithm::MlDsa44, &pk65, &MSG, &sig44),
                Err(Error::InvalidPublicKey)
            );
            // The right key with the other set's signature has the wrong length.
            assert_eq!(
                verify(Algorithm::MlDsa44, &pk44, &MSG, &sig65),
                Err(Error::MalformedSignature)
            );
            assert_eq!(
                verify(Algorithm::MlDsa65, &pk65, &MSG, &sig44),
                Err(Error::MalformedSignature)
            );
        }
    }
}
