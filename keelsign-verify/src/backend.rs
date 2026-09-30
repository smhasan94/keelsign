//! The built-in verification backend and the non-generic [`verify_pq`].

use crate::algorithm::Algorithm;
use crate::dispatch::{Backend, verify_pq_with};
use crate::error::Error;
use crate::lms;
use crate::trusted_keys::{TrustedKey, TrustedKeys};

/// The verifiers built into this crate.
///
/// - [`Algorithm::LmsHss`]: [`lms::verify`], under the keelsign parameter policy
///   [`lms::ParameterPolicy::cnsa_2_0`].
/// - [`Algorithm::MlDsa44`] and [`Algorithm::MlDsa65`]: not implemented yet (SHA-44);
///   they return [`Error::UnsupportedAlgorithm`] whether or not the `ml-dsa` feature is
///   enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DefaultBackend;

impl Backend for DefaultBackend {
    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match algorithm {
            Algorithm::LmsHss => lms::verify(public_key, message, signature),
            Algorithm::MlDsa44 | Algorithm::MlDsa65 => Err(Error::UnsupportedAlgorithm(algorithm)),
        }
    }
}

/// Verify the post-quantum signature in `tlvs` over `message` with [`DefaultBackend`],
/// and return the trusted key that verified it.
///
/// This is [`verify_pq_with`]`(&DefaultBackend, keys, tlvs, message)`; see there for the
/// order of the checks and the errors.
pub fn verify_pq<'a, 't, I, const N: usize>(
    keys: &TrustedKeys<'a, N>,
    tlvs: I,
    message: &[u8],
) -> Result<TrustedKey<'a>, Error>
where
    I: IntoIterator<Item = (u16, &'t [u8])>,
{
    verify_pq_with(&DefaultBackend, keys, tlvs, message)
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

    use std::vec::Vec;

    use super::*;
    use crate::tlv::{TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG};
    use crate::trusted_keys::key_id_of;

    #[test]
    fn default_backend_ml_dsa_arms_are_unsupported_until_sha_44() {
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65] {
            let pk = [0x44u8; 1952];
            let pk = &pk[..algorithm.public_key_len().unwrap()];
            assert_eq!(
                DefaultBackend.verify(algorithm, pk, b"msg", b"sig"),
                Err(Error::UnsupportedAlgorithm(algorithm)),
                "{algorithm:?}"
            );
            // Through verify_pq: with `ml-dsa` off the dispatcher stops first, with it on
            // the backend answers; the result is the same either way.
            let keys = TrustedKeys::<1>::new(&[TrustedKey {
                algorithm,
                public_key: pk,
            }])
            .unwrap();
            let id = key_id_of(pk);
            let tlvs = [
                (TLV_KEELSIGN_KEY_ID, id.as_slice()),
                (algorithm.tlv_type(), b"sig".as_slice()),
            ];
            assert_eq!(
                verify_pq(&keys, tlvs, b"msg"),
                Err(Error::UnsupportedAlgorithm(algorithm)),
                "{algorithm:?} (ml-dsa feature {})",
                cfg!(feature = "ml-dsa")
            );
        }
    }

    #[test]
    fn trusted_w2_key_is_unsupported_parameter_set_through_verify_pq() {
        // HSS L=1, LMS_SHA256_M24_H10 (0x0B) with LMOTS_SHA256_N24_W2 (0x06): a valid
        // SP 800-208 set outside the keelsign policy.
        let mut pk = Vec::new();
        pk.extend_from_slice(&1u32.to_be_bytes());
        pk.extend_from_slice(&0x0Bu32.to_be_bytes());
        pk.extend_from_slice(&0x06u32.to_be_bytes());
        pk.extend_from_slice(&[0x11; 16 + 24]);
        assert_eq!(pk.len(), 52);
        let keys = TrustedKeys::<2>::new(&[TrustedKey {
            algorithm: Algorithm::LmsHss,
            public_key: &pk,
        }])
        .unwrap();
        let id = key_id_of(&pk);
        // Any signature bytes: the parameter set is refused before the signature is read.
        for sig in [&[][..], &[0u8; 4][..], &[0xA5; 2700][..]] {
            let tlvs = [
                (0x0010, [0u8; 32].as_slice()),
                (TLV_KEELSIGN_KEY_ID, id.as_slice()),
                (TLV_LMS_HSS_SIG, sig),
            ];
            assert_eq!(
                verify_pq(&keys, tlvs, &[0u8; 32]),
                Err(Error::UnsupportedParameterSet)
            );
        }
    }
}
