//! The built-in verification backend and the non-generic [`verify_pq`].

use crate::algorithm::Algorithm;
use crate::dispatch::{Backend, verify_pq_with};
use crate::error::Error;
use crate::lms::{self, ParameterPolicy};
use crate::trusted_keys::{TrustedKey, TrustedKeys};

/// The verifiers built into this crate.
///
/// - [`Algorithm::LmsHss`]: [`lms::verify_with_policy`] under the backend's LMS/HSS
///   policy, one of the two device policies:
///   - [`DefaultBackend::new`] (also [`Default`]):
///     [`ParameterPolicy::keelsign_default`], at most two HSS levels. This is what
///     [`verify_pq`] uses.
///   - [`DefaultBackend::cnsa_2_0`]: the strict [`ParameterPolicy::cnsa_2_0`], single-tree
///     LMS only (`L = 1`), for National Security Systems:
///     [`verify_pq_with`]`(&DefaultBackend::cnsa_2_0(), keys, tlvs, message)`.
///
///   [`ParameterPolicy::rfc_8554_all_sets`] (host tests only) has no constructor here, so
///   no device path can reach it.
/// - [`Algorithm::MlDsa44`] and [`Algorithm::MlDsa65`]: not implemented yet (SHA-44);
///   they return [`Error::UnsupportedAlgorithm`] whether or not the `ml-dsa` feature is
///   enabled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultBackend {
    lms_policy: ParameterPolicy,
}

impl DefaultBackend {
    /// LMS/HSS under [`ParameterPolicy::keelsign_default`] (at most two levels); what
    /// [`verify_pq`] uses.
    pub const fn new() -> Self {
        Self {
            lms_policy: ParameterPolicy::keelsign_default(),
        }
    }

    /// LMS/HSS under the strict [`ParameterPolicy::cnsa_2_0`] (single-tree only), for
    /// National Security Systems deployments:
    /// [`verify_pq_with`]`(&DefaultBackend::cnsa_2_0(), keys, tlvs, message)`. An HSS key
    /// with `L >= 2` is [`Error::UnsupportedParameterSet`].
    pub const fn cnsa_2_0() -> Self {
        Self {
            lms_policy: ParameterPolicy::cnsa_2_0(),
        }
    }

    /// The LMS/HSS policy this backend applies.
    pub const fn lms_policy(&self) -> ParameterPolicy {
        self.lms_policy
    }
}

impl Default for DefaultBackend {
    /// [`DefaultBackend::new`]: [`ParameterPolicy::keelsign_default`].
    fn default() -> Self {
        Self::new()
    }
}

impl Backend for DefaultBackend {
    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        match algorithm {
            Algorithm::LmsHss => {
                lms::verify_with_policy(&self.lms_policy, public_key, message, signature)
            }
            Algorithm::MlDsa44 | Algorithm::MlDsa65 => Err(Error::UnsupportedAlgorithm(algorithm)),
        }
    }
}

/// Verify the post-quantum signature in `tlvs` over `message` with
/// [`DefaultBackend::new`] (LMS/HSS under [`ParameterPolicy::keelsign_default`]), and
/// return the trusted key that verified it.
///
/// This is [`verify_pq_with`]`(&DefaultBackend::new(), keys, tlvs, message)`; see there
/// for the order of the checks and the errors. For the strict single-tree CNSA 2.0 policy
/// call [`verify_pq_with`]`(&DefaultBackend::cnsa_2_0(), keys, tlvs, message)`.
pub fn verify_pq<'a, 't, I, const N: usize, const E: usize>(
    keys: &TrustedKeys<'a, N, E>,
    tlvs: I,
    message: &[u8],
) -> Result<TrustedKey<'a>, Error>
where
    I: IntoIterator<Item = (u16, &'t [u8])>,
{
    verify_pq_with(&DefaultBackend::new(), keys, tlvs, message)
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
            for backend in [DefaultBackend::new(), DefaultBackend::cnsa_2_0()] {
                assert_eq!(
                    backend.verify(algorithm, pk, b"msg", b"sig"),
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?} {backend:?}"
                );
            }
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
            assert_eq!(
                verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, tlvs, b"msg"),
                Err(Error::UnsupportedAlgorithm(algorithm)),
                "{algorithm:?} strict (ml-dsa feature {})",
                cfg!(feature = "ml-dsa")
            );
        }
    }

    #[test]
    fn trusted_w2_key_is_unsupported_parameter_set_through_verify_pq() {
        // HSS L=1, LMS_SHA256_M24_H10 (0x0B) with LMOTS_SHA256_N24_W2 (0x06): a valid
        // SP 800-208 set outside both device policies.
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
            assert_eq!(
                verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, tlvs, &[0u8; 32]),
                Err(Error::UnsupportedParameterSet)
            );
        }
    }

    #[test]
    fn default_backend_offers_only_the_two_device_policies() {
        assert_eq!(
            DefaultBackend::new().lms_policy(),
            ParameterPolicy::keelsign_default()
        );
        assert_eq!(DefaultBackend::default(), DefaultBackend::new());
        assert_eq!(
            DefaultBackend::cnsa_2_0().lms_policy(),
            ParameterPolicy::cnsa_2_0()
        );
        assert_ne!(DefaultBackend::new(), DefaultBackend::cnsa_2_0());
        for backend in [DefaultBackend::new(), DefaultBackend::cnsa_2_0()] {
            assert_ne!(
                backend.lms_policy(),
                ParameterPolicy::rfc_8554_all_sets(),
                "{backend:?}"
            );
        }
        assert_eq!(DefaultBackend::new().lms_policy().max_levels(), 2);
        assert_eq!(DefaultBackend::cnsa_2_0().lms_policy().max_levels(), 1);
    }

    #[test]
    fn cnsa_2_0_backend_rejects_two_level_keys_and_accepts_single_trees_through_verify_pq_with() {
        use crate::lms::{MSG, hss};

        let cases = [
            // (levels, hash) -> expected under keelsign_default, under cnsa_2_0
            (hss(&[(0x05, 0x04)], 6), Ok(()), Ok(())),
            (hss(&[(0x0A, 0x08)], 7), Ok(()), Ok(())),
            (
                hss(&[(0x05, 0x04), (0x05, 0x04)], 8),
                Ok(()),
                Err(Error::UnsupportedParameterSet),
            ),
            (
                hss(&[(0x0A, 0x08), (0x0A, 0x08)], 9),
                Ok(()),
                Err(Error::UnsupportedParameterSet),
            ),
        ];
        for (s, expect_default, expect_cnsa_2_0) in &cases {
            let keys = TrustedKeys::<1>::new(&[TrustedKey {
                algorithm: Algorithm::LmsHss,
                public_key: &s.pk,
            }])
            .unwrap();
            let id = key_id_of(&s.pk);
            let tlvs = [
                (TLV_KEELSIGN_KEY_ID, id.as_slice()),
                (TLV_LMS_HSS_SIG, s.sig.as_slice()),
            ];
            let levels = u32::from_be_bytes(s.pk[..4].try_into().unwrap());
            assert_eq!(
                verify_pq(&keys, tlvs, MSG).map(|k| k.public_key),
                expect_default.map(|()| s.pk.as_slice()),
                "L={levels}"
            );
            assert_eq!(
                verify_pq_with(&DefaultBackend::new(), &keys, tlvs, MSG).map(|_| ()),
                *expect_default,
                "L={levels}"
            );
            assert_eq!(
                verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, tlvs, MSG).map(|_| ()),
                *expect_cnsa_2_0,
                "L={levels}"
            );
            // The backend alone gives the same answers.
            assert_eq!(
                DefaultBackend::cnsa_2_0().verify(Algorithm::LmsHss, &s.pk, MSG, &s.sig),
                *expect_cnsa_2_0,
                "L={levels}"
            );
            if levels == 1 {
                // A single tree still has to verify: another message fails.
                assert_eq!(
                    verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, tlvs, b"other").map(|_| ()),
                    Err(Error::SignatureInvalid)
                );
            }
        }
    }
}
