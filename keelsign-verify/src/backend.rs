//! The built-in verification backend and the non-generic [`verify_pq`].

use crate::algorithm::Algorithm;
use crate::dispatch::{Backend, verify_pq_with};
use crate::error::Error;
use crate::lms::{self, ParameterPolicy};
use crate::mldsa;
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
/// - [`Algorithm::MlDsa44`] and [`Algorithm::MlDsa65`] (SHA-44): [`mldsa::verify`], pure
///   FIPS 204 `ML-DSA.Verify` with [`MLDSA_CONTEXT`](crate::tlv::MLDSA_CONTEXT), under
///   [`DefaultBackend::new`] only ([`DefaultBackend::allows_ml_dsa`]).
///   [`DefaultBackend::cnsa_2_0`] refuses them with [`Error::UnsupportedParameterSet`]:
///   ML-DSA-44 and ML-DSA-65 are never CNSA 2.0 algorithms (docs/image-format.md). Without
///   the `ml-dsa` feature [`verify_pq_with`] answers [`Error::UnsupportedAlgorithm`] before
///   any backend is called, and [`mldsa::verify`] gives the same answer if the backend is
///   called directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DefaultBackend {
    lms_policy: ParameterPolicy,
    ml_dsa: bool,
}

impl DefaultBackend {
    /// LMS/HSS under [`ParameterPolicy::keelsign_default`] (at most two levels) and
    /// ML-DSA-44/65 (with the `ml-dsa` feature); what [`verify_pq`] uses.
    pub const fn new() -> Self {
        Self {
            lms_policy: ParameterPolicy::keelsign_default(),
            ml_dsa: true,
        }
    }

    /// LMS/HSS under the strict [`ParameterPolicy::cnsa_2_0`] (single-tree only), for
    /// National Security Systems deployments:
    /// [`verify_pq_with`]`(&DefaultBackend::cnsa_2_0(), keys, tlvs, message)`. An HSS key
    /// with `L >= 2` is [`Error::UnsupportedParameterSet`], and so is every ML-DSA-44/65
    /// signature: they are never CNSA 2.0 algorithms (docs/image-format.md).
    pub const fn cnsa_2_0() -> Self {
        Self {
            lms_policy: ParameterPolicy::cnsa_2_0(),
            ml_dsa: false,
        }
    }

    /// The LMS/HSS policy this backend applies.
    pub const fn lms_policy(&self) -> ParameterPolicy {
        self.lms_policy
    }

    /// Whether this backend verifies ML-DSA-44/65 signatures: `true` for
    /// [`DefaultBackend::new`], `false` for [`DefaultBackend::cnsa_2_0`] (which answers
    /// them with [`Error::UnsupportedParameterSet`]). Independent of the `ml-dsa` feature,
    /// which [`Algorithm::is_enabled`] reports.
    pub const fn allows_ml_dsa(&self) -> bool {
        self.ml_dsa
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
            Algorithm::MlDsa44 | Algorithm::MlDsa65 => {
                if self.ml_dsa {
                    mldsa::verify(algorithm, public_key, message, signature)
                } else {
                    Err(Error::UnsupportedParameterSet)
                }
            }
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
    fn default_backend_verifies_ml_dsa_and_cnsa_2_0_refuses_it() {
        assert!(DefaultBackend::new().allows_ml_dsa());
        assert!(DefaultBackend::default().allows_ml_dsa());
        assert!(!DefaultBackend::cnsa_2_0().allows_ml_dsa());
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65] {
            let (pk, sig) = ml_dsa_signed(algorithm, MSG);
            let keys = TrustedKeys::<1>::new(&[TrustedKey {
                algorithm,
                public_key: &pk,
            }])
            .unwrap();
            let id = key_id_of(&pk);
            let tlvs = [
                (TLV_KEELSIGN_KEY_ID, id.as_slice()),
                (algorithm.tlv_type(), sig.as_slice()),
            ];
            if cfg!(feature = "ml-dsa") {
                // The backend alone.
                assert_eq!(
                    DefaultBackend::new().verify(algorithm, &pk, MSG, &sig),
                    Ok(()),
                    "{algorithm:?}"
                );
                assert_eq!(
                    DefaultBackend::new().verify(algorithm, &pk, b"other", &sig),
                    Err(Error::SignatureInvalid),
                    "{algorithm:?}"
                );
                // Through verify_pq / verify_pq_with.
                assert_eq!(
                    verify_pq(&keys, tlvs, MSG).map(|k| k.public_key),
                    Ok(pk.as_slice()),
                    "{algorithm:?}"
                );
                assert_eq!(
                    verify_pq_with(&DefaultBackend::new(), &keys, tlvs, MSG).map(|_| ()),
                    Ok(()),
                    "{algorithm:?}"
                );
                // The strict backend refuses ML-DSA whatever the signature.
                for s in [sig.as_slice(), b"sig".as_slice(), &[]] {
                    assert_eq!(
                        DefaultBackend::cnsa_2_0().verify(algorithm, &pk, MSG, s),
                        Err(Error::UnsupportedParameterSet),
                        "{algorithm:?}"
                    );
                }
                assert_eq!(
                    verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, tlvs, MSG),
                    Err(Error::UnsupportedParameterSet),
                    "{algorithm:?}"
                );
            } else {
                // Feature off: the dispatcher refuses before any backend runs, under both.
                assert_eq!(
                    verify_pq(&keys, tlvs, MSG),
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?}"
                );
                assert_eq!(
                    verify_pq_with(&DefaultBackend::cnsa_2_0(), &keys, tlvs, MSG),
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?}"
                );
                // Called directly, DefaultBackend::new() gives the same answer.
                assert_eq!(
                    DefaultBackend::new().verify(algorithm, &pk, MSG, &sig),
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?}"
                );
                assert_eq!(
                    DefaultBackend::cnsa_2_0().verify(algorithm, &pk, MSG, &sig),
                    Err(Error::UnsupportedParameterSet),
                    "{algorithm:?}"
                );
            }
        }
    }

    const MSG: &[u8] = &[0xC3; 32];

    /// An ML-DSA public key and a signature over `msg` with the keelsign context. Without
    /// the `ml-dsa` feature, right-length placeholder bytes (never verified).
    fn ml_dsa_signed(algorithm: Algorithm, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        #[cfg(feature = "ml-dsa")]
        {
            use ml_dsa::{MlDsa44, MlDsa65, MlDsaParams, Seed, SigningKey};
            fn sign<P: MlDsaParams>(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
                let sk = SigningKey::<P>::from_seed(&Seed::try_from(&[7u8; 32][..]).unwrap());
                let sig = sk
                    .expanded_key()
                    .sign_deterministic(msg, crate::tlv::MLDSA_CONTEXT)
                    .unwrap()
                    .encode();
                (
                    sk.expanded_key().verifying_key().encode().to_vec(),
                    sig.to_vec(),
                )
            }
            match algorithm {
                Algorithm::MlDsa44 => sign::<MlDsa44>(msg),
                _ => sign::<MlDsa65>(msg),
            }
        }
        #[cfg(not(feature = "ml-dsa"))]
        {
            let _ = msg;
            let pk = std::vec![0x44u8; algorithm.public_key_len().unwrap()];
            let sig_len = if algorithm == Algorithm::MlDsa44 {
                2420
            } else {
                3309
            };
            (pk, std::vec![0u8; sig_len])
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
        assert!(DefaultBackend::new().allows_ml_dsa());
        assert!(!DefaultBackend::cnsa_2_0().allows_ml_dsa());
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
