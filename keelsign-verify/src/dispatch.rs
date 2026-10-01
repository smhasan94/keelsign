//! Post-quantum signature selection and dispatch to a verification backend.

use crate::algorithm::Algorithm;
use crate::error::Error;
use crate::tlv::TLV_KEELSIGN_KEY_ID;
use crate::trusted_keys::{TrustedKey, TrustedKeys};

/// A signature verifier for one or more [`Algorithm`]s.
///
/// [`verify_pq_with`] only calls it for an enabled algorithm, with a trusted public key
/// whose algorithm matches the signature TLV.
pub trait Backend {
    /// Verify `signature` over `message` under `public_key`.
    ///
    /// `message` is the 32-byte image digest `M`: SHA-256 over the image header, body and
    /// protected TLV area, the value of MCUboot's `IMAGE_TLV_SHA256`
    /// ([docs/image-format.md, Signing mode](https://github.com/smhasan94/keelsign/blob/main/docs/image-format.md#signing-mode)). ML-DSA
    /// backends sign it as pure ML-DSA with
    /// [`MLDSA_CONTEXT`](crate::tlv::MLDSA_CONTEXT), never HashML-DSA.
    /// `signature` is the raw signature TLV value, passed through unchanged (it may be
    /// empty; rejecting it is the backend's job).
    ///
    /// Return `Ok(())` if it verifies, [`Error::SignatureInvalid`] if it does not,
    /// [`Error::UnsupportedParameterSet`] if the key or signature uses a parameter set
    /// the backend cannot handle (for
    /// [`DefaultBackend::cnsa_2_0`](crate::DefaultBackend::cnsa_2_0), any ML-DSA signature),
    /// [`Error::MalformedSignature`] or [`Error::InvalidPublicKey`] for a signature or key
    /// that does not decode, and [`Error::UnsupportedAlgorithm`]`(algorithm)` if the backend
    /// does not implement `algorithm`.
    fn verify(
        &self,
        algorithm: Algorithm,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error>;
}

/// The key-ID and post-quantum signature TLVs picked out of a TLV area.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelectedSignature<'t> {
    /// Value of the key-ID TLV, not yet length-checked (see [`TrustedKeys::find`]).
    pub key_id: &'t [u8],
    /// The algorithm named by the signature TLV's type.
    pub algorithm: Algorithm,
    /// Value of the signature TLV.
    pub signature: &'t [u8],
}

/// Pick the key-ID TLV and the single post-quantum signature TLV out of `tlvs`, given as
/// `(type, value)` pairs.
///
/// TLV types other than the key-ID and post-quantum signature TLVs are ignored (MCUboot
/// hashes, Ed25519 and so on are handled elsewhere).
///
/// Fails closed:
/// - a second signature TLV is [`Error::MultiplePqSignatures`] and a second key-ID TLV is
///   [`Error::MultipleKeyIds`], rather than picking one;
/// - otherwise no signature TLV is [`Error::MissingPqSignature`], then no key-ID TLV is
///   [`Error::MissingKeyId`].
pub fn select_pq_signature<'t, I>(tlvs: I) -> Result<SelectedSignature<'t>, Error>
where
    I: IntoIterator<Item = (u16, &'t [u8])>,
{
    let mut key_id = None;
    let mut signature = None;
    // Only the key-ID and PQ signature TLVs are recognised. Every other TLV type is
    // ignored, including the reserved IDs of `KEELSIGN_TLV_RANGE` (0x4BA4..=0x4BAF):
    // docs/image-format.md requires verifiers to ignore unknown TLVs. A future keelsign
    // TLV with verification meaning must be added to this scan.
    for (tlv_type, value) in tlvs {
        if tlv_type == TLV_KEELSIGN_KEY_ID {
            if key_id.replace(value).is_some() {
                return Err(Error::MultipleKeyIds);
            }
        } else if let Some(algorithm) = Algorithm::from_tlv_type(tlv_type)
            && signature.replace((algorithm, value)).is_some()
        {
            return Err(Error::MultiplePqSignatures);
        }
    }
    let (algorithm, signature) = signature.ok_or(Error::MissingPqSignature)?;
    let key_id = key_id.ok_or(Error::MissingKeyId)?;
    Ok(SelectedSignature {
        key_id,
        algorithm,
        signature,
    })
}

/// Verify the post-quantum signature in `tlvs` over `message` with `backend`, and return
/// the trusted key that verified it. [`verify_pq`](crate::verify_pq) is this function with
/// the built-in [`DefaultBackend`](crate::DefaultBackend).
///
/// It first scans `tlvs` (see [`select_pq_signature`]), failing as soon as it sees a
/// second key-ID TLV ([`Error::MultipleKeyIds`]) or a second post-quantum signature TLV
/// ([`Error::MultiplePqSignatures`]), whichever comes first in TLV order. After the
/// scan it requires, in order:
/// 1. a post-quantum signature TLV ([`Error::MissingPqSignature`]);
/// 2. a key-ID TLV ([`Error::MissingKeyId`]) of the right length
///    ([`Error::InvalidKeyId`]);
/// 3. a trusted key with that ID ([`Error::KeyNotTrusted`]);
/// 4. the key's algorithm matching the signature TLV's ([`Error::KeyAlgorithmMismatch`]);
/// 5. the algorithm being compiled in ([`Error::UnsupportedAlgorithm`]);
///
/// then calls `backend` and passes its error through unchanged.
///
/// The returned key is a copy borrowing the key material (`'a`), not the key set, so it
/// outlives the borrow of `keys`.
pub fn verify_pq_with<'a, 't, B, I, const N: usize, const E: usize>(
    backend: &B,
    keys: &TrustedKeys<'a, N, E>,
    tlvs: I,
    message: &[u8],
) -> Result<TrustedKey<'a>, Error>
where
    B: Backend + ?Sized,
    I: IntoIterator<Item = (u16, &'t [u8])>,
{
    let selected = select_pq_signature(tlvs)?;
    let key = *keys.find(selected.key_id)?;
    if key.algorithm != selected.algorithm {
        return Err(Error::KeyAlgorithmMismatch);
    }
    if !selected.algorithm.is_enabled() {
        return Err(Error::UnsupportedAlgorithm(selected.algorithm));
    }
    backend.verify(
        selected.algorithm,
        key.public_key,
        message,
        selected.signature,
    )?;
    Ok(key)
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

    use core::cell::{Cell, RefCell};
    use std::vec::Vec;

    use super::*;
    use crate::tlv::{KEY_ID_LEN, TLV_LMS_HSS_SIG, TLV_MLDSA44_SIG, TLV_MLDSA65_SIG};
    use crate::trusted_keys::key_id_of;

    /// One recorded backend call.
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Call {
        algorithm: Algorithm,
        public_key: Vec<u8>,
        message: Vec<u8>,
        signature: Vec<u8>,
    }

    /// A mock backend that records every call and returns a fixed result.
    struct RecordingBackend {
        result: Result<(), Error>,
        calls: RefCell<Vec<Call>>,
        count: Cell<usize>,
    }

    impl RecordingBackend {
        fn returning(result: Result<(), Error>) -> Self {
            Self {
                result,
                calls: RefCell::new(Vec::new()),
                count: Cell::new(0),
            }
        }

        fn accepting() -> Self {
            Self::returning(Ok(()))
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.borrow().clone()
        }
    }

    impl Backend for RecordingBackend {
        fn verify(
            &self,
            algorithm: Algorithm,
            public_key: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), Error> {
            self.count.set(self.count.get() + 1);
            self.calls.borrow_mut().push(Call {
                algorithm,
                public_key: public_key.to_vec(),
                message: message.to_vec(),
                signature: signature.to_vec(),
            });
            self.result
        }
    }

    static MLDSA44_PK: [u8; 1312] = [0x44; 1312];
    static MLDSA65_PK: [u8; 1952] = [0x65; 1952];
    static LMS_PK_A: [u8; 60] = crate::lms::test_public_key(0xA0);
    static LMS_PK_B: [u8; 60] = crate::lms::test_public_key(0xB0);
    const SIG: &[u8] = b"signature bytes";
    const MSG: &[u8] = b"image digest";

    fn key(algorithm: Algorithm, public_key: &[u8]) -> TrustedKey<'_> {
        TrustedKey {
            algorithm,
            public_key,
        }
    }

    fn pk_for(algorithm: Algorithm) -> &'static [u8] {
        match algorithm {
            Algorithm::MlDsa44 => &MLDSA44_PK,
            Algorithm::MlDsa65 => &MLDSA65_PK,
            Algorithm::LmsHss => &LMS_PK_A,
        }
    }

    fn lms_keys() -> TrustedKeys<'static, 4> {
        TrustedKeys::new(&[
            key(Algorithm::LmsHss, &LMS_PK_A),
            key(Algorithm::LmsHss, &LMS_PK_B),
        ])
        .unwrap()
    }

    /// Run `verify_pq_with` over owned TLVs.
    fn run<const N: usize>(
        backend: &RecordingBackend,
        keys: &TrustedKeys<'static, N>,
        tlvs: &[(u16, Vec<u8>)],
    ) -> Result<TrustedKey<'static>, Error> {
        verify_pq_with(
            backend,
            keys,
            tlvs.iter().map(|(t, v)| (*t, v.as_slice())),
            MSG,
        )
    }

    fn id_tlv(public_key: &[u8]) -> (u16, Vec<u8>) {
        (TLV_KEELSIGN_KEY_ID, key_id_of(public_key).to_vec())
    }

    fn sig_tlv(tlv_type: u16) -> (u16, Vec<u8>) {
        (tlv_type, SIG.to_vec())
    }

    #[test]
    fn missing_key_id_tlv_is_missing_key_id() {
        let backend = RecordingBackend::accepting();
        let tlvs = [(0x0010, [0u8; 32].to_vec()), sig_tlv(TLV_LMS_HSS_SIG)];
        assert_eq!(run(&backend, &lms_keys(), &tlvs), Err(Error::MissingKeyId));
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn no_pq_tlv_is_missing_pq_signature() {
        let backend = RecordingBackend::accepting();
        let tlvs = [id_tlv(&LMS_PK_A), (0x0010, [0u8; 32].to_vec())];
        assert_eq!(
            run(&backend, &lms_keys(), &tlvs),
            Err(Error::MissingPqSignature)
        );
        // With neither TLV, the missing signature is reported first.
        assert_eq!(
            run(&backend, &lms_keys(), &[]),
            Err(Error::MissingPqSignature)
        );
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn two_pq_tlvs_is_multiple_pq_signatures() {
        let backend = RecordingBackend::accepting();
        for (first, second) in [
            (TLV_LMS_HSS_SIG, TLV_LMS_HSS_SIG),
            (TLV_LMS_HSS_SIG, TLV_MLDSA44_SIG),
            (TLV_MLDSA65_SIG, TLV_LMS_HSS_SIG),
        ] {
            let tlvs = [id_tlv(&LMS_PK_A), sig_tlv(first), sig_tlv(second)];
            assert_eq!(
                run(&backend, &lms_keys(), &tlvs),
                Err(Error::MultiplePqSignatures),
                "{first:#06x} + {second:#06x}"
            );
        }
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn duplicate_key_id_tlv_is_multiple_key_ids() {
        let backend = RecordingBackend::accepting();
        // Two key IDs fail closed even when both name trusted keys, or are identical.
        for second in [&LMS_PK_B, &LMS_PK_A] {
            let tlvs = [id_tlv(&LMS_PK_A), sig_tlv(TLV_LMS_HSS_SIG), id_tlv(second)];
            assert_eq!(
                run(&backend, &lms_keys(), &tlvs),
                Err(Error::MultipleKeyIds)
            );
        }
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn key_algorithm_mismatch_is_its_own_variant() {
        let backend = RecordingBackend::accepting();
        // An LMS key named by an ML-DSA-44 signature TLV, and the reverse.
        let keys = TrustedKeys::<4>::new(&[
            key(Algorithm::LmsHss, &LMS_PK_A),
            key(Algorithm::MlDsa44, &MLDSA44_PK),
        ])
        .unwrap();
        let tlvs = [id_tlv(&LMS_PK_A), sig_tlv(TLV_MLDSA44_SIG)];
        assert_eq!(
            run(&backend, &keys, &tlvs),
            Err(Error::KeyAlgorithmMismatch)
        );
        let tlvs = [id_tlv(&MLDSA44_PK), sig_tlv(TLV_LMS_HSS_SIG)];
        assert_eq!(
            run(&backend, &keys, &tlvs),
            Err(Error::KeyAlgorithmMismatch)
        );
        let tlvs = [id_tlv(&MLDSA44_PK), sig_tlv(TLV_MLDSA65_SIG)];
        assert_eq!(
            run(&backend, &keys, &tlvs),
            Err(Error::KeyAlgorithmMismatch)
        );
        assert!(backend.calls().is_empty());
    }

    #[test]
    fn backend_rejection_passes_through_as_signature_invalid() {
        let backend = RecordingBackend::returning(Err(Error::SignatureInvalid));
        let tlvs = [id_tlv(&LMS_PK_A), sig_tlv(TLV_LMS_HSS_SIG)];
        assert_eq!(
            run(&backend, &lms_keys(), &tlvs),
            Err(Error::SignatureInvalid)
        );
        assert_eq!(backend.calls().len(), 1);

        let backend = RecordingBackend::returning(Err(Error::UnsupportedParameterSet));
        assert_eq!(
            run(&backend, &lms_keys(), &tlvs),
            Err(Error::UnsupportedParameterSet)
        );
    }

    #[test]
    fn backend_success_returns_the_selected_key() {
        let backend = RecordingBackend::accepting();
        let tlvs = [
            (0x0001, [0u8; 32].to_vec()),
            sig_tlv(TLV_LMS_HSS_SIG),
            id_tlv(&LMS_PK_B),
        ];
        let verified = run(&backend, &lms_keys(), &tlvs).unwrap();
        assert_eq!(verified, key(Algorithm::LmsHss, &LMS_PK_B));
        assert_eq!(
            backend.calls(),
            [Call {
                algorithm: Algorithm::LmsHss,
                public_key: LMS_PK_B.to_vec(),
                message: MSG.to_vec(),
                signature: SIG.to_vec(),
            }]
        );
    }

    #[test]
    fn non_keelsign_tlvs_are_ignored() {
        let backend = RecordingBackend::accepting();
        // MCUboot KEYHASH, SHA256, ED25519, a reserved keelsign ID (0x4BA4), Nordic's
        // vendor IDs 0x00A0 (installer image) and 0x00A1 (PERIPHCONF), which keelsign
        // used before SHA-37, and 0xFFFF around the keelsign TLVs, with junk values.
        let tlvs = [
            (0x0001, [1u8; 32].to_vec()),
            (0x00A0, [5u8; 16].to_vec()),
            (0x0010, [2u8; 32].to_vec()),
            id_tlv(&LMS_PK_A),
            (0x0024, [3u8; 64].to_vec()),
            sig_tlv(TLV_LMS_HSS_SIG),
            (0x4BA4, [4u8; 7].to_vec()),
            (0x00A1, [6u8; 2420].to_vec()),
            (0xFFFF, Vec::new()),
        ];
        assert!(crate::tlv::KEELSIGN_TLV_RANGE.contains(&0x4BA4));
        assert_eq!(
            run(&backend, &lms_keys(), &tlvs),
            Ok(key(Algorithm::LmsHss, &LMS_PK_A))
        );
        assert_eq!(backend.calls().len(), 1);

        let selected = select_pq_signature(tlvs.iter().map(|(t, v)| (*t, v.as_slice()))).unwrap();
        assert_eq!(selected.algorithm, Algorithm::LmsHss);
        assert_eq!(selected.key_id, key_id_of(&LMS_PK_A));
        assert_eq!(selected.signature, SIG);
    }

    #[test]
    fn dispatch_table_routes_every_tlv_id() {
        for &algorithm in Algorithm::ALL {
            let pk = pk_for(algorithm);
            let keys = TrustedKeys::<1>::new(&[key(algorithm, pk)]).unwrap();
            let backend = RecordingBackend::accepting();
            let tlvs = [id_tlv(pk), sig_tlv(algorithm.tlv_type())];
            let result = run(&backend, &keys, &tlvs);
            if algorithm.is_enabled() {
                assert_eq!(result, Ok(key(algorithm, pk)), "{algorithm:?}");
                let calls = backend.calls();
                assert_eq!(calls.len(), 1, "{algorithm:?}");
                assert_eq!(calls[0].algorithm, algorithm);
                assert_eq!(calls[0].public_key, pk);
            } else {
                assert_eq!(
                    result,
                    Err(Error::UnsupportedAlgorithm(algorithm)),
                    "{algorithm:?}"
                );
                assert!(backend.calls().is_empty(), "{algorithm:?}");
            }
        }
        assert!(Algorithm::LmsHss.is_enabled());
        assert_eq!(Algorithm::MlDsa44.is_enabled(), cfg!(feature = "ml-dsa"));
        assert_eq!(Algorithm::MlDsa65.is_enabled(), cfg!(feature = "ml-dsa"));
    }

    #[cfg(not(feature = "ml-dsa"))]
    #[test]
    fn compiled_out_algorithm_is_unsupported_algorithm_and_backend_not_called() {
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65] {
            assert!(!algorithm.is_enabled());
            let pk = pk_for(algorithm);
            let keys = TrustedKeys::<1>::new(&[key(algorithm, pk)]).unwrap();
            let backend = RecordingBackend::accepting();
            let tlvs = [id_tlv(pk), sig_tlv(algorithm.tlv_type())];
            assert_eq!(
                run(&backend, &keys, &tlvs),
                Err(Error::UnsupportedAlgorithm(algorithm))
            );
            assert_eq!(backend.count.get(), 0, "backend must not be called");
        }
    }

    #[cfg(feature = "ml-dsa")]
    #[test]
    fn enabled_algorithm_reaches_backend() {
        for algorithm in [Algorithm::MlDsa44, Algorithm::MlDsa65] {
            assert!(algorithm.is_enabled());
            let pk = pk_for(algorithm);
            let keys = TrustedKeys::<1>::new(&[key(algorithm, pk)]).unwrap();
            let backend = RecordingBackend::returning(Err(Error::SignatureInvalid));
            let tlvs = [id_tlv(pk), sig_tlv(algorithm.tlv_type())];
            assert_eq!(run(&backend, &keys, &tlvs), Err(Error::SignatureInvalid));
            assert_eq!(backend.count.get(), 1);
            assert_eq!(backend.calls()[0].algorithm, algorithm);
        }
    }

    /// (name, TLVs, backend result, expected error).
    type NegativeCase = (&'static str, Vec<(u16, Vec<u8>)>, Result<(), Error>, Error);

    #[test]
    fn every_negative_case_has_its_own_variant() {
        let keys = TrustedKeys::<4>::new(&[
            key(Algorithm::LmsHss, &LMS_PK_A),
            key(Algorithm::MlDsa44, &MLDSA44_PK),
            key(Algorithm::MlDsa65, &MLDSA65_PK),
        ])
        .unwrap();
        let short_id = (TLV_KEELSIGN_KEY_ID, [0u8; KEY_ID_LEN - 1].to_vec());
        let lms_sig = sig_tlv(TLV_LMS_HSS_SIG);

        let mut cases: Vec<NegativeCase> = Vec::from([
            (
                "missing key ID",
                Vec::from([lms_sig.clone()]),
                Ok(()),
                Error::MissingKeyId,
            ),
            (
                "bad key-ID length",
                Vec::from([short_id, lms_sig.clone()]),
                Ok(()),
                Error::InvalidKeyId,
            ),
            (
                "two key IDs",
                Vec::from([id_tlv(&LMS_PK_A), id_tlv(&LMS_PK_A), lms_sig.clone()]),
                Ok(()),
                Error::MultipleKeyIds,
            ),
            (
                "no PQ signature",
                Vec::from([id_tlv(&LMS_PK_A)]),
                Ok(()),
                Error::MissingPqSignature,
            ),
            (
                "two PQ signatures",
                Vec::from([id_tlv(&LMS_PK_A), lms_sig.clone(), lms_sig.clone()]),
                Ok(()),
                Error::MultiplePqSignatures,
            ),
            (
                "unknown key",
                Vec::from([id_tlv(&LMS_PK_B), lms_sig.clone()]),
                Ok(()),
                Error::KeyNotTrusted,
            ),
            (
                "algorithm mismatch",
                Vec::from([id_tlv(&LMS_PK_A), sig_tlv(TLV_MLDSA44_SIG)]),
                Ok(()),
                Error::KeyAlgorithmMismatch,
            ),
            (
                "backend rejects signature",
                Vec::from([id_tlv(&LMS_PK_A), lms_sig.clone()]),
                Err(Error::SignatureInvalid),
                Error::SignatureInvalid,
            ),
            (
                "backend refuses parameter set",
                Vec::from([id_tlv(&LMS_PK_A), lms_sig.clone()]),
                Err(Error::UnsupportedParameterSet),
                Error::UnsupportedParameterSet,
            ),
            (
                "backend finds signature malformed",
                Vec::from([id_tlv(&LMS_PK_A), lms_sig.clone()]),
                Err(Error::MalformedSignature),
                Error::MalformedSignature,
            ),
            (
                "backend finds public key malformed",
                Vec::from([id_tlv(&LMS_PK_A), lms_sig.clone()]),
                Err(Error::InvalidPublicKey),
                Error::InvalidPublicKey,
            ),
        ]);
        // Compiled-out only exists while some algorithm is disabled (`ml-dsa` off).
        if let Some(&disabled) = Algorithm::ALL.iter().find(|a| !a.is_enabled()) {
            cases.push((
                "compiled-out algorithm",
                Vec::from([id_tlv(pk_for(disabled)), sig_tlv(disabled.tlv_type())]),
                Ok(()),
                Error::UnsupportedAlgorithm(disabled),
            ));
        }
        assert_eq!(cases.len(), if cfg!(feature = "ml-dsa") { 11 } else { 12 });

        for (name, tlvs, backend_result, expected) in &cases {
            let backend = RecordingBackend::returning(*backend_result);
            assert_eq!(run(&backend, &keys, tlvs), Err(*expected), "{name}");
        }
        for (i, (name_a, _, _, a)) in cases.iter().enumerate() {
            for (name_b, _, _, b) in &cases[i + 1..] {
                assert_ne!(a, b, "`{name_a}` and `{name_b}` share a variant");
            }
        }
    }

    #[test]
    fn empty_signature_reaches_backend_unchanged() {
        // The dispatcher does not judge the signature bytes; rejecting an empty
        // signature is the backend's job.
        let backend = RecordingBackend::accepting();
        let tlvs = [id_tlv(&LMS_PK_A), (TLV_LMS_HSS_SIG, Vec::new())];
        assert_eq!(
            run(&backend, &lms_keys(), &tlvs),
            Ok(key(Algorithm::LmsHss, &LMS_PK_A))
        );
        let calls = backend.calls();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].signature.is_empty());
        assert_eq!(calls[0].algorithm, Algorithm::LmsHss);
        assert_eq!(calls[0].public_key, LMS_PK_A);
        assert_eq!(calls[0].message, MSG);
    }

    /// Supporting evidence for SHA-171 TP3 only; the end-to-end rotation test with real
    /// signatures through `verify_pq` is
    /// `lms_kat::host_kat::image_signed_with_key_b_verifies_against_a_b_and_fails_against_a`
    /// (SHA-65).
    #[test]
    fn rotation_with_mock_backend_selects_key_b_from_a_b_and_fails_with_a_only() {
        let a = key(Algorithm::LmsHss, &LMS_PK_A);
        let b = key(Algorithm::LmsHss, &LMS_PK_B);
        // An image signed with the new key B.
        let tlvs = [id_tlv(&LMS_PK_B), sig_tlv(TLV_LMS_HSS_SIG)];

        // During rotation the device trusts A and B: B is selected.
        let backend = RecordingBackend::accepting();
        let both = TrustedKeys::<2>::new(&[a, b]).unwrap();
        assert_eq!(run(&backend, &both, &tlvs), Ok(b));
        assert_eq!(backend.calls()[0].public_key, LMS_PK_B);

        // A device that only trusts A rejects it without calling the backend.
        let backend = RecordingBackend::accepting();
        let a_only = TrustedKeys::<2>::new(&[a]).unwrap();
        assert_eq!(run(&backend, &a_only, &tlvs), Err(Error::KeyNotTrusted));
        assert!(backend.calls().is_empty());
    }
}
