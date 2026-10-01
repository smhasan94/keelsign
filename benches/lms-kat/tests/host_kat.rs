//! Host known-answer tests for LMS/HSS verify (SHA-65): RFC 8554 Appendix F, the NIST
//! ACVP LMS sigVer vectors (SHA-256/192), signatures by the independent signer hsslms
//! 0.1.3, derived negatives and the key-rotation check, all through
//! `keelsign_verify::verify_pq` with the default backend (`keelsign_default()`), and every
//! case also under the strict `cnsa_2_0()` device path
//! (`verify_pq_with(&DefaultBackend::cnsa_2_0(), ..)`, SHA-240) and the RFC policy.

// Host test code, not no_std firmware: failing a test with a message is the point.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use keelsign_verify::lms::ParameterPolicy;
use keelsign_verify::{Error, KeySetError, TrustedKeys};
use lms_kat::{
    Case, Expect, Fixture, KeyInfo, LMS_TARGET, Outcome, ParseError, Source, TARGET_CASES,
    check_rotation, ids, run_fixture, verify_case, verify_case_cnsa_2_0, verify_case_rfc_all_sets,
};

const LMS_HOST: &[u8] = include_bytes!("../fixtures/lms-host.bin");

fn cases(bytes: &[u8]) -> Vec<Case<'_>> {
    Fixture::parse(bytes)
        .expect("fixture header")
        .cases()
        .collect::<Result<_, _>>()
        .expect("fixture cases")
}

fn host_case(id: u16) -> Case<'static> {
    Fixture::parse(LMS_HOST)
        .unwrap()
        .case(id)
        .unwrap_or_else(|| panic!("case {id} missing from the host fixture"))
}

/// Asserts all three expectations of `case` and returns the outcome.
fn assert_case(case: &Case<'_>) -> Outcome {
    let outcome = Outcome::run(case);
    assert!(
        outcome.passed(),
        "case {} ({:?}): {outcome:?}",
        case.id,
        case.source
    );
    outcome
}

#[test]
fn rfc8554_test_case_1_verifies_through_verify_pq() {
    let tc1 = host_case(ids::RFC_TC1);
    assert_eq!(tc1.source, Source::Rfc8554);
    assert_eq!(
        KeyInfo::of(tc1.pk),
        Some(KeyInfo {
            levels: 2,
            lms_typecode: 0x05,
            lmots_typecode: 0x04
        })
    );
    assert_eq!(tc1.pk.len(), 60);
    assert_eq!(tc1.sig.len(), 2644);
    assert!(tc1.msg.starts_with(b"The powers not delegated"));
    assert_eq!(verify_case(&tc1), Ok(()));
    assert_eq!(verify_case_rfc_all_sets(&tc1), Ok(()));
    // The same bytes with a different message fail.
    let mut other = tc1;
    other.msg = b"The powers not delegated to the United States";
    assert_eq!(verify_case(&other), Err(Error::SignatureInvalid));
}

#[test]
fn rfc8554_test_case_2_is_unsupported_parameter_set_and_verifies_under_rfc_policy() {
    let tc2 = host_case(ids::RFC_TC2);
    assert_eq!(
        KeyInfo::of(tc2.pk),
        Some(KeyInfo {
            levels: 2,
            lms_typecode: 0x06,
            lmots_typecode: 0x03
        })
    );
    assert!(!ParameterPolicy::keelsign_default().allows(0x06, 0x03));
    assert_eq!(verify_case(&tc2), Err(Error::UnsupportedParameterSet));
    assert_eq!(verify_case_rfc_all_sets(&tc2), Ok(()));
    assert_case(&tc2);
}

#[test]
fn acvp_lms_sigver_m24_16_cases_match_under_rfc_policy_and_are_unsupported_gated() {
    let acvp: Vec<Case<'_>> = cases(LMS_HOST)
        .into_iter()
        .filter(|c| c.source == Source::Acvp)
        .collect();
    assert_eq!(acvp.len(), 16, "2 revisions x 2 groups x 4 cases");
    let mut valid = 0;
    for case in &acvp {
        let info = KeyInfo::of(case.pk).unwrap();
        assert_eq!(info.levels, 1, "ACVP LMS cases are wrapped as HSS L=1");
        assert!(matches!(
            (info.lms_typecode, info.lmots_typecode),
            (0x0A, 0x05) | (0x0B, 0x06)
        ));
        assert_eq!(case.pk.len(), 52);
        assert_eq!(
            verify_case(case),
            Err(Error::UnsupportedParameterSet),
            "tc {}",
            case.id
        );
        let rfc = verify_case_rfc_all_sets(case);
        assert_eq!(rfc, case.expect_rfc_all_sets.result(), "tc {}", case.id);
        assert!(matches!(
            case.expect_rfc_all_sets,
            Expect::Ok | Expect::SignatureInvalid
        ));
        valid += usize::from(rfc.is_ok());
    }
    // One valid case per group.
    assert_eq!(valid, 4);
}

#[test]
fn hsslms_signed_w8_cases_verify_under_keelsign_default() {
    // SHA-256 (M32) and SHA-256/192 (M24), W8, one and two levels, H5 and H10.
    let expected = [
        (ids::M32_H5_L1, 1, 0x05, 0x04, 60, 1296),
        (ids::M32_H5H5_L2, 2, 0x05, 0x04, 60, 2644),
        (ids::M32_H10_L1, 1, 0x06, 0x04, 60, 1456),
        (ids::M32_H5H10_L2, 2, 0x05, 0x04, 60, 2804),
        (ids::M24_H5_L1, 1, 0x0A, 0x08, 52, 784),
        (ids::M24_H5H5_L2, 2, 0x0A, 0x08, 52, 1612),
        (ids::M24_H10_L1, 1, 0x0B, 0x08, 52, 904),
        (ids::ROTATION_A, 1, 0x05, 0x04, 60, 1296),
        (ids::ROTATION_B, 1, 0x05, 0x04, 60, 1296),
    ];
    for (id, levels, lms, ots, pk_len, sig_len) in expected {
        let case = host_case(id);
        assert_eq!(case.source, Source::Hsslms);
        assert_eq!(
            KeyInfo::of(case.pk),
            Some(KeyInfo {
                levels,
                lms_typecode: lms,
                lmots_typecode: ots
            }),
            "{id}"
        );
        assert_eq!((case.pk.len(), case.sig.len()), (pk_len, sig_len), "{id}");
        assert_eq!(case.msg.len(), 32, "{id}");
        assert_eq!(verify_case(&case), Ok(()), "{id}");
        assert_eq!(verify_case_rfc_all_sets(&case), Ok(()), "{id}");
        // Any other message fails.
        let mut other = case;
        let msg = [0u8; 32];
        other.msg = &msg;
        assert_eq!(verify_case(&other), Err(Error::SignatureInvalid), "{id}");
    }
    // Outside the keelsign device policies, but valid RFC 8554 / SP 800-208 signatures.
    for id in [ids::M32_W4, ids::M24_W2, ids::HSS_L3] {
        let case = host_case(id);
        assert_eq!(
            verify_case(&case),
            Err(Error::UnsupportedParameterSet),
            "{id}"
        );
        assert_eq!(verify_case_rfc_all_sets(&case), Ok(()), "{id}");
    }
}

#[test]
fn every_host_case_matches_all_three_expectations() {
    let all = cases(LMS_HOST);
    let failures: Vec<Outcome> = all
        .iter()
        .map(Outcome::run)
        .filter(|o| !o.passed())
        .collect();
    assert!(
        failures.is_empty(),
        "{} of {} cases failed: {failures:?}",
        failures.len(),
        all.len()
    );
    for source in [Source::Rfc8554, Source::Acvp, Source::Hsslms] {
        assert!(all.iter().any(|c| c.source == source), "{source:?}");
    }
    // The strict column follows the script's stated rule: the default expectation for an
    // `L = 1` key, `UnsupportedParameterSet` for every other `L`.
    for case in &all {
        let levels = KeyInfo::of(case.pk).unwrap().levels;
        let rule = if levels == 1 {
            case.expect_default
        } else {
            Expect::UnsupportedParameterSet
        };
        assert_eq!(
            case.expect_cnsa_2_0, rule,
            "case {} (L = {levels})",
            case.id
        );
    }
    // The deviation is exercised: valid two-level cases that only the strict policy
    // refuses, and single-tree cases valid under all three.
    assert!(
        all.iter().any(|c| c.expect_default == Expect::Ok
            && c.expect_cnsa_2_0 == Expect::UnsupportedParameterSet)
    );
    assert!(all.iter().any(|c| c.expect_default == Expect::Ok
        && c.expect_cnsa_2_0 == Expect::Ok
        && c.expect_rfc_all_sets == Expect::Ok));
    let summary = run_fixture(LMS_HOST, |_, _| {}).unwrap();
    assert!(summary.all_passed(), "{summary:?}");
    assert_eq!(summary.total as usize, all.len());
}

#[test]
fn negative_cases_return_their_expected_variant() {
    let all = cases(LMS_HOST);
    // Every error variant the LMS backend can return appears under the default policy.
    for expect in [
        Expect::SignatureInvalid,
        Expect::UnsupportedParameterSet,
        Expect::MalformedSignature,
    ] {
        let matching: Vec<&Case<'_>> = all.iter().filter(|c| c.expect_default == expect).collect();
        assert!(!matching.is_empty(), "no {expect:?} case");
        for case in matching {
            assert_eq!(verify_case(case), expect.result(), "case {}", case.id);
        }
    }
    // A public key of the wrong length never reaches the backend on the device path:
    // the key set refuses it.
    let tc1 = host_case(ids::RFC_TC1);
    assert_eq!(
        TrustedKeys::<2>::new(&[keelsign_verify::TrustedKey {
            algorithm: keelsign_verify::Algorithm::LmsHss,
            public_key: &tc1.pk[..59],
        }])
        .unwrap_err(),
        KeySetError::InvalidPublicKeyLength(keelsign_verify::Algorithm::LmsHss)
    );
    let mut short_key = tc1;
    short_key.pk = &tc1.pk[..59];
    assert_eq!(verify_case(&short_key), Err(Error::InvalidPublicKey));
    // Directly, the backend reports it as InvalidPublicKey too.
    assert_eq!(
        verify_case_rfc_all_sets(&short_key),
        Err(Error::InvalidPublicKey)
    );
    // Trailing byte and patched L.
    let trailing = host_case(ids::TC1_TRAILING_BYTE);
    assert_eq!(verify_case(&trailing), Err(Error::MalformedSignature));
    let l3 = host_case(ids::TC1_KEY_L3);
    assert_eq!(verify_case(&l3), Err(Error::UnsupportedParameterSet));
    assert_eq!(
        verify_case_cnsa_2_0(&l3),
        Err(Error::UnsupportedParameterSet)
    );
    assert_eq!(
        verify_case_rfc_all_sets(&l3),
        Err(Error::MalformedSignature)
    );
    // Every case derived from TC1 (401-406, 5xx) is under TC1's L = 2 key, so the strict
    // policy refuses it before reading the signature, whatever the default result is.
    let derived: Vec<&Case<'_>> = all
        .iter()
        .filter(|c| c.source == Source::Rfc8554 && c.id > ids::RFC_TC2)
        .collect();
    assert_eq!(derived.len(), 6 + tc1.sig.len().div_ceil(97));
    for case in derived {
        assert_eq!(
            case.expect_cnsa_2_0,
            Expect::UnsupportedParameterSet,
            "{}",
            case.id
        );
        assert_eq!(
            verify_case_cnsa_2_0(case),
            Err(Error::UnsupportedParameterSet),
            "{}",
            case.id
        );
    }
}

#[test]
fn tampered_signature_is_signature_invalid() {
    for id in [ids::TC1_LAST_BYTE_FLIPPED, ids::TC1_C_FLIPPED] {
        let case = host_case(id);
        assert_eq!(case.sig.len(), 2644);
        assert_eq!(verify_case(&case), Err(Error::SignatureInvalid), "{id}");
        assert_case(&case);
    }
}

#[test]
fn wrong_leaf_index_is_signature_invalid() {
    // The bottom-level q (the leaf of the tree that signs the message).
    let case = host_case(ids::TC1_BOTTOM_Q_FLIPPED);
    let tc1 = host_case(ids::RFC_TC1);
    let bottom = 4 + 1292 + 56;
    assert_ne!(case.sig[bottom..bottom + 4], tc1.sig[bottom..bottom + 4]);
    assert_eq!(verify_case(&case), Err(Error::SignatureInvalid));
    assert_case(&case);
}

#[test]
fn wrong_tree_index_is_signature_invalid() {
    // The top-level q (which bottom-level tree the top tree signed).
    let case = host_case(ids::TC1_TOP_Q_FLIPPED);
    let tc1 = host_case(ids::RFC_TC1);
    assert_ne!(case.sig[4..8], tc1.sig[4..8]);
    assert_eq!(verify_case(&case), Err(Error::SignatureInvalid));
    assert_case(&case);
}

#[test]
fn q_equal_to_two_pow_h_is_signature_invalid() {
    // RFC 8554 Algorithm 6a step 2i: q must be below 2^h. The bottom tree of hsslms case
    // 302 is M32_H5, so q = 32 is the first out-of-range leaf index.
    let case = host_case(ids::M32_H5H5_L2_Q_TWO_POW_H);
    let base = host_case(ids::M32_H5H5_L2);
    let bottom = 4 + 1292 + 56;
    assert_eq!(case.source, Source::Hsslms);
    assert_eq!(case.pk, base.pk);
    assert_eq!(case.sig.len(), base.sig.len());
    assert_eq!(case.sig[bottom..bottom + 4], 32u32.to_be_bytes());
    assert_eq!(case.sig[..bottom], base.sig[..bottom]);
    assert_eq!(case.sig[bottom + 4..], base.sig[bottom + 4..]);
    assert_eq!(verify_case(&case), Err(Error::SignatureInvalid));
    assert_eq!(
        verify_case_rfc_all_sets(&case),
        Err(Error::SignatureInvalid)
    );
    assert_case(&case);
    // Also on the target fixture.
    let target = Fixture::parse(LMS_TARGET).unwrap();
    assert_eq!(target.case(ids::M32_H5H5_L2_Q_TWO_POW_H), Some(case));
}

#[test]
fn lm_ots_typecode_mismatch_in_signature_is_rejected() {
    // RFC 8554 Algorithm 6a step 2c: the LM-OTS typecode inside the signature must be the
    // public key's. Only the bottom-level signature's typecode differs from hsslms case
    // 302 (N32_W8 -> N24_W8, a valid W8 code of the other hash size); every length is
    // taken from the public key and the parameter gate covers public keys only, so the
    // case reaches the typecode check. The typecode bytes are not hashed, so it is that
    // check alone that rejects it.
    let case = host_case(ids::M32_H5H5_L2_LMOTS_TYPECODE_MISMATCH);
    let base = host_case(ids::M32_H5H5_L2);
    let ots = 4 + 1292 + 56 + 4;
    assert_eq!(case.source, Source::Hsslms);
    assert_eq!(case.pk, base.pk);
    assert_eq!(case.sig.len(), base.sig.len());
    assert_eq!(base.sig[ots..ots + 4], 0x04u32.to_be_bytes());
    assert_eq!(case.sig[ots..ots + 4], 0x08u32.to_be_bytes());
    assert_eq!(case.sig[..ots], base.sig[..ots]);
    assert_eq!(case.sig[ots + 4..], base.sig[ots + 4..]);
    assert!(ParameterPolicy::keelsign_default().allows(0x05, 0x04));
    assert_eq!(verify_case(&case), Err(Error::SignatureInvalid));
    assert_eq!(
        verify_case_rfc_all_sets(&case),
        Err(Error::SignatureInvalid)
    );
    assert_case(&case);
    // Also on the target fixture.
    let target = Fixture::parse(LMS_TARGET).unwrap();
    assert_eq!(
        target.case(ids::M32_H5H5_L2_LMOTS_TYPECODE_MISMATCH),
        Some(case)
    );
}

#[test]
fn truncated_signature_is_malformed_signature() {
    let truncated: Vec<Case<'_>> = cases(LMS_HOST)
        .into_iter()
        .filter(|c| c.id >= ids::TC1_TRUNCATED)
        .collect();
    let tc1 = host_case(ids::RFC_TC1);
    assert_eq!(truncated.len(), tc1.sig.len().div_ceil(97));
    for (k, case) in truncated.iter().enumerate() {
        assert_eq!(case.sig.len(), 97 * k);
        assert_eq!(case.sig, &tc1.sig[..97 * k]);
        assert_eq!(
            verify_case(case),
            Err(Error::MalformedSignature),
            "{}",
            case.id
        );
        assert_eq!(
            verify_case_rfc_all_sets(case),
            Err(Error::MalformedSignature),
            "{}",
            case.id
        );
    }
}

#[test]
fn two_level_cases_are_unsupported_under_cnsa_2_0_and_single_tree_cases_match_default() {
    // Every case whose key has L != 1 is refused by the strict device path, valid or not
    // under the default (1, 302, 304, 312 are valid two-level signatures).
    for id in [
        ids::RFC_TC1,
        ids::M32_H5H5_L2,
        ids::M32_H5H10_L2,
        ids::M24_H5H5_L2,
        ids::RFC_TC2,
        ids::HSS_L3,
        ids::TC1_KEY_L3,
        ids::M32_H5H5_L2_Q_TWO_POW_H,
        ids::M32_H5H5_L2_LMOTS_TYPECODE_MISMATCH,
    ] {
        let case = host_case(id);
        assert_ne!(KeyInfo::of(case.pk).unwrap().levels, 1, "{id}");
        assert_eq!(
            verify_case_cnsa_2_0(&case),
            Err(Error::UnsupportedParameterSet),
            "{id}"
        );
        assert_eq!(
            case.expect_cnsa_2_0,
            Expect::UnsupportedParameterSet,
            "{id}"
        );
    }
    for id in [
        ids::RFC_TC1,
        ids::M32_H5H5_L2,
        ids::M32_H5H10_L2,
        ids::M24_H5H5_L2,
    ] {
        assert_eq!(verify_case(&host_case(id)), Ok(()), "{id}");
    }
    // Single trees (L = 1), W8, both hash sizes and both heights: the strict result is the
    // default one, Ok.
    for id in [
        ids::M32_H5_L1,
        ids::M32_H10_L1,
        ids::M24_H5_L1,
        ids::M24_H10_L1,
        ids::ROTATION_A,
        ids::ROTATION_B,
    ] {
        let case = host_case(id);
        assert_eq!(KeyInfo::of(case.pk).unwrap().levels, 1, "{id}");
        assert_eq!(verify_case_cnsa_2_0(&case), Ok(()), "{id}");
        assert_eq!(verify_case_cnsa_2_0(&case), verify_case(&case), "{id}");
        let mut other = case;
        let msg = [0u8; 32];
        other.msg = &msg;
        assert_eq!(
            verify_case_cnsa_2_0(&other),
            Err(Error::SignatureInvalid),
            "{id}"
        );
    }
    assert!(host_case(ids::M24_H5_L1).pk.len() == 52 && host_case(ids::M32_H5_L1).pk.len() == 60);
}

#[test]
fn hss_three_levels_is_unsupported_parameter_set() {
    let l3 = host_case(ids::HSS_L3);
    assert_eq!(KeyInfo::of(l3.pk).unwrap().levels, 3);
    assert_eq!(verify_case(&l3), Err(Error::UnsupportedParameterSet));
    // A genuine three-level signature: it verifies once three levels are allowed.
    assert_eq!(verify_case_rfc_all_sets(&l3), Ok(()));
    let patched = host_case(ids::TC1_KEY_L3);
    assert_eq!(KeyInfo::of(patched.pk).unwrap().levels, 3);
    assert_eq!(verify_case(&patched), Err(Error::UnsupportedParameterSet));
}

#[test]
fn image_signed_with_key_b_verifies_against_a_b_and_fails_against_a() {
    let a = host_case(ids::ROTATION_A);
    let b = host_case(ids::ROTATION_B);
    assert_eq!(check_rotation(&a, &b), Ok(()));
    // The on-target fixture holds the same pair.
    let target = Fixture::parse(LMS_TARGET).unwrap();
    assert_eq!(target.case(ids::ROTATION_A), Some(a));
    assert_eq!(target.case(ids::ROTATION_B), Some(b));
    // The check itself rejects a non-rotation pair.
    assert!(check_rotation(&a, &a).is_err());
}

#[test]
fn target_subset_is_subset_of_host_set() {
    let host = cases(LMS_HOST);
    let target = cases(LMS_TARGET);
    assert_eq!(target.len() as u32, TARGET_CASES);
    for case in &target {
        assert!(
            host.contains(case),
            "target case {} is not in the host set",
            case.id
        );
    }
    let target_ids: Vec<u16> = target.iter().map(|c| c.id).collect();
    for id in [
        ids::RFC_TC1,
        ids::RFC_TC2,
        ids::M32_H5H5_L2,
        ids::M24_H5_L1,
        ids::M24_H5H5_L2,
        ids::ROTATION_A,
        ids::ROTATION_B,
        ids::M32_W4,
        ids::HSS_L3,
        ids::TC1_LAST_BYTE_FLIPPED,
        ids::M32_H5H5_L2_Q_TWO_POW_H,
        ids::M32_H5H5_L2_LMOTS_TYPECODE_MISMATCH,
    ] {
        assert!(
            target_ids.contains(&id),
            "target fixture must hold case {id}"
        );
    }
    assert!(target.iter().any(|c| c.source == Source::Acvp));
    // The on-target run checks the strict policy on both sides: single trees it accepts
    // and valid two-level cases it refuses.
    for id in [ids::M24_H5_L1, ids::ROTATION_A, ids::ROTATION_B] {
        let case = target.iter().find(|c| c.id == id).unwrap();
        assert_eq!(case.expect_cnsa_2_0, Expect::Ok, "{id}");
    }
    for id in [ids::RFC_TC1, ids::M32_H5H5_L2, ids::M24_H5H5_L2] {
        let case = target.iter().find(|c| c.id == id).unwrap();
        assert_eq!(case.expect_default, Expect::Ok, "{id}");
        assert_eq!(
            case.expect_cnsa_2_0,
            Expect::UnsupportedParameterSet,
            "{id}"
        );
    }
    for case in &target {
        let outcome = Outcome::run(case);
        assert_eq!(outcome.default, case.expect_default.result(), "{}", case.id);
        assert_eq!(
            outcome.cnsa_2_0,
            case.expect_cnsa_2_0.result(),
            "{}",
            case.id
        );
        assert_eq!(
            outcome.rfc_all_sets,
            case.expect_rfc_all_sets.result(),
            "{}",
            case.id
        );
    }
    let summary = run_fixture(LMS_TARGET, |_, _| {}).unwrap();
    assert!(summary.all_passed(), "{summary:?}");
    assert_eq!(summary.total, TARGET_CASES);
}

#[test]
fn parser_rejects_truncated_input() {
    let bytes = LMS_TARGET;
    let first = Fixture::parse(bytes)
        .unwrap()
        .cases()
        .next()
        .unwrap()
        .unwrap();
    // Per-case header: id (2), source (1), three expectations (3), three lengths (6).
    let first_end = 8 + 12 + first.pk.len() + first.sig.len() + first.msg.len();
    for cut in 0..8 {
        assert_eq!(
            Fixture::parse(&bytes[..cut]).unwrap_err(),
            ParseError::Truncated
        );
    }
    for cut in (8..first_end).step_by(97).chain([first_end - 1]) {
        let results: Vec<_> = Fixture::parse(&bytes[..cut]).unwrap().cases().collect();
        assert_eq!(results, [Err(ParseError::Truncated)], "cut at {cut}");
    }
    let mut bad = bytes.to_vec();
    bad[0] ^= 0xff;
    assert_eq!(Fixture::parse(&bad).unwrap_err(), ParseError::BadMagic);
    // Version 1 (two expectations) and any later version are refused.
    for version in [1u8, 3] {
        let mut bad = bytes.to_vec();
        bad[4] = version;
        assert_eq!(
            Fixture::parse(&bad).unwrap_err(),
            ParseError::UnsupportedVersion(u16::from(version))
        );
    }
    let mut bad = bytes.to_vec();
    bad[8 + 2] = 9;
    assert_eq!(
        Fixture::parse(&bad).unwrap().cases().next(),
        Some(Err(ParseError::UnknownSource(9)))
    );
    // Each of the three expectation bytes (default, cnsa_2_0, rfc_all_sets).
    for (at, code) in [(8 + 3, 5u8), (8 + 4, 6), (8 + 5, 0xff)] {
        let mut bad = bytes.to_vec();
        bad[at] = code;
        assert_eq!(
            Fixture::parse(&bad).unwrap().cases().next(),
            Some(Err(ParseError::BadExpectation(code))),
            "byte {at}"
        );
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(
        Fixture::parse(&trailing).unwrap().cases().last(),
        Some(Err(ParseError::TrailingBytes))
    );
}
