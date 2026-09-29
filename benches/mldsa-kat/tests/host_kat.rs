//! Host known-answer tests for ML-DSA-44/65 verify (SHA-34): NIST ACVP sigVer
//! (external interface, pure) and the full Wycheproof verify sets, including the
//! regression cases for the ml-dsa advisories pinned in CLAUDE.md.

// Host test code, not no_std firmware: failing a test with a message is the point.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use mldsa_kat::{
    Case, Fixture, MLDSA44_TARGET, MLDSA65_TARGET, Outcome, ParamSet, ParseError, Source,
    run_fixture, verify_for,
};

const MLDSA44_HOST: &[u8] = include_bytes!("../fixtures/mldsa44-host.bin");
const MLDSA65_HOST: &[u8] = include_bytes!("../fixtures/mldsa65-host.bin");

fn cases(bytes: &[u8]) -> Vec<Case<'_>> {
    Fixture::parse(bytes)
        .expect("fixture header")
        .cases()
        .collect::<Result<_, _>>()
        .expect("fixture cases")
}

/// Runs every case from `source` and asserts that each matches its expectation.
/// Returns the cases that ran.
fn run_source(bytes: &[u8], param_set: ParamSet, source: Source) -> Vec<Case<'_>> {
    let fixture = Fixture::parse(bytes).expect("fixture header");
    assert_eq!(fixture.param_set, param_set);
    let selected: Vec<Case<'_>> = cases(bytes)
        .into_iter()
        .filter(|c| c.source == source)
        .collect();
    let failures: Vec<Outcome> = selected
        .iter()
        .map(|c| Outcome::new(c, verify_for(param_set, c)))
        .filter(|o| !o.passed())
        .collect();
    assert!(
        failures.is_empty(),
        "ML-DSA-{} {}: {} of {} cases failed: {failures:?}",
        param_set.number(),
        source.name(),
        failures.len(),
        selected.len()
    );
    selected
}

fn acvp_sigver(bytes: &[u8], param_set: ParamSet) {
    let ran = run_source(bytes, param_set, Source::Acvp);
    assert_eq!(ran.len(), 15, "ACVP external/pure group has 15 cases");
    assert!(
        ran.iter().any(|c| c.expect_valid),
        "ACVP set has valid cases"
    );
    assert!(
        ran.iter().any(|c| !c.expect_valid),
        "ACVP set has invalid cases"
    );
}

fn wycheproof(bytes: &[u8], param_set: ParamSet, count: usize, pk_len: usize, sig_len: usize) {
    let ran = run_source(bytes, param_set, Source::Wycheproof);
    assert_eq!(ran.len(), count, "Wycheproof case count");
    // The malformed-input cases go through the length / decode / context checks of
    // `verify_case` and must come out invalid; `run_source` already checked that.
    let wrong_pk = ran.iter().filter(|c| c.pk.len() != pk_len).count();
    let wrong_sig = ran.iter().filter(|c| c.sig.len() != sig_len).count();
    let long_ctx = ran.iter().filter(|c| c.ctx.len() > 255).count();
    assert!(wrong_pk > 0, "Wycheproof has wrong-length public keys");
    assert!(wrong_sig > 0, "Wycheproof has wrong-length signatures");
    assert!(
        long_ctx > 0,
        "Wycheproof has contexts longer than 255 bytes"
    );
    for c in ran
        .iter()
        .filter(|c| c.pk.len() != pk_len || c.sig.len() != sig_len || c.ctx.len() > 255)
    {
        assert!(
            !c.expect_valid,
            "tcId {} is malformed but expected valid",
            c.tc_id
        );
    }
}

/// Wycheproof tcIds (expected validity) that regress the advisories fixed in the ml-dsa
/// pin: a repeated hint index (CVE-2026-24850 / GHSA-5x2r-hc65-25f9) and
/// `use_hint(1, 0)` (GHSA-h37v-hp6w-2pp8).
fn advisory_regressions(host: &[u8], target: &[u8], param_set: ParamSet, ids: [(u32, bool); 3]) {
    let host_cases = cases(host);
    let target_cases = cases(target);
    for (tc_id, valid) in ids {
        let case = host_cases
            .iter()
            .find(|c| c.source == Source::Wycheproof && c.tc_id == tc_id)
            .unwrap_or_else(|| panic!("Wycheproof tcId {tc_id} missing from the host fixture"));
        assert_eq!(case.expect_valid, valid, "tcId {tc_id} expectation");
        assert_eq!(
            verify_for(param_set, case),
            valid,
            "ML-DSA-{} Wycheproof tcId {tc_id}: advisory regression",
            param_set.number()
        );
        assert!(
            target_cases.contains(case),
            "advisory tcId {tc_id} must also be in the on-target fixture"
        );
    }
}

#[test]
fn acvp_sigver_mldsa44() {
    acvp_sigver(MLDSA44_HOST, ParamSet::MlDsa44);
}

#[test]
fn acvp_sigver_mldsa65() {
    acvp_sigver(MLDSA65_HOST, ParamSet::MlDsa65);
}

#[test]
fn wycheproof_mldsa44() {
    wycheproof(MLDSA44_HOST, ParamSet::MlDsa44, 180, 1312, 2420);
}

#[test]
fn wycheproof_mldsa65() {
    wycheproof(MLDSA65_HOST, ParamSet::MlDsa65, 210, 1952, 3309);
}

#[test]
fn advisory_regressions_mldsa44() {
    advisory_regressions(
        MLDSA44_HOST,
        MLDSA44_TARGET,
        ParamSet::MlDsa44,
        [(18, false), (147, true), (148, false)],
    );
}

#[test]
fn advisory_regressions_mldsa65() {
    advisory_regressions(
        MLDSA65_HOST,
        MLDSA65_TARGET,
        ParamSet::MlDsa65,
        [(19, false), (161, true), (162, false)],
    );
}

#[test]
fn target_subset_is_subset_of_host_set() {
    for (host, target, param_set) in [
        (MLDSA44_HOST, MLDSA44_TARGET, ParamSet::MlDsa44),
        (MLDSA65_HOST, MLDSA65_TARGET, ParamSet::MlDsa65),
    ] {
        let host_cases = cases(host);
        let target_cases = cases(target);
        assert!(!target_cases.is_empty(), "target fixture is empty");
        assert!(target_cases.iter().any(|c| c.expect_valid));
        assert!(target_cases.iter().any(|c| !c.expect_valid));
        for case in &target_cases {
            assert!(
                host_cases.contains(case),
                "ML-DSA-{} target case {} tcId {} is not in the host set",
                param_set.number(),
                case.source.name(),
                case.tc_id
            );
        }
        // The same runner the boards use accepts the whole target fixture.
        let summary = run_fixture(target, param_set, |_, _| {}).expect("target fixture parses");
        assert!(summary.all_passed(), "target fixture: {summary:?}");
        assert_eq!(summary.total as usize, target_cases.len());
    }
}

#[test]
fn parser_rejects_truncated_input() {
    let bytes = MLDSA44_TARGET;
    let first_case_end = {
        let fixture = Fixture::parse(bytes).unwrap();
        let first = fixture.cases().next().unwrap().unwrap();
        8 + 16 + first.ctx.len() + first.msg.len() + first.pk.len() + first.sig.len()
    };

    // Every cut inside the header is rejected.
    for cut in 0..8 {
        assert_eq!(
            Fixture::parse(&bytes[..cut]).unwrap_err(),
            ParseError::Truncated
        );
    }
    // Every cut inside the first case ends the iteration with `Truncated`.
    for cut in (8..first_case_end).step_by(97).chain([first_case_end - 1]) {
        let fixture = Fixture::parse(&bytes[..cut]).unwrap();
        let results: Vec<_> = fixture.cases().collect();
        assert_eq!(results.len(), 1, "cut at {cut}");
        assert_eq!(results[0], Err(ParseError::Truncated), "cut at {cut}");
    }
    // A cut at the end of a later case stops at that point with `Truncated`, not a panic.
    let cut = bytes.len() - 1;
    let last = Fixture::parse(&bytes[..cut])
        .unwrap()
        .cases()
        .last()
        .unwrap();
    assert_eq!(last, Err(ParseError::Truncated));

    // Header corruption.
    let mut bad_magic = bytes.to_vec();
    bad_magic[0] ^= 0xff;
    assert_eq!(
        Fixture::parse(&bad_magic).unwrap_err(),
        ParseError::BadMagic
    );
    let mut bad_set = bytes.to_vec();
    bad_set[4] = 87;
    assert_eq!(
        Fixture::parse(&bad_set).unwrap_err(),
        ParseError::UnknownParamSet(87)
    );
    let mut bad_source = bytes.to_vec();
    bad_source[8 + 4] = 7;
    assert_eq!(
        Fixture::parse(&bad_source).unwrap().cases().next(),
        Some(Err(ParseError::UnknownSource(7)))
    );
    let mut bad_expect = bytes.to_vec();
    bad_expect[8 + 5] = 2;
    assert_eq!(
        Fixture::parse(&bad_expect).unwrap().cases().next(),
        Some(Err(ParseError::BadExpectation(2)))
    );
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert_eq!(
        Fixture::parse(&trailing).unwrap().cases().last(),
        Some(Err(ParseError::TrailingBytes))
    );
    // A fixture for the other parameter set is refused by the runner.
    assert_eq!(
        run_fixture(bytes, ParamSet::MlDsa65, |_, _| {}).unwrap_err(),
        ParseError::WrongParamSet(ParamSet::MlDsa44)
    );
}
