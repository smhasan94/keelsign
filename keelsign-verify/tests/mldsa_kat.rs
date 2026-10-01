//! NIST known-answer tests through the ML-DSA code that ships (SHA-44, test plan TP4).
//!
//! SHA-34's script-generated host fixtures (`benches/mldsa-kat/fixtures/mldsa{44,65}-host.bin`,
//! from `scripts/gen_mldsa_vectors.py`: NIST ACVP-Server `v1.1.0.43` ML-DSA sigVer, pure,
//! external interface, 15 + 15 cases, and the full Wycheproof verify sets, 180 + 210 cases,
//! including the regressions for the advisories fixed in the `ml-dsa` pin) run through
//! [`keelsign_verify::mldsa::verify_with_context`]. Each case must match its expectation,
//! give the exact [`Error`] variant where the cause is known from the case's shape, and
//! agree with `mldsa_kat::verify_for` (the `ml-dsa` crate called directly).
#![cfg(feature = "ml-dsa")]
// Host test code, not no_std firmware: failing a test with a message is the point.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use keelsign_verify::{Algorithm, Error, mldsa};
use mldsa_kat::{Case, Fixture, ParamSet, Source, verify_for};

fn read(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../benches/mldsa-kat/fixtures")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Runs every case from `source` in `file` through `keelsign_verify::mldsa` and returns
/// how many ran.
fn run(file: &str, param_set: ParamSet, source: Source) -> usize {
    let bytes = read(file);
    let fixture = Fixture::parse(&bytes).expect("fixture header");
    assert_eq!(fixture.param_set, param_set, "{file}");
    let (algorithm, pk_len, sig_len) = match param_set {
        ParamSet::MlDsa44 => (Algorithm::MlDsa44, 1312, 2420),
        ParamSet::MlDsa65 => (Algorithm::MlDsa65, 1952, 3309),
    };
    let cases: Vec<Case<'_>> = fixture
        .cases()
        .collect::<Result<Vec<_>, _>>()
        .expect("fixture cases")
        .into_iter()
        .filter(|c| c.source == source)
        .collect();
    let mut failures = Vec::new();
    let (mut wrong_pk, mut wrong_sig, mut long_ctx, mut valid, mut invalid) = (0, 0, 0, 0, 0);
    for c in &cases {
        let got = mldsa::verify_with_context(algorithm, c.pk, c.msg, c.ctx, c.sig);
        // The same verdict as ml-dsa called directly.
        if got.is_ok() != verify_for(param_set, c) {
            failures.push(format!(
                "tcId {}: keelsign {got:?} vs ml-dsa {}",
                c.tc_id,
                verify_for(param_set, c)
            ));
        }
        // The expectation.
        if got.is_ok() != c.expect_valid {
            failures.push(format!(
                "tcId {}: got {got:?}, expected valid={}",
                c.tc_id, c.expect_valid
            ));
        }
        // The exact variant where the cause is known from the case's shape (checked in
        // this order by `mldsa::verify_param`).
        let want = if c.pk.len() != pk_len {
            wrong_pk += 1;
            Some(Error::InvalidPublicKey)
        } else if c.sig.len() != sig_len {
            wrong_sig += 1;
            Some(Error::MalformedSignature)
        } else if c.ctx.len() > 255 {
            long_ctx += 1;
            // Only when the signature decodes; a malformed one is MalformedSignature.
            (got != Err(Error::MalformedSignature)).then_some(Error::SignatureInvalid)
        } else {
            None
        };
        if let Some(want) = want
            && got != Err(want)
        {
            failures.push(format!("tcId {}: got {got:?}, want {want:?}", c.tc_id));
        }
        // Every failure is one of the three ML-DSA variants.
        if let Err(e) = got
            && !matches!(
                e,
                Error::InvalidPublicKey | Error::MalformedSignature | Error::SignatureInvalid
            )
        {
            failures.push(format!("tcId {}: unexpected variant {e:?}", c.tc_id));
        }
        if c.expect_valid {
            valid += 1;
        } else {
            invalid += 1;
        }
    }
    assert!(
        failures.is_empty(),
        "ML-DSA-{} {} through keelsign_verify::mldsa: {} problems:\n{}",
        param_set.number(),
        source.name(),
        failures.len(),
        failures.join("\n")
    );
    assert!(
        valid > 0 && invalid > 0,
        "{file} {}: valid and invalid cases",
        source.name()
    );
    if source == Source::Wycheproof {
        assert!(wrong_pk > 0, "Wycheproof has wrong-length public keys");
        assert!(wrong_sig > 0, "Wycheproof has wrong-length signatures");
        assert!(
            long_ctx > 0,
            "Wycheproof has contexts longer than 255 bytes"
        );
    }
    cases.len()
}

#[test]
fn acvp_sigver_mldsa44_through_keelsign_verify() {
    assert_eq!(run("mldsa44-host.bin", ParamSet::MlDsa44, Source::Acvp), 15);
}

#[test]
fn acvp_sigver_mldsa65_through_keelsign_verify() {
    assert_eq!(run("mldsa65-host.bin", ParamSet::MlDsa65, Source::Acvp), 15);
}

#[test]
fn wycheproof_mldsa44_through_keelsign_verify() {
    assert_eq!(
        run("mldsa44-host.bin", ParamSet::MlDsa44, Source::Wycheproof),
        180
    );
}

#[test]
fn wycheproof_mldsa65_through_keelsign_verify() {
    assert_eq!(
        run("mldsa65-host.bin", ParamSet::MlDsa65, Source::Wycheproof),
        210
    );
}
