//! Host run of the SHA-46 policy matrix: `policy-matrix.bin` against MANIFEST.json, and
//! every cell through `keelsign_verify::verify_with` (the same runner the boards use).

// Host test code, not no_std firmware: failing a test with a message is the point.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing
)]

use std::fs;
use std::path::PathBuf;

use keelsign_verify::{Algorithm, DefaultBackend, Policy};
use policy_kat::{
    Case, ED25519_TEST_KEY, Expect, Fixture, IMAGES, InMemory, POLICY_TARGET, ParseError,
    TARGET_CASES, policy_name, run_fixture,
};

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/images")
}

fn manifest() -> String {
    fs::read_to_string(fixture_dir().join("MANIFEST.json")).unwrap()
}

/// The text of the JSON object stored under `"key": {` (brace-matched).
fn object<'a>(json: &'a str, key: &str) -> &'a str {
    let start = json
        .find(&format!("\"{key}\": {{"))
        .unwrap_or_else(|| panic!("no object `{key}`"));
    let body = &json[start..];
    let open = body.find('{').unwrap();
    let mut depth = 0;
    for (i, c) in body[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[open..=open + i];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated `{key}`");
}

fn field(object: &str, name: &str) -> Option<String> {
    let needle = format!("\"{name}\": ");
    let start = object.find(&needle)? + needle.len();
    let rest = &object[start..];
    let end = rest.find([',', '\n']).unwrap_or(rest.len());
    Some(rest[..end].trim().trim_matches('"').to_owned())
}

/// The names of the outputs MANIFEST.json marks `in_policy_matrix_bin`, sorted.
fn indexed_outputs(manifest: &str) -> Vec<String> {
    let outputs = object(manifest, "outputs");
    let mut names: Vec<String> = outputs
        .lines()
        .filter_map(|l| {
            l.strip_prefix("    \"")?
                .strip_suffix("\": {")
                .map(str::to_owned)
        })
        .filter(|name| {
            field(object(outputs, name), "in_policy_matrix_bin").as_deref() == Some("true")
        })
        .collect();
    names.sort();
    names
}

fn cases() -> Vec<Case<'static>> {
    Fixture::parse(POLICY_TARGET)
        .unwrap()
        .cases()
        .collect::<Result<_, _>>()
        .unwrap()
}

#[test]
fn index_matches_manifest_and_every_case_passes() {
    let manifest = manifest();
    let outputs = object(&manifest, "outputs");
    let cases = cases();
    assert_eq!(cases.len() as u32, TARGET_CASES);
    // The index is exactly the in_policy_matrix_bin outputs, in name order.
    let names: Vec<&str> = cases.iter().map(|c| c.name).collect();
    assert_eq!(names, indexed_outputs(&manifest));
    // Each case's key and cells are the manifest's.
    for case in &cases {
        let entry = object(outputs, case.name);
        let algorithm = field(entry, "algorithm").map(|a| match a.as_str() {
            "LmsHss" => Algorithm::LmsHss,
            "MlDsa44" => Algorithm::MlDsa44,
            "MlDsa65" => Algorithm::MlDsa65,
            other => panic!("{other}"),
        });
        assert_eq!(case.algorithm, algorithm, "{}", case.name);
        let pk: String = case.public_key.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            pk,
            field(entry, "public_key_hex").unwrap_or_default(),
            "{}",
            case.name
        );
        let policy = object(entry, "policy");
        for (&p, key) in Policy::ALL
            .iter()
            .zip(["classical_only", "pq_only", "hybrid"])
        {
            assert_eq!(
                case.expect(p).unwrap().name(),
                field(policy, key).unwrap(),
                "{} {key}",
                case.name
            );
        }
        // Each case's image is embedded once, and is the committed file.
        let data = policy_kat::image(case.name).unwrap();
        assert_eq!(data, fs::read(fixture_dir().join(case.name)).unwrap());
    }
    assert_eq!(IMAGES.len(), cases.len());
    // The Ed25519 test key is the SubjectPublicKeyInfo's last 32 bytes.
    let spki = fs::read(fixture_dir().join("keys/ed25519-test-key.spki.der")).unwrap();
    assert_eq!(spki.len(), 44);
    assert_eq!(ED25519_TEST_KEY, spki[12..]);
    // The codes are the script's POLICY_CODES, in order.
    let codes = object(object(&manifest, "policy_matrix"), "codes");
    for (i, e) in Expect::ALL.iter().enumerate() {
        assert_eq!(field(codes, &i.to_string()).unwrap(), e.name(), "code {i}");
        assert_eq!(Expect::from_code(i as u8), Some(*e));
    }
    assert_eq!(Expect::from_code(Expect::ALL.len() as u8), None);

    // Every cell passes through the runner, as on the boards.
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; 256];
    let mut failures = Vec::new();
    let summary = run_fixture(
        POLICY_TARGET,
        &DefaultBackend::new(),
        &mut InMemory,
        &mut tlv_buf,
        &mut chunk,
        |case, outcome| {
            if !outcome.passed() {
                failures.push(format!(
                    "{} {}: expect {} got {}",
                    case.name,
                    policy_name(outcome.policy),
                    outcome.expect.name(),
                    outcome.got_name()
                ));
            }
        },
    )
    .unwrap();
    assert!(failures.is_empty(), "{failures:#?}");
    assert_eq!(summary.total, TARGET_CASES * Policy::ALL.len() as u32);
    assert!(summary.all_passed());
}

#[test]
fn parser_rejects_truncated_input_and_unknown_codes() {
    // Every truncation is an error, never a panic, and never a full set of cases.
    for cut in 0..POLICY_TARGET.len() {
        let bytes = &POLICY_TARGET[..cut];
        let result = Fixture::parse(bytes).map(|f| f.cases().collect::<Result<Vec<_>, _>>());
        match result {
            Err(e) => assert!(
                matches!(e, ParseError::Truncated | ParseError::BadMagic),
                "{cut}: {e:?}"
            ),
            Ok(cases) => assert!(cases.is_err(), "{cut}: parsed a truncated index"),
        }
    }
    // Header faults.
    let mut bad = POLICY_TARGET.to_vec();
    bad[0] = b'X';
    assert_eq!(Fixture::parse(&bad).unwrap_err(), ParseError::BadMagic);
    let mut bad = POLICY_TARGET.to_vec();
    bad[4] = 2;
    assert_eq!(
        Fixture::parse(&bad).unwrap_err(),
        ParseError::UnsupportedVersion(2)
    );
    // The first case: u8 name_len at 8, then the name, the algorithm, the key, the codes.
    let first = cases()[0];
    let alg_at = 8 + 1 + first.name.len();
    let codes_at = alg_at + 3 + first.public_key.len();
    fn first_err(bytes: &[u8]) -> Result<(), ParseError> {
        Fixture::parse(bytes)
            .unwrap()
            .cases()
            .next()
            .unwrap()
            .map(|_| ())
    }
    let mut bad = POLICY_TARGET.to_vec();
    bad[alg_at] = 4;
    assert_eq!(first_err(&bad), Err(ParseError::UnknownAlgorithm(4)));
    let mut bad = POLICY_TARGET.to_vec();
    bad[codes_at + 1] = Expect::ALL.len() as u8;
    assert_eq!(
        first_err(&bad),
        Err(ParseError::BadExpectation(Expect::ALL.len() as u8))
    );
    let mut bad = POLICY_TARGET.to_vec();
    bad[9] = 0xFF;
    assert_eq!(first_err(&bad), Err(ParseError::BadName));
    // Trailing bytes after the last case.
    let mut bad = POLICY_TARGET.to_vec();
    bad.push(0);
    let all: Result<Vec<_>, _> = Fixture::parse(&bad).unwrap().cases().collect();
    assert_eq!(all.unwrap_err(), ParseError::TrailingBytes);
    // An index naming an image that is not embedded: the cell fails, it does not panic.
    let mut renamed = POLICY_TARGET.to_vec();
    renamed[9] = b'X';
    let mut failed = 0;
    let summary = run_fixture(
        &renamed,
        &DefaultBackend::new(),
        &mut InMemory,
        &mut [0u8; 4096],
        &mut [0u8; 256],
        |_, outcome| {
            if !outcome.passed() {
                assert_eq!(outcome.got_name(), "UnknownImage");
                failed += 1;
            }
        },
    )
    .unwrap();
    assert_eq!(failed, 3);
    assert!(!summary.all_passed());
}
