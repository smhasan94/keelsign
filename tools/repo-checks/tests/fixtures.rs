//! The ML-DSA KAT fixtures in benches/mldsa-kat/fixtures/ are script-generated and match
//! their manifest (CLAUDE.md: fixtures are regenerated only by script).

use repo_checks::{python_script, run_capture, sha256_hex, workspace_root};
use std::fs;

const FIXTURES: [(&str, u16); 4] = [
    ("mldsa44-host.bin", 44),
    ("mldsa44-target.bin", 44),
    ("mldsa65-host.bin", 65),
    ("mldsa65-target.bin", 65),
];

/// Upstream pins: (name in the manifest, commit, upstream sha256).
const SOURCES: [(&str, &str, &str); 3] = [
    (
        "acvp",
        "975de31eb83d87039ec88934fdc47d8c312b892d",
        "47cdd6314c7f746d02421ffcba89d4dbc7bb875ac49e07a029fdfc26fba55437",
    ),
    (
        "wycheproof44",
        "3fa63dd0344abb611f1fb1d77e119938603ea230",
        "0ca1b5df4575263e29b31fae7569a3da41df9a3b6fee56720a992d0cd1153b68",
    ),
    (
        "wycheproof65",
        "3fa63dd0344abb611f1fb1d77e119938603ea230",
        "49ac366d76115eab56b7116f10d06e288e6f23fe6cfb90b26bfb2d731a8d1e02",
    ),
];

fn manifest() -> String {
    let path = workspace_root().join("benches/mldsa-kat/fixtures/MANIFEST.json");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of the JSON object stored under `"key": {` in `json`, up to its closing
/// brace (brace-matched; the manifest has no braces inside strings).
fn json_object<'a>(json: &'a str, key: &str) -> &'a str {
    let start = json
        .find(&format!("\"{key}\": {{"))
        .unwrap_or_else(|| panic!("MANIFEST.json has no object `{key}`"));
    let body = &json[start..];
    let open = body.find('{').expect("object opens");
    let mut depth = 0usize;
    for (i, c) in body[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &body[open..open + i + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated object `{key}`");
}

/// A top-level scalar field of a JSON object (`"field": value`), without quotes.
fn json_field<'a>(object: &'a str, field: &str) -> &'a str {
    // The field is on its own line at the object's first indentation level; nested
    // `cases` entries come later under their own keys, so the first match is ours.
    let needle = format!("\"{field}\": ");
    let start = object
        .find(&needle)
        .unwrap_or_else(|| panic!("no field `{field}` in {object:.80}"))
        + needle.len();
    let rest = &object[start..];
    let end = rest.find([',', '\n']).unwrap_or(rest.len());
    rest[..end].trim().trim_matches('"')
}

#[test]
fn mldsa_fixtures_match_manifest() {
    let manifest = manifest();
    let outputs = json_object(&manifest, "outputs");
    for (name, param_set) in FIXTURES {
        let path = workspace_root()
            .join("benches/mldsa-kat/fixtures")
            .join(name);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let entry = json_object(outputs, name);
        assert_eq!(
            sha256_hex(&bytes),
            json_field(entry, "sha256"),
            "{name}: sha256 differs from MANIFEST.json; regenerate with scripts/gen_mldsa_vectors.py"
        );
        assert_eq!(
            bytes.len().to_string(),
            json_field(entry, "bytes"),
            "{name}: size"
        );
        assert_eq!(&bytes[..4], b"KSMD", "{name}: magic");
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            param_set,
            "{name}: param set"
        );
        let count = u16::from_le_bytes([bytes[6], bytes[7]]);
        assert_eq!(
            count.to_string(),
            json_field(entry, "count"),
            "{name}: count"
        );
        assert_eq!(json_field(entry, "param_set"), param_set.to_string());
        assert_eq!(
            entry.matches("\"tc_id\":").count(),
            usize::from(count),
            "{name}: manifest lists every selected tcId"
        );
    }
    // The hash implementation itself (FIPS 180-4 test vector "abc").
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn manifest_pins_sources() {
    let manifest = manifest();
    let script = fs::read_to_string(workspace_root().join("scripts/gen_mldsa_vectors.py"))
        .expect("read scripts/gen_mldsa_vectors.py");
    let sources = json_object(&manifest, "sources");
    for (name, commit, sha256) in SOURCES {
        let entry = json_object(sources, name);
        assert_eq!(json_field(entry, "commit"), commit, "{name}: commit");
        assert_eq!(
            json_field(entry, "sha256"),
            sha256,
            "{name}: upstream sha256"
        );
        let url = json_field(entry, "url");
        assert!(
            url.starts_with("https://raw.githubusercontent.com/") && url.contains(commit),
            "{name}: URL must be pinned to commit {commit}: {url}"
        );
        for pin in [commit, sha256] {
            assert!(
                script.contains(pin),
                "scripts/gen_mldsa_vectors.py must pin `{pin}` ({name})"
            );
        }
    }
    assert!(
        manifest.contains("\"generator\": \"scripts/gen_mldsa_vectors.py\""),
        "MANIFEST.json names its generator"
    );
}

#[test]
#[ignore = "needs network access to raw.githubusercontent.com and python3"]
fn fixture_script_regenerates_identically() {
    let (ok, stdout, stderr) = run_capture(python_script("gen_mldsa_vectors.py").arg("--check"));
    assert!(
        ok,
        "gen_mldsa_vectors.py --check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("fixtures match a fresh regeneration"));
}

// ---- SHA-65: LMS/HSS fixtures in benches/lms-kat/fixtures/ -----------------------------

/// (file, case count) of the LMS/HSS fixtures.
const LMS_FIXTURES: [(&str, u16); 2] = [("lms-host.bin", 66), ("lms-target.bin", 14)];

/// Upstream pins of scripts/gen_lms_vectors.py: (name in the manifest, pinned URL part,
/// upstream sha256).
const LMS_SOURCES: [(&str, &str, &str); 4] = [
    (
        "rfc8554",
        "https://www.rfc-editor.org/rfc/rfc8554.txt",
        "d5bfdbd457dfe7bc5f67cc1f62482999c2f55bf8033f2af56da323f2ffc2c055",
    ),
    (
        "acvp_sp800_208",
        "975de31eb83d87039ec88934fdc47d8c312b892d",
        "015bb30cb60d4fb24bc69d0cb074965c5fd10d1c70b01d09a5914d4947e2dedf",
    ),
    (
        "acvp_lms_1_0",
        "975de31eb83d87039ec88934fdc47d8c312b892d",
        "298bf08f3dab576483b731dc58a4feab18b93e1e741bc6192133285962cf77dd",
    ),
    (
        "hsslms",
        "hsslms-0.1.3.tar.gz",
        "8d0a1f2bbc5f10f53f6abb394247bf185976088fbbb698a7f8c14031e97a4be5",
    ),
];

fn lms_manifest() -> String {
    let path = workspace_root().join("benches/lms-kat/fixtures/MANIFEST.json");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn lms_fixtures_match_manifest() {
    let manifest = lms_manifest();
    let outputs = json_object(&manifest, "outputs");
    for (name, count) in LMS_FIXTURES {
        let path = workspace_root().join("benches/lms-kat/fixtures").join(name);
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let entry = json_object(outputs, name);
        assert_eq!(
            sha256_hex(&bytes),
            json_field(entry, "sha256"),
            "{name}: sha256 differs from MANIFEST.json; regenerate with scripts/gen_lms_vectors.py"
        );
        assert_eq!(
            bytes.len().to_string(),
            json_field(entry, "bytes"),
            "{name}: size"
        );
        assert_eq!(&bytes[..4], b"KSLM", "{name}: magic");
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            1,
            "{name}: version"
        );
        let header_count = u16::from_le_bytes([bytes[6], bytes[7]]);
        assert_eq!(header_count, count, "{name}: case count");
        assert_eq!(
            json_field(entry, "count"),
            count.to_string(),
            "{name}: count"
        );
        assert_eq!(
            entry.matches("\"id\":").count(),
            usize::from(count),
            "{name}: manifest lists every case"
        );
    }
    let host = json_object(outputs, "lms-host.bin");
    for source in ["\"rfc8554\"", "\"acvp\"", "\"hsslms\""] {
        assert!(host.contains(source), "host fixture has {source} cases");
    }
}

#[test]
fn lms_manifest_pins_sources() {
    let manifest = lms_manifest();
    let script = fs::read_to_string(workspace_root().join("scripts/gen_lms_vectors.py"))
        .expect("read scripts/gen_lms_vectors.py");
    let sources = json_object(&manifest, "sources");
    for (name, pin, sha256) in LMS_SOURCES {
        let entry = json_object(sources, name);
        assert_eq!(
            json_field(entry, "sha256"),
            sha256,
            "{name}: upstream sha256"
        );
        let url = json_field(entry, "url");
        assert!(url.starts_with("https://"), "{name}: {url}");
        assert!(
            url.contains(pin),
            "{name}: URL must be pinned to `{pin}`: {url}"
        );
        for needle in [pin, sha256] {
            assert!(
                script.contains(needle),
                "scripts/gen_lms_vectors.py must pin `{needle}` ({name})"
            );
        }
    }
    // The signer is vendored at run time, never installed.
    assert!(json_object(sources, "hsslms").contains("\"hsslms==0.1.3\""));
    for forbidden in ["pip install", "subprocess", "ensurepip"] {
        assert!(
            !script.contains(forbidden),
            "scripts/gen_lms_vectors.py must not `{forbidden}`"
        );
    }
    assert!(
        manifest.contains("\"generator\": \"scripts/gen_lms_vectors.py\""),
        "MANIFEST.json names its generator"
    );
}

#[test]
#[ignore = "needs network access to rfc-editor.org, raw.githubusercontent.com and files.pythonhosted.org, and python3"]
fn lms_fixture_script_regenerates_identically() {
    let (ok, stdout, stderr) = run_capture(python_script("gen_lms_vectors.py").arg("--check"));
    assert!(
        ok,
        "gen_lms_vectors.py --check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("fixtures match a fresh regeneration"));
}
