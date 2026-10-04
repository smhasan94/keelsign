//! Helpers shared by the `sign`, `inspect` and imgtool integration tests (SHA-51). Each
//! test binary uses a different subset.
#![allow(dead_code)]

use keelsign::keys::PrivateKey;
use keelsign_verify::image::{IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH, Image};
use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, Ed25519Key, Policy, TrustedKey, TrustedKeys, VerifiedImage,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Run the real `keelsign` binary.
pub fn keelsign(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keelsign"));
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env_remove("KEELSIGN_TEST_PW");
    cmd.output().expect("run keelsign")
}

/// A fresh, empty directory for one test.
pub fn scratch(group: &str, test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(group)
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

pub fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

pub fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[track_caller]
pub fn assert_exit(out: &Output, code: i32) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "expected exit {code}\nstdout:\n{}\nstderr:\n{}",
        stdout(out),
        stderr(out)
    );
}

/// The repository root.
pub fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// The path of a file under `tests/fixtures/images/`.
pub fn fixture_path(name: &str) -> PathBuf {
    repo().join("tests/fixtures/images").join(name)
}

/// The bytes of a file under `tests/fixtures/images/`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = fixture_path(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `tests/fixtures/images/MANIFEST.json`.
pub fn manifest() -> serde_json::Value {
    let text = std::fs::read_to_string(fixture_path("MANIFEST.json")).expect("read MANIFEST");
    serde_json::from_str(&text).expect("MANIFEST.json is JSON")
}

/// The MANIFEST entry of one output image.
pub fn manifest_entry(name: &str) -> serde_json::Value {
    manifest()["outputs"][name].clone()
}

/// Generate a key with `keelsign keygen` as `dir/<name>.pem` (optionally encrypted with
/// the first line of `passphrase_file`).
pub fn keygen(dir: &Path, alg: &str, name: &str, passphrase_file: Option<&Path>) -> PathBuf {
    let path = dir.join(format!("{name}.pem"));
    let out = match passphrase_file {
        None => keelsign(&[&"keygen", &"--alg", &alg, &"--out", &path]),
        Some(pw) => keelsign(&[
            &"keygen",
            &"--alg",
            &alg,
            &"--out",
            &path,
            &"--passphrase-file",
            &pw,
        ]),
    };
    assert_exit(&out, 0);
    path
}

/// Load an unencrypted key file.
pub fn load_key(path: &Path) -> PrivateKey {
    let bytes = std::fs::read(path).expect("read key");
    PrivateKey::from_bytes(&bytes, None).expect("load key")
}

/// The raw Ed25519 public key of the fixtures' imgtool test key.
pub fn ed25519_test_public_key() -> [u8; 32] {
    let der = fixture("keys/ed25519-test-key.spki.der");
    der[der.len() - 32..].try_into().expect("32 bytes")
}

/// The raw Ed25519 public key of a key file.
pub fn ed25519_public(key: &PrivateKey) -> [u8; 32] {
    match key {
        PrivateKey::Ed25519(k) => k.verifying_key().to_bytes(),
        _ => panic!("not an Ed25519 key"),
    }
}

/// The keelsign-verify algorithm of an ML-DSA key.
pub fn pq_algorithm(key: &PrivateKey) -> Algorithm {
    match key {
        PrivateKey::MlDsa44(_) => Algorithm::MlDsa44,
        PrivateKey::MlDsa65(_) => Algorithm::MlDsa65,
        PrivateKey::Ed25519(_) => panic!("not an ML-DSA key"),
    }
}

/// `keelsign_verify::verify` of `bytes` under `policy`, trusting the ML-DSA key `pq`
/// and/or the Ed25519 public key `ed`.
pub fn verify(
    bytes: &[u8],
    pq: Option<&PrivateKey>,
    ed: Option<[u8; 32]>,
    policy: Policy,
) -> Result<VerifiedImage<'static>, keelsign_verify::Error> {
    // Leak the key material so the verified image can be returned ('static); tests only.
    let pq_keys: Vec<TrustedKey<'static>> = pq
        .map(|k| TrustedKey {
            algorithm: pq_algorithm(k),
            public_key: Box::leak(k.raw_public_key().into_boxed_slice()),
        })
        .into_iter()
        .collect();
    let ed_keys: Vec<Ed25519Key<'static>> = ed
        .map(|k| Ed25519Key {
            public_key: Box::leak(Box::new(k)),
        })
        .into_iter()
        .collect();
    let keys = TrustedKeys::<1, 1>::with_ed25519(&pq_keys, &ed_keys).expect("key set");
    let mut reader: &[u8] = bytes;
    let mut tlv_buf = vec![0u8; bytes.len()];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    keelsign_verify::verify(&mut reader, &keys, policy, &mut tlv_buf, &mut chunk)
}

/// (type, protected, value) of every TLV, protected area first.
pub fn tlv_list(image: &Image<'_>) -> Vec<(u16, bool, Vec<u8>)> {
    image
        .tlvs()
        .map(|t| (t.tlv_type, t.protected, t.value.to_vec()))
        .collect()
}

/// The types of the unprotected TLVs.
pub fn unprotected_types(image: &Image<'_>) -> Vec<u16> {
    image.unprotected().iter().map(|t| t.tlv_type).collect()
}

/// The value of the only unprotected TLV of `tlv_type`.
pub fn unprotected_value<'a>(image: &Image<'a>, tlv_type: u16) -> &'a [u8] {
    let mut values = image
        .unprotected()
        .iter()
        .filter(|t| t.tlv_type == tlv_type)
        .map(|t| t.value);
    let value = values
        .next()
        .unwrap_or_else(|| panic!("no TLV {tlv_type:#06x}"));
    assert!(values.next().is_none(), "two TLVs {tlv_type:#06x}");
    value
}

/// The image digest `M`.
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    let image = Image::parse(bytes).expect("parse");
    let mut reader: &[u8] = bytes;
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    keelsign_verify::image_digest(&mut reader, &image, &mut chunk).expect("digest")
}

/// `bytes` with every KEYHASH + ED25519 pair removed from the unprotected TLV area,
/// rebuilt independently of keelsign's own code: the hashed prefix verbatim, then a new
/// info header and the remaining TLVs.
pub fn strip_ed25519_pair(bytes: &[u8]) -> Vec<u8> {
    let image = Image::parse(bytes).expect("parse");
    let mut tlvs: Vec<(u16, &[u8])> = Vec::new();
    for tlv in image.unprotected().iter() {
        if tlv.tlv_type == IMAGE_TLV_ED25519 {
            assert_eq!(
                tlvs.pop().map(|(t, _)| t),
                Some(IMAGE_TLV_KEYHASH),
                "ED25519 follows its KEYHASH"
            );
            continue;
        }
        tlvs.push((tlv.tlv_type, tlv.value));
    }
    let end = image.hashed_range().end as usize;
    let mut out = bytes[..end].to_vec();
    let tot: usize = 4 + tlvs.iter().map(|(_, v)| 4 + v.len()).sum::<usize>();
    out.extend_from_slice(&0x6907u16.to_le_bytes());
    out.extend_from_slice(&u16::try_from(tot).expect("fits").to_le_bytes());
    for (t, v) in tlvs {
        out.extend_from_slice(&t.to_le_bytes());
        out.extend_from_slice(&u16::try_from(v.len()).expect("fits").to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    keelsign::keys::hex(bytes)
}
