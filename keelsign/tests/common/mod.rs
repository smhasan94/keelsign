//! Helpers shared by the `sign`, `inspect`, `verify`, exit-code and imgtool integration
//! tests (SHA-51, SHA-53). Each test binary uses a different subset.
#![allow(dead_code)]

use keelsign::keys::PrivateKey;
use keelsign_verify::image::{IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH, Image};
use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, Ed25519Key, Policy, TrustedKey, TrustedKeys, VerifiedImage,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The real `keelsign` binary as an `assert_cmd` command (SHA-53 tests), without the
/// test passphrase variable.
pub fn cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(env!("CARGO_BIN_EXE_keelsign"));
    cmd.env_remove("KEELSIGN_TEST_PW");
    cmd
}

/// The DER `SubjectPublicKeyInfo` of a raw public key, built independently of keelsign's
/// own encoder. `algorithm` is a MANIFEST.json name (`MlDsa44`, `MlDsa65`, `LmsHss`) or
/// `Ed25519`. ML-DSA and Ed25519 keys go in the BIT STRING as they are (RFC 9881,
/// RFC 8410); an HSS/LMS key goes in as the DER OCTET STRING of the key (RFC 8708 §4).
pub fn spki_der_for(algorithm: &str, raw: &[u8]) -> Vec<u8> {
    use pkcs8::der::Encode as _;
    use pkcs8::der::asn1::{BitStringRef, OctetStringRef};
    let (oid, bits) = match algorithm {
        "MlDsa44" => (keelsign::keys::ID_ML_DSA_44, raw.to_vec()),
        "MlDsa65" => (keelsign::keys::ID_ML_DSA_65, raw.to_vec()),
        "Ed25519" => (keelsign::keys::ID_ED25519, raw.to_vec()),
        "LmsHss" => (
            keelsign::keys::ID_HSS_LMS_HASHSIG,
            OctetStringRef::new(raw)
                .and_then(|o| o.to_der())
                .expect("OCTET STRING"),
        ),
        other => panic!("unknown algorithm {other}"),
    };
    pkcs8::SubjectPublicKeyInfoRef {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        subject_public_key: BitStringRef::from_bytes(&bits).expect("BIT STRING"),
    }
    .to_der()
    .expect("encode SPKI")
}

/// Write the public key `raw` of `algorithm` (see [`spki_der_for`]) as
/// `dir/<name>.pub.pem` (PEM) or `dir/<name>.pub.der` (DER).
pub fn write_pub(dir: &Path, name: &str, algorithm: &str, raw: &[u8], pem: bool) -> PathBuf {
    let der = spki_der_for(algorithm, raw);
    if pem {
        let path = dir.join(format!("{name}.pub.pem"));
        let text = pkcs8::der::Document::try_from(der.as_slice())
            .expect("DER")
            .to_pem("PUBLIC KEY", pkcs8::LineEnding::LF)
            .expect("PEM");
        std::fs::write(&path, text).expect("write PEM");
        path
    } else {
        let path = dir.join(format!("{name}.pub.der"));
        std::fs::write(&path, der).expect("write DER");
        path
    }
}

/// Every output image of MANIFEST.json as (name, entry), sorted by name.
pub fn manifest_outputs() -> Vec<(String, serde_json::Value)> {
    manifest()["outputs"]
        .as_object()
        .expect("outputs")
        .iter()
        .map(|(name, entry)| (name.clone(), entry.clone()))
        .collect()
}

/// Bytes of a lowercase hex string.
pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

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

/// The keelsign-verify algorithm of a post-quantum (ML-DSA or LMS/HSS) key.
pub fn pq_algorithm(key: &PrivateKey) -> Algorithm {
    match key {
        PrivateKey::MlDsa44(_) => Algorithm::MlDsa44,
        PrivateKey::MlDsa65(_) => Algorithm::MlDsa65,
        PrivateKey::LmsHss(_) => Algorithm::LmsHss,
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

/// SHA-67: generate an LMS/HSS H10 key `dir/<name>.pem` (with `levels` HSS levels and,
/// optionally, encrypted) and its state file and journal with `keelsign keygen`.
pub fn keygen_lms(dir: &Path, name: &str, levels: u8, passphrase_file: Option<&Path>) -> PathBuf {
    let path = dir.join(format!("{name}.pem"));
    let levels = levels.to_string();
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
        &"keygen",
        &"--alg",
        &"lms-sha256-m32-h10",
        &"--hss-levels",
        &levels,
        &"--out",
        &path,
    ];
    if let Some(pw) = &passphrase_file {
        args.push(&"--passphrase-file");
        args.push(pw);
    }
    assert_exit(&keelsign(&args), 0);
    path
}

/// The state file of an LMS/HSS key file.
pub fn state_path(key: &Path) -> PathBuf {
    keelsign::lms_state::state_path(key)
}

/// The journal of an LMS/HSS key file.
pub fn journal_path(key: &Path) -> PathBuf {
    keelsign::lms_state::journal_path(key)
}

/// The state file of an LMS/HSS key file, as JSON.
pub fn read_state(key: &Path) -> serde_json::Value {
    let bytes = std::fs::read(state_path(key)).expect("read state file");
    serde_json::from_slice(&bytes).expect("state file is JSON")
}

/// The `next_leaf` of an LMS/HSS key's state file.
pub fn next_leaf(key: &Path) -> u64 {
    read_state(key)["next_leaf"].as_u64().expect("next_leaf")
}

/// The lines of an LMS/HSS key's journal.
pub fn journal_lines(key: &Path) -> Vec<String> {
    std::fs::read_to_string(journal_path(key))
        .expect("read journal")
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The bottom-level leaf index `q` of the LMS/HSS signature TLV of a signed image.
pub fn signed_leaf(bytes: &[u8]) -> u32 {
    let image = Image::parse(bytes).expect("parse");
    let sig = unprotected_value(&image, keelsign_verify::tlv::TLV_LMS_HSS_SIG);
    keelsign::inspect::hss_summary(sig)
        .expect("HSS signature")
        .q
}
