//! `keelsign verify` (SHA-53): agreement with the device crate on every fixture, imgtool
//! Ed25519 images, key rotation, tampering, malformed and missing inputs, policies,
//! public key files, padded images and the output, through the real binary.

mod common;

use common::*;
use keelsign::keys::{KeyIdentity, PublicKey};
use keelsign::verify::{ExitClass, exit_class};
use keelsign_verify::image::Image;
use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, DefaultBackend, Ed25519Key, Error, ImageError, Policy,
    TrustedKey, TrustedKeys, VerifiedImage,
};
use predicates::prelude::*;
use std::path::{Path, PathBuf};

/// `keelsign verify` with `args`.
fn verify_cmd(args: &[&dyn AsRef<std::ffi::OsStr>]) -> assert_cmd::assert::Assert {
    let mut command = cmd();
    command.arg("verify");
    for arg in args {
        command.arg(arg);
    }
    command.assert()
}

/// The `--policy` value and MANIFEST.json cell name of a policy.
fn names(policy: Policy) -> (&'static str, &'static str) {
    match policy {
        Policy::ClassicalOnly => ("classical", "classical_only"),
        Policy::PqOnly => ("pq", "pq_only"),
        Policy::Hybrid => ("hybrid", "hybrid"),
        other => panic!("unknown policy {other:?}"),
    }
}

/// The verdict string MANIFEST.json uses: `Ok`, or the error as Debug prints it, with a
/// TLV type as `0x%04X`.
fn verdict(result: &Result<VerifiedImage<'_>, Error>) -> String {
    match result {
        Ok(_) => "Ok".to_owned(),
        Err(Error::Image(ImageError::KeelsignTlvProtected(t))) => {
            format!("Image(KeelsignTlvProtected(0x{t:04X}))")
        }
        Err(e) => format!("{e:?}"),
    }
}

fn algorithm(name: &str) -> Algorithm {
    match name {
        "MlDsa44" => Algorithm::MlDsa44,
        "MlDsa65" => Algorithm::MlDsa65,
        "LmsHss" => Algorithm::LmsHss,
        other => panic!("unknown algorithm {other}"),
    }
}

/// The library verdict on `bytes`: `keelsign_verify::verify_with` (the default backend,
/// or CNSA 2.0) against the post-quantum key `pq` and the Ed25519 key `ed`.
fn library(
    bytes: &[u8],
    pq: &[(Algorithm, Vec<u8>)],
    ed: &[[u8; 32]],
    policy: Policy,
    cnsa_2_0: bool,
) -> Result<VerifiedImage<'static>, Error> {
    let pq: Vec<TrustedKey<'static>> = pq
        .iter()
        .map(|(algorithm, key)| TrustedKey {
            algorithm: *algorithm,
            public_key: Box::leak(key.clone().into_boxed_slice()),
        })
        .collect();
    let ed: Vec<Ed25519Key<'static>> = ed
        .iter()
        .map(|key| Ed25519Key {
            public_key: Box::leak(Box::new(*key)),
        })
        .collect();
    let keys = TrustedKeys::<8, 8>::with_ed25519(&pq, &ed).expect("key set");
    let backend = if cnsa_2_0 {
        DefaultBackend::cnsa_2_0()
    } else {
        DefaultBackend::new()
    };
    let mut reader: &[u8] = bytes;
    let mut tlv_buf = vec![0u8; bytes.len()];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    keelsign_verify::verify_with(
        &backend,
        &mut reader,
        &keys,
        policy,
        &mut tlv_buf,
        &mut chunk,
    )
}

/// The ML-DSA-44 image-fixture test key from MANIFEST.json.
fn mldsa44_test_key() -> Vec<u8> {
    let manifest = manifest();
    unhex(
        manifest["keys"]["mldsa-test-key:mldsa44"]["public_key_hex"]
            .as_str()
            .expect("key"),
    )
}

/// The post-quantum key the policy matrix trusts for an output: its own, or (for an image
/// without one, so `--policy pq` has a key to name) the ML-DSA-44 test key.
fn fixture_pq_key(entry: &serde_json::Value) -> (String, Vec<u8>) {
    match (
        entry["algorithm"].as_str(),
        entry["public_key_hex"].as_str(),
    ) {
        (Some(alg), Some(key)) => (alg.to_owned(), unhex(key)),
        _ => ("MlDsa44".to_owned(), mldsa44_test_key()),
    }
}

/// The Ed25519 test key's `SubjectPublicKeyInfo` (the committed DER file).
fn ed25519_pub() -> PathBuf {
    fixture_path("keys/ed25519-test-key.spki.der")
}

/// Generate a key with `keelsign keygen` and export its public key with `keelsign
/// pubkey` (PEM); returns (private, public, identity).
fn key_pair(dir: &Path, alg: &str, name: &str) -> (PathBuf, PathBuf, KeyIdentity) {
    let private = keygen(dir, alg, name, None);
    let public = dir.join(format!("{name}.pub.pem"));
    assert_exit(
        &keelsign(&[&"pubkey", &"--key", &private, &"--out", &public]),
        0,
    );
    let identity = PublicKey::from_bytes(&std::fs::read(&public).expect("read"))
        .expect("public key")
        .identity();
    (private, public, identity)
}

fn hex_of(identity: KeyIdentity) -> String {
    match identity {
        KeyIdentity::KeyId(id) => hex(&id),
        KeyIdentity::KeyHash(hash) => hex(&hash),
    }
}

/// `keelsign sign` of the imgtool Ed25519 golden image with `key` (and, replacing
/// imgtool's pair, `hybrid_key`).
fn sign(dir: &Path, name: &str, key: &Path, hybrid_key: Option<&Path>) -> PathBuf {
    let output = dir.join(name);
    let input = fixture_path("mcuboot-ed25519.bin");
    let out = match hybrid_key {
        None => keelsign(&[&"sign", &"--key", &key, &input, &output]),
        Some(ed) => keelsign(&[
            &"sign",
            &"--key",
            &key,
            &"--hybrid-key",
            &ed,
            // The golden image carries imgtool's Ed25519 pair: replace it with `ed`'s.
            &"--replace",
            &input,
            &output,
        ]),
    };
    assert_exit(&out, 0);
    output
}

/// The offset of a TLV value inside `bytes`.
fn value_offset(bytes: &[u8], value: &[u8]) -> usize {
    value.as_ptr() as usize - bytes.as_ptr() as usize
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write");
    path
}

/// AC1: on every MANIFEST.json image under every policy, the binary's exit code and
/// message are the library's verdict (`keelsign_verify::verify_with`, classified by
/// `exit_class`, its `Display` on standard error), and that verdict is the manifest's cell.
#[test]
fn verify_agrees_with_keelsign_verify_on_every_manifest_fixture_and_policy() {
    let dir = scratch("verify", "agreement");
    let ed = ed25519_test_public_key();
    let outputs = manifest_outputs();
    assert_eq!(outputs.len(), 58, "MANIFEST.json outputs");
    let mut checked = 0;
    for (name, entry) in &outputs {
        let image = fixture_path(name);
        let bytes = fixture(name);
        let (alg, pq) = fixture_pq_key(entry);
        let pq_pub = write_pub(&dir, &name.replace('/', "-"), &alg, &pq, checked % 2 == 0);
        for &policy in Policy::ALL {
            let (flag, cell) = names(policy);
            let expected = entry["policy"][cell].as_str().expect("policy cell");
            let result = library(
                &bytes,
                &[(algorithm(&alg), pq.clone())],
                &[ed],
                policy,
                false,
            );
            assert_eq!(
                verdict(&result),
                expected,
                "{name} {cell}: library vs manifest"
            );

            let assert = verify_cmd(&[
                &"--pub",
                &pq_pub,
                &"--pub",
                &ed25519_pub(),
                &"--policy",
                &flag,
                &image,
            ]);
            match &result {
                Ok(verified) => {
                    let assert = assert.code(0).stderr(predicate::str::is_empty());
                    let out = stdout(assert.get_output());
                    assert!(
                        out.starts_with(&format!("verified: {}\n", image.display())),
                        "{out}"
                    );
                    assert!(out.contains(&format!("image digest: {}\n", hex(&verified.digest))));
                    assert_eq!(
                        hex(&verified.digest),
                        entry["digest_hex"].as_str().expect("digest"),
                        "{name}"
                    );
                }
                Err(e) => match exit_class(e) {
                    ExitClass::NotVerified => {
                        assert
                            .code(9)
                            .stdout(predicate::str::is_empty())
                            .stderr(format!(
                                "error: {}: not verified under policy {flag}: {e}\n",
                                image.display()
                            ));
                    }
                    ExitClass::Malformed => {
                        let Err(parse) = Image::parse(&bytes) else {
                            panic!("{name}: malformed but parses");
                        };
                        assert
                            .code(7)
                            .stdout(predicate::str::is_empty())
                            .stderr(format!(
                                "error: {}: not an MCUboot image keelsign reads: {parse}\n",
                                image.display()
                            ));
                    }
                    ExitClass::Internal => panic!("{name}: internal error {e}"),
                },
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 58);
    // The big-endian image is the malformed case.
    verify_cmd(&[
        &"--pub",
        &ed25519_pub(),
        &fixture_path("rejected/mcuboot-ed25519-bigendian.bin"),
    ])
    .code(7)
    .stderr(predicate::str::contains("bad header magic"));
}

/// AC2: imgtool's Ed25519 images verify under `--policy classical` with the imgtool test
/// key (padded and 200 KB ones too); its RSA-2048 and ECDSA P-256 images have no Ed25519
/// signature for keelsign to check.
#[test]
fn imgtool_ed25519_fixtures_verify_under_policy_classical() {
    for name in [
        "mcuboot-ed25519.bin",
        "mcuboot-ed25519-padded.bin",
        "mcuboot-ed25519-200k.bin",
    ] {
        verify_cmd(&[
            &"--pub",
            &ed25519_pub(),
            &"--policy",
            &"classical",
            &fixture_path(name),
        ])
        .code(0)
        .stdout(predicate::str::contains("policy: classical\n"))
        .stdout(predicate::str::contains(
            "ed25519 key: 15bd85175f163ec727380037b5c48ae9f83fc2cb8e12fa5a678be4809f2b3190\n",
        ));
    }
    for name in ["mcuboot-rsa2048.bin", "mcuboot-ecdsa-p256.bin"] {
        verify_cmd(&[
            &"--pub",
            &ed25519_pub(),
            &"--policy",
            &"classical",
            &fixture_path(name),
        ])
        .code(9)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::ends_with(
            "not verified under policy classical: Ed25519 half rejected: no ED25519 \
                 signature TLV\n",
        ));
    }
}

/// AC3: an image signed with key B verifies with `--pub A --pub B` and names B; with
/// `--pub A` alone it is not verified. The same for the Ed25519 half under hybrid.
#[test]
fn rotation_key_b_passes_with_pubs_a_and_b_and_fails_with_a_only() {
    let dir = scratch("verify", "rotation");
    let (_, a_pub, _) = key_pair(&dir, "ml-dsa-65", "a");
    let (b, b_pub, b_id) = key_pair(&dir, "ml-dsa-65", "b");
    let image = sign(&dir, "by-b.bin", &b, None);

    verify_cmd(&[&"--pub", &a_pub, &"--pub", &b_pub, &image])
        .code(0)
        .stdout(predicate::str::contains(format!(
            "pq key: ml-dsa-65 {}\n",
            hex_of(b_id)
        )));
    verify_cmd(&[&"--pub", &b_pub, &"--pub", &a_pub, &image]).code(0);
    verify_cmd(&[&"--pub", &a_pub, &image])
        .code(9)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains(
            "not verified under policy pq: post-quantum key ID is not in the trusted key set",
        ));

    // Ed25519 rotation under hybrid, with B's ML-DSA key trusted throughout.
    let (_, ed_a_pub, _) = key_pair(&dir, "ed25519", "ed-a");
    let (ed_b, ed_b_pub, ed_b_hash) = key_pair(&dir, "ed25519", "ed-b");
    let hybrid = sign(&dir, "hybrid-by-b.bin", &b, Some(&ed_b));
    verify_cmd(&[
        &"--pub",
        &b_pub,
        &"--pub",
        &ed_a_pub,
        &"--pub",
        &ed_b_pub,
        &"--policy",
        &"hybrid",
        &hybrid,
    ])
    .code(0)
    .stdout(predicate::str::contains(format!(
        "ed25519 key: {}\n",
        hex_of(ed_b_hash)
    )));
    verify_cmd(&[
        &"--pub",
        &b_pub,
        &"--pub",
        &ed_a_pub,
        &"--policy",
        &"hybrid",
        &hybrid,
    ])
    .code(9)
    .stderr(predicate::str::contains(
        "not verified under policy hybrid: Ed25519 half rejected: KEYHASH is not in the \
             trusted Ed25519 key set",
    ));
}

/// TP2: a changed body, a changed TLV or the wrong key: exit 9 with the reason, nothing on
/// standard output.
#[test]
fn tampered_body_tlv_and_wrong_key_exit_9_with_the_reason() {
    let dir = scratch("verify", "tamper");
    let ed = ed25519_pub();

    // The generated tamper fixtures, each with its own key.
    for (name, policy, reason) in [
        (
            "keelsign-hybrid-bad-body.bin",
            "hybrid",
            "image rule broken: image digest does not match the SHA256 TLV",
        ),
        (
            "keelsign-mldsa44-bad-body.bin",
            "pq",
            "image rule broken: image digest does not match the SHA256 TLV",
        ),
        (
            "keelsign-mldsa44-bad-sig.bin",
            "pq",
            "post-quantum signature is invalid",
        ),
        (
            "keelsign-mldsa65-short-sig.bin",
            "pq",
            "post-quantum signature is malformed",
        ),
        (
            "keelsign-mldsa44-bad-key-id.bin",
            "pq",
            "post-quantum key ID is not in the trusted key set",
        ),
        (
            "keelsign-hybrid-bad-ed25519.bin",
            "hybrid",
            "Ed25519 half rejected: Ed25519 signature is invalid",
        ),
    ] {
        let entry = manifest_entry(name);
        let (alg, key) = fixture_pq_key(&entry);
        let public = write_pub(&dir, name, &alg, &key, true);
        let image = fixture_path(name);
        verify_cmd(&[
            &"--pub",
            &public,
            &"--pub",
            &ed,
            &"--policy",
            &policy,
            &image,
        ])
        .code(9)
        .stdout(predicate::str::is_empty())
        .stderr(format!(
            "error: {}: not verified under policy {policy}: {reason}\n",
            image.display()
        ));
    }

    // An image signed here, then changed one byte at a time.
    let (pq, pq_pub, _) = key_pair(&dir, "ml-dsa-65", "pq");
    let (ed_key, ed_pub, _) = key_pair(&dir, "ed25519", "ed");
    let signed = sign(&dir, "signed.bin", &pq, Some(&ed_key));
    let bytes = std::fs::read(&signed).expect("read");
    verify_cmd(&[&"--pub", &pq_pub, &"--pub", &ed_pub, &signed]).code(0);
    let image = Image::parse(&bytes).expect("parse");
    let header_size = usize::from(image.header().hdr_size);
    let pq_sig = unprotected_value(&image, 0x4BA2);
    let ed_sig = unprotected_value(&image, 0x24);
    let cases = [
        (
            "body.bin",
            header_size + 10,
            "image rule broken: image digest does not match the SHA256 TLV",
        ),
        (
            "pq-tlv.bin",
            value_offset(&bytes, pq_sig) + 5,
            "post-quantum signature is invalid",
        ),
        (
            "ed-tlv.bin",
            value_offset(&bytes, ed_sig) + 5,
            "Ed25519 half rejected: Ed25519 signature is invalid",
        ),
    ];
    for (name, offset, reason) in cases {
        let mut tampered = bytes.clone();
        tampered[offset] ^= 0x01;
        let path = write(&dir, name, &tampered);
        verify_cmd(&[&"--pub", &pq_pub, &"--pub", &ed_pub, &path])
            .code(9)
            .stdout(predicate::str::is_empty())
            .stderr(format!(
                "error: {}: not verified under policy hybrid: {reason}\n",
                path.display()
            ));
    }

    // The wrong key.
    let (_, other_pub, _) = key_pair(&dir, "ml-dsa-65", "other");
    verify_cmd(&[&"--pub", &other_pub, &signed])
        .code(9)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::starts_with(format!(
            "error: {}: not verified under policy pq: post-quantum key ID is not in the \
             trusted key set",
            signed.display()
        )));
}

/// TP3: a malformed image exits 7; a missing or unreadable image or `--pub` file exits 1;
/// a `--pub` file that is not a public key exits 5; bad arguments exit 2.
#[test]
fn malformed_image_exits_7_and_missing_or_unreadable_files_exit_1() {
    let dir = scratch("verify", "malformed");
    let entry = manifest_entry("keelsign-mldsa44.bin");
    let (alg, key) = fixture_pq_key(&entry);
    let public = write_pub(&dir, "mldsa44", &alg, &key, true);
    let image = fixture_path("keelsign-mldsa44.bin");
    verify_cmd(&[&"--pub", &public, &image]).code(0);

    // Malformed images: 7.
    let bytes = fixture("keelsign-mldsa44.bin");
    let big = dir.join("big.bin");
    std::fs::File::create(&big)
        .and_then(|f| f.set_len(65 << 20))
        .expect("sparse 65 MiB file");
    for (path, needle) in [
        (
            write(&dir, "garbage.bin", b"not an MCUboot image"),
            "not an MCUboot image keelsign reads",
        ),
        (
            write(&dir, "empty.bin", b""),
            "not an MCUboot image keelsign reads",
        ),
        (
            write(&dir, "truncated.bin", &bytes[..bytes.len() / 2]),
            "not an MCUboot image keelsign reads",
        ),
        (
            fixture_path("rejected/mcuboot-ed25519-bigendian.bin"),
            "bad header magic",
        ),
        (big, "larger than 64 MiB"),
    ] {
        verify_cmd(&[&"--pub", &public, &path])
            .code(7)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::starts_with(format!(
                "error: {}: ",
                path.display()
            )))
            .stderr(predicate::str::contains(needle));
    }

    // Missing or unreadable files: 1.
    let missing = dir.join("missing.bin");
    verify_cmd(&[&"--pub", &public, &missing])
        .code(1)
        .stderr(predicate::str::contains(format!(
            "read image {}",
            missing.display()
        )));
    let missing_pub = dir.join("missing.pub.pem");
    verify_cmd(&[&"--pub", &missing_pub, &image])
        .code(1)
        .stderr(predicate::str::contains(format!(
            "read key file {}",
            missing_pub.display()
        )));
    verify_cmd(&[&"--pub", &dir, &image]).code(1);

    // Not a public key: 5.
    let private = keygen(&dir, "ml-dsa-44", "private", None);
    let unknown_oid = {
        use pkcs8::der::Encode as _;
        pkcs8::SubjectPublicKeyInfoRef {
            algorithm: pkcs8::AlgorithmIdentifierRef {
                oid: pkcs8::ObjectIdentifier::new_unwrap("1.3.101.113"),
                parameters: None,
            },
            subject_public_key: pkcs8::der::asn1::BitStringRef::from_bytes(&[0; 57]).expect("bits"),
        }
        .to_der()
        .expect("der")
    };
    for (path, needle) in [
        (private, "holds a private key, not a public key"),
        (
            write(&dir, "garbage.pub", b"\x01\x02\x03"),
            "corrupt or invalid key file",
        ),
        (
            write(&dir, "ed448.pub.der", &unknown_oid),
            "unsupported public key algorithm OID 1.3.101.113",
        ),
    ] {
        verify_cmd(&[&"--pub", &path, &image])
            .code(5)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(needle));
    }

    // Usage: 2.
    verify_cmd(&[&"--pub", &public, &"--policy", &"strict", &image]).code(2);
    verify_cmd(&[&image])
        .code(2)
        .stderr(predicate::str::contains("--pub <FILE>"));
    let nine: Vec<PathBuf> = (0..9u8)
        .map(|i| write_pub(&dir, &format!("pq{i}"), "MlDsa44", &[i; 1312], false))
        .collect();
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = Vec::new();
    for path in &nine {
        args.push(&"--pub");
        args.push(path);
    }
    args.push(&image);
    verify_cmd(&args).code(2).stderr(predicate::str::contains(
        "9 post-quantum --pub keys given; at most 8",
    ));
    // Eight are accepted.
    let eight = &args[2..];
    verify_cmd(eight).code(9);
    let der = write_pub(&dir, "mldsa44-again", &alg, &key, false);
    verify_cmd(&[&"--pub", &public, &"--pub", &der, &image])
        .code(2)
        .stderr(predicate::str::contains("are the same ml-dsa-44 key"));
}

/// Deferred from SHA-46: `--policy classical|pq|hybrid`, and the policy inferred from the
/// keys when it is not given.
#[test]
fn policy_flag_values_and_inference() {
    let dir = scratch("verify", "policy");
    let name = "keelsign-hybrid-ed25519-mldsa44.bin";
    let (alg, key) = fixture_pq_key(&manifest_entry(name));
    let pq = write_pub(&dir, "pq", &alg, &key, true);
    let ed = ed25519_pub();
    let image = fixture_path(name);

    for (args, line) in [
        (
            vec![&pq as &dyn AsRef<std::ffi::OsStr>, &"--pub", &ed],
            "policy: hybrid (inferred from the keys given)",
        ),
        (vec![&pq], "policy: pq (inferred from the keys given)"),
        (
            vec![&ed],
            "policy: classical (inferred from the keys given)",
        ),
    ] {
        let mut all: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"--pub"];
        all.extend(args);
        all.push(&image);
        verify_cmd(&all)
            .code(0)
            .stdout(predicate::str::contains(format!("\n{line}\n")));
    }
    for flag in ["classical", "pq", "hybrid"] {
        verify_cmd(&[&"--pub", &pq, &"--pub", &ed, &"--policy", &flag, &image])
            .code(0)
            .stdout(predicate::str::contains(format!("\npolicy: {flag}\n")));
    }
    for (keys, flag, needle) in [
        (&pq, "hybrid", "--policy hybrid needs an Ed25519 key"),
        (&pq, "classical", "--policy classical needs an Ed25519 key"),
        (&ed, "pq", "--policy pq needs a post-quantum key"),
        (&ed, "hybrid", "--policy hybrid needs a post-quantum key"),
    ] {
        verify_cmd(&[&"--pub", keys, &"--policy", &flag, &image])
            .code(2)
            .stdout(predicate::str::is_empty())
            .stderr(predicate::str::contains(needle));
    }
    for bad in ["Hybrid", "classical-only", ""] {
        verify_cmd(&[&"--pub", &pq, &"--policy", &bad, &image]).code(2);
    }
    // The policy decides what is checked: the PQ-only image is not verified under
    // classical, whatever keys are given.
    let pq_only = fixture_path("keelsign-mldsa44.bin");
    verify_cmd(&[&"--pub", &pq, &"--pub", &ed, &pq_only])
        .code(9)
        .stderr(predicate::str::contains(
            "not verified under policy hybrid: Ed25519 half rejected: no ED25519 signature TLV",
        ));
    verify_cmd(&[&"--pub", &pq, &"--pub", &ed, &"--policy", &"pq", &pq_only]).code(0);
}

/// Deferred from SHA-240: `--cnsa-2.0` verifies with `DefaultBackend::cnsa_2_0()`: a
/// single-tree LMS image passes, a two-level HSS image and ML-DSA images do not.
#[test]
fn cnsa_2_0_flag_refuses_hss2_and_ml_dsa_and_accepts_single_tree_lms() {
    let dir = scratch("verify", "cnsa");
    for (name, strict) in [
        ("keelsign-lms-m32-h5.bin", None),
        (
            "keelsign-hss2-m32-h5h5.bin",
            Some("unsupported post-quantum parameter set"),
        ),
        (
            "keelsign-mldsa44.bin",
            Some("unsupported post-quantum parameter set"),
        ),
        (
            "keelsign-mldsa65.bin",
            Some("unsupported post-quantum parameter set"),
        ),
    ] {
        let entry = manifest_entry(name);
        let (alg, key) = fixture_pq_key(&entry);
        let public = write_pub(&dir, name, &alg, &key, false);
        let image = fixture_path(name);
        let bytes = fixture(name);
        let pq = [(algorithm(&alg), key)];
        verify_cmd(&[&"--pub", &public, &image]).code(0);
        let assert = verify_cmd(&[&"--pub", &public, &"--cnsa-2.0", &image]);
        let library = library(&bytes, &pq, &[], Policy::PqOnly, true);
        match strict {
            None => {
                assert.code(0);
                assert!(library.is_ok(), "{name}");
            }
            Some(reason) => {
                assert.code(9).stderr(predicate::str::ends_with(format!(
                    "not verified under policy pq: {reason}\n"
                )));
                assert_eq!(library, Err(Error::UnsupportedParameterSet), "{name}");
            }
        }
    }
}

/// `--pub` reads `SubjectPublicKeyInfo` PEM and DER, from `keelsign pubkey` or built
/// independently, and a mix of algorithms in one key set.
#[test]
fn pub_accepts_pem_and_der_and_mixed_algorithms() {
    let dir = scratch("verify", "pub_formats");
    let lms_name = "keelsign-hybrid-ed25519-lms.bin";
    let (lms_alg, lms_key) = fixture_pq_key(&manifest_entry(lms_name));
    let (m44_alg, m44_key) = fixture_pq_key(&manifest_entry("keelsign-mldsa44.bin"));
    let (m65_alg, m65_key) = fixture_pq_key(&manifest_entry("keelsign-mldsa65.bin"));
    let ed_der = ed25519_pub();
    let ed_pem = write_pub(&dir, "ed", "Ed25519", &ed25519_test_public_key(), true);
    for pem in [true, false] {
        let lms = write_pub(&dir, &format!("lms-{pem}"), &lms_alg, &lms_key, pem);
        verify_cmd(&[&"--pub", &lms, &"--pub", &ed_der, &fixture_path(lms_name)])
            .code(0)
            .stdout(predicate::str::contains("policy: hybrid"))
            .stdout(predicate::str::contains("pq key: lms-hss "));
        verify_cmd(&[&"--pub", &lms, &"--pub", &ed_pem, &fixture_path(lms_name)]).code(0);
    }
    let m44 = write_pub(&dir, "m44", &m44_alg, &m44_key, false);
    let m65 = write_pub(&dir, "m65", &m65_alg, &m65_key, true);
    let (single_alg, single_key) = fixture_pq_key(&manifest_entry("keelsign-lms-m32-h5.bin"));
    let lms = write_pub(&dir, "lms", &single_alg, &single_key, false);
    for (name, line) in [
        ("keelsign-mldsa44.bin", "pq key: ml-dsa-44 "),
        ("keelsign-mldsa65.bin", "pq key: ml-dsa-65 "),
        ("keelsign-lms-m32-h5.bin", "pq key: lms-hss "),
    ] {
        verify_cmd(&[
            &"--pub",
            &m44,
            &"--pub",
            &ed_pem,
            &"--pub",
            &m65,
            &"--pub",
            &lms,
            &"--policy",
            &"pq",
            &fixture_path(name),
        ])
        .code(0)
        .stdout(predicate::str::contains(line));
    }

    // `keelsign pubkey` output, PEM and DER, with text before the PEM header.
    let private = keygen(&dir, "ml-dsa-44", "own", None);
    let der = dir.join("own.pub.der");
    assert_exit(
        &keelsign(&[
            &"pubkey",
            &"--key",
            &private,
            &"--format",
            &"der",
            &"--out",
            &der,
        ]),
        0,
    );
    let pem = keelsign(&[&"pubkey", &"--key", &private]);
    assert_exit(&pem, 0);
    let pem = write(
        &dir,
        "own.pub.pem",
        &[b"Trusted signing key\n".as_slice(), &pem.stdout].concat(),
    );
    let signed = sign(&dir, "own.bin", &private, None);
    verify_cmd(&[&"--pub", &der, &signed]).code(0);
    verify_cmd(&[&"--pub", &pem, &signed]).code(0);
}

/// Bytes after the TLV area (padding, a slot trailer) are ignored, and reported.
#[test]
fn padded_image_is_accepted_and_trailing_bytes_reported() {
    let padded = fixture_path("mcuboot-ed25519-padded.bin");
    let plain = fixture_path("mcuboot-ed25519.bin");
    let padded_out = verify_cmd(&[&"--pub", &ed25519_pub(), &padded])
        .code(0)
        .stdout(predicate::str::ends_with(
            "image: 8192 bytes (5877 trailing bytes ignored)\n",
        ))
        .get_output()
        .stdout
        .clone();
    let plain_out = verify_cmd(&[&"--pub", &ed25519_pub(), &plain])
        .code(0)
        .stdout(predicate::str::contains("image: ").not())
        .get_output()
        .stdout
        .clone();
    // The same image otherwise: every line but the first and last agree.
    let padded_lines: Vec<&str> = std::str::from_utf8(&padded_out)
        .expect("utf-8")
        .lines()
        .collect();
    let plain_lines: Vec<&str> = std::str::from_utf8(&plain_out)
        .expect("utf-8")
        .lines()
        .collect();
    assert_eq!(padded_lines[1..padded_lines.len() - 1], plain_lines[1..]);
}

/// The success output: fixed lines in a fixed order, naming the keys that verified.
#[test]
fn verify_output_lines_are_stable_and_name_the_keys() {
    let dir = scratch("verify", "output");
    let name = "keelsign-hybrid-ed25519-mldsa44.bin";
    let entry = manifest_entry(name);
    let (alg, key) = fixture_pq_key(&entry);
    let pq = write_pub(&dir, "pq", &alg, &key, true);
    let image = fixture_path(name);
    let bytes = fixture(name);
    let verified = library(
        &bytes,
        &[(algorithm(&alg), key.clone())],
        &[ed25519_test_public_key()],
        Policy::Hybrid,
        false,
    )
    .expect("verifies");
    let counter = match verified.security_counter {
        Some(c) => c.to_string(),
        None => "none".to_owned(),
    };
    let expected = format!(
        "verified: {}\npolicy: hybrid (inferred from the keys given)\nversion: 1.2.3+4\n\
         security counter: {counter}\nimage digest: {}\npq key: ml-dsa-44 {}\ned25519 key: {}\n",
        image.display(),
        entry["digest_hex"].as_str().expect("digest"),
        hex(&keelsign_verify::key_id_of(&key)),
        "15bd85175f163ec727380037b5c48ae9f83fc2cb8e12fa5a678be4809f2b3190",
    );
    assert_eq!(
        hex(&keelsign_verify::key_id_of(&key)),
        entry["key_id_hex"].as_str().expect("key id")
    );
    verify_cmd(&[&"--pub", &pq, &"--pub", &ed25519_pub(), &image])
        .code(0)
        .stdout(expected)
        .stderr(predicate::str::is_empty());
}
