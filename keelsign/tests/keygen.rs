//! `keelsign keygen` and `keelsign pubkey`, run as the real binary (SHA-49 acceptance
//! criteria and test plan).

use keelsign::keys::{KeyAlgorithm, PrivateKey, hex};
use pkcs8::DecodePublicKey as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ALGS: [&str; 3] = ["ml-dsa-44", "ml-dsa-65", "ed25519"];
const PASSPHRASE: &[u8] = b"correct horse battery staple";

fn keelsign(args: &[&dyn AsRef<std::ffi::OsStr>]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keelsign"));
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env_remove("KEELSIGN_TEST_PW");
    cmd.output().expect("run keelsign")
}

/// A fresh, empty directory for one test.
fn scratch(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("keygen")
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[track_caller]
fn assert_exit(out: &Output, code: i32) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "expected exit {code}\nstdout:\n{}\nstderr:\n{}",
        stdout(out),
        stderr(out)
    );
}

fn algorithm(name: &str) -> KeyAlgorithm {
    KeyAlgorithm::ALL
        .into_iter()
        .find(|a| a.name() == name)
        .expect("known algorithm")
}

/// The `key id:` / `keyhash:` line of keygen's stdout or pubkey's stderr.
fn identity_line(text: &str) -> String {
    text.lines()
        .find(|l| l.starts_with("key id: ") || l.starts_with("keyhash: "))
        .unwrap_or_else(|| panic!("no key id / keyhash line in:\n{text}"))
        .to_owned()
}

fn write_passphrase_file(dir: &Path) -> PathBuf {
    let path = dir.join("passphrase.txt");
    let mut contents = PASSPHRASE.to_vec();
    contents.push(b'\n');
    std::fs::write(&path, contents).expect("write passphrase file");
    path
}

/// Sign a 32-byte message with `key`, verify it with the exported public key `spki_pem`
/// (ML-DSA with keelsign's image context), check that a flipped signature or message byte
/// fails, and return the key ID / KEYHASH line of the exported key.
fn sign_and_verify(key: &PrivateKey, spki_pem: &str) -> String {
    use ml_dsa::{MlDsa44, MlDsa65};
    let msg = [0x5au8; 32];
    let mut bad_msg = msg;
    bad_msg[31] ^= 1;
    let ctx = keelsign_verify::tlv::MLDSA_CONTEXT;
    macro_rules! mldsa {
        ($k:expr, $p:ty) => {{
            let sig = $k
                .expanded_key()
                .sign_deterministic(&msg, ctx)
                .expect("sign");
            let vk = ml_dsa::VerifyingKey::<$p>::from_public_key_pem(spki_pem).expect("spki");
            assert!(
                vk.verify_with_context(&msg, ctx, &sig),
                "signature verifies"
            );
            assert!(
                !vk.verify_with_context(&bad_msg, ctx, &sig),
                "flipped message"
            );
            let mut enc = sig.encode();
            enc[0] ^= 1;
            if let Some(bad_sig) = ml_dsa::Signature::<$p>::decode(&enc) {
                assert!(
                    !vk.verify_with_context(&msg, ctx, &bad_sig),
                    "flipped signature"
                );
            }
            assert!(!vk.verify_with_context(&msg, b"other-context", &sig));
            format!("key id: {}", hex(&keelsign_verify::key_id_of(&vk.encode())))
        }};
    }
    match key {
        PrivateKey::MlDsa44(k) => mldsa!(k, MlDsa44),
        PrivateKey::MlDsa65(k) => mldsa!(k, MlDsa65),
        PrivateKey::Ed25519(k) => {
            use ed25519_dalek::Signer as _;
            let sig = k.sign(&msg);
            let vk = ed25519_dalek::VerifyingKey::from_public_key_pem(spki_pem).expect("spki");
            vk.verify_strict(&msg, &sig).expect("signature verifies");
            assert!(vk.verify_strict(&bad_msg, &sig).is_err(), "flipped message");
            let mut bytes = sig.to_bytes();
            bytes[0] ^= 1;
            let bad_sig = ed25519_dalek::Signature::from_bytes(&bytes);
            assert!(
                vk.verify_strict(&msg, &bad_sig).is_err(),
                "flipped signature"
            );
            format!(
                "keyhash: {}",
                hex(&keelsign_verify::keyhash_of(&vk.to_bytes()))
            )
        }
        PrivateKey::LmsHss(k) => {
            // Rebuild the caches keygen started the state file with, sign leaf 0 and
            // verify against the exported RFC 8708 public key.
            let (rebuilt, caches) = keelsign::lms_sign::HssPrivateKey::from_levels(
                k.trees().to_vec(),
                keelsign::lms_sign::DEFAULT_CACHE_FLOOR,
                None,
            )
            .expect("rebuild");
            assert_eq!(rebuilt.public_key(), k.public_key());
            let public = keelsign::keys::PublicKey::from_bytes(spki_pem.as_bytes()).expect("spki");
            let sig = k.sign(0, &msg, &caches, None).expect("sign");
            keelsign_verify::lms::verify(public.raw(), &msg, &sig).expect("signature verifies");
            assert!(keelsign_verify::lms::verify(public.raw(), &bad_msg, &sig).is_err());
            let mut bad_sig = sig.clone();
            let last = bad_sig.len() - 1;
            bad_sig[last] ^= 1;
            assert!(keelsign_verify::lms::verify(public.raw(), &msg, &bad_sig).is_err());
            format!("key id: {}", hex(&keelsign_verify::key_id_of(public.raw())))
        }
    }
}

#[test]
fn keygen_roundtrip_sign_verify_each_algorithm() {
    let dir = scratch("roundtrip");
    for alg in ALGS {
        let key_path = dir.join(format!("{alg}.pem"));
        let out = keelsign(&[&"keygen", &"--alg", &alg, &"--out", &key_path]);
        assert_exit(&out, 0);
        let printed = stdout(&out);
        assert!(
            printed.contains(&format!("algorithm: {alg}\n")),
            "{printed}"
        );
        assert!(printed.contains("(PKCS#8 PEM, not encrypted)"), "{printed}");
        let key_file = std::fs::read(&key_path).expect("read key");
        assert!(key_file.starts_with(b"-----BEGIN PRIVATE KEY-----\n"));

        // pubkey to stdout and to a file give the same PEM.
        let out = keelsign(&[&"pubkey", &"--key", &key_path]);
        assert_exit(&out, 0);
        let spki_pem = stdout(&out);
        assert!(spki_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(identity_line(&stderr(&out)), identity_line(&printed));
        let pub_path = dir.join(format!("{alg}.pub.pem"));
        let out = keelsign(&[
            &"pubkey", &"--key", &key_path, &"--alg", &alg, &"--out", &pub_path,
        ]);
        assert_exit(&out, 0);
        assert_eq!(std::fs::read_to_string(&pub_path).expect("pub"), spki_pem);

        let key = PrivateKey::from_bytes(&key_file, None).expect("load generated key");
        assert_eq!(key.algorithm(), algorithm(alg));
        assert_eq!(key.public_key_spki_pem().expect("spki"), spki_pem);
        let exported_identity = sign_and_verify(&key, &spki_pem);
        assert_eq!(identity_line(&printed), exported_identity);
    }
}

#[test]
fn keygen_roundtrip_encrypted_each_algorithm() {
    let dir = scratch("encrypted");
    let pw_file = write_passphrase_file(&dir);
    for alg in ALGS {
        let key_path = dir.join(format!("{alg}.pem"));
        let out = keelsign(&[
            &"keygen",
            &"--alg",
            &alg,
            &"--out",
            &key_path,
            &"--passphrase-file",
            &pw_file,
        ]);
        assert_exit(&out, 0);
        let printed = stdout(&out);
        assert!(printed.contains("(PKCS#8 PEM, encrypted)"), "{printed}");
        let key_file = std::fs::read(&key_path).expect("read key");
        assert!(key_file.starts_with(b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));

        // One algorithm takes the passphrase from the environment.
        let out = if alg == "ml-dsa-65" {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_keelsign"));
            cmd.args(["pubkey", "--key"])
                .arg(&key_path)
                .args(["--passphrase-env", "KEELSIGN_TEST_PW"])
                .env(
                    "KEELSIGN_TEST_PW",
                    std::str::from_utf8(PASSPHRASE).expect("UTF-8"),
                );
            cmd.output().expect("run keelsign")
        } else {
            keelsign(&[
                &"pubkey",
                &"--key",
                &key_path,
                &"--passphrase-file",
                &pw_file,
            ])
        };
        assert_exit(&out, 0);
        let spki_pem = stdout(&out);
        assert_eq!(identity_line(&stderr(&out)), identity_line(&printed));

        let key = PrivateKey::from_bytes(&key_file, Some(PASSPHRASE)).expect("decrypt key");
        assert_eq!(key.algorithm(), algorithm(alg));
        assert_eq!(identity_line(&printed), sign_and_verify(&key, &spki_pem));
    }
}

#[test]
fn der_format_roundtrip() {
    let dir = scratch("der");
    let pw_file = write_passphrase_file(&dir);
    for alg in ALGS {
        for encrypted in [false, true] {
            let key_path = dir.join(format!("{alg}-{encrypted}.der"));
            let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
                &"keygen",
                &"--alg",
                &alg,
                &"--out",
                &key_path,
                &"--format",
                &"der",
            ];
            if encrypted {
                args.extend([&"--passphrase-file" as &dyn AsRef<_>, &pw_file]);
            }
            let out = keelsign(&args);
            assert_exit(&out, 0);
            let expected = if encrypted {
                "(PKCS#8 DER, encrypted)"
            } else {
                "(PKCS#8 DER, not encrypted)"
            };
            assert!(stdout(&out).contains(expected), "{}", stdout(&out));
            let key_file = std::fs::read(&key_path).expect("read key");
            assert_eq!(key_file.first(), Some(&0x30), "DER SEQUENCE");

            let pub_path = dir.join(format!("{alg}-{encrypted}.pub.der"));
            let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![
                &"pubkey",
                &"--key",
                &key_path,
                &"--out",
                &pub_path,
                &"--format",
                &"der",
            ];
            if encrypted {
                args.extend([&"--passphrase-file" as &dyn AsRef<_>, &pw_file]);
            }
            assert_exit(&keelsign(&args), 0);

            let key =
                PrivateKey::from_bytes(&key_file, encrypted.then_some(PASSPHRASE)).expect("load");
            assert_eq!(key.algorithm(), algorithm(alg));
            let spki = std::fs::read(&pub_path).expect("read pub");
            assert_eq!(spki, key.public_key_spki_der().expect("spki").as_bytes());
            if !encrypted {
                assert_eq!(key_file, key.to_pkcs8_der().expect("der").as_bytes());
            }
        }
    }
    // DER is never written to the terminal.
    let key_path = dir.join("ed25519-false.der");
    let out = keelsign(&[&"pubkey", &"--key", &key_path, &"--format", &"der"]);
    assert_exit(&out, 2);
    assert!(stderr(&out).contains("--out"), "{}", stderr(&out));
    assert!(out.stdout.is_empty());
}

#[test]
fn keygen_rejects_unknown_algorithm() {
    let dir = scratch("unknown_alg");
    let key_path = dir.join("lms.pem");
    let out = keelsign(&[&"keygen", &"--alg", &"lms", &"--out", &key_path]);
    assert_exit(&out, 2);
    let err = stderr(&out);
    for alg in ALGS {
        assert!(err.contains(alg), "stderr lists {alg}:\n{err}");
    }
    assert!(err.contains("lms"), "{err}");
    assert!(!key_path.exists(), "no key file is written");
}

#[cfg(unix)]
#[test]
fn private_key_is_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |p: &Path| std::fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    let dir = scratch("mode");
    let pw_file = write_passphrase_file(&dir);

    let plain = dir.join("plain.pem");
    assert_exit(
        &keelsign(&[&"keygen", &"--alg", &"ed25519", &"--out", &plain]),
        0,
    );
    assert_eq!(mode(&plain), 0o600, "plain key");

    let encrypted = dir.join("encrypted.pem");
    assert_exit(
        &keelsign(&[
            &"keygen",
            &"--alg",
            &"ml-dsa-44",
            &"--out",
            &encrypted,
            &"--passphrase-file",
            &pw_file,
        ]),
        0,
    );
    assert_eq!(mode(&encrypted), 0o600, "encrypted key");

    let der = dir.join("key.der");
    assert_exit(
        &keelsign(&[
            &"keygen",
            &"--alg",
            &"ml-dsa-65",
            &"--out",
            &der,
            &"--format",
            &"der",
        ]),
        0,
    );
    assert_eq!(mode(&der), 0o600, "DER key");

    // A world-readable file replaced with --force becomes 0600.
    let replaced = dir.join("replaced.pem");
    std::fs::write(&replaced, b"old").expect("write");
    std::fs::set_permissions(&replaced, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    assert_eq!(mode(&replaced), 0o644);
    assert_exit(
        &keelsign(&[
            &"keygen", &"--alg", &"ed25519", &"--out", &replaced, &"--force",
        ]),
        0,
    );
    assert_eq!(mode(&replaced), 0o600, "key replaced with --force");
}

#[test]
fn overwrite_without_force_fails_with_force_succeeds() {
    let dir = scratch("overwrite");
    let key_path = dir.join("key.pem");
    let out = keelsign(&[&"keygen", &"--alg", &"ml-dsa-44", &"--out", &key_path]);
    assert_exit(&out, 0);
    let first_id = identity_line(&stdout(&out));
    let before = std::fs::read(&key_path).expect("read");
    let mtime = std::fs::metadata(&key_path)
        .expect("metadata")
        .modified()
        .expect("mtime");

    let out = keelsign(&[&"keygen", &"--alg", &"ml-dsa-44", &"--out", &key_path]);
    assert_exit(&out, 3);
    let err = stderr(&out);
    assert!(err.contains(&key_path.display().to_string()), "{err}");
    assert!(err.contains("--force"), "{err}");
    assert!(out.stdout.is_empty());
    assert_eq!(std::fs::read(&key_path).expect("read"), before, "unchanged");
    assert_eq!(
        std::fs::metadata(&key_path)
            .expect("metadata")
            .modified()
            .expect("mtime"),
        mtime
    );

    let out = keelsign(&[
        &"keygen",
        &"--alg",
        &"ml-dsa-44",
        &"--out",
        &key_path,
        &"--force",
    ]);
    assert_exit(&out, 0);
    assert_ne!(identity_line(&stdout(&out)), first_id, "a new key");
    assert_ne!(std::fs::read(&key_path).expect("read"), before);

    // The same rule for `pubkey --out`.
    let pub_path = dir.join("key.pub.pem");
    assert_exit(
        &keelsign(&[&"pubkey", &"--key", &key_path, &"--out", &pub_path]),
        0,
    );
    let pub_before = std::fs::read(&pub_path).expect("read");
    let other_key = dir.join("other.pem");
    assert_exit(
        &keelsign(&[&"keygen", &"--alg", &"ml-dsa-44", &"--out", &other_key]),
        0,
    );
    let out = keelsign(&[&"pubkey", &"--key", &other_key, &"--out", &pub_path]);
    assert_exit(&out, 3);
    let err = stderr(&out);
    assert!(
        err.contains(&pub_path.display().to_string()) && err.contains("--force"),
        "{err}"
    );
    assert_eq!(std::fs::read(&pub_path).expect("read"), pub_before);
    let out = keelsign(&[
        &"pubkey", &"--key", &other_key, &"--out", &pub_path, &"--force",
    ]);
    assert_exit(&out, 0);
    assert_ne!(std::fs::read(&pub_path).expect("read"), pub_before);

    // No temporary files are left behind.
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["key.pem", "key.pub.pem", "other.pem"]);
}

#[test]
fn wrong_passphrase_is_a_clear_error() {
    let dir = scratch("wrong_passphrase");
    let pw_file = write_passphrase_file(&dir);
    let wrong = dir.join("wrong.txt");
    std::fs::write(&wrong, b"Tr0ub4dor&3\n").expect("write");
    for alg in ALGS {
        let key_path = dir.join(format!("{alg}.pem"));
        assert_exit(
            &keelsign(&[
                &"keygen",
                &"--alg",
                &alg,
                &"--out",
                &key_path,
                &"--passphrase-file",
                &pw_file,
            ]),
            0,
        );
        let pub_path = dir.join(format!("{alg}.pub.pem"));
        let out = keelsign(&[
            &"pubkey",
            &"--key",
            &key_path,
            &"--out",
            &pub_path,
            &"--passphrase-file",
            &wrong,
        ]);
        assert_exit(&out, 4);
        let err = stderr(&out);
        assert!(err.contains("wrong passphrase"), "{err}");
        assert!(err.contains(&key_path.display().to_string()), "{err}");
        assert!(!pub_path.exists(), "no output file");
        assert!(out.stdout.is_empty());
    }
}

#[test]
fn missing_or_unexpected_passphrase_is_a_clear_error() {
    let dir = scratch("passphrase_presence");
    let pw_file = write_passphrase_file(&dir);
    let encrypted = dir.join("encrypted.pem");
    assert_exit(
        &keelsign(&[
            &"keygen",
            &"--alg",
            &"ed25519",
            &"--out",
            &encrypted,
            &"--passphrase-file",
            &pw_file,
        ]),
        0,
    );
    let out = keelsign(&[&"pubkey", &"--key", &encrypted]);
    assert_exit(&out, 4);
    let err = stderr(&out);
    assert!(err.contains("is encrypted"), "{err}");
    assert!(err.contains(&encrypted.display().to_string()), "{err}");

    let plain = dir.join("plain.pem");
    assert_exit(
        &keelsign(&[&"keygen", &"--alg", &"ed25519", &"--out", &plain]),
        0,
    );
    let out = keelsign(&[&"pubkey", &"--key", &plain, &"--passphrase-file", &pw_file]);
    assert_exit(&out, 4);
    let err = stderr(&out);
    assert!(err.contains("not encrypted"), "{err}");
    assert!(err.contains(&plain.display().to_string()), "{err}");

    // An empty passphrase is a usage error, and no key is written.
    let empty = dir.join("empty.txt");
    std::fs::write(&empty, b"\n").expect("write");
    let key_path = dir.join("never.pem");
    let out = keelsign(&[
        &"keygen",
        &"--alg",
        &"ed25519",
        &"--out",
        &key_path,
        &"--passphrase-file",
        &empty,
    ]);
    assert_exit(&out, 2);
    assert!(stderr(&out).contains("empty"), "{}", stderr(&out));
    assert!(!key_path.exists());

    // So is an unset passphrase variable.
    let out = keelsign(&[
        &"keygen",
        &"--alg",
        &"ed25519",
        &"--out",
        &key_path,
        &"--passphrase-env",
        &"KEELSIGN_TEST_PW",
    ]);
    assert_exit(&out, 2);
    assert!(
        stderr(&out).contains("KEELSIGN_TEST_PW"),
        "{}",
        stderr(&out)
    );
    assert!(!key_path.exists());
}

/// `der` (a PKCS#8 `EncryptedPrivateKeyInfo` with PBES2) with its PBES2 parameters
/// changed by `edit`, re-encoded.
fn reencode_encrypted(
    der: &[u8],
    edit: impl FnOnce(&mut pkcs8::pkcs5::pbes2::Parameters),
) -> Vec<u8> {
    use pkcs8::der::{Decode as _, Encode as _};
    let encrypted = pkcs8::EncryptedPrivateKeyInfoRef::from_der(der).expect("parse");
    let mut scheme = encrypted.encryption_algorithm.clone();
    let pkcs8::pkcs5::EncryptionScheme::Pbes2(params) = &mut scheme else {
        panic!("keygen writes PBES2");
    };
    edit(params);
    pkcs8::EncryptedPrivateKeyInfo {
        encryption_algorithm: scheme,
        encrypted_data: encrypted.encrypted_data,
    }
    .to_der()
    .expect("encode")
}

/// Deterministic pseudo-random bytes (64-bit LCG).
fn noise(len: usize) -> Vec<u8> {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..len)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 56) as u8
        })
        .collect()
}

#[test]
fn corrupt_key_file_is_a_clear_error() {
    let dir = scratch("corrupt");
    let pw_file = write_passphrase_file(&dir);
    let gen_key = |name: &str, alg: &str, extra: &[&dyn AsRef<std::ffi::OsStr>]| {
        let path = dir.join(name);
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> =
            vec![&"keygen", &"--alg", &alg, &"--out", &path];
        args.extend_from_slice(extra);
        assert_exit(&keelsign(&args), 0);
        std::fs::read(&path).expect("read")
    };
    let good_pem = gen_key("good.pem", "ml-dsa-44", &[]);
    let good_der = gen_key("good.der", "ed25519", &[&"--format", &"der"]);
    let encrypted_pem = gen_key("enc.pem", "ed25519", &[&"--passphrase-file", &pw_file]);
    let pub_pem = keelsign(&[&"pubkey", &"--key", &dir.join("good.pem")]).stdout;

    let mut flipped = good_pem.clone();
    // The first base64 character after the header encodes the outer SEQUENCE tag.
    let body = b"-----BEGIN PRIVATE KEY-----\n".len();
    flipped[body] = if flipped[body] == b'M' { b'N' } else { b'M' };

    let mut der_trailing = good_der.clone();
    der_trailing.push(0);

    // ML-DSA-44 PKCS#8 whose private key is RFC 9881 `both` (starts 0x30) or
    // `expandedKey` (starts 0x04).
    let mldsa_both = vec![
        0x30, 0x14, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, 0x11, 0x04, 0x02, 0x30, 0x00,
    ];
    let mut mldsa_expanded = mldsa_both.clone();
    mldsa_expanded[20] = 0x04;
    // ML-DSA-44 seed key with NULL AlgorithmIdentifier parameters.
    let mut mldsa_null_params = vec![
        0x30, 0x36, 0x02, 0x01, 0x00, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, 0x11, 0x05, 0x00, 0x04, 0x22, 0x80, 0x20,
    ];
    mldsa_null_params.extend_from_slice(&[7u8; 32]);
    // Ed25519 PKCS#8 v2 whose public key belongs to a different private key (the RFC 8410
    // example public key next to the seed 0x01 * 32).
    let mut ed25519_mismatch = vec![
        0x30, 0x51, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    ed25519_mismatch.extend_from_slice(&[1u8; 32]);
    ed25519_mismatch.extend_from_slice(&[0x81, 0x21, 0x00]);
    ed25519_mismatch.extend_from_slice(&[
        0x19, 0xbf, 0x44, 0x09, 0x69, 0x84, 0xcd, 0xfe, 0x85, 0x41, 0xba, 0xc1, 0x67, 0xdc, 0x3b,
        0x96, 0xc8, 0x50, 0x86, 0xaa, 0x30, 0xb6, 0xb6, 0xcb, 0x0c, 0x5c, 0x38, 0xad, 0x70, 0x31,
        0x66, 0xe1,
    ]);
    // ML-DSA-44 PKCS#8 v2: a valid seed with a publicKey that is not its public key.
    let mut mldsa_v2_bad_public = vec![
        0x30, 0x3b, 0x02, 0x01, 0x01, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, 0x11, 0x04, 0x22, 0x80, 0x20,
    ];
    mldsa_v2_bad_public.extend_from_slice(&[7u8; 32]);
    mldsa_v2_bad_public.extend_from_slice(&[0x81, 0x05, 0x00, b'G', b'A', b'R', b'B']);

    // Encrypted keys whose KDF parameters are out of range or whose scheme is not PBES2,
    // re-encoded from a generated encrypted DER key.
    let encrypted_der = gen_key(
        "enc.der",
        "ed25519",
        &[&"--format", &"der", &"--passphrase-file", &pw_file],
    );
    let scrypt = |n: u64, r: u16, p: u16| {
        reencode_encrypted(&encrypted_der, |params| {
            let pkcs8::pkcs5::pbes2::Kdf::Scrypt(scrypt) = &mut params.kdf else {
                panic!("keygen writes scrypt");
            };
            scrypt.cost_parameter = n;
            scrypt.block_size = r;
            scrypt.parallelization = p;
        })
    };
    let pbkdf2_over_cap = reencode_encrypted(&encrypted_der, |params| {
        let pkcs8::pkcs5::pbes2::Kdf::Scrypt(scrypt) = &params.kdf else {
            panic!("keygen writes scrypt");
        };
        params.kdf = pkcs8::pkcs5::pbes2::Kdf::Pbkdf2(pkcs8::pkcs5::pbes2::Pbkdf2Params {
            salt: scrypt.salt,
            iteration_count: 10_000_001,
            key_length: None,
            prf: pkcs8::pkcs5::pbes2::Pbkdf2Prf::HmacWithSha256,
        });
    });
    let pbkdf2_sha1 = reencode_encrypted(&encrypted_der, |params| {
        let pkcs8::pkcs5::pbes2::Kdf::Scrypt(scrypt) = &params.kdf else {
            panic!("keygen writes scrypt");
        };
        params.kdf = pkcs8::pkcs5::pbes2::Kdf::Pbkdf2(pkcs8::pkcs5::pbes2::Pbkdf2Params {
            salt: scrypt.salt,
            iteration_count: 2048,
            key_length: None,
            prf: pkcs8::pkcs5::pbes2::Pbkdf2Prf::HmacWithSha1,
        });
    });
    // PBES1 (pbeWithSHA1AndDES-CBC, 1.2.840.113549.1.5.10): patch the last byte of the
    // PBES2 OID (1.2.840.113549.1.5.13).
    let pbes2_oid = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d,
    ];
    let at = encrypted_der
        .windows(pbes2_oid.len())
        .position(|w| w == pbes2_oid)
        .expect("PBES2 OID");
    let mut pbes1 = encrypted_der.clone();
    pbes1[at + pbes2_oid.len() - 1] = 0x0a;

    let ecdsa = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../tests/fixtures/images/keys/ecdsa-p256-test-key.pem"),
    )
    .expect("read ECDSA fixture");

    // (file name, contents, pass the passphrase, expected reason in stderr)
    let cases: Vec<(&str, Vec<u8>, bool, &str)> = vec![
        ("empty.pem", Vec::new(), false, "empty"),
        (
            "noise.bin",
            noise(64),
            false,
            "neither a PEM file nor a DER",
        ),
        (
            "truncated.pem",
            good_pem[..good_pem.len() / 2].to_vec(),
            false,
            "invalid PEM",
        ),
        ("flipped.pem", flipped, false, "corrupt"),
        (
            "public.pem",
            pub_pem,
            false,
            "public key, not a private key",
        ),
        ("trailing.der", der_trailing, false, "corrupt"),
        (
            "truncated-encrypted.pem",
            encrypted_pem[..encrypted_pem.len() - 40].to_vec(),
            true,
            "invalid PEM",
        ),
        ("ecdsa.pem", ecdsa, false, "unsupported key algorithm"),
        ("mldsa-both.der", mldsa_both, false, "seed"),
        ("mldsa-expanded.der", mldsa_expanded, false, "seed"),
        (
            "mldsa-null-params.der",
            mldsa_null_params,
            false,
            "parameters",
        ),
        (
            "ed25519-mismatch.der",
            ed25519_mismatch,
            false,
            "does not match",
        ),
        (
            "mldsa-v2-bad-public.der",
            mldsa_v2_bad_public,
            false,
            "public key in the file does not match the private key",
        ),
        ("scrypt-n0.der", scrypt(0, 8, 1), true, "scrypt cost N = 0"),
        ("scrypt-n3.der", scrypt(3, 8, 1), true, "scrypt cost N = 3"),
        (
            "scrypt-n2p21.der",
            scrypt(1 << 21, 8, 1),
            true,
            "scrypt cost N = 2097152",
        ),
        (
            "scrypt-rp-overflow.der",
            scrypt(1 << 14, u16::MAX, u16::MAX),
            true,
            "scrypt block size r = 65535",
        ),
        (
            "scrypt-1gib.der",
            scrypt(1 << 20, 8, 1),
            true,
            "scrypt needs 128·r·N = 1024 MiB",
        ),
        (
            "pbkdf2-sha1.der",
            pbkdf2_sha1,
            true,
            "unsupported PBKDF2 PRF; keelsign reads HMAC-SHA-256",
        ),
        (
            "scrypt-p-over-cap.der",
            scrypt(1 << 14, 8, 17),
            true,
            "scrypt parallelization p = 17",
        ),
        (
            "pbkdf2-over-cap.der",
            pbkdf2_over_cap,
            true,
            "PBKDF2 iteration count 10000001",
        ),
        ("pbes1.der", pbes1, true, "unsupported encryption scheme"),
    ];
    for (name, contents, with_passphrase, reason) in cases {
        let path = dir.join(name);
        std::fs::write(&path, &contents).expect("write case");
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"pubkey", &"--key", &path];
        if with_passphrase {
            args.extend([&"--passphrase-file" as &dyn AsRef<_>, &pw_file]);
        }
        let out = keelsign(&args);
        assert_exit(&out, 5);
        let err = stderr(&out);
        assert!(
            err.contains(&path.display().to_string()),
            "{name}: path in stderr:\n{err}"
        );
        assert!(err.contains(reason), "{name}: `{reason}` in stderr:\n{err}");
        assert!(out.stdout.is_empty(), "{name}: no output");
    }
}

#[test]
fn algorithm_mismatch_is_a_clear_error() {
    let dir = scratch("mismatch");
    for (alg, wrong) in [
        ("ml-dsa-44", "ml-dsa-65"),
        ("ml-dsa-65", "ed25519"),
        ("ed25519", "ml-dsa-44"),
    ] {
        let key_path = dir.join(format!("{alg}.pem"));
        assert_exit(
            &keelsign(&[&"keygen", &"--alg", &alg, &"--out", &key_path]),
            0,
        );
        let pub_path = dir.join(format!("{alg}.pub.pem"));
        let out = keelsign(&[
            &"pubkey", &"--key", &key_path, &"--alg", &wrong, &"--out", &pub_path,
        ]);
        assert_exit(&out, 6);
        let err = stderr(&out);
        assert!(err.contains(alg) && err.contains(wrong), "{err}");
        assert!(err.contains(&key_path.display().to_string()), "{err}");
        assert!(!pub_path.exists());
    }
}

#[test]
fn oversized_key_and_passphrase_files_are_refused() {
    let dir = scratch("oversized");
    let big = dir.join("big.pem");
    let mut contents = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
    contents.resize(1024 * 1024 + 1, b'A');
    std::fs::write(&big, &contents).expect("write");
    let out = keelsign(&[&"pubkey", &"--key", &big]);
    assert_exit(&out, 5);
    assert!(
        stderr(&out).contains("larger than 1 MiB"),
        "{}",
        stderr(&out)
    );

    // The same cap for a passphrase file; no key is written.
    let key_path = dir.join("never.pem");
    let out = keelsign(&[
        &"keygen",
        &"--alg",
        &"ed25519",
        &"--out",
        &key_path,
        &"--passphrase-file",
        &big,
    ]);
    assert_exit(&out, 2);
    assert!(
        stderr(&out).contains("larger than 1 MiB"),
        "{}",
        stderr(&out)
    );
    assert!(!key_path.exists());

    // A device that never ends is read only up to the cap.
    #[cfg(unix)]
    {
        let out = keelsign(&[&"pubkey", &"--key", &"/dev/zero"]);
        assert_exit(&out, 5);
        assert!(
            stderr(&out).contains("larger than 1 MiB"),
            "{}",
            stderr(&out)
        );
    }
}

#[test]
fn pubkey_refuses_to_overwrite_its_own_key() {
    let dir = scratch("same_file");
    let key_path = dir.join("key.pem");
    assert_exit(
        &keelsign(&[&"keygen", &"--alg", &"ed25519", &"--out", &key_path]),
        0,
    );
    let before = std::fs::read(&key_path).expect("read");
    let out = keelsign(&[
        &"pubkey", &"--key", &key_path, &"--out", &key_path, &"--force",
    ]);
    assert_exit(&out, 2);
    assert!(stderr(&out).contains("is the key file"), "{}", stderr(&out));
    assert_eq!(std::fs::read(&key_path).expect("read"), before);

    // Also through a symlink to the key.
    #[cfg(unix)]
    {
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&key_path, &link).expect("symlink");
        let out = keelsign(&[&"pubkey", &"--key", &key_path, &"--out", &link, &"--force"]);
        assert_exit(&out, 2);
        assert_eq!(std::fs::read(&key_path).expect("read"), before);
    }
}

#[cfg(unix)]
#[test]
fn dangling_symlink_at_out_is_refused() {
    let dir = scratch("dangling");
    let link = dir.join("key.pem");
    let target = dir.join("nonexistent");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let out = keelsign(&[&"keygen", &"--alg", &"ed25519", &"--out", &link]);
    assert_exit(&out, 3);
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert!(!target.exists(), "nothing is written through the link");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("link")
            .file_type()
            .is_symlink()
    );
}

#[cfg(unix)]
#[test]
fn force_replaces_a_symlink_not_its_target() {
    let dir = scratch("force_symlink");
    let target = dir.join("target.txt");
    std::fs::write(&target, b"secret-target\n").expect("write");
    let link = dir.join("key.pem");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    let out = keelsign(&[&"keygen", &"--alg", &"ed25519", &"--out", &link, &"--force"]);
    assert_exit(&out, 0);
    assert_eq!(std::fs::read(&target).expect("read"), b"secret-target\n");
    let meta = std::fs::symlink_metadata(&link).expect("metadata");
    assert!(
        meta.file_type().is_file(),
        "the link is replaced by the key file"
    );
    let key = std::fs::read(&link).expect("read key");
    PrivateKey::from_bytes(&key, None).expect("a key");
}

#[test]
fn conflicting_passphrase_sources_are_a_usage_error() {
    let dir = scratch("conflicting_passphrase");
    let pw_file = write_passphrase_file(&dir);
    let key_path = dir.join("key.pem");
    let out = keelsign(&[
        &"keygen",
        &"--alg",
        &"ed25519",
        &"--out",
        &key_path,
        &"--passphrase-file",
        &pw_file,
        &"--passphrase-env",
        &"KEELSIGN_TEST_PW",
    ]);
    assert_exit(&out, 2);
    assert!(
        stderr(&out).contains("cannot be used with"),
        "{}",
        stderr(&out)
    );
    assert!(!key_path.exists());
}

#[test]
fn mldsa_v2_key_with_matching_public_key_loads() {
    // ML-DSA-44 seed key (seed 0x07 * 32) as PKCS#8 v2 with its own public key.
    let mut v1 = vec![
        0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
        0x04, 0x03, 0x11, 0x04, 0x22, 0x80, 0x20,
    ];
    v1.extend_from_slice(&[7u8; 32]);
    let public = PrivateKey::from_bytes(&v1, None)
        .expect("v1 seed key")
        .raw_public_key();
    assert_eq!(public.len(), 1312);
    // SEQUENCE (1369) { INTEGER 1, AlgorithmIdentifier, OCTET STRING { [0] seed },
    // [1] IMPLICIT BIT STRING (1313) { 0 unused bits, public key } }.
    let mut v2 = vec![0x30, 0x82, 0x05, 0x59, 0x02, 0x01, 0x01];
    v2.extend_from_slice(&v1[5..]);
    v2.extend_from_slice(&[0x81, 0x82, 0x05, 0x21, 0x00]);
    v2.extend_from_slice(&public);
    assert_eq!(v2.len(), 4 + 0x0559);

    let key = PrivateKey::from_bytes(&v2, None).expect("v2 key with matching public key");
    assert_eq!(key.raw_public_key(), public);

    let dir = scratch("mldsa_v2_matching");
    let path = dir.join("v2.der");
    std::fs::write(&path, &v2).expect("write");
    let out = keelsign(&[&"pubkey", &"--key", &path, &"--alg", &"ml-dsa-44"]);
    assert_exit(&out, 0);
    assert!(stdout(&out).starts_with("-----BEGIN PUBLIC KEY-----\n"));
}

/// SHA-67: `keygen --alg lms-sha256-m32-h10` (PEM, DER, encrypted, two levels) and
/// `pubkey` for LMS/HSS keys; the exported RFC 8708 public key verifies a signature of the
/// key. H15 and H20 take seconds to minutes and are not generated here.
#[test]
fn keygen_lms_h10_rows_round_trip_through_pubkey() {
    let dir = scratch("lms");
    let pw_file = write_passphrase_file(&dir);
    let alg = "lms-sha256-m32-h10";
    for (name, extra, levels) in [
        ("pem", &[][..], 1u32),
        ("der", &["--format", "der"][..], 1),
        ("encrypted", &["--passphrase-file"][..], 1),
        ("l2", &["--hss-levels", "2"][..], 2),
    ] {
        let key_path = dir.join(format!("{name}.key"));
        let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> =
            vec![&"keygen", &"--alg", &alg, &"--out", &key_path];
        for arg in extra {
            args.push(arg);
        }
        if name == "encrypted" {
            args.push(&pw_file);
        }
        let out = keelsign(&args);
        assert_exit(&out, 0);
        let printed = stdout(&out);
        assert!(printed.contains("algorithm: lms-hss\n"), "{printed}");
        let set = if levels == 1 {
            "parameter set: LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=1\n"
        } else {
            "parameter set: LMS_SHA256_M32_H10+LMS_SHA256_M32_H10/LMOTS_SHA256_N32_W8, L=2\n"
        };
        assert!(printed.contains(set), "{printed}");
        // keygen writes the key, then its state file and an empty journal.
        let state = keelsign::lms_state::state_path(&key_path);
        let journal = keelsign::lms_state::journal_path(&key_path);
        let signatures = if levels == 1 { 1024 } else { 1024 * 1024 };
        for line in [
            format!("signatures: {signatures}\n"),
            format!("state: {} (next leaf 0)\n", state.display()),
            format!("journal: {}\n", journal.display()),
        ] {
            assert!(printed.contains(&line), "{line} in:\n{printed}");
        }
        assert!(stderr(&out).contains("stateful"), "{}", stderr(&out));
        let state_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).expect("state")).expect("JSON");
        assert_eq!(state_json["format"], "keelsign-lms-state");
        assert_eq!(state_json["next_leaf"], 0);
        assert_eq!(state_json["leaves"], signatures);
        assert_eq!(
            state_json["levels"].as_array().map(Vec::len),
            Some(levels as usize)
        );
        assert_eq!(std::fs::read(&journal).expect("journal"), b"");

        let mut pub_args: Vec<&dyn AsRef<std::ffi::OsStr>> =
            vec![&"pubkey", &"--key", &key_path, &"--alg", &alg];
        if name == "encrypted" {
            pub_args.push(&"--passphrase-file");
            pub_args.push(&pw_file);
        }
        let out = keelsign(&pub_args);
        assert_exit(&out, 0);
        let spki_pem = stdout(&out);
        assert!(spki_pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(stderr(&out).contains("algorithm: lms-hss\n"));
        assert_eq!(identity_line(&stderr(&out)), identity_line(&printed));
        // `verify --pub` reads it: an RFC 8708 SubjectPublicKeyInfo of an L-level key.
        let public = keelsign::keys::PublicKey::from_bytes(spki_pem.as_bytes()).expect("spki");
        assert_eq!(public.algorithm_name(), "lms-hss");
        assert_eq!(public.raw()[..4], levels.to_be_bytes());

        let key_file = std::fs::read(&key_path).expect("read key");
        let passphrase = (name == "encrypted").then_some(PASSPHRASE);
        let key = PrivateKey::from_bytes(&key_file, passphrase).expect("load generated key");
        assert_eq!(key.algorithm(), KeyAlgorithm::LmsHss);
        if name == "pem" || name == "l2" {
            assert_eq!(identity_line(&printed), sign_and_verify(&key, &spki_pem));
        }
    }

    // An existing state file or journal is never replaced without --force (exit 3).
    let lone = dir.join("lone.pem");
    std::fs::write(keelsign::lms_state::state_path(&lone), b"{}").expect("write");
    let out = keelsign(&[&"keygen", &"--alg", &alg, &"--out", &lone]);
    assert_exit(&out, 3);
    assert!(stderr(&out).contains("lone.pem.state"), "{}", stderr(&out));
    assert!(!lone.exists(), "no key file without its state");
    std::fs::remove_file(keelsign::lms_state::state_path(&lone)).expect("rm");
    std::fs::write(keelsign::lms_state::journal_path(&lone), b"").expect("write");
    assert_exit(&keelsign(&[&"keygen", &"--alg", &alg, &"--out", &lone]), 3);
    let out = keelsign(&[&"keygen", &"--alg", &alg, &"--out", &lone, &"--force"]);
    assert_exit(&out, 0);
    assert!(lone.exists() && keelsign::lms_state::state_path(&lone).exists());

    // `--hss-levels` is for LMS/HSS only, and 1 or 2.
    let out = keelsign(&[
        &"keygen",
        &"--alg",
        &"ml-dsa-44",
        &"--hss-levels",
        &"1",
        &"--out",
        &dir.join("x.pem"),
    ]);
    assert_exit(&out, 2);
    assert!(stderr(&out).contains("--hss-levels"), "{}", stderr(&out));
    for levels in ["0", "3"] {
        let out = keelsign(&[
            &"keygen",
            &"--alg",
            &alg,
            &"--hss-levels",
            &levels,
            &"--out",
            &dir.join("y.pem"),
        ]);
        assert_exit(&out, 2);
    }
    assert!(!dir.join("x.pem").exists() && !dir.join("y.pem").exists());

    // `pubkey --alg` with another family is an algorithm mismatch.
    let out = keelsign(&[
        &"pubkey",
        &"--key",
        &dir.join("pem.key"),
        &"--alg",
        &"ml-dsa-44",
    ]);
    assert_exit(&out, 6);
    assert!(stderr(&out).contains("lms-hss"), "{}", stderr(&out));
}
