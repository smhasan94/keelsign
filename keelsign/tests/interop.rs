//! Interoperability with OpenSSL and MCUboot's imgtool. Ignored by default: they need
//! external tools. Run with
//!
//! ```sh
//! OPENSSL=/path/to/openssl-3.5-or-newer PATH=/path/to/imgtool-venv/bin:$PATH \
//!     cargo test -p keelsign --locked --test interop -- --ignored
//! ```
//!
//! `OPENSSL` defaults to `openssl`. ML-DSA needs OpenSSL 3.5 or newer; imgtool 2.4.0 is
//! the version the image fixtures were made with.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ALGS: [&str; 3] = ["ml-dsa-44", "ml-dsa-65", "ed25519"];

fn openssl() -> Command {
    Command::new(std::env::var_os("OPENSSL").unwrap_or_else(|| "openssl".into()))
}

fn scratch(test: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("interop")
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[track_caller]
fn run_ok(cmd: &mut Command) -> Output {
    let out = cmd
        .output()
        .unwrap_or_else(|e| panic!("could not start {:?}: {e}", cmd.get_program()));
    assert!(
        out.status.success(),
        "{cmd:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn keelsign() -> Command {
    Command::new(env!("CARGO_BIN_EXE_keelsign"))
}

/// Generate `<alg>.pem` (and `<alg>.enc.pem` encrypted under `pw.txt`) in `dir`, and
/// return (key, encrypted key, public key PEM written by `keelsign pubkey`).
fn generate(dir: &Path, alg: &str) -> (PathBuf, PathBuf, String) {
    let pw = dir.join("pw.txt");
    std::fs::write(&pw, b"interop passphrase\n").expect("write passphrase");
    let key = dir.join(format!("{alg}.pem"));
    let enc = dir.join(format!("{alg}.enc.pem"));
    run_ok(keelsign().args(["keygen", "--alg", alg, "--out"]).arg(&key));
    run_ok(
        keelsign()
            .args(["keygen", "--alg", alg, "--out"])
            .arg(&enc)
            .arg("--passphrase-file")
            .arg(&pw),
    );
    let out = run_ok(keelsign().args(["pubkey", "--key"]).arg(&key));
    (key, enc, String::from_utf8(out.stdout).expect("UTF-8"))
}

/// `openssl asn1parse` prints the algorithm OID of every generated file, by name
/// (OpenSSL 3.5+) or in dotted form (older OpenSSL, LibreSSL).
#[test]
#[ignore = "needs openssl ($OPENSSL, default `openssl`)"]
fn generated_files_parse_with_openssl_asn1parse() {
    let dir = scratch("asn1parse");
    for (alg, names) in [
        ("ml-dsa-44", ["ML-DSA-44", "2.16.840.1.101.3.4.3.17"]),
        ("ml-dsa-65", ["ML-DSA-65", "2.16.840.1.101.3.4.3.18"]),
        ("ed25519", ["ED25519", "1.3.101.112"]),
    ] {
        let (key, _, pubkey) = generate(&dir, alg);
        let pub_path = dir.join(format!("{alg}.pub.pem"));
        std::fs::write(&pub_path, pubkey).expect("write public key");
        for file in [&key, &pub_path] {
            let out = run_ok(openssl().arg("asn1parse").arg("-in").arg(file));
            let text = String::from_utf8_lossy(&out.stdout).to_uppercase();
            assert!(
                text.contains("OBJECT") && names.iter().any(|n| text.contains(n)),
                "{}: asn1parse shows none of {names:?}:\n{text}",
                file.display()
            );
        }
    }
}

/// OpenSSL reads every generated private key, plain and encrypted, and derives the same
/// public key as `keelsign pubkey`.
#[test]
#[ignore = "needs OpenSSL 3.5 or newer ($OPENSSL, default `openssl`)"]
fn mldsa_keys_read_by_openssl() {
    let version = run_ok(openssl().arg("version"));
    let version = String::from_utf8_lossy(&version.stdout).into_owned();
    let numbers: Vec<u32> = version
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .split('.')
        .filter_map(|n| n.parse().ok())
        .collect();
    assert!(
        version.starts_with("OpenSSL") && numbers.as_slice() >= [3, 5].as_slice(),
        "ML-DSA needs OpenSSL 3.5 or newer; $OPENSSL is `{}`",
        version.trim()
    );

    let dir = scratch("pkey");
    let pw = dir.join("pw.txt");
    for alg in ALGS {
        let (key, enc, pubkey) = generate(&dir, alg);
        let out = run_ok(openssl().args(["pkey", "-pubout", "-in"]).arg(&key));
        assert_eq!(String::from_utf8_lossy(&out.stdout), pubkey, "{alg}");

        let enc_pub = run_ok(
            keelsign()
                .args(["pubkey", "--key"])
                .arg(&enc)
                .arg("--passphrase-file")
                .arg(&pw),
        );
        let mut passin = std::ffi::OsString::from("file:");
        passin.push(&pw);
        let out = run_ok(
            openssl()
                .args(["pkey", "-pubout", "-in"])
                .arg(&enc)
                .arg("-passin")
                .arg(&passin),
        );
        assert_eq!(out.stdout, enc_pub.stdout, "{alg} (encrypted)");
    }
}

/// imgtool reads a generated Ed25519 key: the same public key, and its KEYHASH is the one
/// keelsign prints.
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn ed25519_key_matches_imgtool() {
    let dir = scratch("imgtool");
    let (key, _, pubkey) = generate(&dir, "ed25519");

    let out = run_ok(
        Command::new("imgtool")
            .args(["getpub", "-e", "pem", "-k"])
            .arg(&key),
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        pubkey.trim(),
        "imgtool getpub"
    );

    let out = run_ok(
        Command::new("imgtool")
            .args(["getpubhash", "-e", "raw", "-k"])
            .arg(&key),
    );
    let keyhash = keelsign::keys::hex(&out.stdout);
    let printed = run_ok(keelsign().args(["pubkey", "--key"]).arg(&key));
    let printed = String::from_utf8_lossy(&printed.stderr).into_owned();
    assert!(
        printed.contains(&format!("keyhash: {keyhash}\n")),
        "imgtool getpubhash {keyhash} vs keelsign:\n{printed}"
    );
}
