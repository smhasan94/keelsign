//! SHA-53 TP1: every subcommand and every exit code, through the real binary with
//! `assert_cmd`. The codes are fixed in keelsign/src/error.rs and documented in
//! docs/verify.md, docs/keys.md and docs/signing.md.

mod common;

use assert_cmd::assert::Assert;
use common::*;
use predicates::prelude::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The invocations of one test, and the exit codes they produced.
struct Seen {
    dir: PathBuf,
    codes: BTreeSet<i32>,
}

impl Seen {
    fn new(test: &str) -> Self {
        Self {
            dir: scratch("exit_codes", test),
            codes: BTreeSet::new(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// Run `keelsign args`, expect exit `code`, and for a failure an `error:` message on
    /// standard error (that names `needle`) and nothing on standard output.
    #[track_caller]
    fn run(&mut self, args: &[&dyn AsRef<std::ffi::OsStr>], code: i32, needle: &str) -> Assert {
        let mut command = cmd();
        for arg in args {
            command.arg(arg);
        }
        let assert = command.assert().code(code);
        self.codes.insert(code);
        if code == 0 {
            assert.stderr(predicate::str::contains("error:").not())
        } else if code == 2 && needle.is_empty() {
            // clap's own usage errors.
            assert
                .stdout(predicate::str::is_empty())
                .stderr(predicate::str::contains("error:"))
        } else {
            assert
                .stdout(predicate::str::is_empty())
                .stderr(predicate::str::starts_with("error: "))
                .stderr(predicate::str::contains(needle))
        }
    }
}

/// The arguments of one invocation.
type Args<'a> = Vec<&'a dyn AsRef<std::ffi::OsStr>>;

fn write(path: &Path, bytes: &[u8]) -> PathBuf {
    std::fs::write(path, bytes).expect("write");
    path.to_path_buf()
}

#[test]
fn every_exit_code_is_produced_by_a_real_invocation() {
    let mut seen = Seen::new("every_code");
    let key = seen.path("signing.pem");
    let ed = seen.path("ed.pem");
    let encrypted = seen.path("encrypted.pem");
    let pw = write(&seen.path("pw.txt"), b"correct horse\n");
    let wrong_pw = write(&seen.path("wrong.txt"), b"battery staple\n");
    let garbage = write(&seen.path("garbage.bin"), b"not an image, not a key");
    let image = fixture_path("mcuboot-ed25519.bin");
    let signed = seen.path("signed.bin");
    let resigned = seen.path("resigned.bin");
    let public = seen.path("signing.pub.pem");
    let other_public = seen.path("other.pub.pem");
    let missing = seen.path("missing.bin");

    // keygen: 0, 2 (unknown --alg, by clap; empty passphrase), 3.
    seen.run(&[&"keygen", &"--alg", &"ml-dsa-65", &"--out", &key], 0, "");
    seen.run(&[&"keygen", &"--alg", &"ed25519", &"--out", &ed], 0, "");
    seen.run(&[&"keygen", &"--alg", &"rsa", &"--out", &key], 2, "");
    let empty = write(&seen.path("empty.txt"), b"\n");
    seen.run(
        &[
            &"keygen",
            &"--alg",
            &"ml-dsa-44",
            &"--out",
            &seen.path("x.pem"),
            &"--passphrase-file",
            &empty,
        ],
        2,
        "empty",
    );
    seen.run(
        &[&"keygen", &"--alg", &"ml-dsa-65", &"--out", &key],
        3,
        "--force",
    );
    seen.run(
        &[
            &"keygen",
            &"--alg",
            &"ml-dsa-44",
            &"--out",
            &encrypted,
            &"--passphrase-file",
            &pw,
        ],
        0,
        "",
    );

    // pubkey: 0, 4 (missing and wrong passphrase), 5, 6.
    seen.run(&[&"pubkey", &"--key", &key, &"--out", &public], 0, "");
    seen.run(&[&"pubkey", &"--key", &encrypted], 4, "encrypted");
    seen.run(
        &[
            &"pubkey",
            &"--key",
            &encrypted,
            &"--passphrase-file",
            &wrong_pw,
        ],
        4,
        "wrong passphrase",
    );
    seen.run(&[&"pubkey", &"--key", &garbage], 5, "corrupt");
    seen.run(
        &[&"pubkey", &"--key", &key, &"--alg", &"ml-dsa-44"],
        6,
        "--alg ml-dsa-44",
    );

    // sign: 0, 2 (OUT is IN), 6, 7, 8.
    seen.run(&[&"sign", &"--key", &key, &image, &signed], 0, "");
    seen.run(
        &[&"sign", &"--key", &key, &signed, &signed],
        2,
        "is the input image",
    );
    seen.run(&[&"sign", &"--key", &ed, &image, &resigned], 6, "--key");
    seen.run(
        &[&"sign", &"--key", &key, &garbage, &resigned],
        7,
        "not an MCUboot image",
    );
    seen.run(
        &[&"sign", &"--key", &key, &signed, &resigned],
        8,
        "--replace",
    );

    // inspect: 0, 1, 7.
    seen.run(&[&"inspect", &signed], 0, "")
        .stdout(predicate::str::contains("0x4ba0"));
    seen.run(&[&"inspect", &missing], 1, "missing.bin");
    seen.run(&[&"inspect", &garbage], 7, "not an MCUboot image");

    // verify: 0, 1, 2, 5, 7, 9.
    seen.run(&[&"verify", &"--pub", &public, &signed], 0, "")
        .stdout(predicate::str::starts_with("verified: "));
    seen.run(&[&"verify", &"--pub", &public, &missing], 1, "missing.bin");
    seen.run(
        &[&"verify", &"--pub", &seen.path("nope.pem"), &signed],
        1,
        "nope.pem",
    );
    seen.run(&[&"verify", &signed], 2, "");
    seen.run(
        &[
            &"verify",
            &"--pub",
            &public,
            &"--policy",
            &"strict",
            &signed,
        ],
        2,
        "",
    );
    seen.run(
        &[
            &"verify",
            &"--pub",
            &public,
            &"--policy",
            &"hybrid",
            &signed,
        ],
        2,
        "needs an Ed25519 key",
    );
    seen.run(
        &[&"verify", &"--pub", &key, &signed],
        5,
        "holds a private key",
    );
    seen.run(
        &[&"verify", &"--pub", &public, &garbage],
        7,
        "not an MCUboot image",
    );
    seen.run(&[&"pubkey", &"--key", &ed, &"--out", &other_public], 0, "");
    seen.run(
        &[
            &"verify",
            &"--pub",
            &other_public,
            &"--policy",
            &"pq",
            &signed,
        ],
        2,
        "needs a post-quantum key",
    );
    let wrong = seen.path("wrong.pem");
    seen.run(
        &[&"keygen", &"--alg", &"ml-dsa-65", &"--out", &wrong],
        0,
        "",
    );
    let wrong_public = seen.path("wrong.pub.pem");
    seen.run(
        &[&"pubkey", &"--key", &wrong, &"--out", &wrong_public],
        0,
        "",
    );
    seen.run(
        &[&"verify", &"--pub", &wrong_public, &signed],
        9,
        "not verified under policy pq: post-quantum key ID is not in the trusted key set",
    );

    let all: BTreeSet<i32> = (0..=9).collect();
    assert_eq!(seen.codes, all, "every exit code 0..=9 is produced");
}

#[test]
fn every_subcommand_has_a_success_and_a_failure_case() {
    let mut seen = Seen::new("every_subcommand");
    let key = seen.path("k.pem");
    let public = seen.path("k.pub.pem");
    let signed = seen.path("signed.bin");
    let image = fixture_path("mcuboot-ed25519.bin");
    let missing = seen.path("missing");

    // `keelsign` with no command, and --help / --version.
    cmd()
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Usage: keelsign"));
    let help = cmd().arg("--help").output().expect("run --help");
    assert_eq!(help.status.code(), Some(0));
    for command in ["keygen", "pubkey", "sign", "inspect", "verify"] {
        assert!(
            stdout(&help).contains(&format!("  {command} ")),
            "--help lists {command}"
        );
        cmd()
            .args([command, "--help"])
            .assert()
            .code(0)
            .stdout(predicate::str::contains(format!(
                "Usage: keelsign {command}"
            )));
    }
    cmd()
        .arg("--version")
        .assert()
        .code(0)
        .stdout(predicate::str::starts_with("keelsign "));

    let cases: [(&str, Args<'_>, Args<'_>, i32, &str); 5] = [
        (
            "keygen",
            vec![&"keygen", &"--alg", &"ml-dsa-44", &"--out", &key],
            vec![&"keygen", &"--alg", &"ml-dsa-44", &"--out", &key],
            3,
            "refusing to overwrite",
        ),
        (
            "pubkey",
            vec![&"pubkey", &"--key", &key, &"--out", &public],
            vec![&"pubkey", &"--key", &missing],
            1,
            "read key file",
        ),
        (
            "sign",
            vec![&"sign", &"--key", &key, &image, &signed],
            vec![&"sign", &"--key", &key, &image, &signed],
            3,
            "refusing to overwrite",
        ),
        (
            "inspect",
            vec![&"inspect", &"--json", &signed],
            vec![&"inspect", &missing],
            1,
            "read image",
        ),
        (
            "verify",
            vec![&"verify", &"--pub", &public, &signed],
            vec![&"verify", &"--pub", &public, &image],
            9,
            "no post-quantum signature TLV",
        ),
    ];
    for (name, ok, fail, code, needle) in cases {
        seen.run(&ok, 0, "");
        seen.run(&fail, code, needle);
        assert!(seen.codes.contains(&0), "{name}");
    }
}
