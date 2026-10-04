//! Interoperability of `keelsign sign` and `keelsign verify` with MCUboot's imgtool 2.4.0
//! (SHA-51 AC1, AC2, TP1; SHA-53 AC2; SHA-67 LMS/HSS). Ignored by default: they need imgtool
//! on `PATH`.
//! Run with
//!
//! ```sh
//! PATH=/path/to/imgtool-venv/bin:$PATH \
//!     cargo test -p keelsign --locked --test imgtool -- --ignored
//! ```
//!
//! CI installs `imgtool==2.4.0` in a virtual environment and runs them (ci.yml).

mod common;

use common::*;
use keelsign_verify::Policy;
use keelsign_verify::image::Image;
use std::path::Path;
use std::process::{Command, Output};

fn imgtool() -> Command {
    Command::new("imgtool")
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

/// A TLV as (type, len, data hex).
type TlvRow = (u64, u64, String);

/// `imgtool dumpinfo --format json` of `image`, as (protected, unprotected) TLV lists.
fn dumpinfo(image: &Path) -> (Vec<TlvRow>, Vec<TlvRow>) {
    let out = run_ok(imgtool().args(["dumpinfo", "--format", "json"]).arg(image));
    let report: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("dumpinfo --format json writes JSON");
    let list = |key: &str| -> Vec<TlvRow> {
        report["tlv_area"][key]
            .as_array()
            .map(|tlvs| {
                tlvs.iter()
                    .map(|t| {
                        (
                            t["type"].as_u64().expect("type"),
                            t["len"].as_u64().expect("len"),
                            t["data"].as_str().expect("data").to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    (list("tlvs_prot"), list("tlvs"))
}

/// The TLVs keelsign-verify parses, in the same form.
fn parsed(bytes: &[u8]) -> (Vec<TlvRow>, Vec<TlvRow>) {
    let image = Image::parse(bytes).expect("parse");
    let list = |protected: bool| {
        image
            .tlvs()
            .filter(|t| t.protected == protected)
            .map(|t| (u64::from(t.tlv_type), t.value.len() as u64, hex(t.value)))
            .collect()
    };
    (list(true), list(false))
}

fn assert_imgtool_validates(key: &Path, image: &Path) {
    let out = run_ok(imgtool().arg("verify").arg("--key").arg(key).arg(image));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("Image was correctly validated"),
        "imgtool verify {}: {text}",
        image.display()
    );
}

/// AC1 / TP1: images signed by imgtool (Ed25519, RSA-2048, ECDSA P-256) and then by
/// `keelsign sign` still dump with `imgtool dumpinfo`, which lists the keelsign key-ID
/// and PQ TLVs (as vendor TLVs) after every MCUboot TLV; imgtool still validates the
/// Ed25519 image.
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn signed_images_dump_with_imgtool_dumpinfo_and_list_vendor_tlvs() {
    let dir = scratch("imgtool", "dumpinfo");
    for (alg, pq_type, pq_len) in [("ml-dsa-44", 0x4BA1, 2420), ("ml-dsa-65", 0x4BA2, 3309)] {
        let key_path = keygen(&dir, alg, alg, None);
        let key = load_key(&key_path);
        for name in [
            "mcuboot-ed25519.bin",
            "mcuboot-rsa2048.bin",
            "mcuboot-ecdsa-p256.bin",
        ] {
            let output = dir.join(format!("{alg}-{name}"));
            assert_exit(
                &keelsign(&[&"sign", &"--key", &key_path, &fixture_path(name), &output]),
                0,
            );
            let bytes = std::fs::read(&output).expect("read");
            let (protected, unprotected) = dumpinfo(&output);
            assert_eq!(
                (protected.clone(), unprotected.clone()),
                parsed(&bytes),
                "{name}"
            );

            let (in_protected, in_unprotected) = dumpinfo(&fixture_path(name));
            assert_eq!(protected, in_protected, "{name}: protected TLVs unchanged");
            assert_eq!(
                unprotected[..in_unprotected.len()],
                in_unprotected[..],
                "{name}: imgtool's TLVs first, unchanged"
            );
            let added: Vec<(u64, u64)> = unprotected[in_unprotected.len()..]
                .iter()
                .map(|(t, l, _)| (*t, *l))
                .collect();
            assert_eq!(added, [(0x4BA0, 16), (pq_type, pq_len)], "{name}");

            verify(&bytes, Some(&key), None, Policy::PqOnly)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            if name == "mcuboot-ed25519.bin" {
                assert_imgtool_validates(&fixture_path("keys/ed25519-test-key.pem"), &output);
            }
        }
    }
}

/// AC2 / TP1: an unsigned image built by `imgtool sign` (SHA256 TLV only) signed by
/// `keelsign sign --hybrid-key` validates with `imgtool verify` under the keelsign
/// Ed25519 key, and with keelsign-verify under every policy.
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn imgtool_built_unsigned_image_signs_hybrid_and_verifies_with_imgtool() {
    let dir = scratch("imgtool", "hybrid");
    let body: Vec<u8> = (0..1536u32).map(|i| (i * 7 + 3) as u8).collect();
    let body_path = dir.join("body.bin");
    std::fs::write(&body_path, &body).expect("write body");
    let unsigned = dir.join("unsigned.bin");
    run_ok(
        imgtool()
            .args([
                "sign",
                "--header-size",
                "0x200",
                "--pad-header",
                "--align",
                "4",
                "--version",
                "1.2.3+4",
                "--slot-size",
                "0x10000",
            ])
            .arg(&body_path)
            .arg(&unsigned),
    );
    let (_, tlvs) = dumpinfo(&unsigned);
    assert_eq!(
        tlvs.iter().map(|(t, l, _)| (*t, *l)).collect::<Vec<_>>(),
        [(0x10, 32)],
        "imgtool sign without --key writes only the SHA256 TLV"
    );

    for alg in ["ml-dsa-44", "ml-dsa-65"] {
        let pq_path = keygen(&dir, alg, alg, None);
        let ed_path = keygen(&dir, "ed25519", &format!("ed-{alg}"), None);
        let pq = load_key(&pq_path);
        let ed_public = ed25519_public(&load_key(&ed_path));
        let output = dir.join(format!("hybrid-{alg}.bin"));
        assert_exit(
            &keelsign(&[
                &"sign",
                &"--key",
                &pq_path,
                &"--hybrid-key",
                &ed_path,
                &unsigned,
                &output,
            ]),
            0,
        );
        assert_imgtool_validates(&ed_path, &output);
        let (_, tlvs) = dumpinfo(&output);
        let types: Vec<u64> = tlvs.iter().map(|(t, _, _)| *t).collect();
        let pq_type = if alg == "ml-dsa-44" { 0x4BA1 } else { 0x4BA2 };
        assert_eq!(types, [0x10, 0x01, 0x24, 0x4BA0, pq_type]);
        let bytes = std::fs::read(&output).expect("read");
        for policy in [Policy::Hybrid, Policy::ClassicalOnly, Policy::PqOnly] {
            verify(&bytes, Some(&pq), Some(ed_public), policy)
                .unwrap_or_else(|e| panic!("{alg} {policy:?}: {e}"));
        }
    }
}

/// An image built and signed by `imgtool sign` from a fresh body (`--key`, if given).
fn imgtool_sign(dir: &Path, name: &str, key: Option<&Path>) -> std::path::PathBuf {
    let body: Vec<u8> = (0..1536u32).map(|i| (i * 13 + 5) as u8).collect();
    let body_path = dir.join(format!("{name}.body.bin"));
    std::fs::write(&body_path, &body).expect("write body");
    let output = dir.join(name);
    let mut cmd = imgtool();
    cmd.args([
        "sign",
        "--header-size",
        "0x200",
        "--pad-header",
        "--align",
        "4",
        "--version",
        "1.2.3+4",
        "--slot-size",
        "0x10000",
    ]);
    if let Some(key) = key {
        cmd.arg("--key").arg(key);
    }
    run_ok(cmd.arg(&body_path).arg(&output));
    output
}

/// `imgtool getpub -e pem` of `key`, written to `out`.
fn imgtool_getpub_pem(key: &Path, out: &Path) -> std::path::PathBuf {
    let pem = run_ok(imgtool().args(["getpub", "-e", "pem", "-k"]).arg(key));
    std::fs::write(out, &pem.stdout).expect("write getpub output");
    out.to_path_buf()
}

/// SHA-53 AC2: an image signed by `imgtool sign` with a keelsign Ed25519 key verifies with
/// `keelsign verify --policy classical`, trusting either `keelsign pubkey`'s or `imgtool
/// getpub -e pem`'s public key file; a flipped body byte fails both keelsign (exit 9) and
/// `imgtool verify`.
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn imgtool_signed_ed25519_image_round_trips_through_keelsign_verify() {
    let dir = scratch("imgtool", "round_trip");
    let key = keygen(&dir, "ed25519", "ed", None);
    let keelsign_pub = dir.join("ed.pub.pem");
    assert_exit(
        &keelsign(&[&"pubkey", &"--key", &key, &"--out", &keelsign_pub]),
        0,
    );
    let imgtool_pub = imgtool_getpub_pem(&key, &dir.join("ed.imgtool.pub.pem"));
    let signed = imgtool_sign(&dir, "signed.bin", Some(&key));
    assert_imgtool_validates(&key, &signed);
    for public in [&keelsign_pub, &imgtool_pub] {
        let out = keelsign(&[
            &"verify",
            &"--pub",
            public,
            &"--policy",
            &"classical",
            &signed,
        ]);
        assert_exit(&out, 0);
        assert!(
            stdout(&out).contains("policy: classical\n"),
            "{}",
            stdout(&out)
        );
    }

    let mut bytes = std::fs::read(&signed).expect("read");
    bytes[0x200 + 100] ^= 0x01;
    let tampered = dir.join("tampered.bin");
    std::fs::write(&tampered, &bytes).expect("write");
    let out = keelsign(&[
        &"verify",
        &"--pub",
        &keelsign_pub,
        &"--policy",
        &"classical",
        &tampered,
    ]);
    assert_exit(&out, 9);
    assert!(
        stderr(&out).contains("image digest does not match the SHA256 TLV"),
        "{}",
        stderr(&out)
    );
    let out = imgtool()
        .arg("verify")
        .arg("--key")
        .arg(&key)
        .arg(&tampered)
        .output()
        .expect("run imgtool verify");
    assert!(
        !out.status.success(),
        "imgtool verify accepts the tampered image"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("Image was correctly validated"));
}

/// SHA-53: imgtool's RSA-2048 and ECDSA P-256 images carry no Ed25519 signature, so
/// `keelsign verify --policy classical` refuses them (exit 9); an RSA public key file from
/// `imgtool getpub` is not a key keelsign reads (exit 5).
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn rsa_and_ecdsa_imgtool_images_are_not_classically_verifiable_by_keelsign() {
    let dir = scratch("imgtool", "rsa_ecdsa");
    let ed_pub = fixture_path("keys/ed25519-test-key.spki.der");
    for key in ["keys/rsa2048-test-key.pem", "keys/ecdsa-p256-test-key.pem"] {
        let key = fixture_path(key);
        let name = format!("{}.bin", key.file_stem().expect("name").to_string_lossy());
        let signed = imgtool_sign(&dir, &name, Some(&key));
        assert_imgtool_validates(&key, &signed);
        let out = keelsign(&[
            &"verify",
            &"--pub",
            &ed_pub,
            &"--policy",
            &"classical",
            &signed,
        ]);
        assert_exit(&out, 9);
        assert!(
            stderr(&out).contains("Ed25519 half rejected: no ED25519 signature TLV"),
            "{}",
            stderr(&out)
        );
    }
    let rsa_pub = imgtool_getpub_pem(
        &fixture_path("keys/rsa2048-test-key.pem"),
        &dir.join("rsa.pub.pem"),
    );
    let out = keelsign(&[
        &"verify",
        &"--pub",
        &rsa_pub,
        &fixture_path("mcuboot-rsa2048.bin"),
    ]);
    assert_exit(&out, 5);
    assert!(
        stderr(&out).contains("unsupported public key algorithm OID 1.2.840.113549.1.1.1"),
        "{}",
        stderr(&out)
    );
}

/// SHA-53: an unsigned imgtool image signed by `keelsign sign --hybrid-key` validates with
/// `imgtool verify` and with `keelsign verify` (hybrid, inferred; and classical with the
/// `imgtool getpub` key).
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn keelsign_hybrid_output_verifies_with_both_imgtool_and_keelsign_verify() {
    let dir = scratch("imgtool", "hybrid_verify");
    let unsigned = imgtool_sign(&dir, "unsigned.bin", None);
    let pq = keygen(&dir, "ml-dsa-65", "pq", None);
    let ed = keygen(&dir, "ed25519", "ed", None);
    let pq_pub = dir.join("pq.pub.der");
    assert_exit(
        &keelsign(&[
            &"pubkey",
            &"--key",
            &pq,
            &"--format",
            &"der",
            &"--out",
            &pq_pub,
        ]),
        0,
    );
    let ed_pub = imgtool_getpub_pem(&ed, &dir.join("ed.imgtool.pub.pem"));
    let signed = dir.join("hybrid.bin");
    assert_exit(
        &keelsign(&[
            &"sign",
            &"--key",
            &pq,
            &"--hybrid-key",
            &ed,
            &unsigned,
            &signed,
        ]),
        0,
    );
    assert_imgtool_validates(&ed, &signed);
    let out = keelsign(&[&"verify", &"--pub", &pq_pub, &"--pub", &ed_pub, &signed]);
    assert_exit(&out, 0);
    assert!(
        stdout(&out).contains("policy: hybrid (inferred from the keys given)\n"),
        "{}",
        stdout(&out)
    );
    let out = keelsign(&[
        &"verify",
        &"--pub",
        &ed_pub,
        &"--policy",
        &"classical",
        &signed,
    ]);
    assert_exit(&out, 0);
}

/// SHA-67: an imgtool-built image signed by `keelsign sign` with an LMS/HSS key and an
/// Ed25519 `--hybrid-key` validates with `imgtool verify` under the Ed25519 key;
/// `imgtool dumpinfo` lists the key-ID and LMS/HSS TLVs (1,456 bytes for H10) after
/// imgtool's own, and keelsign-verify accepts it under every policy.
#[test]
#[ignore = "needs imgtool 2.4.0 on PATH"]
fn lms_hybrid_image_passes_imgtool_verify() {
    let dir = scratch("imgtool", "lms_hybrid");
    let unsigned = imgtool_sign(&dir, "unsigned.bin", None);
    let lms_path = keygen_lms(&dir, "lms", 1, None);
    let ed_path = keygen(&dir, "ed25519", "ed", None);
    let output = dir.join("hybrid-lms.bin");
    assert_exit(
        &keelsign(&[
            &"sign",
            &"--key",
            &lms_path,
            &"--hybrid-key",
            &ed_path,
            &unsigned,
            &output,
        ]),
        0,
    );
    assert_imgtool_validates(&ed_path, &output);
    let bytes = std::fs::read(&output).expect("read");
    let (protected, tlvs) = dumpinfo(&output);
    assert_eq!((protected, tlvs.clone()), parsed(&bytes));
    let rows: Vec<(u64, u64)> = tlvs.iter().map(|(t, l, _)| (*t, *l)).collect();
    assert_eq!(
        rows,
        [
            (0x10, 32),
            (0x01, 32),
            (0x24, 64),
            (0x4BA0, 16),
            (0x4BA3, 1456)
        ]
    );
    let lms = load_key(&lms_path);
    let ed_public = ed25519_public(&load_key(&ed_path));
    for policy in [Policy::Hybrid, Policy::ClassicalOnly, Policy::PqOnly] {
        verify(&bytes, Some(&lms), Some(ed_public), policy)
            .unwrap_or_else(|e| panic!("{policy:?}: {e}"));
    }
}
