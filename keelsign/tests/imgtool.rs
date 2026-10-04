//! Interoperability of `keelsign sign` with MCUboot's imgtool 2.4.0 (SHA-51 AC1, AC2,
//! TP1). Ignored by default: they need imgtool on `PATH`. Run with
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
