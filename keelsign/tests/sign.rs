//! `keelsign sign`, run as the real binary (SHA-51 acceptance criteria and test plan).

mod common;

use common::*;
use keelsign::keys::PrivateKey;
use keelsign_verify::image::{
    IMAGE_TLV_ED25519, IMAGE_TLV_KEYHASH, IMAGE_TLV_SEC_CNT, IMAGE_TLV_SHA256, Image,
};
use keelsign_verify::tlv::{
    TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG, TLV_MLDSA44_SIG, TLV_MLDSA65_SIG,
};
use keelsign_verify::{Policy, key_id_of, keyhash_of};
use std::path::{Path, PathBuf};

const PASSPHRASE: &[u8] = b"sign test passphrase";

fn sign_args(key: &Path, input: &Path, output: &Path, extra: &[&str]) -> std::process::Output {
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"sign", &"--key", &key];
    for e in extra {
        args.push(e);
    }
    args.push(&input);
    args.push(&output);
    keelsign(&args)
}

fn sign_hybrid(
    key: &Path,
    ed: &Path,
    input: &Path,
    output: &Path,
    extra: &[&str],
) -> std::process::Output {
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> =
        vec![&"sign", &"--key", &key, &"--hybrid-key", &ed];
    for e in extra {
        args.push(e);
    }
    args.push(&input);
    args.push(&output);
    keelsign(&args)
}

fn pq_type(alg: &str) -> u16 {
    match alg {
        "ml-dsa-44" => TLV_MLDSA44_SIG,
        "ml-dsa-65" => TLV_MLDSA65_SIG,
        _ => panic!("{alg}"),
    }
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write");
    path
}

/// AC1 / TP1 stand-in: signing imgtool's Ed25519 golden image appends the key ID and the
/// ML-DSA TLV after every MCUboot TLV, keeps everything before them byte-for-byte, and
/// the result verifies under all three policies.
#[test]
fn sign_imgtool_ed25519_golden_adds_pq_tlvs_and_verifies() {
    let dir = scratch("sign", "golden");
    let input = fixture_path("mcuboot-ed25519.bin");
    let in_bytes = fixture("mcuboot-ed25519.bin");
    let in_image = Image::parse(&in_bytes).expect("parse input");
    let hashed_end = in_image.hashed_range().end as usize;
    let unprotected_start = hashed_end + 4;
    let in_unprotected_end = in_image.tlv_end() as usize;
    for alg in ["ml-dsa-44", "ml-dsa-65"] {
        let key_path = keygen(&dir, alg, alg, None);
        let key = load_key(&key_path);
        let output = dir.join(format!("signed-{alg}.bin"));
        let out = sign_args(&key_path, &input, &output, &[]);
        assert_exit(&out, 0);
        let bytes = std::fs::read(&output).expect("read output");
        let image = Image::parse(&bytes).expect("output parses with the E2.1 parser");

        // Header, body and protected area unchanged.
        assert_eq!(bytes[..hashed_end], in_bytes[..hashed_end]);
        assert_eq!(image.header(), in_image.header());
        assert_eq!(image.hashed_range(), in_image.hashed_range());
        assert_eq!(image.tlv_end() as usize, bytes.len());
        // The old unprotected TLVs, byte-for-byte and in order, then key ID and PQ.
        assert_eq!(
            bytes[unprotected_start..in_unprotected_end],
            in_bytes[unprotected_start..in_unprotected_end]
        );
        assert_eq!(
            unprotected_types(&image),
            [
                IMAGE_TLV_SHA256,
                IMAGE_TLV_KEYHASH,
                IMAGE_TLV_ED25519,
                TLV_KEELSIGN_KEY_ID,
                pq_type(alg)
            ]
        );
        let key_id = key_id_of(&key.raw_public_key());
        assert_eq!(unprotected_value(&image, TLV_KEELSIGN_KEY_ID), key_id);

        let ed = Some(ed25519_test_public_key());
        for policy in [Policy::PqOnly, Policy::Hybrid, Policy::ClassicalOnly] {
            verify(&bytes, Some(&key), ed, policy)
                .unwrap_or_else(|e| panic!("{alg} {policy:?}: {e}"));
        }

        let text = stdout(&out);
        let digest_hex = manifest_entry("mcuboot-ed25519.bin")["digest_hex"]
            .as_str()
            .expect("digest_hex")
            .to_owned();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], format!("algorithm: {alg}"));
        assert_eq!(lines[1], format!("key id: {}", hex(&key_id)));
        assert_eq!(lines[2], format!("image digest: {digest_hex}"));
        assert_eq!(
            lines[3],
            format!(
                "signed: {} ({} bytes, +{} bytes of TLVs)",
                output.display(),
                bytes.len(),
                bytes.len() - in_bytes.len()
            )
        );
        assert_eq!(lines.len(), 4, "{text}");
    }
}

/// AC1: images signed by imgtool with RSA-2048 or ECDSA P-256 (and the 200 KiB Ed25519
/// image) keep every MCUboot TLV and gain a verifiable ML-DSA signature.
#[test]
fn sign_preserves_rsa_and_ecdsa_images() {
    let dir = scratch("sign", "rsa_ecdsa");
    let key_path = keygen(&dir, "ml-dsa-44", "pq", None);
    let key = load_key(&key_path);
    for name in [
        "mcuboot-rsa2048.bin",
        "mcuboot-ecdsa-p256.bin",
        "mcuboot-ed25519-200k.bin",
    ] {
        let in_bytes = fixture(name);
        let in_image = Image::parse(&in_bytes).expect("parse");
        let output = dir.join(name);
        assert_exit(&sign_args(&key_path, &fixture_path(name), &output, &[]), 0);
        let bytes = std::fs::read(&output).expect("read");
        let image = Image::parse(&bytes).expect("parse output");
        let hashed_end = in_image.hashed_range().end as usize;
        assert_eq!(
            bytes[..hashed_end],
            in_bytes[..hashed_end],
            "{name}: prefix"
        );
        let (start, end) = (hashed_end + 4, in_bytes.len());
        assert_eq!(bytes[start..end], in_bytes[start..end], "{name}: old TLVs");
        // it_tlv_tot grew, so compare the TLVs, not the info header.
        let before = tlv_list(&in_image);
        let after = tlv_list(&image);
        assert_eq!(after[..before.len()], before[..], "{name}");
        assert_eq!(
            after[before.len()..]
                .iter()
                .map(|(t, p, _)| (*t, *p))
                .collect::<Vec<_>>(),
            [(TLV_KEELSIGN_KEY_ID, false), (TLV_MLDSA44_SIG, false)],
            "{name}"
        );
        let verified = verify(&bytes, Some(&key), None, Policy::PqOnly)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex(&verified.digest), hex(&digest(&in_bytes)));
    }
}

/// AC2: `--hybrid-key` on an image without an Ed25519 pair adds KEYHASH + ED25519 before
/// the key ID and PQ TLV; the SHA256 TLV is untouched and still the digest.
#[test]
fn hybrid_key_adds_ed25519_pair_and_pq_tlv_and_sha256_stays_correct() {
    use ed25519_dalek::Verifier as _;
    let dir = scratch("sign", "hybrid");
    let golden = fixture("mcuboot-ed25519.bin");
    let unsigned = strip_ed25519_pair(&golden);
    let input = write(&dir, "unsigned.bin", &unsigned);
    let unsigned_image = Image::parse(&unsigned).expect("parse stripped");
    assert_eq!(unprotected_types(&unsigned_image), [IMAGE_TLV_SHA256]);

    for alg in ["ml-dsa-44", "ml-dsa-65"] {
        let pq_path = keygen(&dir, alg, alg, None);
        let ed_path = keygen(&dir, "ed25519", &format!("ed-{alg}"), None);
        let pq = load_key(&pq_path);
        let ed = load_key(&ed_path);
        let ed_public = ed25519_public(&ed);
        let output = dir.join(format!("hybrid-{alg}.bin"));
        let out = sign_hybrid(&pq_path, &ed_path, &input, &output, &[]);
        assert_exit(&out, 0);
        let bytes = std::fs::read(&output).expect("read");
        let image = Image::parse(&bytes).expect("parse");
        assert_eq!(
            unprotected_types(&image),
            [
                IMAGE_TLV_SHA256,
                IMAGE_TLV_KEYHASH,
                IMAGE_TLV_ED25519,
                TLV_KEELSIGN_KEY_ID,
                pq_type(alg)
            ]
        );
        let keyhash = keyhash_of(&ed_public);
        assert_eq!(unprotected_value(&image, IMAGE_TLV_KEYHASH), keyhash);
        assert!(
            stdout(&out).contains(&format!("keyhash: {}\n", hex(&keyhash))),
            "{}",
            stdout(&out)
        );

        // The SHA256 TLV is the one imgtool wrote and still the recomputed digest.
        let m = digest(&bytes);
        let sha256 = unprotected_value(&image, IMAGE_TLV_SHA256);
        assert_eq!(sha256, unprotected_value(&unsigned_image, IMAGE_TLV_SHA256));
        assert_eq!(sha256, m);
        assert_eq!(
            hex(&m),
            manifest_entry("mcuboot-ed25519.bin")["digest_hex"]
                .as_str()
                .expect("digest_hex")
        );

        // The Ed25519 signature is RFC 8032 over M.
        let signature =
            ed25519_dalek::Signature::from_slice(unprotected_value(&image, IMAGE_TLV_ED25519))
                .expect("64 bytes");
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&ed_public).expect("key");
        vk.verify_strict(&m, &signature).expect("verify_strict");
        assert!(vk.verify(&[0u8; 32], &signature).is_err());

        for policy in [Policy::Hybrid, Policy::ClassicalOnly, Policy::PqOnly] {
            verify(&bytes, Some(&pq), Some(ed_public), policy)
                .unwrap_or_else(|e| panic!("{alg} {policy:?}: {e}"));
        }
    }
}

/// AC2: an image that already has an Ed25519 pair is refused with `--hybrid-key` (exit 8)
/// unless `--replace`, which swaps the pair for the new key's.
#[test]
fn hybrid_key_refuses_an_image_that_already_has_an_ed25519_pair_unless_replace() {
    let dir = scratch("sign", "hybrid_refuse");
    let pq_path = keygen(&dir, "ml-dsa-65", "pq", None);
    let ed_path = keygen(&dir, "ed25519", "ed", None);
    let pq = load_key(&pq_path);
    let ed_public = ed25519_public(&load_key(&ed_path));
    let input = fixture_path("mcuboot-ed25519.bin");
    let output = dir.join("out.bin");

    let out = sign_hybrid(&pq_path, &ed_path, &input, &output, &[]);
    assert_exit(&out, 8);
    assert!(stderr(&out).contains("Ed25519"), "{}", stderr(&out));
    assert!(stderr(&out).contains("--replace"), "{}", stderr(&out));
    assert!(!output.exists(), "no output on refusal");

    assert_exit(
        &sign_hybrid(&pq_path, &ed_path, &input, &output, &["--replace"]),
        0,
    );
    let bytes = std::fs::read(&output).expect("read");
    let image = Image::parse(&bytes).expect("parse");
    assert_eq!(
        unprotected_types(&image),
        [
            IMAGE_TLV_SHA256,
            IMAGE_TLV_KEYHASH,
            IMAGE_TLV_ED25519,
            TLV_KEELSIGN_KEY_ID,
            TLV_MLDSA65_SIG
        ]
    );
    assert_eq!(
        unprotected_value(&image, IMAGE_TLV_KEYHASH),
        keyhash_of(&ed_public)
    );
    verify(&bytes, Some(&pq), Some(ed_public), Policy::Hybrid).expect("hybrid");
    // imgtool's key no longer verifies the image.
    assert!(
        verify(
            &bytes,
            None,
            Some(ed25519_test_public_key()),
            Policy::ClassicalOnly
        )
        .is_err()
    );
}

/// TP3: re-signing without `--replace` is refused with exit 8 and writes nothing;
/// `--replace` leaves exactly one key ID and one PQ signature TLV.
#[test]
fn signing_twice_without_replace_exits_8_and_replace_yields_exactly_one_pq_tlv() {
    let dir = scratch("sign", "twice");
    let k44_path = keygen(&dir, "ml-dsa-44", "k44", None);
    let k65_path = keygen(&dir, "ml-dsa-65", "k65", None);
    let k44 = load_key(&k44_path);
    let k65 = load_key(&k65_path);
    let once = dir.join("once.bin");
    assert_exit(
        &sign_args(&k44_path, &fixture_path("mcuboot-ed25519.bin"), &once, &[]),
        0,
    );

    let twice = dir.join("twice.bin");
    let out = sign_args(&k44_path, &once, &twice, &[]);
    assert_exit(&out, 8);
    assert!(stderr(&out).contains("keelsign TLVs"), "{}", stderr(&out));
    assert!(!twice.exists(), "no output file after exit 8");

    let count = |image: &Image<'_>, t: u16| {
        image
            .unprotected()
            .iter()
            .filter(|x| x.tlv_type == t)
            .count()
    };
    // Same parameter set.
    assert_exit(&sign_args(&k44_path, &once, &twice, &["--replace"]), 0);
    let bytes = std::fs::read(&twice).expect("read");
    let image = Image::parse(&bytes).expect("parse");
    assert_eq!(count(&image, TLV_KEELSIGN_KEY_ID), 1);
    assert_eq!(count(&image, TLV_MLDSA44_SIG), 1);
    assert_eq!(
        std::fs::metadata(&once).expect("meta").len() as usize,
        bytes.len()
    );
    verify(&bytes, Some(&k44), None, Policy::PqOnly).expect("verify");
    // Another parameter set: the TLV type changes.
    let swapped = dir.join("swapped.bin");
    assert_exit(&sign_args(&k65_path, &once, &swapped, &["--replace"]), 0);
    let bytes = std::fs::read(&swapped).expect("read");
    let image = Image::parse(&bytes).expect("parse");
    assert_eq!(count(&image, TLV_KEELSIGN_KEY_ID), 1);
    assert_eq!(count(&image, TLV_MLDSA44_SIG), 0);
    assert_eq!(count(&image, TLV_MLDSA65_SIG), 1);
    verify(&bytes, Some(&k65), None, Policy::PqOnly).expect("verify");
    assert!(verify(&bytes, Some(&k44), None, Policy::PqOnly).is_err());

    // An LMS-signed hybrid image: refused, then its LMS TLV replaced by ML-DSA; the
    // imgtool Ed25519 pair stays and still verifies.
    let lms = fixture_path("keelsign-hybrid-ed25519-lms.bin");
    let from_lms = dir.join("from-lms.bin");
    assert_exit(&sign_args(&k44_path, &lms, &from_lms, &[]), 8);
    assert!(!from_lms.exists());
    assert_exit(&sign_args(&k44_path, &lms, &from_lms, &["--replace"]), 0);
    let bytes = std::fs::read(&from_lms).expect("read");
    let image = Image::parse(&bytes).expect("parse");
    assert_eq!(
        unprotected_types(&image),
        [
            IMAGE_TLV_SHA256,
            IMAGE_TLV_KEYHASH,
            IMAGE_TLV_ED25519,
            TLV_KEELSIGN_KEY_ID,
            TLV_MLDSA44_SIG
        ]
    );
    assert_eq!(count(&image, TLV_LMS_HSS_SIG), 0);
    verify(
        &bytes,
        Some(&k44),
        Some(ed25519_test_public_key()),
        Policy::Hybrid,
    )
    .expect("hybrid verify");

    // A keelsign TLV in the protected area is an image-rule failure: exit 7 even with
    // --replace (which only edits the unprotected area).
    let reserved = fixture_path("keelsign-hybrid-reserved-tlv-protected.bin");
    let out_reserved = dir.join("reserved.bin");
    let out = sign_args(&k44_path, &reserved, &out_reserved, &["--replace"]);
    assert_exit(&out, 7);
    assert!(
        stderr(&out).contains("is in the protected area"),
        "{}",
        stderr(&out)
    );
    assert!(!out_reserved.exists());
}

/// TP4: signing never changes the header, body or protected TLVs, so the digest and the
/// SHA256 TLV stay the same and the protected security counter is still reported.
#[test]
fn protected_tlvs_untouched_digest_unchanged() {
    let dir = scratch("sign", "protected");
    let key_path = keygen(&dir, "ml-dsa-65", "pq", None);
    let key = load_key(&key_path);
    for (name, extra) in [
        ("mcuboot-ed25519.bin", &[][..]),
        ("keelsign-mldsa44-protected-tlvs.bin", &["--replace"][..]),
    ] {
        let in_bytes = fixture(name);
        let in_image = Image::parse(&in_bytes).expect("parse");
        assert!(
            in_image.protected().is_some(),
            "{name} has a protected area"
        );
        let output = dir.join(name);
        assert_exit(
            &sign_args(&key_path, &fixture_path(name), &output, extra),
            0,
        );
        let bytes = std::fs::read(&output).expect("read");
        let image = Image::parse(&bytes).expect("parse");

        let hashed_end = in_image.hashed_range().end as usize;
        assert_eq!(bytes[..hashed_end], in_bytes[..hashed_end], "{name}");
        let protected = |image: &Image<'_>| -> Vec<(u16, Vec<u8>)> {
            image
                .protected()
                .expect("protected area")
                .iter()
                .map(|t| (t.tlv_type, t.value.to_vec()))
                .collect()
        };
        assert_eq!(protected(&image), protected(&in_image), "{name}");
        assert!(
            protected(&image)
                .iter()
                .any(|(t, v)| *t == IMAGE_TLV_SEC_CNT && v == &7u32.to_le_bytes()),
            "{name}: SEC_CNT 7"
        );

        let m = digest(&bytes);
        assert_eq!(m, digest(&in_bytes), "{name}");
        assert_eq!(unprotected_value(&image, IMAGE_TLV_SHA256), m, "{name}");
        assert_eq!(
            hex(&m),
            manifest_entry(name)["digest_hex"].as_str().expect("digest"),
            "{name}"
        );
        let verified = verify(&bytes, Some(&key), None, Policy::PqOnly).expect("verify");
        assert_eq!(verified.security_counter, Some(7), "{name}");
        assert_eq!(verified.digest, m);
    }
}

/// Inputs that are not signable MCUboot images are refused with exit 7 and a message
/// naming the reason; nothing is written.
#[test]
fn sign_rejects_bad_inputs_with_exit_7() {
    let dir = scratch("sign", "bad_inputs");
    let key_path = keygen(&dir, "ml-dsa-44", "pq", None);
    let golden = fixture("mcuboot-ed25519.bin");
    let garbage = write(&dir, "garbage.bin", b"this is not an MCUboot image at all");
    let truncated = write(&dir, "truncated.bin", &golden[..golden.len() - 10]);
    let cases: Vec<(PathBuf, bool, &str)> = vec![
        (garbage, false, "bad header magic"),
        (truncated, false, "truncated"),
        (
            fixture_path("rejected/mcuboot-ed25519-bigendian.bin"),
            false,
            "bad header magic",
        ),
        (
            fixture_path("mcuboot-ed25519-padded.bin"),
            false,
            "5877 bytes follow the TLV area",
        ),
        (
            fixture_path("keelsign-hybrid-bad-sha256.bin"),
            true,
            "image digest does not match the SHA256 TLV",
        ),
        (
            fixture_path("keelsign-hybrid-no-sha256.bin"),
            true,
            "no SHA256 TLV",
        ),
        (
            fixture_path("keelsign-hybrid-two-sha256.bin"),
            true,
            "more than one SHA256 TLV",
        ),
        (
            fixture_path("keelsign-hybrid-sha384-only.bin"),
            true,
            "no SHA256 TLV",
        ),
        (
            fixture_path("keelsign-hybrid-sig-pure.bin"),
            true,
            "SIG_PURE",
        ),
        (
            fixture_path("keelsign-hybrid-flag-encrypted.bin"),
            true,
            "encrypted images are not supported",
        ),
        (
            fixture_path("keelsign-hybrid-flag-compressed.bin"),
            true,
            "compressed images are not supported",
        ),
    ];
    for (i, (input, replace, reason)) in cases.iter().enumerate() {
        let output = dir.join(format!("out-{i}.bin"));
        let extra: &[&str] = if *replace { &["--replace"] } else { &[] };
        let out = sign_args(&key_path, input, &output, extra);
        assert_exit(&out, 7);
        let err = stderr(&out);
        assert!(err.starts_with("error: "), "{err}");
        assert!(
            err.contains(reason),
            "{}: `{reason}` in {err}",
            input.display()
        );
        assert!(
            err.contains(&input.display().to_string()),
            "names the input: {err}"
        );
        assert!(!output.exists(), "{}", input.display());
    }
}

/// `--key` must be ML-DSA and `--hybrid-key` Ed25519 (exit 6); the shared passphrase
/// opens whichever key is encrypted; a wrong or unneeded passphrase is exit 4.
#[test]
fn sign_key_algorithm_and_passphrase_rules() {
    let dir = scratch("sign", "keys");
    let pw = dir.join("pw.txt");
    std::fs::write(&pw, [PASSPHRASE, b"\n"].concat()).expect("write pw");
    let bad_pw = dir.join("bad-pw.txt");
    std::fs::write(&bad_pw, b"not the passphrase\n").expect("write pw");
    let pq_path = keygen(&dir, "ml-dsa-44", "pq", None);
    let ed_path = keygen(&dir, "ed25519", "ed", None);
    let pq_enc = keygen(&dir, "ml-dsa-65", "pq-enc", Some(&pw));
    let ed_enc = keygen(&dir, "ed25519", "ed-enc", Some(&pw));
    let unsigned = write(
        &dir,
        "unsigned.bin",
        &strip_ed25519_pair(&fixture("mcuboot-ed25519.bin")),
    );
    let out_path = dir.join("out.bin");
    let pw_arg = pw.display().to_string();
    let bad_arg = bad_pw.display().to_string();

    // Ed25519 as --key, ML-DSA as --hybrid-key.
    let out = sign_args(&ed_path, &unsigned, &out_path, &[]);
    assert_exit(&out, 6);
    assert!(stderr(&out).contains("--key"), "{}", stderr(&out));
    assert!(stderr(&out).contains("ML-DSA"), "{}", stderr(&out));
    let out = sign_hybrid(&pq_path, &pq_path, &unsigned, &out_path, &[]);
    assert_exit(&out, 6);
    assert!(stderr(&out).contains("--hybrid-key"), "{}", stderr(&out));
    assert!(!out_path.exists());

    // Encrypted --key, plain --hybrid-key, and the other way round.
    for (pq, ed) in [(&pq_enc, &ed_path), (&pq_path, &ed_enc), (&pq_enc, &ed_enc)] {
        let _ = std::fs::remove_file(&out_path);
        let out = sign_hybrid(
            pq,
            ed,
            &unsigned,
            &out_path,
            &["--passphrase-file", &pw_arg],
        );
        assert_exit(&out, 0);
        let bytes = std::fs::read(&out_path).expect("read");
        let pq_key = PrivateKey::from_bytes(&std::fs::read(pq).expect("read"), Some(PASSPHRASE))
            .or_else(|_| PrivateKey::from_bytes(&std::fs::read(pq).expect("read"), None))
            .expect("load");
        verify(&bytes, Some(&pq_key), None, Policy::PqOnly).expect("verify");
    }
    // The environment variable works as well.
    let _ = std::fs::remove_file(&out_path);
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_keelsign"));
    cmd.args(["sign", "--key"])
        .arg(&pq_enc)
        .args(["--passphrase-env", "KEELSIGN_SIGN_PW"])
        .arg(&unsigned)
        .arg(&out_path)
        .env(
            "KEELSIGN_SIGN_PW",
            std::str::from_utf8(PASSPHRASE).expect("utf8"),
        );
    assert_exit(&cmd.output().expect("run"), 0);

    // Wrong passphrase, missing passphrase, passphrase for unencrypted keys.
    let _ = std::fs::remove_file(&out_path);
    for (pq, ed, extra) in [
        (&pq_enc, None, vec!["--passphrase-file", bad_arg.as_str()]),
        (
            &pq_path,
            Some(&ed_enc),
            vec!["--passphrase-file", bad_arg.as_str()],
        ),
        (&pq_enc, None, vec![]),
        (&pq_path, Some(&ed_enc), vec![]),
        (
            &pq_path,
            Some(&ed_path),
            vec!["--passphrase-file", pw_arg.as_str()],
        ),
    ] {
        let out = match ed {
            Some(ed) => sign_hybrid(pq, ed, &unsigned, &out_path, &extra),
            None => sign_args(pq, &unsigned, &out_path, &extra),
        };
        assert_exit(&out, 4);
        assert!(!out_path.exists());
    }
}

/// OUT must not exist (exit 3) unless `--force`; IN and OUT must differ (exit 2); a
/// signed image that fails the self-check is never written.
#[test]
fn sign_output_file_rules() {
    let dir = scratch("sign", "output");
    let key_path = keygen(&dir, "ml-dsa-44", "pq", None);
    let input_bytes = fixture("mcuboot-ed25519.bin");
    let input = write(&dir, "in.bin", &input_bytes);
    let output = write(&dir, "out.bin", b"existing");

    let out = sign_args(&key_path, &input, &output, &[]);
    assert_exit(&out, 3);
    assert!(stderr(&out).contains("--force"), "{}", stderr(&out));
    assert_eq!(std::fs::read(&output).expect("read"), b"existing");

    assert_exit(&sign_args(&key_path, &input, &output, &["--force"]), 0);
    let signed = std::fs::read(&output).expect("read");
    Image::parse(&signed).expect("parse");
    assert!(signed.len() > input_bytes.len());
    // No temporary file is left behind.
    let names: Vec<String> = std::fs::read_dir(&dir)
        .expect("read dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !names.iter().any(|n| n.contains("keelsign-tmp")),
        "{names:?}"
    );

    // IN == OUT, also with --force, and OUT == the key file.
    for extra in [&[][..], &["--force"][..]] {
        let out = sign_args(&key_path, &input, &input, extra);
        assert_exit(&out, 2);
        assert_eq!(std::fs::read(&input).expect("read"), input_bytes);
    }
    let key_before = std::fs::read(&key_path).expect("read key");
    let out = sign_args(&key_path, &input, &key_path, &["--force"]);
    assert_exit(&out, 2);
    assert_eq!(std::fs::read(&key_path).expect("read key"), key_before);

    // A self-check failure writes nothing, with or without --force.
    let key = load_key(&key_path);
    let mut tampered = signed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let target = dir.join("never.bin");
    for force in [false, true] {
        let err = keelsign::sign::check_and_write(&target, &tampered, &key, None, force)
            .expect_err("self-check fails");
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("does not verify"), "{err}");
        assert!(!target.exists());
    }
    keelsign::sign::check_and_write(&target, &signed, &key, None, false).expect("writes");
    assert_eq!(std::fs::read(&target).expect("read"), signed);
}

/// ML-DSA signing is hedged: two runs over the same image and key give different
/// signatures, and both verify.
#[test]
fn hedged_signatures_differ_between_runs_and_both_verify() {
    let dir = scratch("sign", "hedged");
    let key_path = keygen(&dir, "ml-dsa-44", "pq", None);
    let key = load_key(&key_path);
    let input = fixture_path("mcuboot-ed25519.bin");
    let (a, b) = (dir.join("a.bin"), dir.join("b.bin"));
    assert_exit(&sign_args(&key_path, &input, &a, &[]), 0);
    assert_exit(&sign_args(&key_path, &input, &b, &[]), 0);
    let (a, b) = (std::fs::read(&a).expect("a"), std::fs::read(&b).expect("b"));
    let (ia, ib) = (Image::parse(&a).expect("a"), Image::parse(&b).expect("b"));
    assert_ne!(
        unprotected_value(&ia, TLV_MLDSA44_SIG),
        unprotected_value(&ib, TLV_MLDSA44_SIG)
    );
    assert_eq!(a.len(), b.len());
    for bytes in [&a, &b] {
        verify(bytes, Some(&key), None, Policy::PqOnly).expect("verify");
    }
}
