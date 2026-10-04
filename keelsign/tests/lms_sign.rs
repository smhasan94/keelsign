//! SHA-67: `keelsign keygen`, `pubkey`, `sign` and `verify` with stateful LMS/HSS keys,
//! through the real binary: consecutive leaves, the state advancing before any signature,
//! crash safety, refused states (exit 10), exhaustion (exit 11), the lock, and images at
//! the first and last leaves.
//!
//! The crash and lock tests use the debug-build hooks `KEELSIGN_TEST_CRASH_AFTER_RESERVE`
//! and `KEELSIGN_TEST_HOLD_LOCK` (keelsign/src/lms_state.rs).

mod common;

use common::*;
use keelsign_verify::Policy;
use keelsign_verify::image::Image;
use keelsign_verify::tlv::{TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

fn image() -> PathBuf {
    fixture_path("mcuboot-ed25519.bin")
}

/// `keelsign sign --key key IN OUT` plus `extra` arguments.
fn sign(key: &Path, input: &Path, output: &Path, extra: &[&str]) -> Output {
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"sign", &"--key", &key];
    for arg in extra {
        args.push(arg);
    }
    args.push(&input);
    args.push(&output);
    keelsign(&args)
}

/// `keelsign sign` started in the background with `env` set.
fn spawn_sign(key: &Path, output: &Path, env: &[(&str, &Path)]) -> Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keelsign"));
    cmd.arg("sign")
        .arg("--key")
        .arg(key)
        .arg(image())
        .arg(output)
        .env_remove("KEELSIGN_TEST_PW")
        .env_remove("KEELSIGN_TEST_CRASH_AFTER_RESERVE")
        .env_remove("KEELSIGN_TEST_HOLD_LOCK")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in env {
        cmd.env(name, value);
    }
    cmd.spawn().expect("start keelsign sign")
}

/// Wait (up to 60 s) until `path` exists.
#[track_caller]
fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "{} never appeared",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The `leaf: N of T` line of `sign`'s report.
fn reported_leaf(out: &Output) -> u64 {
    let text = stdout(out);
    text.lines()
        .find_map(|l| l.strip_prefix("leaf: "))
        .and_then(|rest| rest.split(' ').next())
        .and_then(|n| n.parse().ok())
        .unwrap_or_else(|| panic!("no `leaf:` line in:\n{text}"))
}

/// `keelsign verify --pub public IMAGE` with `extra` arguments, expecting `code`.
#[track_caller]
fn verify_cli(publics: &[&Path], image: &Path, extra: &[&str], code: i32) -> Output {
    let mut args: Vec<&dyn AsRef<std::ffi::OsStr>> = vec![&"verify"];
    for public in publics {
        args.push(&"--pub");
        args.push(public);
    }
    for arg in extra {
        args.push(arg);
    }
    args.push(&image);
    let out = keelsign(&args);
    assert_exit(&out, code);
    out
}

fn export_public(key: &Path, out: &Path) -> PathBuf {
    assert_exit(&keelsign(&[&"pubkey", &"--key", &key, &"--out", &out]), 0);
    out.to_path_buf()
}

/// AC1: two signs in a row use leaves 0 and 1, and the state file names the next leaf
/// before any signature is computed (seen while the second sign holds its reservation).
#[test]
fn two_sequential_signs_use_leaves_0_and_1_and_the_state_advances_before_signing() {
    let dir = scratch("lms_sign", "sequential");
    let key = keygen_lms(&dir, "k", 1, None);
    assert_eq!(next_leaf(&key), 0);
    assert!(journal_lines(&key).is_empty());

    let first = dir.join("first.bin");
    let out = sign(&key, &image(), &first, &[]);
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 0);
    assert!(
        stdout(&out).contains("leaf: 0 of 1024 (1023 left)\n"),
        "{}",
        stdout(&out)
    );
    assert!(stdout(&out).contains(&format!(
        "state: {} (next leaf 1)\n",
        state_path(&key).display()
    )));
    assert_eq!(signed_leaf(&std::fs::read(&first).expect("read")), 0);
    assert_eq!(next_leaf(&key), 1);

    // The second sign stops right after its reservation (holding the lock): the state
    // file on disk already names leaf 2 and the journal records leaf 1, while no image
    // has been written yet.
    let release = dir.join("release");
    let second = dir.join("second.bin");
    let child = spawn_sign(&key, &second, &[("KEELSIGN_TEST_HOLD_LOCK", &release)]);
    wait_for(&dir.join("release.held"));
    assert_eq!(next_leaf(&key), 2, "the state advances before signing");
    let lines = journal_lines(&key);
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("reserved 0 ") && lines[1].starts_with("reserved 1 "));
    assert!(!second.exists(), "nothing is signed yet");
    std::fs::write(&release, b"").expect("release");
    let out = child.wait_with_output().expect("wait");
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 1);
    let bytes = std::fs::read(&second).expect("read");
    assert_eq!(signed_leaf(&bytes), 1);
    assert_eq!(next_leaf(&key), 2);

    let lms = load_key(&key);
    for image in [&first, &second] {
        let bytes = std::fs::read(image).expect("read");
        verify(&bytes, Some(&lms), None, Policy::PqOnly).expect("verifies");
        assert_eq!(
            unprotected_value(&Image::parse(&bytes).expect("parse"), TLV_KEELSIGN_KEY_ID),
            keelsign_verify::key_id_of(&lms.raw_public_key())
        );
    }
}

/// AC2: a crash after the reservation (before any signature) wastes the reserved leaf;
/// the next sign uses the one after it.
#[test]
fn crash_after_reservation_skips_the_reserved_leaf() {
    let dir = scratch("lms_sign", "crash");
    let key = keygen_lms(&dir, "k", 1, None);
    let crashed = dir.join("crashed.bin");
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_keelsign"));
    let out = cmd
        .args(["sign", "--key"])
        .arg(&key)
        .arg(image())
        .arg(&crashed)
        .env_remove("KEELSIGN_TEST_HOLD_LOCK")
        .env("KEELSIGN_TEST_CRASH_AFTER_RESERVE", "1")
        .output()
        .expect("run");
    assert!(!out.status.success(), "the process aborts");
    assert_ne!(out.status.code(), Some(0));
    assert!(!crashed.exists(), "no image is written");
    assert_eq!(next_leaf(&key), 1, "leaf 0 is spent");
    assert_eq!(journal_lines(&key).len(), 1);
    assert!(journal_lines(&key)[0].starts_with("reserved 0 "));

    let after = dir.join("after.bin");
    let out = sign(&key, &image(), &after, &[]);
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 1);
    let bytes = std::fs::read(&after).expect("read");
    assert_eq!(signed_leaf(&bytes), 1, "leaf 0 is never used");
    verify(&bytes, Some(&load_key(&key)), None, Policy::PqOnly).expect("verifies");
    assert_eq!(next_leaf(&key), 2);
}

/// AC3: a missing state file or journal, a state file restored from a copy (behind the
/// journal), another key's state file (also: a key file whose public key was altered) or
/// a corrupt one is refused with exit 10 and a clear message, before anything is signed.
#[test]
fn missing_rolled_back_foreign_or_corrupt_state_is_refused_with_exit_10() {
    let dir = scratch("lms_sign", "refused");
    let key = keygen_lms(&dir, "k", 1, None);
    let out_path = dir.join("out.bin");
    let refuse = |needle: &str| {
        let out = sign(&key, &image(), &out_path, &[]);
        assert_exit(&out, 10);
        let err = stderr(&out);
        assert!(err.starts_with("error: "), "{err}");
        assert!(err.contains(needle), "`{needle}` in:\n{err}");
        assert!(stdout(&out).is_empty());
        assert!(!out_path.exists(), "nothing is written");
    };

    let state = state_path(&key);
    let journal = journal_path(&key);
    let fresh = std::fs::read(&state).expect("read");

    // Missing state file, missing journal.
    std::fs::remove_file(&state).expect("rm");
    refuse("k.pem.state is missing");
    std::fs::write(&state, &fresh).expect("restore");
    std::fs::rename(&journal, dir.join("journal.bak")).expect("mv");
    refuse("k.pem.journal is missing");
    std::fs::rename(dir.join("journal.bak"), &journal).expect("mv back");

    // Rolled back: sign twice, then restore the state file copied after the first sign.
    assert_exit(&sign(&key, &image(), &dir.join("a.bin"), &[]), 0);
    let after_first = std::fs::read(&state).expect("read");
    assert_exit(&sign(&key, &image(), &dir.join("b.bin"), &[]), 0);
    std::fs::write(&state, &after_first).expect("roll back");
    refuse("restored from a copy");
    let err = stderr(&sign(&key, &image(), &out_path, &[]));
    assert!(
        err.contains("next leaf is 1") && err.contains("leaf 1 as used"),
        "{err}"
    );
    assert!(err.contains("retire this key"), "{err}");
    assert_eq!(journal_lines(&key).len(), 2, "a refusal reserves nothing");

    // Another key's state file.
    let other = keygen_lms(&dir, "other", 1, None);
    std::fs::copy(state_path(&other), &state).expect("copy");
    refuse("belongs to another key");

    // Corrupt state file.
    std::fs::write(&state, b"{\"format\": \"something else\"}").expect("write");
    refuse("corrupt LMS/HSS state");
    std::fs::write(&state, b"not json").expect("write");
    refuse("corrupt LMS/HSS state");

    // A key file whose public key (root) was altered no longer matches its state file.
    let original = load_key(&other);
    let der = original.to_pkcs8_der().expect("der");
    let mut bytes = der.as_bytes().to_vec();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let altered = dir.join("altered.der");
    std::fs::write(&altered, &bytes).expect("write");
    std::fs::copy(state_path(&other), state_path(&altered)).expect("copy state");
    std::fs::copy(journal_path(&other), journal_path(&altered)).expect("copy journal");
    let out = sign(&altered, &image(), &out_path, &[]);
    assert_exit(&out, 10);
    assert!(
        stderr(&out).contains("belongs to another key"),
        "{}",
        stderr(&out)
    );
    assert!(!out_path.exists());
}

/// AC4: an H10 key whose 1,024 leaves are used refuses to sign with `LeafIndexExhausted`
/// (exit 11); the last leaf, 1,023, still signs.
#[test]
fn exhausted_h10_key_refuses_with_leaf_index_exhausted_exit_11() {
    let dir = scratch("lms_sign", "exhausted");
    let key = keygen_lms(&dir, "k", 1, None);
    keelsign::lms_state::StateFile::set_next_leaf(&key, 1023).expect("skip ahead");
    let last = dir.join("last.bin");
    let out = sign(&key, &image(), &last, &[]);
    assert_exit(&out, 0);
    assert!(
        stdout(&out).contains("leaf: 1023 of 1024 (0 left)\n"),
        "{}",
        stdout(&out)
    );
    assert_eq!(signed_leaf(&std::fs::read(&last).expect("read")), 1023);
    assert_eq!(next_leaf(&key), 1024);

    let refused = dir.join("refused.bin");
    let out = sign(&key, &image(), &refused, &[]);
    assert_exit(&out, 11);
    let err = stderr(&out);
    assert!(err.starts_with("error: LeafIndexExhausted: "), "{err}");
    assert!(
        err.contains("1024") && err.contains("generate a new key"),
        "{err}"
    );
    assert!(!refused.exists());
    assert_eq!(next_leaf(&key), 1024);
    assert_eq!(journal_lines(&key).len(), 1);
}

/// TP2: while one `sign` holds the key's lock, another fails at once with exit 10
/// ("locked"); once the first finishes, the second signs with the next leaf.
#[test]
fn concurrent_sign_fails_on_the_lock_while_another_holds_it() {
    let dir = scratch("lms_sign", "lock");
    let key = keygen_lms(&dir, "k", 1, None);
    let release = dir.join("release");
    let first = dir.join("first.bin");
    let child = spawn_sign(&key, &first, &[("KEELSIGN_TEST_HOLD_LOCK", &release)]);
    wait_for(&dir.join("release.held"));

    let second = dir.join("second.bin");
    let out = sign(&key, &image(), &second, &[]);
    assert_exit(&out, 10);
    assert!(
        stderr(&out).contains("locked by another keelsign process"),
        "{}",
        stderr(&out)
    );
    assert!(!second.exists());

    std::fs::write(&release, b"").expect("release");
    let out = child.wait_with_output().expect("wait");
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 0);
    let out = sign(&key, &image(), &second, &[]);
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 1);
}

/// TP2: signs started in parallel without hooks either sign or fail on the lock (exit
/// 10), and retried until every one has signed, no two share a leaf.
#[test]
fn parallel_signs_without_hooks_never_share_a_leaf() {
    let dir = scratch("lms_sign", "parallel");
    let key = keygen_lms(&dir, "k", 1, None);
    const SIGNERS: usize = 6;
    let outputs: Vec<PathBuf> = (0..SIGNERS)
        .map(|i| dir.join(format!("signed-{i}.bin")))
        .collect();
    let mut pending: Vec<usize> = (0..SIGNERS).collect();
    let mut leaves = Vec::new();
    let mut rounds = 0;
    while !pending.is_empty() {
        rounds += 1;
        assert!(rounds <= 100, "signers still pending: {pending:?}");
        let children: Vec<(usize, Child)> = pending
            .iter()
            .map(|&i| (i, spawn_sign(&key, &outputs[i], &[])))
            .collect();
        pending.clear();
        for (i, child) in children {
            let out = child.wait_with_output().expect("wait");
            match out.status.code() {
                Some(0) => leaves.push(reported_leaf(&out)),
                Some(10) => {
                    assert!(stderr(&out).contains("locked"), "{}", stderr(&out));
                    assert!(!outputs[i].exists());
                    pending.push(i);
                }
                other => panic!("signer {i} exited {other:?}:\n{}", stderr(&out)),
            }
        }
    }
    leaves.sort_unstable();
    assert_eq!(
        leaves,
        (0..SIGNERS as u64).collect::<Vec<_>>(),
        "distinct leaves"
    );
    let mut signed: Vec<u32> = outputs
        .iter()
        .map(|o| signed_leaf(&std::fs::read(o).expect("read")))
        .collect();
    signed.sort_unstable();
    assert_eq!(signed, (0..SIGNERS as u32).collect::<Vec<_>>());
    assert_eq!(next_leaf(&key), SIGNERS as u64);
    assert_eq!(journal_lines(&key).len(), SIGNERS);
}

/// TP3 (host half): images signed at leaves 0, 1 and 1,023 of an H10 key verify with
/// `keelsign verify` (keelsign-verify's default policy) and with `--cnsa-2.0`. The images
/// and the public key are kept in `target/tmp/lms_sign/leaves/` for the on-target check
/// (docs/signing.md, "On-target check").
#[test]
fn images_at_leaves_0_1_and_1023_verify_with_keelsign_verify_and_cnsa_2_0() {
    let dir = scratch("lms_sign", "leaves");
    let key = keygen_lms(&dir, "lms", 1, None);
    let public = export_public(&key, &dir.join("lms.pub.pem"));
    let lms = load_key(&key);
    let mut images = Vec::new();
    for leaf in [0u64, 1, 1023] {
        if leaf == 1023 {
            keelsign::lms_state::StateFile::set_next_leaf(&key, 1023).expect("skip ahead");
        }
        let output = dir.join(format!("leaf-{leaf}.bin"));
        let out = sign(&key, &image(), &output, &[]);
        assert_exit(&out, 0);
        assert_eq!(reported_leaf(&out), leaf);
        let bytes = std::fs::read(&output).expect("read");
        assert_eq!(u64::from(signed_leaf(&bytes)), leaf);
        verify_cli(&[&public], &output, &[], 0);
        let out = verify_cli(&[&public], &output, &["--cnsa-2.0"], 0);
        assert!(stdout(&out).starts_with("verified: "), "{}", stdout(&out));
        verify(&bytes, Some(&lms), None, Policy::PqOnly).expect("verifies");
        images.push(output);
    }
    // The on-target harness: scripts/lms_image_kat.py packs the three images into a KSLM
    // v2 fixture, which the lms-kat runner (the code the boards run) passes on the host.
    let fixture = dir.join("lms-leaves.bin");
    let out = Command::new("python3")
        .arg(repo().join("scripts/lms_image_kat.py"))
        .arg("--pub")
        .arg(&public)
        .arg("--out")
        .arg(&fixture)
        .args(&images)
        .output()
        .expect("run python3 scripts/lms_image_kat.py");
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(stdout(&out).contains("wrote 3 cases"), "{}", stdout(&out));
    let bytes = std::fs::read(&fixture).expect("read fixture");
    let mut ids = Vec::new();
    let summary = lms_kat::run_fixture(&bytes, |case, outcome| {
        ids.push(case.id);
        assert!(outcome.passed(), "case {}: {outcome:?}", case.id);
        assert_eq!(case.pk, lms.raw_public_key().as_slice());
    })
    .expect("fixture parses");
    assert_eq!((summary.total, summary.passed), (3, 3));
    assert_eq!(ids, [700, 701, 702]);
    println!(
        "on-target inputs (docs/signing.md#on-target-check): {}",
        dir.display()
    );
}

/// keygen, pubkey (PEM and DER), sign and verify for H10 keys with one and two levels;
/// the two-level key is refused under `--cnsa-2.0` (exit 9).
#[test]
fn keygen_pubkey_sign_verify_round_trip_for_h10_l1_and_l2() {
    let dir = scratch("lms_sign", "round_trip");
    for levels in [1u8, 2] {
        let key = keygen_lms(&dir, &format!("l{levels}"), levels, None);
        let pem = export_public(&key, &dir.join(format!("l{levels}.pub.pem")));
        let der = dir.join(format!("l{levels}.pub.der"));
        assert_exit(
            &keelsign(&[
                &"pubkey",
                &"--key",
                &key,
                &"--format",
                &"der",
                &"--out",
                &der,
            ]),
            0,
        );
        let output = dir.join(format!("l{levels}.signed.bin"));
        let out = sign(&key, &image(), &output, &[]);
        assert_exit(&out, 0);
        let total = if levels == 1 { 1024 } else { 1024 * 1024 };
        assert!(
            stdout(&out).contains(&format!("leaf: 0 of {total}")),
            "{}",
            stdout(&out)
        );
        assert!(stdout(&out).contains("algorithm: lms-hss\n"));
        for public in [&pem, &der] {
            let out = verify_cli(&[public], &output, &[], 0);
            assert!(stdout(&out).contains("lms-hss"), "{}", stdout(&out));
        }
        let cnsa = verify_cli(
            &[&pem],
            &output,
            &["--cnsa-2.0"],
            if levels == 1 { 0 } else { 9 },
        );
        if levels == 2 {
            assert!(stderr(&cnsa).contains("parameter set"), "{}", stderr(&cnsa));
        }
        let bytes = std::fs::read(&output).expect("read");
        let parsed = Image::parse(&bytes).expect("parse");
        assert_eq!(
            unprotected_types(&parsed),
            [0x10, 0x01, 0x24, TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG]
        );
        let sig = unprotected_value(&parsed, TLV_LMS_HSS_SIG);
        let summary = keelsign::inspect::hss_summary(sig).expect("summary");
        assert_eq!(summary.levels, u32::from(levels));
        // M32 H10 W8: 1,456 bytes with one level.
        if levels == 1 {
            assert_eq!(sig.len(), 1456);
        }
        // A second signature on a two-level key uses bottom leaf 1 of bottom tree 0.
        let again = dir.join(format!("l{levels}.again.bin"));
        assert_exit(&sign(&key, &image(), &again, &[]), 0);
        assert_eq!(signed_leaf(&std::fs::read(&again).expect("read")), 1);
        verify_cli(&[&pem], &again, &[], 0);
        // `inspect` shows the leaf of every level, top first.
        let expected: &[u64] = if levels == 1 { &[1] } else { &[0, 1] };
        assert_eq!(inspect_leaf_indices(&again), expected);
        assert_eq!(inspect_leaf_indices(&output), vec![0; usize::from(levels)]);
    }
}

/// A hybrid image (LMS/HSS + Ed25519) verifies under the classical, pq and hybrid
/// policies, with the TLVs in the documented order.
#[test]
fn hybrid_lms_image_verifies_under_all_three_policies() {
    let dir = scratch("lms_sign", "hybrid");
    let key = keygen_lms(&dir, "lms", 1, None);
    let ed = keygen(&dir, "ed25519", "ed", None);
    let lms_pub = export_public(&key, &dir.join("lms.pub.pem"));
    let ed_pub = export_public(&ed, &dir.join("ed.pub.pem"));
    let output = dir.join("hybrid.bin");
    let out = keelsign(&[
        &"sign",
        &"--key",
        &key,
        &"--hybrid-key",
        &ed,
        &image(),
        &output,
        &"--replace",
    ]);
    assert_exit(&out, 0);
    assert!(stdout(&out).contains("keyhash: "), "{}", stdout(&out));
    let bytes = std::fs::read(&output).expect("read");
    let image = Image::parse(&bytes).expect("parse");
    assert_eq!(
        unprotected_types(&image),
        [0x10, 0x01, 0x24, TLV_KEELSIGN_KEY_ID, TLV_LMS_HSS_SIG],
        "the fixture's Ed25519 pair is replaced by the new one"
    );
    for policy in ["classical", "pq", "hybrid"] {
        verify_cli(&[&lms_pub, &ed_pub], &output, &["--policy", policy], 0);
    }
    let lms = load_key(&key);
    let ed_public = ed25519_public(&load_key(&ed));
    for policy in [Policy::ClassicalOnly, Policy::PqOnly, Policy::Hybrid] {
        verify(&bytes, Some(&lms), Some(ed_public), policy)
            .unwrap_or_else(|e| panic!("{policy:?}: {e}"));
    }
}

/// An encrypted LMS/HSS key signs with its passphrase; a refusal before the reservation
/// (wrong or missing passphrase, an already-signed image without `--replace`, an
/// existing OUT) spends no leaf; `--replace` re-signs with a new leaf, never the old one.
#[test]
fn encrypted_lms_key_signs_with_passphrase_and_replace_reuses_no_leaf() {
    let dir = scratch("lms_sign", "encrypted");
    let pw = dir.join("pw.txt");
    std::fs::write(&pw, b"correct horse\n").expect("write");
    let wrong = dir.join("wrong.txt");
    std::fs::write(&wrong, b"battery staple\n").expect("write");
    let key = keygen_lms(&dir, "k", 1, Some(&pw));
    assert!(
        std::fs::read_to_string(&key)
            .expect("read")
            .starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
    );
    let first = dir.join("first.bin");
    let pw_arg = pw.to_str().expect("utf-8");
    let wrong_arg = wrong.to_str().expect("utf-8");

    assert_exit(&sign(&key, &image(), &first, &[]), 4);
    assert_exit(
        &sign(&key, &image(), &first, &["--passphrase-file", wrong_arg]),
        4,
    );
    assert_exit(
        &sign(
            &key,
            &dir.join("missing.bin"),
            &first,
            &["--passphrase-file", pw_arg],
        ),
        1,
    );
    assert_eq!(next_leaf(&key), 0, "no leaf is spent on a refusal");
    assert!(journal_lines(&key).is_empty());

    let out = sign(&key, &image(), &first, &["--passphrase-file", pw_arg]);
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 0);

    // Re-signing needs --replace (exit 8, no leaf spent) and an absent OUT (exit 3).
    let second = dir.join("second.bin");
    assert_exit(
        &sign(&key, &first, &second, &["--passphrase-file", pw_arg]),
        8,
    );
    let missing_ed = dir.join("missing-ed.pem");
    let missing_ed = missing_ed.to_str().expect("utf-8");
    let flags = [
        "--passphrase-file",
        pw_arg,
        "--replace",
        "--hybrid-key",
        missing_ed,
    ];
    assert_exit(&sign(&key, &first, &dir.join("third.bin"), &flags), 1);
    std::fs::write(&second, b"exists").expect("write");
    assert_exit(
        &sign(
            &key,
            &first,
            &second,
            &["--passphrase-file", pw_arg, "--replace"],
        ),
        3,
    );
    std::fs::remove_file(&second).expect("rm");
    assert_eq!(next_leaf(&key), 1);

    let out = sign(
        &key,
        &first,
        &second,
        &["--passphrase-file", pw_arg, "--replace"],
    );
    assert_exit(&out, 0);
    assert_eq!(reported_leaf(&out), 1, "a new leaf, not leaf 0 again");
    let bytes = std::fs::read(&second).expect("read");
    let image = Image::parse(&bytes).expect("parse");
    let sigs = image
        .unprotected()
        .iter()
        .filter(|t| t.tlv_type == TLV_LMS_HSS_SIG)
        .count();
    assert_eq!(sigs, 1, "the old signature is replaced");
    assert_eq!(signed_leaf(&bytes), 1);
    let lms = keelsign::keys::PrivateKey::from_bytes(
        &std::fs::read(&key).expect("read"),
        Some(b"correct horse"),
    )
    .expect("decrypt");
    verify(&bytes, Some(&lms), None, Policy::PqOnly).expect("verifies");
    assert_eq!(next_leaf(&key), 2);
    assert_eq!(journal_lines(&key).len(), 2);
}
