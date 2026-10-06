//! SHA-62: keelsign's MCUboot image-check hook (`mcuboot/keelsign_mcuboot_hooks.c`), its
//! host harness against the pinned MCUboot headers (`mcuboot/hooktest`, docs/mcuboot.md).
//!
//! The harness tests are ignored: they need the pinned MCUboot checkout, cloned over the
//! network by `scripts/fetch_mcuboot.py` or taken from `KEELSIGN_MCUBOOT_DIR` (for example
//! the west workspace's `bootloader/mcuboot`). CI step `MCUboot hook harness (network)`:
//! `cargo test -p repo-checks --locked --test mcuboot -- --ignored hook_` (the harness
//! tests and `hook_glue_compiles_against_mcuboot_v2_5_0_rc1_headers`).

use repo_checks::{cargo_in, mcuboot_checkout, run_ok, workspace_root};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, OnceLock};

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

// ---- host hook harness (D13) ------------------------------------------------------------

/// The `field` string of output `name` in tests/fixtures/images/MANIFEST.json.
fn manifest_field(name: &str, field: &str) -> String {
    static MANIFEST: OnceLock<String> = OnceLock::new();
    let manifest = MANIFEST.get_or_init(|| read("tests/fixtures/images/MANIFEST.json"));
    let outputs = &manifest[manifest.find("\"outputs\": {").expect("outputs")..];
    let start = outputs
        .find(&format!("\n    \"{name}\": {{"))
        .unwrap_or_else(|| panic!("MANIFEST.json has no output {name}"));
    let object = &outputs[start..];
    let object = &object[..object.find("\n    }").expect("object end")];
    let needle = format!("\"{field}\": \"");
    let at = object
        .find(&needle)
        .unwrap_or_else(|| panic!("MANIFEST.json {name} has no {field}"))
        + needle.len();
    object[at..]
        .split('"')
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn image_path(name: &str) -> PathBuf {
    workspace_root().join("tests/fixtures/images").join(name)
}

/// `cc` (or `$CC`) with SDKROOT set on macOS when the environment does not set it.
fn c_compiler() -> Command {
    let cc = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let mut cmd = Command::new(cc);
    if cfg!(target_os = "macos") && std::env::var_os("SDKROOT").is_none() {
        let sdk = run_ok(Command::new("xcrun").args(["--sdk", "macosx", "--show-sdk-path"]));
        cmd.env("SDKROOT", sdk.trim());
    }
    cmd
}

/// The sanitizers of the harness build, as for the libkeelsign C harness
/// (`KEELSIGN_FFI_SANITIZE`, else ASan + UBSan on Linux and UBSan elsewhere).
fn sanitizers() -> Option<String> {
    match std::env::var("KEELSIGN_FFI_SANITIZE") {
        Ok(v) if v.is_empty() || v == "none" => None,
        Ok(v) => Some(v),
        Err(_) if cfg!(target_os = "linux") => Some("address,undefined".to_owned()),
        Err(_) => Some("undefined".to_owned()),
    }
}

/// Host `libkeelsign.a` (`--profile ffi`) with `features` ("" or "ed25519"), built once
/// per test binary in its own target directory.
fn library(features: &str) -> PathBuf {
    static LIBS: Mutex<Vec<(String, PathBuf)>> = Mutex::new(Vec::new());
    let mut libs = LIBS.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((_, lib)) = libs.iter().find(|(f, _)| f == features) {
        return lib.clone();
    }
    let target_dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "mcuboot-ffi-{}",
        if features.is_empty() {
            "none"
        } else {
            features
        }
    ));
    let mut cmd = cargo_in(&workspace_root(), &target_dir);
    cmd.args([
        "build",
        "-p",
        "keelsign-ffi",
        "--profile",
        "ffi",
        "--locked",
    ]);
    for var in ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET"] {
        cmd.env_remove(var);
    }
    if !features.is_empty() {
        cmd.args(["--features", features]);
    }
    run_ok(&mut cmd);
    let lib = target_dir.join("ffi").join("libkeelsign.a");
    assert!(lib.is_file(), "expected {}", lib.display());
    libs.push((features.to_owned(), lib.clone()));
    lib
}

/// The hook's key table for `policy` from `--raw` keys and key files
/// (`scripts/keelsign_embed_keys.py`), written to `dir/keelsign_mcuboot_keys.c`.
fn embed_keys(dir: &Path, policy: &str, raw: &[String], files: &[PathBuf]) -> PathBuf {
    let out = dir.join("keelsign_mcuboot_keys.c");
    let mut cmd = repo_checks::python_script("keelsign_embed_keys.py");
    cmd.args(["--policy", policy, "--out"]).arg(&out);
    for key in raw {
        cmd.args(["--raw", key]);
    }
    cmd.args(files);
    run_ok(&mut cmd);
    out
}

/// The include directories and C sources of the glue built against `mcuboot`.
fn glue_args(mcuboot: &Path) -> Vec<PathBuf> {
    let root = workspace_root();
    vec![
        PathBuf::from("-I"),
        root.join("mcuboot/hooktest/port"),
        PathBuf::from("-I"),
        mcuboot.join("boot/bootutil/include"),
        PathBuf::from("-I"),
        root.join("mcuboot/include"),
        PathBuf::from("-I"),
        root.join("keelsign-ffi/include"),
    ]
}

/// Compile and link the harness: the glue, the harness, the file-backed flash, MCUboot's
/// `fault_injection_hardening.c` and `keys_c`, against `lib`, as C99 with warnings as
/// errors and sanitizers, with the extra `defines` (for example
/// `-DMCUBOOT_SWAP_USING_OFFSET`).
fn build_harness(mcuboot: &Path, keys_c: &Path, lib: &Path, defines: &[&str], out: &Path) {
    let root = workspace_root();
    let mut cmd = c_compiler();
    cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-g"])
        .args(defines)
        .args(glue_args(mcuboot));
    if let Some(s) = sanitizers() {
        cmd.arg(format!("-fsanitize={s}"))
            .arg("-fno-sanitize-recover=all")
            .arg("-fno-omit-frame-pointer");
    }
    cmd.arg(root.join("mcuboot/keelsign_mcuboot_hooks.c"))
        .arg(root.join("mcuboot/hooktest/harness.c"))
        .arg(root.join("mcuboot/hooktest/flash_stub.c"))
        .arg(mcuboot.join("boot/bootutil/src/fault_injection_hardening.c"))
        .arg(keys_c)
        .arg(lib)
        .arg("-o")
        .arg(out);
    if cfg!(target_os = "linux") {
        cmd.args(["-lpthread", "-ldl"]);
    }
    run_ok(&mut cmd);
}

/// One harness binary: its own directory under `CARGO_TARGET_TMPDIR`, its key table.
struct Harness {
    binary: PathBuf,
}

impl Harness {
    /// Build a harness named `name` trusting `raw` / `files` keys under `policy`, linked
    /// with `libkeelsign.a` of `features`, against MCUboot v2.4.0 (or v2.5.0-rc1).
    fn new(
        name: &str,
        policy: &str,
        raw: &[String],
        files: &[PathBuf],
        features: &str,
        rc1: bool,
    ) -> Harness {
        Harness::with_defines(name, policy, raw, files, features, rc1, &[])
    }

    /// As [`Harness::new`] for the PQ-only policy and the default library, with the glue
    /// built as MCUboot builds it under swap using offset (`MCUBOOT_SWAP_USING_OFFSET`,
    /// Zephyr `CONFIG_BOOT_SWAP_USING_OFFSET`, the sample's mode).
    fn swap_offset(name: &str, raw: &[String]) -> Harness {
        Harness::with_defines(
            name,
            "pq_only",
            raw,
            &[],
            "",
            false,
            &["-DMCUBOOT_SWAP_USING_OFFSET=1"],
        )
    }

    fn with_defines(
        name: &str,
        policy: &str,
        raw: &[String],
        files: &[PathBuf],
        features: &str,
        rc1: bool,
        defines: &[&str],
    ) -> Harness {
        let mcuboot = mcuboot_checkout(rc1);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("mcuboot-hooktest")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create harness dir");
        let keys_c = embed_keys(&dir, policy, raw, files);
        let binary = dir.join("harness");
        build_harness(&mcuboot, &keys_c, &library(features), defines, &binary);
        Harness { binary }
    }

    /// Run the harness on fixture `image` with `extra` arguments: (the `log:` lines, the
    /// hook verdict, the logged status).
    fn run(&self, image: &Path, extra: &[&str]) -> (Vec<String>, String, i64) {
        let out = Command::new(&self.binary)
            .args(extra)
            .arg(image)
            .env("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
            .env("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
            .output()
            .expect("run hook harness");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success() && stderr.is_empty(),
            "hook harness {extra:?} {} exited {} with stderr:\n{stderr}\nstdout:\n{stdout}",
            image.display(),
            out.status
        );
        let logs: Vec<String> = stdout
            .lines()
            .filter_map(|l| l.strip_prefix("log: "))
            .map(str::to_owned)
            .collect();
        let last = stdout.lines().last().unwrap_or_default();
        let fields: Vec<&str> = last.split(' ').collect();
        let verdict = fields
            .first()
            .and_then(|f| f.strip_prefix("hook="))
            .unwrap_or_else(|| panic!("no hook= in `{last}`"))
            .to_owned();
        let status = fields
            .get(1)
            .and_then(|f| f.strip_prefix("status="))
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("no status= in `{last}`"));
        (logs, verdict, status)
    }
}

/// `lms:<hex>`, the raw public key of fixture `image` from MANIFEST.json.
fn raw_lms_key(image: &str) -> String {
    format!("lms:{}", manifest_field(image, "public_key_hex"))
}

/// AC2 (host): a tampered image (one body byte flipped, so the image digest no longer
/// matches) makes the hook log a line naming keelsign and return `FIH_FAILURE`, with
/// keelsign's status 70 (`KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH`).
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_tampered_image_logs_keelsign_and_fails() {
    let image = "keelsign-hybrid-bad-body.bin";
    let harness = Harness::new("tampered", "pq_only", &[raw_lms_key(image)], &[], "", false);
    let (logs, verdict, status) = harness.run(&image_path(image), &[]);
    assert_eq!(
        (verdict.as_str(), status),
        ("FAILURE", 70),
        "logs: {logs:?}"
    );
    assert_eq!(
        logs,
        ["ERR keelsign: image 0 slot 0 rejected: status 70"],
        "the reject line names keelsign"
    );
    // The same in the secondary slot (an update candidate).
    let (logs, verdict, status) = harness.run(&image_path(image), &["--slot", "1"]);
    assert_eq!((verdict.as_str(), status), ("FAILURE", 70));
    assert_eq!(logs, ["ERR keelsign: image 0 slot 1 rejected: status 70"]);
}

/// AC2 (host): an image signed by a key the bootloader does not trust (an HSS L=2 image
/// against the LMS_SHA256_M32_H5 key) is rejected with a keelsign line, status 15
/// (`KEELSIGN_ERR_KEY_NOT_TRUSTED`).
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_wrong_key_logs_keelsign_and_fails() {
    let harness = Harness::new(
        "wrong-key",
        "pq_only",
        &[raw_lms_key("keelsign-lms-m32-h5.bin")],
        &[],
        "",
        false,
    );
    let (logs, verdict, status) = harness.run(&image_path("keelsign-hss2-m32-h5h5.bin"), &[]);
    assert_eq!(
        (verdict.as_str(), status),
        ("FAILURE", 15),
        "logs: {logs:?}"
    );
    assert_eq!(logs, ["ERR keelsign: image 0 slot 0 rejected: status 15"]);
}

/// AC3 (host): a good post-quantum image makes the hook log `verified` and return
/// `FIH_BOOT_HOOK_REGULAR`, never `FIH_SUCCESS`, so MCUboot's own validation (its SHA256
/// and classical signature TLVs, the security counter) still runs; in either slot and in
/// a slot larger than the image (erased tail). An image with only MCUboot's own
/// signature does not get past the keelsign gate (status 13,
/// `KEELSIGN_ERR_MISSING_PQ_SIGNATURE`). The glue also compiles under the LOW and
/// MEDIUM fault-injection-hardening profiles.
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_good_pq_image_returns_regular_never_success() {
    let image = "keelsign-lms-m32-h5.bin";
    let harness = Harness::new("good", "pq_only", &[raw_lms_key(image)], &[], "", false);
    for extra in [
        &[][..],
        &["--slot", "1"][..],
        &["--slot-size", "0x76000"][..],
    ] {
        let (logs, verdict, status) = harness.run(&image_path(image), extra);
        let slot = if extra.first() == Some(&"--slot") {
            1
        } else {
            0
        };
        assert_eq!(
            (verdict.as_str(), status),
            ("REGULAR", 0),
            "{extra:?}: {logs:?}"
        );
        assert_eq!(
            logs,
            [format!(
                "INF keelsign: image 0 slot {slot} verified (pq key 0, ed25519 key 4294967295)"
            )]
        );
    }
    for classical in ["mcuboot-ecdsa-p256.bin", "mcuboot-ed25519.bin"] {
        let (logs, verdict, status) = harness.run(&image_path(classical), &[]);
        assert_eq!(
            (verdict.as_str(), status),
            ("FAILURE", 13),
            "{classical}: {logs:?}"
        );
    }

    let mcuboot = mcuboot_checkout(false);
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR")).join("mcuboot-hooktest/fih");
    fs::create_dir_all(&scratch).expect("create fih dir");
    for profile in ["MCUBOOT_FIH_PROFILE_LOW", "MCUBOOT_FIH_PROFILE_MEDIUM"] {
        run_ok(
            c_compiler()
                .args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-c"])
                .arg(format!("-D{profile}"))
                .args(glue_args(&mcuboot))
                .arg(workspace_root().join("mcuboot/keelsign_mcuboot_hooks.c"))
                .arg("-o")
                .arg(scratch.join(format!("{profile}.o"))),
        );
    }
}

/// AC3 (host): under `KEELSIGN_POLICY_HYBRID` (the `ed25519` library) an image with
/// imgtool's Ed25519 pair (KEYHASH + ED25519) and keelsign's LMS/HSS signature passes
/// the hook, which names both keys; a bad Ed25519 signature (58) or an image without the
/// post-quantum half (13) is rejected.
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_hybrid_policy_accepts_imgtool_ed25519_plus_lms_image() {
    let image = "keelsign-hybrid-ed25519-lms.bin";
    let harness = Harness::new(
        "hybrid",
        "hybrid",
        &[raw_lms_key(image)],
        &[image_path("keys/ed25519-test-key.spki.der")],
        "ed25519",
        false,
    );
    let (logs, verdict, status) = harness.run(&image_path(image), &[]);
    assert_eq!((verdict.as_str(), status), ("REGULAR", 0), "logs: {logs:?}");
    assert_eq!(
        logs,
        ["INF keelsign: image 0 slot 0 verified (pq key 0, ed25519 key 1)"]
    );
    for (bad, expected) in [
        ("keelsign-hybrid-bad-ed25519.bin", 58),
        ("mcuboot-ed25519.bin", 13),
    ] {
        let (logs, verdict, status) = harness.run(&image_path(bad), &[]);
        assert_eq!(
            (verdict.as_str(), status),
            ("FAILURE", expected),
            "{bad}: {logs:?}"
        );
        assert_eq!(
            logs,
            [format!(
                "ERR keelsign: image 0 slot 0 rejected: status {expected}"
            )]
        );
    }
}

/// D1 (fail closed): a slot whose flash area cannot be opened is rejected with a keelsign
/// line (status 42, `KEELSIGN_ERR_READ_OTHER`), never passed to MCUboot.
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_unopenable_slot_fails_closed() {
    let image = "keelsign-lms-m32-h5.bin";
    let harness = Harness::new("unmapped", "pq_only", &[raw_lms_key(image)], &[], "", false);
    let (logs, verdict, status) = harness.run(&image_path(image), &["--unmapped"]);
    assert_eq!(
        (verdict.as_str(), status),
        ("FAILURE", 42),
        "logs: {logs:?}"
    );
    assert_eq!(
        logs,
        ["ERR keelsign: image 0 slot 0 rejected: status 42 (flash area)"]
    );
}

/// B1 (swap using offset, the sample's MCUboot mode): MCUboot places the update image in
/// the secondary slot one sector in (`swap_offset.c`) and validates it from there
/// (`boot_get_state_secondary_offset`, `image_validate.c`). The glue built with
/// `MCUBOOT_SWAP_USING_OFFSET` reads it from the same offset: a good image at 0x1000 in
/// slot 1 returns `FIH_BOOT_HOOK_REGULAR` (never `FIH_SUCCESS`), and the primary slot is
/// still read from offset 0.
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_swap_offset_secondary_image_at_sector_offset_returns_regular() {
    let image = "keelsign-lms-m32-h5.bin";
    let harness = Harness::swap_offset("swap-offset-good", &[raw_lms_key(image)]);
    let (logs, verdict, status) = harness.run(
        &image_path(image),
        &[
            "--slot",
            "1",
            "--slot-offset",
            "0x1000",
            "--slot-size",
            "0x76000",
        ],
    );
    assert_eq!((verdict.as_str(), status), ("REGULAR", 0), "logs: {logs:?}");
    assert_eq!(
        logs,
        ["INF keelsign: image 0 slot 1 verified (pq key 0, ed25519 key 4294967295)"]
    );
    let (logs, verdict, status) = harness.run(&image_path(image), &["--slot-size", "0x76000"]);
    assert_eq!((verdict.as_str(), status), ("REGULAR", 0), "logs: {logs:?}");
    assert_eq!(
        logs,
        ["INF keelsign: image 0 slot 0 verified (pq key 0, ed25519 key 4294967295)"]
    );
}

/// B1: under swap using offset a tampered image (one body byte flipped) at 0x1000 in slot
/// 1 is rejected with a keelsign line and status 70 (`KEELSIGN_ERR_IMAGE_DIGEST_MISMATCH`),
/// so the image is verified where it is, not skipped.
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_swap_offset_tampered_image_at_sector_offset_fails() {
    let image = "keelsign-hybrid-bad-body.bin";
    let harness = Harness::swap_offset("swap-offset-tampered", &[raw_lms_key(image)]);
    let (logs, verdict, status) = harness.run(
        &image_path(image),
        &[
            "--slot",
            "1",
            "--slot-offset",
            "0x1000",
            "--slot-size",
            "0x76000",
        ],
    );
    assert_eq!(
        (verdict.as_str(), status),
        ("FAILURE", 70),
        "logs: {logs:?}"
    );
    assert_eq!(logs, ["ERR keelsign: image 0 slot 1 rejected: status 70"]);
}

/// B1 (fail closed): a secondary-slot offset at or past the end of the flash area (here an
/// empty slot of one 0x1000 sector whose image would start at 0x1000) is rejected with a
/// keelsign line and status 40 (`KEELSIGN_ERR_READ_OUT_OF_BOUNDS`), without reading.
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_swap_offset_at_area_end_fails_closed() {
    let harness =
        Harness::swap_offset("swap-offset-end", &[raw_lms_key("keelsign-lms-m32-h5.bin")]);
    let empty =
        Path::new(env!("CARGO_TARGET_TMPDIR")).join("mcuboot-hooktest/swap-offset-end/empty.bin");
    fs::write(&empty, b"").expect("write empty slot");
    let (logs, verdict, status) = harness.run(
        &empty,
        &[
            "--slot",
            "1",
            "--slot-offset",
            "0x1000",
            "--slot-size",
            "0x1000",
        ],
    );
    assert_eq!(
        (verdict.as_str(), status),
        ("FAILURE", 40),
        "logs: {logs:?}"
    );
    assert_eq!(logs, ["ERR keelsign: image 0 slot 1 rejected: status 40"]);
}

/// B1: without `MCUBOOT_SWAP_USING_OFFSET` (scratch, move, overwrite-only) both slots are
/// read from offset 0, as before: a good image at offset 0 passes in either slot, and the
/// glue does not apply an offset it was not built for (an image at 0x1000 in slot 1 has no
/// header at 0: status 30, `KEELSIGN_ERR_PARSE_BAD_MAGIC`).
#[test]
#[ignore = "needs the pinned MCUboot checkout (network, or KEELSIGN_MCUBOOT_DIR); CI step `MCUboot hook harness (network)`"]
fn hook_harness_without_swap_offset_reads_both_slots_from_offset_0() {
    let image = "keelsign-lms-m32-h5.bin";
    let harness = Harness::new(
        "no-swap-offset",
        "pq_only",
        &[raw_lms_key(image)],
        &[],
        "",
        false,
    );
    for slot in ["0", "1"] {
        let (logs, verdict, status) = harness.run(
            &image_path(image),
            &["--slot", slot, "--slot-size", "0x76000"],
        );
        assert_eq!(
            (verdict.as_str(), status),
            ("REGULAR", 0),
            "slot {slot}: {logs:?}"
        );
    }
    let (logs, verdict, status) = harness.run(
        &image_path(image),
        &[
            "--slot",
            "1",
            "--slot-offset",
            "0x1000",
            "--slot-size",
            "0x76000",
        ],
    );
    assert_eq!(
        (verdict.as_str(), status),
        ("FAILURE", 30),
        "logs: {logs:?}"
    );
}

/// Forward compatibility: the glue builds against MCUboot v2.5.0-rc1's headers (same
/// `boot_image_check_hook` prototype, same `boot_get_state_secondary_offset`) and
/// behaves the same there, with and without swap using offset.
#[test]
#[ignore = "needs the MCUboot v2.5.0-rc1 checkout (network); CI step `MCUboot hook harness (network)`"]
fn hook_glue_compiles_against_mcuboot_v2_5_0_rc1_headers() {
    let image = "keelsign-lms-m32-h5.bin";
    let harness = Harness::new("rc1", "pq_only", &[raw_lms_key(image)], &[], "", true);
    let (_, verdict, status) = harness.run(&image_path(image), &[]);
    assert_eq!((verdict.as_str(), status), ("REGULAR", 0));
    let (_, verdict, status) = harness.run(&image_path("keelsign-hss2-m32-h5h5.bin"), &[]);
    assert_eq!((verdict.as_str(), status), ("FAILURE", 15));
    let swap_offset = Harness::with_defines(
        "rc1-swap-offset",
        "pq_only",
        &[raw_lms_key(image)],
        &[],
        "",
        true,
        &["-DMCUBOOT_SWAP_USING_OFFSET=1"],
    );
    let (_, verdict, status) = swap_offset.run(
        &image_path(image),
        &["--slot", "1", "--slot-offset", "0x1000"],
    );
    assert_eq!((verdict.as_str(), status), ("REGULAR", 0));
}

/// The CI `ci` job runs every `hook_` test (network step): the harness tests and the
/// v2.5.0-rc1 compile check, whose names all start with `hook_`.
#[test]
fn ci_runs_the_mcuboot_hook_harness() {
    let ci = read(".github/workflows/ci.yml");
    let job = repo_checks::ci_job(&ci, "ci");
    let command = "cargo test -p repo-checks --locked --test mcuboot -- --ignored hook_";
    let step = job
        .lines()
        .find(|l| l.trim_start().starts_with("run: ") && l.contains("--test mcuboot"))
        .expect("ci job must run the mcuboot repo-checks");
    assert_eq!(
        step.trim_start().strip_prefix("run: "),
        Some(command),
        "ci job must run `{command}` (the filter must reach the rc1 compile check)"
    );
    assert!(job.contains("name: MCUboot hook harness (network)"));
    let source = read("tools/repo-checks/tests/mcuboot.rs");
    for name in [
        "hook_harness_tampered_image_logs_keelsign_and_fails",
        "hook_harness_swap_offset_secondary_image_at_sector_offset_returns_regular",
        "hook_glue_compiles_against_mcuboot_v2_5_0_rc1_headers",
    ] {
        assert!(
            source.contains(&format!("fn {name}()")) && name.starts_with("hook_"),
            "{name} must exist and match the CI filter `hook_`"
        );
    }
}

// ---- Zephyr module, west manifest and sample (text level, not ignored) -------------------

/// D4: with SB_CONFIG_KEELSIGN, sysbuild turns MCUboot's image-access hooks on and its TLV
/// allow list off (keelsign TLVs are not on it), and the module refuses to configure an
/// MCUboot image where the allow list is on or the hooks are off, so a misconfiguration
/// never builds (the toolchain check is `zephyr_build_with_allow_list_enabled_is_refused`).
#[test]
fn sysbuild_forces_allow_list_off_and_hooks_on() {
    let sysbuild = read("sysbuild/CMakeLists.txt");
    for needle in [
        "function(${SYSBUILD_CURRENT_MODULE_NAME}_pre_cmake)",
        "set_config_bool(mcuboot CONFIG_KEELSIGN y)",
        "set_config_bool(mcuboot CONFIG_BOOT_IMAGE_ACCESS_HOOKS y)",
        "set_config_bool(mcuboot CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST n)",
        "set_config_string(mcuboot CONFIG_KEELSIGN_PUBLIC_KEY_FILE",
        "set_config_bool(${DEFAULT_IMAGE} CONFIG_KEELSIGN_SIGN_IMAGE y)",
        "pubkey --key ${key} --out ${pub} --force",
    ] {
        assert!(
            sysbuild.contains(needle),
            "sysbuild/CMakeLists.txt lacks `{needle}`"
        );
    }
    let module = read("zephyr/CMakeLists.txt");
    for needle in [
        "if(CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST)",
        "message(FATAL_ERROR \"keelsign: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y rejects keelsign TLVs 0x4BA0-0x4BA3 (image_validate.c allowed_unprot_tlvs); set it to n\")",
        "if(NOT CONFIG_BOOT_IMAGE_ACCESS_HOOKS)",
        "if(NOT CONFIG_MCUBOOT)",
        "zephyr_library_link_libraries(MCUBOOT_BOOTUTIL)",
        "mcuboot/keelsign_mcuboot_hooks.c",
        "scripts/keelsign_embed_keys.py",
        "build -p keelsign-ffi --profile ffi --locked",
        "PROPERTY SIGNING_SCRIPT ${KEELSIGN_DIR}/cmake/keelsign_signing.cmake",
    ] {
        assert!(
            module.contains(needle),
            "zephyr/CMakeLists.txt lacks `{needle}`"
        );
    }
    let kconfig = read("sysbuild/Kconfig");
    assert!(kconfig.contains("config KEELSIGN_POLICY_HYBRID"));
    assert!(
        kconfig.contains("depends on BOOT_SIGNATURE_TYPE_ED25519"),
        "D11: the hybrid policy needs MCUboot's Ed25519 signature"
    );
    assert!(
        !kconfig.contains("CLASSICAL_ONLY") && !read("zephyr/Kconfig").contains("CLASSICAL_ONLY"),
        "D11: no classical-only policy in the bootloader"
    );
}

/// §0.9: the module's Kconfig is read by every image, and MCUboot's own symbols exist only
/// in the MCUboot image (an undefined symbol is an error in the application image), so
/// zephyr/Kconfig never refers to them; the app-side options depend on Zephyr's
/// BOOTLOADER_MCUBOOT. D9: no ML-DSA option.
#[test]
fn module_kconfig_refers_to_no_mcuboot_only_symbol() {
    let kconfig = read("zephyr/Kconfig");
    for line in kconfig.lines().map(str::trim) {
        if let Some(rest) = line
            .strip_prefix("depends on ")
            .or_else(|| line.strip_prefix("select "))
            .or_else(|| line.strip_prefix("default ").filter(|r| r.contains(" if ")))
        {
            for symbol in rest
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| {
                    w.chars()
                        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
                })
                .filter(|w| w.len() > 1)
            {
                assert!(
                    !(symbol == "MCUBOOT"
                        || symbol.starts_with("BOOT_")
                        || symbol.starts_with("MCUBOOT_")),
                    "zephyr/Kconfig refers to MCUboot-only symbol {symbol}: `{line}`"
                );
            }
        }
    }
    for symbol in [
        "menuconfig KEELSIGN\n",
        "config KEELSIGN_POLICY_PQ_ONLY\n",
        "config KEELSIGN_POLICY_HYBRID\n",
        "config KEELSIGN_PUBLIC_KEY_FILE\n",
        "config KEELSIGN_LIBRARY\n",
        "config KEELSIGN_RUST_TARGET\n",
        "config KEELSIGN_MIN_MAIN_STACK\n",
        "config KEELSIGN_SIGN_IMAGE\n\tbool \"Sign the application with keelsign after imgtool\"\n\tdepends on BOOTLOADER_MCUBOOT\n",
        "config KEELSIGN_SIGNATURE_KEY_FILE\n",
        "config KEELSIGN_CLI\n",
    ] {
        assert!(kconfig.contains(symbol), "zephyr/Kconfig lacks `{symbol}`");
    }
    assert!(!kconfig.to_lowercase().contains("ml-dsa") && !kconfig.contains("MLDSA"));
    let module = read("zephyr/module.yml");
    for needle in [
        "name: keelsign\n",
        "  cmake: zephyr\n",
        "  kconfig: zephyr/Kconfig\n",
        "  sysbuild-cmake: sysbuild\n",
        "  sysbuild-kconfig: sysbuild/Kconfig\n",
    ] {
        assert!(
            module.contains(needle),
            "zephyr/module.yml lacks `{needle}`"
        );
    }
}

/// D3: west.yml pins Zephyr v4.4.2 by commit (which pins MCUboot v2.4.0), imports only
/// the modules the sample needs, and expects the repository at `keelsign`.
#[test]
fn west_manifest_pins_zephyr_v4_4_2() {
    let west = read("west.yml");
    assert!(
        west.contains(&format!("revision: {}", repo_checks::ZEPHYR_PIN)),
        "west.yml must pin Zephyr {}",
        repo_checks::ZEPHYR_PIN
    );
    assert!(west.contains("      # v4.4.2\n"));
    assert!(west.contains("  self:\n    path: keelsign\n"));
    let allowlist: Vec<&str> = west
        .split("name-allowlist:\n")
        .nth(1)
        .expect("name-allowlist")
        .lines()
        .take_while(|l| l.trim_start().starts_with("- "))
        .map(|l| l.trim().trim_start_matches("- "))
        .collect();
    assert_eq!(
        allowlist,
        [
            "cmsis",
            "cmsis_6",
            "hal_nordic",
            "mbedtls",
            "tf-psa-crypto",
            "mcuboot"
        ]
    );
    assert!(west.contains(repo_checks::MCUBOOT_PIN));
}

/// D12: both images of the sample use one partition table with a 64 KB boot partition:
/// the MCUboot image's sysbuild overlay includes the application's board overlay and
/// links MCUboot into the boot partition (a sysbuild `<image>.overlay` replaces MCUboot's
/// own app.overlay, which does only that).
#[test]
fn sample_partitions_are_shared_by_both_images() {
    let board = read("samples/keelsign_hello/boards/nrf52840dk_nrf52840.overlay");
    for needle in [
        "boot_partition: partition@0 {",
        "reg = <0x00000000 0x00010000>;",
        "slot0_partition: partition@10000 {",
        "reg = <0x00010000 0x00074000>;",
        "slot1_partition: partition@84000 {",
        "reg = <0x00084000 0x00074000>;",
    ] {
        assert!(board.contains(needle), "board overlay lacks `{needle}`");
    }
    // 0x84000 + 0x74000 is the board's storage partition at 0xf8000, unchanged.
    assert_eq!(0x84000 + 0x74000, 0xf8000);
    let mcuboot = read("samples/keelsign_hello/sysbuild/mcuboot.overlay");
    assert!(mcuboot.contains("#include \"../boards/nrf52840dk_nrf52840.overlay\"\n"));
    assert!(mcuboot.contains("zephyr,code-partition = &boot_partition;"));
    assert!(
        !mcuboot.contains("reg = <"),
        "the partition table lives only in the board overlay"
    );
    let conf = read("samples/keelsign_hello/sysbuild/mcuboot.conf");
    assert!(conf.contains("CONFIG_MAIN_STACK_SIZE=16384\n"));
    assert!(conf.contains("CONFIG_MCUBOOT_LOG_LEVEL_INF=y\n"));
    let sysbuild = read("samples/keelsign_hello/sysbuild.conf");
    for needle in [
        "SB_CONFIG_BOOTLOADER_MCUBOOT=y\n",
        "SB_CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y\n",
        "SB_CONFIG_KEELSIGN=y\n",
        "SB_CONFIG_KEELSIGN_SIGNATURE_KEY_FILE=\"keelsign-dev.pem\"\n",
        "SB_CONFIG_KEELSIGN_POLICY_PQ_ONLY=y\n",
    ] {
        assert!(sysbuild.contains(needle), "sysbuild.conf lacks `{needle}`");
    }
    // D8: no committed signing key.
    let ignore = read(".gitignore");
    for needle in [
        "samples/**/*.pem\n",
        "*.pem.state\n",
        "*.pem.journal\n",
        "build*/\n",
    ] {
        assert!(ignore.contains(needle), ".gitignore lacks `{needle}`");
    }
}

// ---- Zephyr sample builds (ignored: west + Zephyr SDK, D6) -------------------------------

/// Run `scripts/zephyr_sample_ci.sh` with `steps` (serialised: the steps share build
/// directories) and return its standard output; panics with the output if it fails.
fn sample_ci(steps: &[&str]) -> String {
    static LOCK: Mutex<()> = Mutex::new(());
    let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    assert!(
        repo_checks::west_available(),
        "the Zephyr workspace is missing: run scripts/zephyr-setup.sh (docs/mcuboot.md#setup)"
    );
    let out = Command::new(workspace_root().join("scripts/zephyr_sample_ci.sh"))
        .args(steps)
        .output()
        .expect("run scripts/zephyr_sample_ci.sh");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "scripts/zephyr_sample_ci.sh {steps:?} failed ({}):\n{stdout}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    stdout
}

/// Cargo's target directory as `scripts/zephyr_sample_ci.sh` sees it: `CARGO_TARGET_DIR`
/// (relative to the repository, where the script runs cargo) or `target/`.
fn cargo_target_dir() -> PathBuf {
    let root = workspace_root();
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) if !dir.is_empty() => root.join(dir),
        _ => root.join("target"),
    }
}

/// The keelsign CLI the script's `setup-key` step builds.
fn keelsign_cli() -> PathBuf {
    cargo_target_dir().join("release/keelsign")
}

/// `setup-key build`, once per test binary.
fn sample_built() {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        sample_ci(&["setup-key", "build"]);
    });
}

/// The unprotected TLV types of `image`, from `keelsign inspect --json` (parsed by
/// python3's json module).
fn unprotected_tlvs(image: &Path) -> Vec<u64> {
    let json = run_ok(
        Command::new(keelsign_cli())
            .args(["inspect", "--json"])
            .arg(image),
    );
    let mut python = Command::new("python3");
    python
        .args([
            "-c",
            "import json, sys; print(' '.join(str(t['type']) for t in json.load(sys.stdin)['unprotected']['tlvs']))",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped());
    let mut child = python.spawn().expect("run python3");
    {
        use std::io::Write;
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(json.as_bytes())
            .expect("write JSON");
    }
    let out = child.wait_with_output().expect("python3");
    assert!(
        out.status.success(),
        "python3 could not read the inspect JSON"
    );
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .map(|t| t.parse().expect("numeric TLV type"))
        .collect()
}

fn config_has(config: &str, line: &str) -> bool {
    read(config).lines().any(|l| l == line)
}

/// AC1: `west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild` produces
/// MCUboot and the keelsign-signed application: MCUboot's hex, the application's
/// `zephyr.signed.keelsign.hex`/`.bin` with keelsign's key ID (0x4BA0) and LMS/HSS
/// signature (0x4BA3) next to imgtool's ECDSA signature (0x22), and an MCUboot image
/// configured with the image-access hooks on and the TLV allow list off.
#[test]
#[ignore = "needs west and the Zephyr SDK (scripts/zephyr-setup.sh); CI job `zephyr-sample`"]
fn zephyr_sample_builds_mcuboot_and_keelsign_signed_app() {
    sample_built();
    let root = workspace_root();
    let app = root.join("build/keelsign_hello/zephyr");
    for file in [
        root.join("build/mcuboot/zephyr/zephyr.hex"),
        app.join("zephyr.signed.keelsign.hex"),
        app.join("zephyr.signed.keelsign.bin"),
    ] {
        assert!(
            fs::metadata(&file).is_ok_and(|m| m.len() > 0),
            "{} was not built",
            file.display()
        );
    }
    let tlvs = unprotected_tlvs(&app.join("zephyr.signed.keelsign.bin"));
    for tlv in [0x22, 0x4BA0, 0x4BA3] {
        assert!(tlvs.contains(&tlv), "TLV {tlv:#06x} missing: {tlvs:x?}");
    }
    let mcuboot = "build/mcuboot/zephyr/.config";
    for line in [
        "CONFIG_KEELSIGN=y",
        "CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y",
        "# CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST is not set",
        "CONFIG_MAIN_STACK_SIZE=16384",
    ] {
        assert!(config_has(mcuboot, line), "{mcuboot} lacks `{line}`");
    }
    assert!(config_has(
        "build/keelsign_hello/zephyr/.config",
        "CONFIG_KEELSIGN_SIGN_IMAGE=y"
    ));
    // The keelsign hex is exactly the keelsign bin, at slot 0 (0x10000).
    let (base, bytes) = decode_hex(&read(
        "build/keelsign_hello/zephyr/zephyr.signed.keelsign.hex",
    ));
    assert_eq!(base, 0x10000, "slot0_partition of the sample");
    assert_eq!(
        bytes,
        fs::read(app.join("zephyr.signed.keelsign.bin")).expect("read bin")
    );
}

/// The lowest address and the contiguous bytes of an Intel HEX file (data, end of file,
/// extended segment and linear addresses; start-address records are skipped).
fn decode_hex(text: &str) -> (u32, Vec<u8>) {
    let mut upper = 0u32;
    let mut data: Vec<(u32, Vec<u8>)> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let raw: Vec<u8> = (1..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("hex digit"))
            .collect();
        let count = usize::from(raw[0]);
        let offset = u32::from(u16::from_be_bytes([raw[1], raw[2]]));
        let payload = &raw[4..4 + count];
        assert_eq!(
            raw.iter().fold(0u8, |a, b| a.wrapping_add(*b)),
            0,
            "checksum of `{line}`"
        );
        match raw[3] {
            0x00 => data.push((upper + offset, payload.to_vec())),
            0x01 => break,
            0x02 => upper = u32::from(u16::from_be_bytes([payload[0], payload[1]])) << 4,
            0x04 => upper = u32::from(u16::from_be_bytes([payload[0], payload[1]])) << 16,
            // Start addresses (objcopy writes one); nothing is programmed.
            0x03 | 0x05 => {}
            other => panic!("unexpected record type {other:#04x}"),
        }
    }
    data.sort_by_key(|(addr, _)| *addr);
    let base = data.first().expect("data records").0;
    let mut bytes = Vec::new();
    for (addr, chunk) in data {
        assert_eq!(addr - base, bytes.len() as u32, "contiguous data");
        bytes.extend(chunk);
    }
    (base, bytes)
}

/// AC3: classical signing still works with keelsign enabled: MCUboot keeps its own
/// ECDSA P-256 signature type, the keelsign-signed application still carries imgtool's
/// ECDSA TLV (0x22) and imgtool verifies it with MCUboot's key; keelsign verifies its own
/// signature with the exported public key.
#[test]
#[ignore = "needs west and the Zephyr SDK (scripts/zephyr-setup.sh); CI job `zephyr-sample`"]
fn zephyr_sample_keeps_mcuboot_ecdsa_enabled() {
    sample_built();
    let root = workspace_root();
    assert!(config_has(
        "build/mcuboot/zephyr/.config",
        "CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y"
    ));
    let image = root.join("build/keelsign_hello/zephyr/zephyr.signed.keelsign.bin");
    assert!(unprotected_tlvs(&image).contains(&0x22));
    let topdir = root.parent().expect("workspace").to_path_buf();
    let imgtool = topdir.join(".venv/bin/imgtool");
    let imgtool = if imgtool.is_file() {
        imgtool
    } else {
        PathBuf::from("imgtool")
    };
    let out = run_ok(
        Command::new(imgtool)
            .arg("verify")
            .arg("--key")
            .arg(topdir.join("bootloader/mcuboot/root-ec-p256.pem"))
            .arg(&image),
    );
    assert!(out.contains("Image was correctly validated"), "{out}");
    run_ok(
        Command::new(keelsign_cli())
            .args(["verify", "--pub"])
            .arg(root.join("build/keelsign.pub.pem"))
            .arg(&image),
    );
}

/// AC3 (Ed25519 + PQ_ONLY): `KEELSIGN_POLICY_PQ_ONLY` works with MCUboot's Ed25519
/// signature too. The full sample build with `SB_CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y`
/// links into the 64 KB boot partition, MCUboot is configured with Ed25519, the hooks and
/// the PQ-only policy, and the application carries imgtool's Ed25519 TLV (0x24) next to
/// keelsign's (0x4BA0, 0x4BA3); imgtool and keelsign both verify it (step
/// `ed25519-build`).
#[test]
#[ignore = "needs west and the Zephyr SDK (scripts/zephyr-setup.sh); CI job `zephyr-sample`"]
fn zephyr_sample_mcuboot_ed25519_pq_only_build_links() {
    let out = sample_ci(&["setup-key", "ed25519-build"]);
    assert!(out.contains("zephyr_sample_ci: ok: ed25519-build"), "{out}");
    let root = workspace_root();
    let mcuboot = "build-ed25519/mcuboot/zephyr/.config";
    for line in [
        "CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y",
        "CONFIG_KEELSIGN_POLICY_PQ_ONLY=y",
        "CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y",
    ] {
        assert!(config_has(mcuboot, line), "{mcuboot} lacks `{line}`");
    }
    assert!(
        fs::metadata(root.join("build-ed25519/mcuboot/zephyr/zephyr.elf"))
            .is_ok_and(|m| m.len() > 0),
        "the Ed25519 MCUboot did not link"
    );
    let tlvs = unprotected_tlvs(
        &root.join("build-ed25519/keelsign_hello/zephyr/zephyr.signed.keelsign.bin"),
    );
    for tlv in [0x24, 0x4BA0, 0x4BA3] {
        assert!(tlvs.contains(&tlv), "TLV {tlv:#06x} missing: {tlvs:x?}");
    }
}

/// AC3 (hybrid): with MCUboot's Ed25519 signature and `SB_CONFIG_KEELSIGN_POLICY_HYBRID`
/// the sample configures, and the hook and `libkeelsign.a` with the `ed25519` feature
/// compile for the MCUboot image. Compile-only: the hybrid MCUboot does not fit the 64 KB
/// boot partition (docs/benchmarks.md#mcuboot-with-keelsign-sha-62).
#[test]
#[ignore = "needs west and the Zephyr SDK (scripts/zephyr-setup.sh); CI job `zephyr-sample`"]
fn zephyr_sample_hybrid_ed25519_build_compiles() {
    let out = sample_ci(&["setup-key", "hybrid-build"]);
    assert!(out.contains("zephyr_sample_ci: ok: hybrid-build"), "{out}");
    assert!(config_has(
        "build-hybrid/mcuboot/zephyr/.config",
        "CONFIG_KEELSIGN_POLICY_HYBRID=y"
    ));
    let keys = read("build-hybrid/mcuboot/modules/keelsign/keelsign_mcuboot_keys.c");
    assert!(keys.contains("KEELSIGN_ALG_ED25519") && keys.contains("KEELSIGN_POLICY_HYBRID"));
}

/// D4 (ticket comment): an MCUboot build with keelsign and MCUboot's TLV allow list on
/// stops at configure time with keelsign's message. Sysbuild always turns the allow list
/// off for keelsign, so the check builds MCUboot on its own with CONFIG_KEELSIGN=y.
#[test]
#[ignore = "needs west and the Zephyr SDK (scripts/zephyr-setup.sh); CI job `zephyr-sample`"]
fn zephyr_build_with_allow_list_enabled_is_refused() {
    let out = sample_ci(&["setup-key", "allow-list-refused"]);
    assert!(
        out.contains("zephyr_sample_ci: ok: allow-list-refused"),
        "{out}"
    );
    let path = cargo_target_dir().join("allow-list-refused.log");
    let log = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let log = log.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(log.contains(
        "keelsign: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y rejects keelsign TLVs 0x4BA0-0x4BA3 (image_validate.c allowed_unprot_tlvs); set it to n"
    ));
}

/// AC4: the MCUboot flash/RAM table in docs/benchmarks.md is what a fresh stock and
/// keelsign build of the sample measure, cell for cell.
#[test]
#[ignore = "needs west and the Zephyr SDK (scripts/zephyr-setup.sh); CI job `zephyr-sample`"]
fn zephyr_sample_sizes_match_recorded_table() {
    sample_built();
    let out = sample_ci(&["stock-build", "sizes"]);
    let measured: Vec<&str> = out
        .lines()
        .skip_while(|l| !l.starts_with("| MCUboot image |"))
        .take_while(|l| l.starts_with('|'))
        .collect();
    assert_eq!(measured.len(), 5, "sizes table:\n{out}");
    let doc = read("docs/benchmarks.md");
    let recorded: Vec<&str> = doc
        .lines()
        .skip_while(|l| !l.starts_with("| MCUboot image |"))
        .take_while(|l| l.starts_with('|'))
        .collect();
    assert_eq!(
        recorded, measured,
        "docs/benchmarks.md#mcuboot-with-keelsign-sha-62 differs from a fresh build"
    );
}

/// TP3 / D7: the `zephyr-sample` CI job builds the sample on a fresh runner with nothing
/// but the two scripts docs/mcuboot.md tells a reader to run, with the repository checked
/// out as `keelsign` inside the workspace and the soft-float Rust target installed.
#[test]
fn ci_has_the_zephyr_sample_job() {
    let ci = read(".github/workflows/ci.yml");
    let job = repo_checks::ci_job(&ci, "zephyr-sample");
    for needle in [
        "    name: zephyr-sample\n",
        "          path: keelsign\n",
        "          targets: thumbv7em-none-eabi\n",
        "run: keelsign/scripts/zephyr-setup.sh\n",
        "run: keelsign/scripts/zephyr_sample_ci.sh all\n",
        "hashFiles('keelsign/west.yml', 'keelsign/scripts/zephyr-setup.sh')",
    ] {
        assert!(job.contains(needle), "zephyr-sample job lacks `{needle}`");
    }
    // Only the documented scripts run west.
    assert!(!job.contains("west build") && !job.contains("west init"));
}

/// D6: the setup script pins what the docs and the repo-checks name, checks the SDK
/// archives' SHA256, never registers anything outside the workspace and refuses a
/// directory that is not a fresh workspace.
#[test]
fn zephyr_setup_script_is_pinned_and_guarded() {
    let setup = read("scripts/zephyr-setup.sh");
    for needle in [
        &format!("WEST_VERSION={}\n", repo_checks::WEST_VERSION),
        &format!("ZEPHYR_REV={}\n", repo_checks::ZEPHYR_PIN),
        &format!("MCUBOOT_REV={}\n", repo_checks::MCUBOOT_PIN),
        &format!("SDK_VERSION={}\n", repo_checks::ZEPHYR_SDK_VERSION),
        &"IMGTOOL_VERSION=2.4.0\n".to_owned(),
        &"SDK_SHA256_macos_aarch64_minimal=867063901f39528a6175a80ebc20367bd6cb440593e7e2650eda30392f1f6b65\n".to_owned(),
        &"SDK_SHA256_macos_aarch64_arm=4008edb5d4840cd994aedd7f1309bfb63e7243729d57839ebf1cc83c1f17c886\n".to_owned(),
        &"SDK_SHA256_linux_x86_64_minimal=ca9bc0ff66fafca1dac9d592a36d953cf16d096a9d09b1c0357f021cf9f6a7eb\n".to_owned(),
        &"SDK_SHA256_linux_x86_64_arm=21b85981cb5a1818d9bc53d82af80f208946ec038b982ff1907287572ed3a634\n".to_owned(),
        &"west init -l keelsign".to_owned(),
        &"west update --narrow -o=--depth=1".to_owned(),
        &"is inside a git work tree".to_owned(),
        &"the workspace may hold only keelsign and what this script installs".to_owned(),
        &"SHA256 mismatch".to_owned(),
    ] {
        assert!(setup.contains(needle.as_str()), "scripts/zephyr-setup.sh lacks `{needle}`");
    }
    assert!(
        !setup.contains("setup.sh -c") && !setup.contains("sudo "),
        "nothing outside the workspace"
    );
}

// ---- docs/mcuboot.md ----------------------------------------------------------------------

/// The lines of every ```sh block of `markdown` (indented blocks too), each line trimmed.
fn doc_sh_blocks(markdown: &str) -> Vec<Vec<String>> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<String>> = None;
    for line in markdown.lines() {
        let trimmed = line.trim();
        match (&mut current, trimmed) {
            (None, "```sh") => current = Some(Vec::new()),
            (Some(_), "```") => blocks.extend(current.take()),
            (Some(block), _) => block.push(trimmed.to_owned()),
            (None, _) => {}
        }
    }
    blocks
}

/// The `# doc: NAME` ... `# end doc` blocks of a script: (NAME, trimmed lines).
fn script_doc_blocks(script: &str) -> Vec<(String, Vec<String>)> {
    let mut blocks = Vec::new();
    let mut current: Option<(String, Vec<String>)> = None;
    for line in script.lines().map(str::trim) {
        if let Some(name) = line.strip_prefix("# doc: ") {
            assert!(current.is_none(), "nested `# doc:` block {name}");
            current = Some((name.to_owned(), Vec::new()));
        } else if line == "# end doc" {
            blocks.push(current.take().expect("`# end doc` without `# doc:`"));
        } else if let Some((_, lines)) = &mut current {
            lines.push(line.to_owned());
        }
    }
    assert!(current.is_none(), "unterminated `# doc:` block");
    blocks
}

/// TP3: a reader following docs/mcuboot.md runs exactly what CI and the repo-checks run:
/// the setup commands are the ones `scripts/zephyr-setup.sh` documents, every command
/// block of `scripts/zephyr_sample_ci.sh` is a `sh` block of the doc, every step is named
/// there, and the on-board procedures P1-P4 are marked NEEDS-HARDWARE.
#[test]
fn doc_commands_match_scripts() {
    let doc = read("docs/mcuboot.md");
    let blocks = doc_sh_blocks(&doc);

    let setup = [
        "mkdir keelsign-ws && cd keelsign-ws",
        "git clone https://github.com/smhasan94/keelsign",
        "keelsign/scripts/zephyr-setup.sh",
    ];
    assert!(
        blocks.iter().any(|b| b == &setup),
        "docs/mcuboot.md must have the setup block {setup:?}"
    );
    for file in ["scripts/zephyr-setup.sh", "west.yml"] {
        let text = read(file);
        let header: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix('#'))
            .map(str::trim)
            .collect();
        assert!(
            header.windows(3).any(|w| w == setup),
            "{file} must document the setup commands {setup:?}"
        );
    }
    assert!(
        blocks
            .iter()
            .any(|b| b == &["rustup target add thumbv7em-none-eabi"])
    );

    let script = read("scripts/zephyr_sample_ci.sh");
    let script_blocks = script_doc_blocks(&script);
    let names: Vec<&str> = script_blocks.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "setup-key",
            "build",
            "verify",
            "variants",
            "ed25519-build",
            "hybrid-build",
            "allow-list-refused",
            "stock-build",
            "sizes"
        ]
    );
    for (name, lines) in &script_blocks {
        assert!(!lines.is_empty(), "empty `# doc: {name}` block");
        assert!(
            blocks.iter().any(|b| b == lines),
            "docs/mcuboot.md has no `sh` block equal to the `{name}` commands of \
             scripts/zephyr_sample_ci.sh:\n{}",
            lines.join("\n")
        );
    }
    let all = script
        .lines()
        .find(|l| l.trim_start().starts_with("all) set -- "))
        .expect("the `all` step list");
    for step in all
        .trim()
        .trim_start_matches("all) set -- ")
        .trim_end_matches(" ;;")
        .split(' ')
    {
        assert!(
            doc.contains(&format!("`{step}`")),
            "docs/mcuboot.md must name the step `{step}`"
        );
    }

    for heading in [
        "### P1: good image boots (NEEDS-HARDWARE)",
        "### P2: tampered image rejected (NEEDS-HARDWARE)",
        "### P3: wrong key rejected (NEEDS-HARDWARE)",
        "### P4: classical fallback (NEEDS-HARDWARE)",
    ] {
        assert!(
            doc.lines().any(|l| l == heading),
            "docs/mcuboot.md lacks `{heading}`"
        );
    }
    let flat = doc.split_whitespace().collect::<Vec<_>>().join(" ");
    for needle in [
        "keelsign: image 0 slot 0 verified (pq key 0, ed25519 key 4294967295)",
        "E: keelsign: image 0 slot 0 rejected: status 70",
        "rejected: status 15",
        "rejected: status 13",
        "hello from keelsign_hello",
        "build/variants/tampered.hex",
        "build/variants/wrong-key.hex",
        "build/variants/bad-ecdsa.hex",
        "probe-rs download --chip nRF52840_xxAA --binary-format hex build/mcuboot/zephyr/zephyr.hex",
        "probe-rs download --chip nRF52840_xxAA --binary-format hex build/keelsign_hello/zephyr/zephyr.signed.keelsign.hex",
        "MCUBOOT_USE_CUSTOM_CRYPTO",
        "boot_image_check_hook",
        repo_checks::ZEPHYR_PIN,
        repo_checks::MCUBOOT_PIN,
        repo_checks::MCUBOOT_RC1_PIN,
        "SHA-328",
    ] {
        assert!(
            flat.contains(needle),
            "docs/mcuboot.md must mention `{needle}`"
        );
    }
}
