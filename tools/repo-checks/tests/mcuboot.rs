//! SHA-62: keelsign's MCUboot image-check hook (`mcuboot/keelsign_mcuboot_hooks.c`), its
//! host harness against the pinned MCUboot headers (`mcuboot/hooktest`, docs/mcuboot.md).
//!
//! The harness tests are ignored: they need the pinned MCUboot checkout, cloned over the
//! network by `scripts/fetch_mcuboot.py` or taken from `KEELSIGN_MCUBOOT_DIR` (for example
//! the west workspace's `bootloader/mcuboot`). CI step `MCUboot hook harness (network)`:
//! `cargo test -p repo-checks --locked --test mcuboot -- --ignored hook_harness`.

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
/// errors and sanitizers.
fn build_harness(mcuboot: &Path, keys_c: &Path, lib: &Path, out: &Path) {
    let root = workspace_root();
    let mut cmd = c_compiler();
    cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-g"])
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
        let mcuboot = mcuboot_checkout(rc1);
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("mcuboot-hooktest")
            .join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create harness dir");
        let keys_c = embed_keys(&dir, policy, raw, files);
        let binary = dir.join("harness");
        build_harness(&mcuboot, &keys_c, &library(features), &binary);
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

/// Forward compatibility: the glue builds against MCUboot v2.5.0-rc1's headers (same
/// `boot_image_check_hook` prototype) and behaves the same there.
#[test]
#[ignore = "needs the MCUboot v2.5.0-rc1 checkout (network)"]
fn hook_glue_compiles_against_mcuboot_v2_5_0_rc1_headers() {
    let image = "keelsign-lms-m32-h5.bin";
    let harness = Harness::new("rc1", "pq_only", &[raw_lms_key(image)], &[], "", true);
    let (_, verdict, status) = harness.run(&image_path(image), &[]);
    assert_eq!((verdict.as_str(), status), ("REGULAR", 0));
    let (_, verdict, status) = harness.run(&image_path("keelsign-hss2-m32-h5h5.bin"), &[]);
    assert_eq!((verdict.as_str(), status), ("FAILURE", 15));
}

/// The CI `ci` job runs the hook harness tests (network step).
#[test]
fn ci_runs_the_mcuboot_hook_harness() {
    let ci = read(".github/workflows/ci.yml");
    let job = repo_checks::ci_job(&ci, "ci");
    for needle in [
        "name: MCUboot hook harness (network)",
        "cargo test -p repo-checks --locked --test mcuboot -- --ignored hook_harness",
    ] {
        assert!(job.contains(needle), "ci job must have `{needle}`");
    }
}
