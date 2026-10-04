//! SHA-60: the C static library `libkeelsign.a` (keelsign-ffi), its cbindgen header,
//! the build profile and the CI steps that check them.

use policy_kat::{Case, ED25519_TEST_KEY, Expect, Fixture, POLICY_TARGET, Policy};
use repo_checks::{ScratchDir, cargo_in, run_ok, workspace_root};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The cbindgen release the header is generated with (CI, docs, header banner).
const CBINDGEN_VERSION: &str = "0.29.4";

/// The command that (re)generates the header, from the repository root.
const CBINDGEN_COMMAND: &str = "cbindgen --config keelsign-ffi/cbindgen.toml --crate keelsign-ffi --output keelsign-ffi/include/keelsign.h keelsign-ffi";

/// The documented build command of the library (without target or features).
const BUILD_COMMAND: &str = "cargo build -p keelsign-ffi --profile ffi --locked";

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of the CI job `name` (two-space indented key), up to the next job.
fn ci_job(ci: &str, name: &str) -> String {
    let start = ci
        .find(&format!("\n  {name}:"))
        .unwrap_or_else(|| panic!("ci.yml must have a `{name}` job"));
    ci[start + 1..]
        .lines()
        .enumerate()
        .take_while(|(i, line)| {
            let next_job = line.starts_with("  ") && !line.starts_with("   ");
            let top_level = !line.is_empty() && !line.starts_with(' ');
            *i == 0 || !(next_job || top_level)
        })
        .map(|(_, line)| format!("{line}\n"))
        .collect()
}

/// The `NAME = number` variants of the Rust `keelsign_status_t` enum in status.rs.
fn rust_status_codes() -> Vec<(String, i64)> {
    let status = read("keelsign-ffi/src/status.rs");
    let start = status
        .find("pub enum keelsign_status_t {")
        .expect("status.rs defines keelsign_status_t");
    let body = &status[start..];
    let body = &body[..body.find("\n}").expect("enum is closed")];
    body.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("KEELSIGN_"))
        .map(|l| {
            let (name, value) = l
                .trim_end_matches(',')
                .split_once(" = ")
                .unwrap_or_else(|| panic!("status.rs: `{l}` has no explicit value"));
            (name.to_owned(), value.parse().expect("numeric value"))
        })
        .collect()
}

/// The `NAME = number` enumerators of `enum keelsign_status_t` in the header.
fn header_status_codes(header: &str) -> Vec<(String, i64)> {
    let start = header
        .find("enum keelsign_status_t")
        .expect("keelsign.h declares enum keelsign_status_t");
    let body = &header[start..];
    let body = &body[body.find('{').expect("enum body")..body.find("};").expect("enum end")];
    body.lines()
        .map(str::trim)
        .filter(|l| l.starts_with("KEELSIGN_"))
        .map(|l| {
            let (name, value) = l
                .trim_end_matches(',')
                .split_once(" = ")
                .unwrap_or_else(|| panic!("keelsign.h: `{l}` has no explicit value"));
            (name.to_owned(), value.parse().expect("numeric value"))
        })
        .collect()
}

/// `#define NAME value` lines of the header.
fn header_defines(header: &str) -> Vec<(String, String)> {
    header
        .lines()
        .filter_map(|l| l.strip_prefix("#define "))
        .filter_map(|l| l.split_once(' '))
        .map(|(n, v)| (n.to_owned(), v.trim().to_owned()))
        .collect()
}

/// `pub const NAME: type = value;` items of the crate root whose value is a number or a
/// `keelsign_*_t(number)`.
fn rust_consts() -> Vec<(String, String)> {
    read("keelsign-ffi/src/lib.rs")
        .lines()
        .filter_map(|l| l.strip_prefix("pub const "))
        .filter_map(|l| {
            let (name, rest) = l.split_once(':')?;
            let value = rest.split_once(" = ")?.1.trim_end_matches(';');
            let value = value
                .split_once('(')
                .map_or(value, |(_, v)| v.trim_end_matches(')'));
            Some((name.to_owned(), value.replace('_', "")))
        })
        .collect()
}

/// AC1 (named check, CI step `keelsign.h drift (cbindgen 0.29.4)`): the committed header
/// is exactly what cbindgen 0.29.4 generates from the sources and config.
#[test]
#[ignore = "needs cbindgen 0.29.4 on PATH (`cargo install cbindgen --version 0.29.4 --locked`); CI step `keelsign.h drift (cbindgen 0.29.4)`"]
fn keelsign_h_matches_cbindgen_output() {
    let root = workspace_root();
    let version = Command::new("cbindgen")
        .arg("--version")
        .output()
        .expect("run cbindgen --version (install cbindgen 0.29.4)");
    let version = String::from_utf8_lossy(&version.stdout);
    assert_eq!(
        version.trim(),
        format!("cbindgen {CBINDGEN_VERSION}"),
        "the header is pinned to cbindgen {CBINDGEN_VERSION}"
    );
    let scratch = ScratchDir::new("ffi_cbindgen");
    let fresh = scratch.path().join("keelsign.h");
    let mut args: Vec<String> = CBINDGEN_COMMAND
        .split(' ')
        .skip(1)
        .map(str::to_owned)
        .collect();
    let at = args.iter().position(|a| a == "--output").unwrap() + 1;
    args[at] = fresh.display().to_string();
    let out = Command::new("cbindgen")
        .current_dir(&root)
        .args(&args)
        .output()
        .expect("run cbindgen");
    assert!(
        out.status.success(),
        "cbindgen failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fresh = fs::read_to_string(&fresh).expect("read generated header");
    assert!(
        fresh == read("keelsign-ffi/include/keelsign.h"),
        "keelsign-ffi/include/keelsign.h differs from cbindgen {CBINDGEN_VERSION} output; \
         regenerate it with `{CBINDGEN_COMMAND}` (never edit it by hand)"
    );
}

/// AC1: the header's status enum is the Rust enum, name for name and number for number,
/// with the documented ranges; its other constants are the crate root's.
#[test]
fn header_status_codes_match_the_rust_enum() {
    let header = read("keelsign-ffi/include/keelsign.h");
    let rust = rust_status_codes();
    let c = header_status_codes(&header);
    assert_eq!(c, rust, "keelsign.h status codes differ from status.rs");
    assert_eq!(rust.len(), 59);
    assert_eq!(rust.first(), Some(&("KEELSIGN_OK".to_owned(), 0)));
    let mut numbers: Vec<i64> = rust.iter().map(|(_, n)| *n).collect();
    numbers.dedup();
    assert_eq!(
        numbers.len(),
        rust.len(),
        "status numbers are distinct and ascending"
    );
    assert!(numbers.windows(2).all(|w| w[0] < w[1]));
    for (name, n) in &rust {
        let ok = match n {
            0 => name == "KEELSIGN_OK",
            1..=4 => true,
            5..=9 => true,
            10..=23 => true,
            30..=39 => name.starts_with("KEELSIGN_ERR_PARSE_"),
            40..=49 => name.starts_with("KEELSIGN_ERR_READ_"),
            50..=59 => name.starts_with("KEELSIGN_ERR_ED25519_"),
            60..=79 => {
                name.starts_with("KEELSIGN_ERR_IMAGE_") || name == "KEELSIGN_ERR_IMAGE_UNKNOWN"
            }
            99 => name == "KEELSIGN_ERR_UNKNOWN",
            _ => false,
        };
        assert!(ok, "{name} = {n} is outside its documented range");
        let catch_all = name.ends_with("_UNKNOWN");
        assert_eq!(
            catch_all,
            [9, 39, 49, 59, 79, 99].contains(n),
            "{name} = {n}: catch-alls are exactly 9, 39, 49, 59, 79 and 99"
        );
    }
    assert!(
        header.contains("typedef int32_t keelsign_status_t;"),
        "C99 callers see keelsign_status_t as int32_t"
    );

    let defines = header_defines(&header);
    let consts = rust_consts();
    assert_eq!(consts.len(), 13, "crate-root constants: {consts:?}");
    for (name, value) in &consts {
        let define = defines
            .iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("keelsign.h does not #define {name}"));
        let rust_value: u64 = if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).unwrap()
        } else {
            value.parse().unwrap()
        };
        assert_eq!(
            define.1.parse::<u64>().ok(),
            Some(rust_value),
            "keelsign.h #define {name} {} differs from lib.rs {value}",
            define.1
        );
    }
    for (name, value) in [
        ("KEELSIGN_ABI_VERSION", "1"),
        ("KEELSIGN_ALG_MLDSA44", "1"),
        ("KEELSIGN_ALG_MLDSA65", "2"),
        ("KEELSIGN_ALG_LMS_HSS", "3"),
        ("KEELSIGN_ALG_ED25519", "4"),
        ("KEELSIGN_POLICY_CLASSICAL_ONLY", "1"),
        ("KEELSIGN_POLICY_PQ_ONLY", "2"),
        ("KEELSIGN_POLICY_HYBRID", "3"),
        ("KEELSIGN_MAX_PQ_KEYS", "8"),
        ("KEELSIGN_MAX_ED25519_KEYS", "8"),
        ("KEELSIGN_TLV_BUF_LEN", "4096"),
        ("KEELSIGN_CHUNK_LEN", "256"),
        ("KEELSIGN_NO_KEY", "4294967295"),
    ] {
        assert!(
            defines.iter().any(|(n, v)| n == name && v == value),
            "keelsign.h must #define {name} {value}"
        );
    }
    for decl in [
        "typedef uint32_t keelsign_alg_t;",
        "typedef uint32_t keelsign_policy_t;",
        "keelsign_status_t keelsign_verify(const uint8_t *image,",
        "const struct keelsign_key_t *keys,",
        "struct keelsign_result_t *out);",
        "keelsign_status_t keelsign_digest(const uint8_t *image, size_t len, uint8_t *out_digest);",
    ] {
        assert!(header.contains(decl), "keelsign.h must declare `{decl}`");
    }
}

/// Scope: the header carries the pointer/length contract of both functions, the build
/// command and the do-not-edit banner.
#[test]
fn header_documents_the_pointer_contract_and_build_command() {
    let header = read("keelsign-ffi/include/keelsign.h");
    for needle in [
        "DO NOT EDIT",
        CBINDGEN_COMMAND,
        BUILD_COMMAND,
        "target[/<triple>]/ffi/libkeelsign.a",
        "#ifndef KEELSIGN_H",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "extern \"C\" {",
        "`image` is non-NULL and readable for `len` bytes, at any alignment.",
        "`keys` is NULL only if `n_keys` is 0",
        "Each `keys[i].key` is non-NULL and readable for `keys[i].key_len` bytes.",
        "`out` is NULL or writable for one `keelsign_result_t` (any alignment).",
        "On any error `*out` is left untouched.",
        "`out_digest` is non-NULL and writable for 32 bytes.",
        "Nothing is retained",
        "`len > UINT32_MAX` (`KEELSIGN_ERR_IMAGE_TOO_LARGE`)",
        "`len == 0` gives\n// `KEELSIGN_ERR_PARSE_TRUNCATED`",
        "pointer identity",
    ] {
        assert!(
            header.contains(needle),
            "keelsign.h must document `{needle}`"
        );
    }
    assert_eq!(
        header.matches("// # Safety").count(),
        2,
        "one Safety section per function"
    );
}

/// AC1: cbindgen is pinned to one version in the config, the header banner and CI.
#[test]
fn cbindgen_version_is_pinned_everywhere() {
    let banner = format!("Generated by cbindgen {CBINDGEN_VERSION}");
    assert!(read("keelsign-ffi/include/keelsign.h").contains(&banner));
    assert!(read("keelsign-ffi/cbindgen.toml").contains(&format!("cbindgen {CBINDGEN_VERSION}")));
    let ci = read(".github/workflows/ci.yml");
    assert!(ci.contains(&format!("tool: cbindgen@{CBINDGEN_VERSION}")));
    assert!(ci.contains(&format!("keelsign.h drift (cbindgen {CBINDGEN_VERSION})")));
    for text in [ci.as_str()] {
        for (at, _) in text.match_indices("cbindgen@") {
            assert!(
                text[at..].starts_with(&format!("cbindgen@{CBINDGEN_VERSION}")),
                "every cbindgen install is pinned to {CBINDGEN_VERSION}"
            );
        }
    }
}

/// AC1 / TP2 / AC4: the `ci` job installs the pinned cbindgen and verifies the header.
#[test]
fn ci_verifies_the_header_and_runs_the_ffi_steps() {
    let ci = read(".github/workflows/ci.yml");
    let host = ci_job(&ci, "ci");
    for needle in [
        &format!("tool: cbindgen@{CBINDGEN_VERSION}"),
        &format!("name: keelsign.h drift (cbindgen {CBINDGEN_VERSION})"),
        &format!("{CBINDGEN_COMMAND} --verify"),
        &"name: C harness (libkeelsign, ASan+UBSan)".to_owned(),
        &"cargo test -p repo-checks --locked --test ffi\n".to_owned(),
    ] {
        assert!(host.contains(needle.as_str()), "ci job must run `{needle}`");
    }
    // TP2 / TP3: every verify-cross matrix entry (both Cortex-M targets, four feature
    // states; repo_checks::verify_crate checks the matrix) lints, builds and checks
    // libkeelsign.a with the same target and features.
    let cross = ci_job(&ci, "verify-cross");
    for needle in [
        "name: cargo clippy (keelsign-ffi)",
        "cargo clippy -p keelsign-ffi --lib --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\" -- -D warnings",
        "name: cargo build (keelsign-ffi, profile ffi)",
        "cargo build -p keelsign-ffi --profile ffi --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\"",
        "name: libkeelsign symbols (no fmt, no panic strings)",
        "python3 scripts/staticlib_sizes.py --check --features \"${{ matrix.features }}\" target/${{ matrix.target }}/ffi/libkeelsign.a",
    ] {
        assert!(
            cross.contains(needle),
            "verify-cross job must run `{needle}`"
        );
    }
}

/// Scope: the manifest and the root `[profile.ffi]` are as specified: `staticlib` named
/// `keelsign`, unpublished, LMS-only default features, and a size-optimised, single-unit,
/// fat-LTO, abort-on-panic profile.
#[test]
fn keelsign_ffi_manifest_and_profile_are_as_specified() {
    let manifest = read("keelsign-ffi/Cargo.toml");
    for needle in [
        "name = \"keelsign-ffi\"",
        "publish = false",
        "[lib]\n",
        "name = \"keelsign\"\ncrate-type = [\"staticlib\"]",
        "default = []\ned25519 = [\"keelsign-verify/ed25519\"]\nml-dsa = [\"keelsign-verify/ml-dsa\"]",
        "keelsign-verify = { path = \"../keelsign-verify\", version = \"=0.0.1\" }",
        "unsafe_code = \"deny\"",
        "unsafe_op_in_unsafe_fn = \"deny\"",
        "undocumented_unsafe_blocks = \"deny\"",
    ] {
        assert!(
            manifest.contains(needle),
            "keelsign-ffi/Cargo.toml must contain `{needle}`"
        );
    }
    let root = read("Cargo.toml");
    let profile = root
        .split("[profile.ffi]\n")
        .nth(1)
        .expect("root Cargo.toml has [profile.ffi]");
    let profile = profile.split("\n[").next().unwrap_or(profile);
    for line in [
        "inherits = \"release\"",
        "opt-level = \"z\"",
        "lto = \"fat\"",
        "codegen-units = 1",
        "panic = \"abort\"",
        "debug = false",
        "strip = \"debuginfo\"",
    ] {
        assert!(
            profile.lines().any(|l| l.trim() == line),
            "[profile.ffi] must set `{line}`"
        );
    }
    let lib = read("keelsign-ffi/src/lib.rs");
    for attr in [
        "#![cfg_attr(not(panic = \"unwind\"), no_std)]",
        "#![deny(unsafe_code)]",
        "#![deny(missing_docs)]",
    ] {
        assert!(
            lib.contains(attr),
            "keelsign-ffi/src/lib.rs must have `{attr}`"
        );
    }
}

// ---- C harness (AC2, TP1, AC4) ----------------------------------------------------------

/// The two library builds the harness links against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Build {
    /// Default features: LMS/HSS only.
    Default,
    /// `--features ed25519,ml-dsa`.
    AllFeatures,
}

impl Build {
    const ALL: [Build; 2] = [Build::Default, Build::AllFeatures];

    fn name(self) -> &'static str {
        match self {
            Build::Default => "default",
            Build::AllFeatures => "ed25519,ml-dsa",
        }
    }

    fn ed25519(self) -> bool {
        self == Build::AllFeatures
    }

    fn ml_dsa(self) -> bool {
        self == Build::AllFeatures
    }
}

/// Harness binaries and key files, built once per test binary.
struct Harness {
    default: PathBuf,
    all_features: PathBuf,
    keys: PathBuf,
}

impl Harness {
    fn binary(&self, build: Build) -> &Path {
        match build {
            Build::Default => &self.default,
            Build::AllFeatures => &self.all_features,
        }
    }
}

/// The sanitizers the harness is built with: `KEELSIGN_FFI_SANITIZE` if set (empty or
/// `none` for none), else AddressSanitizer + UBSan on Linux and UBSan alone elsewhere
/// (ASan hangs on macOS; docs/ffi.md).
fn sanitizers() -> Option<String> {
    match std::env::var("KEELSIGN_FFI_SANITIZE") {
        Ok(v) if v.is_empty() || v == "none" => None,
        Ok(v) => Some(v),
        Err(_) if cfg!(target_os = "linux") => Some("address,undefined".to_owned()),
        Err(_) => Some("undefined".to_owned()),
    }
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

/// Build `libkeelsign.a` with the `ffi` profile for `build` (its own target directory,
/// so the two feature states do not rebuild each other) and return its path.
fn build_library(build: Build) -> PathBuf {
    let root = workspace_root();
    let target_dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("ffi-{}", build.name().replace(',', "-")));
    let mut cmd = cargo_in(&root, &target_dir);
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
    if build == Build::AllFeatures {
        cmd.args(["--features", "ed25519,ml-dsa"]);
    }
    run_ok(&mut cmd);
    let lib = target_dir.join("ffi").join("libkeelsign.a");
    assert!(lib.is_file(), "expected {}", lib.display());
    lib
}

/// Compile `keelsign-ffi/ctest/harness.c` against `lib` as strict C99.
fn compile_harness(lib: &Path, out: &Path) {
    let root = workspace_root();
    let mut cmd = c_compiler();
    cmd.args(["-std=c99", "-Wall", "-Wextra", "-Werror", "-pedantic", "-g"])
        .arg("-I")
        .arg(root.join("keelsign-ffi/include"));
    if let Some(s) = sanitizers() {
        cmd.arg(format!("-fsanitize={s}"))
            .arg("-fno-sanitize-recover=all")
            .arg("-fno-omit-frame-pointer");
    }
    cmd.arg(root.join("keelsign-ffi/ctest/harness.c"))
        .arg(lib)
        .arg("-o")
        .arg(out);
    if cfg!(target_os = "linux") {
        cmd.args(["-lpthread", "-ldl"]);
    }
    run_ok(&mut cmd);
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("ffi-harness");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("keys")).expect("create harness dir");
        let default = dir.join("harness-default");
        let all_features = dir.join("harness-all-features");
        compile_harness(&build_library(Build::Default), &default);
        compile_harness(&build_library(Build::AllFeatures), &all_features);
        Harness {
            default,
            all_features,
            keys: dir.join("keys"),
        }
    })
}

/// Run the harness and return its `status=` line, failing on a sanitizer report or a
/// non-zero exit.
fn run_harness(build: Build, args: &[String]) -> String {
    let h = harness();
    let out = Command::new(h.binary(build))
        .current_dir(workspace_root())
        .args(args)
        .env("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1")
        .env("ASAN_OPTIONS", "detect_leaks=1:abort_on_error=1")
        .output()
        .expect("run harness");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stderr.is_empty(),
        "harness ({}) {args:?} exited {} with stderr:\n{stderr}\nstdout:\n{stdout}",
        build.name(),
        out.status
    );
    let line = stdout.trim().to_owned();
    assert!(
        line.starts_with("status="),
        "unexpected harness output `{line}`"
    );
    line
}

/// The status number of a harness line.
fn status(line: &str) -> i64 {
    line["status=".len()..]
        .split(' ')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no status in `{line}`"))
}

/// The `key=value` field of a harness line.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split(' ')
        .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        .unwrap_or_else(|| panic!("no {key} in `{line}`"))
}

/// Write `bytes` as a key file named `name` and return the `ALG:FILE` argument.
fn key_arg(alg: &str, name: &str, bytes: &[u8]) -> String {
    let path = harness().keys.join(name);
    fs::write(&path, bytes).expect("write key file");
    format!("{alg}:{}", path.display())
}

fn alg_name(case: &Case<'_>) -> &'static str {
    match case.algorithm.map(|a| format!("{a:?}")).as_deref() {
        Some("MlDsa44") => "mldsa44",
        Some("MlDsa65") => "mldsa65",
        Some("LmsHss") => "lms",
        None => "",
        Some(other) => panic!("no harness algorithm for {other}"),
    }
}

/// The status code of a policy-matrix verdict (the numbers of include/keelsign.h).
fn expected_status(expect: Expect) -> i64 {
    match expect {
        Expect::Ok => 0,
        Expect::ParseBadMagic => 30,
        Expect::MissingPqSignature => 13,
        Expect::MissingKeyId => 10,
        Expect::MultiplePqSignatures => 14,
        Expect::SignatureInvalid => 21,
        Expect::UnsupportedMlDsa44 | Expect::UnsupportedMlDsa65 => 17,
        Expect::Ed25519Missing => 51,
        Expect::Ed25519Multiple => 52,
        Expect::Ed25519Unpaired => 53,
        Expect::Ed25519InvalidSignatureLength => 55,
        Expect::Ed25519SignatureInvalid => 58,
        Expect::ImageEncrypted => 60,
        Expect::ImageCompressed => 61,
        Expect::ImageNonBootable => 62,
        Expect::ImageKeelsignTlvProtectedKeyId => 63,
        Expect::ImageSigPure => 64,
        Expect::ImageMissingSha256Tlv => 65,
        Expect::ImageMultipleSha256Tlvs => 66,
        Expect::ImageMultipleSecurityCounters => 68,
        Expect::ImageDigestMismatch => 70,
        Expect::MalformedSignature => 19,
        Expect::KeyNotTrusted => 15,
    }
}

fn policy_arg(policy: Policy) -> &'static str {
    match policy {
        Policy::ClassicalOnly => "classical_only",
        Policy::PqOnly => "pq_only",
        Policy::Hybrid => "hybrid",
        _ => panic!("unknown policy"),
    }
}

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

fn image_path(name: &str) -> String {
    format!("tests/fixtures/images/{name}")
}

fn cases() -> Vec<Case<'static>> {
    let cases: Vec<Case<'static>> = Fixture::parse(POLICY_TARGET)
        .expect("policy-matrix.bin parses")
        .cases()
        .collect::<Result<_, _>>()
        .expect("every case parses");
    assert_eq!(cases.len(), 52);
    cases
}

/// AC2 (CI step `C harness (libkeelsign, ASan+UBSan)`): a C99 program compiled with
/// `-Wall -Wextra -Werror -pedantic` and sanitizers links `libkeelsign.a` (default and
/// `ed25519,ml-dsa` builds) and, through the C ABI, gives every cell of the SHA-46 policy
/// matrix its recorded verdict (52 images × 3 policies × 2 builds), the documented
/// results for a verified image, MANIFEST.json's digest for every image, and Ok for the
/// 200 KB image under ClassicalOnly.
#[test]
fn c_harness_links_libkeelsign_and_verifies_the_golden_fixtures() {
    let ed = key_arg("ed25519", "ed25519-test-key.raw", &ED25519_TEST_KEY);
    let mut cells = 0;
    for (i, case) in cases().iter().enumerate() {
        let mut keys = Vec::new();
        if case.algorithm.is_some() {
            keys.push(key_arg(
                alg_name(case),
                &format!("case-{i}.raw"),
                case.public_key,
            ));
        }
        keys.push(ed.clone());
        for build in Build::ALL {
            for &policy in Policy::ALL {
                let expected = if policy.requires_ed25519() && !build.ed25519() {
                    50
                } else {
                    expected_status(case.expect(policy, build.ml_dsa()).expect("verdict"))
                };
                let mut args = vec![
                    "verify".to_owned(),
                    policy_arg(policy).to_owned(),
                    image_path(case.name),
                ];
                args.extend(keys.iter().cloned());
                let line = run_harness(build, &args);
                assert_eq!(
                    status(&line),
                    expected,
                    "{} under {policy:?} ({} build): `{line}`",
                    case.name,
                    build.name()
                );
                if expected == 0 {
                    assert_eq!(
                        field(&line, "digest"),
                        manifest_field(case.name, "digest_hex")
                    );
                    let pq = if policy.requires_pq() {
                        "0"
                    } else {
                        "4294967295"
                    };
                    let ed_index = if !policy.requires_ed25519() {
                        "4294967295"
                    } else if case.algorithm.is_some() {
                        "1"
                    } else {
                        "0"
                    };
                    assert_eq!(field(&line, "pq_key_index"), pq, "{}: `{line}`", case.name);
                    assert_eq!(field(&line, "ed25519_key_index"), ed_index, "{}", case.name);
                }
                cells += 1;
            }
        }
    }
    assert_eq!(cells, 52 * 3 * 2);

    // The version, image length and security counter of a verified image.
    let lms = cases()
        .into_iter()
        .find(|c| c.name == "keelsign-lms-m32-h5.bin")
        .expect("LMS case");
    let lms_key = key_arg("lms", "lms.raw", lms.public_key);
    for build in Build::ALL {
        let line = run_harness(
            build,
            &[
                "verify".to_owned(),
                "pq_only".to_owned(),
                image_path(lms.name),
                lms_key.clone(),
            ],
        );
        assert_eq!(status(&line), 0, "{line}");
        assert_eq!(field(&line, "version"), "1.2.3+4");
        assert_eq!(field(&line, "has_security_counter"), "0");
        let len = fs::metadata(workspace_root().join(image_path(lms.name)))
            .expect("image")
            .len();
        assert_eq!(field(&line, "image_len"), len.to_string());
    }

    // keelsign_digest over every image, including the big-endian and 200 KB ones.
    let mut images: Vec<&str> = policy_kat::IMAGES.iter().map(|(n, _)| *n).collect();
    images.push("mcuboot-ed25519-200k.bin");
    for build in Build::ALL {
        for name in &images {
            let line = run_harness(build, &["digest".to_owned(), image_path(name)]);
            if manifest_field(name, "expect_parse") == "Ok" {
                assert_eq!(status(&line), 0, "{name}: `{line}`");
                assert_eq!(
                    field(&line, "digest"),
                    manifest_field(name, "digest_hex"),
                    "{name}"
                );
            } else {
                assert_eq!(status(&line), 30, "{name}: `{line}`");
            }
        }
    }
    assert_eq!(
        status(&run_harness(
            Build::AllFeatures,
            &[
                "verify".to_owned(),
                "pq_only".to_owned(),
                image_path("rejected/mcuboot-ed25519-bigendian.bin"),
                lms_key.clone(),
            ],
        )),
        30
    );

    // The 200 KB image (not in the on-target matrix): Ok under ClassicalOnly with the
    // Ed25519 half compiled in, ED25519_NOT_ENABLED without it.
    for (build, expected) in [(Build::AllFeatures, 0), (Build::Default, 50)] {
        let line = run_harness(
            build,
            &[
                "verify".to_owned(),
                "classical_only".to_owned(),
                image_path("mcuboot-ed25519-200k.bin"),
                ed.clone(),
            ],
        );
        assert_eq!(status(&line), expected, "200k ({}): `{line}`", build.name());
    }
}

/// TP1: tampered images, wrong keys and NULL / zero-length / malformed arguments return
/// their documented codes through the C ABI (both builds where the code is the same).
#[test]
fn c_harness_tampered_wrong_key_and_null_inputs_return_documented_codes() {
    let all = cases();
    let find = |name: &str| *all.iter().find(|c| c.name == name).expect("case");
    let lms = find("keelsign-lms-m32-h5.bin");
    let mldsa44 = find("keelsign-mldsa44.bin");
    let hybrid = find("keelsign-hybrid-ed25519-lms.bin");
    let lms_key = key_arg("lms", "tp1-lms.raw", lms.public_key);
    let mldsa_key = key_arg("mldsa44", "tp1-mldsa44.raw", mldsa44.public_key);
    let hybrid_key = key_arg("lms", "tp1-hybrid-lms.raw", hybrid.public_key);
    let mut wrong_ed = ED25519_TEST_KEY;
    wrong_ed[0] ^= 1;
    let wrong_ed = key_arg("ed25519", "tp1-wrong-ed25519.raw", &wrong_ed);

    // Tampered copies of the LMS image, written next to the key files.
    let image = fs::read(workspace_root().join(image_path(lms.name))).expect("image");
    let tampered = |name: &str, at: usize| {
        let mut bytes = image.clone();
        bytes[at] ^= 1;
        let path = harness().keys.join(name);
        fs::write(&path, bytes).expect("write tampered image");
        path.display().to_string()
    };
    let bad_sig = tampered("tp1-lms-bad-sig.bin", image.len() - 1);
    let bad_body = tampered("tp1-lms-bad-body.bin", 600);
    let empty = harness().keys.join("tp1-empty.bin");
    fs::write(&empty, b"").expect("write empty image");

    let verify = |policy: &str, image: String, keys: &[&String]| {
        let mut args = vec!["verify".to_owned(), policy.to_owned(), image];
        args.extend(keys.iter().map(|k| (*k).clone()));
        args
    };
    // (case, args, default build, all-features build)
    let checks: Vec<(&str, Vec<String>, i64, i64)> = vec![
        (
            "valid LMS image",
            verify("pq_only", image_path(lms.name), &[&lms_key]),
            0,
            0,
        ),
        (
            "LMS signature byte flipped",
            verify("pq_only", bad_sig, &[&lms_key]),
            21,
            21,
        ),
        (
            "LMS body byte flipped",
            verify("pq_only", bad_body, &[&lms_key]),
            70,
            70,
        ),
        (
            "keelsign-hybrid-bad-body.bin",
            verify(
                "pq_only",
                image_path("keelsign-hybrid-bad-body.bin"),
                &[&hybrid_key],
            ),
            70,
            70,
        ),
        (
            "keelsign-mldsa44-bad-sig.bin",
            verify(
                "pq_only",
                image_path("keelsign-mldsa44-bad-sig.bin"),
                &[&mldsa_key],
            ),
            17,
            21,
        ),
        (
            "keelsign-mldsa44-bad-key-id.bin",
            verify(
                "pq_only",
                image_path("keelsign-mldsa44-bad-key-id.bin"),
                &[&mldsa_key],
            ),
            15,
            15,
        ),
        (
            "LMS image with an ML-DSA-44 key",
            verify("pq_only", image_path(lms.name), &[&mldsa_key]),
            15,
            15,
        ),
        (
            "hybrid image with the wrong Ed25519 key",
            verify("hybrid", image_path(hybrid.name), &[&hybrid_key, &wrong_ed]),
            50,
            56,
        ),
        (
            "zero-length image",
            verify("pq_only", empty.display().to_string(), &[&lms_key]),
            31,
            31,
        ),
        (
            "no keys",
            verify("pq_only", image_path(lms.name), &[]),
            15,
            15,
        ),
        (
            "policy 0",
            verify("0", image_path(lms.name), &[&lms_key]),
            3,
            3,
        ),
    ];
    for build in Build::ALL {
        for (what, args, default, all_features) in &checks {
            let expected = if build == Build::Default {
                *default
            } else {
                *all_features
            };
            let line = run_harness(build, args);
            assert_eq!(
                status(&line),
                expected,
                "{what} ({} build): `{line}`",
                build.name()
            );
        }
        // NULL image, NULL keys, NULL digest output, zero length, policy 7, algorithm 9,
        // nine keys, a duplicate key and a short key: 1,1,1,31,3,4,5,6,7.
        let line = run_harness(
            build,
            &[
                "abuse".to_owned(),
                image_path(lms.name),
                lms_key.split_once(':').expect("ALG:FILE").1.to_owned(),
            ],
        );
        assert_eq!(line, "status=1,1,1,31,3,4,5,6,7", "{} build", build.name());
    }
}

// ---- nm check (TP3) and cross builds (TP2) ----------------------------------------------

/// Fragments of mangled names of formatting code.
const FORMATTING: [&str; 9] = [
    "4core3fmt",
    "core..fmt",
    "Formatter",
    "fmt5write",
    "7Display",
    "5Debug",
    "8LowerHex",
    "8UpperHex",
    "9Arguments",
];

/// The allowlisted libcore trap funnels (scripts/staticlib_sizes.py `PANIC_ALLOWLIST`).
const PANIC_FUNNELS: [&str; 8] = [
    "9panicking9panic_fmt",
    "panic_const_div_by_zero",
    "len_mismatch_fail",
    "panic_bounds_check",
    "9panicking5panic17h",
    "16slice_index_fail",
    "6option13expect_failed",
    "6result13unwrap_failed",
];

/// Panic message text that must not be in the library.
const PANIC_STRINGS: [&str; 5] = [
    "panicked",
    "attempt to ",
    "index out of bounds",
    "called `Option::unwrap()`",
    "called `Result::unwrap()`",
];

/// TP3 (host half; the thumb half is `staticlib_sizes.py --check` in the `verify-cross`
/// job): the host `libkeelsign.a` of both builds exports exactly `keelsign_verify` and
/// `keelsign_digest`, has no formatting symbol, no panic symbol but the allowlisted
/// libcore trap funnels, and no panic message text. The literal "no `panic_fmt`" is not
/// reachable on stable (docs/ffi.md#nm-check).
#[test]
fn staticlib_has_no_formatting_symbols_or_panic_strings() {
    for build in Build::ALL {
        let lib = build_library(build);
        let members = run_ok(Command::new("ar").arg("t").arg(&lib));
        let member = members
            .lines()
            .map(str::trim)
            .filter(|m| m.starts_with("keelsign-"))
            .collect::<Vec<_>>();
        assert_eq!(
            member.len(),
            1,
            "one keelsign-* member in {}: {member:?}",
            lib.display()
        );
        let member = member[0];
        let scratch = ScratchDir::new(&format!("ffi_nm_{}", build.name().replace(',', "_")));
        run_ok(
            Command::new("ar")
                .current_dir(scratch.path())
                .arg("x")
                .arg(&lib)
                .arg(member),
        );
        let object = scratch.path().join(member);
        let symbols = run_ok(Command::new("nm").arg(&object));
        let mut exports = Vec::new();
        for line in symbols.lines() {
            let mut fields = line.split_whitespace().rev();
            let (Some(name), Some(kind)) = (fields.next(), fields.next()) else {
                continue;
            };
            let name = name
                .strip_prefix('_')
                .filter(|_| cfg!(target_os = "macos"))
                .unwrap_or(name);
            if kind == "T" {
                exports.push(name.to_owned());
            }
            for fragment in FORMATTING {
                assert!(
                    !name.contains(fragment),
                    "{} build: formatting symbol {name}",
                    build.name()
                );
            }
            let panicky = ["panic", "_fail", "unwrap", "assert", "unreachable"]
                .iter()
                .any(|m| name.contains(m));
            if panicky && kind != "U" {
                assert!(
                    PANIC_FUNNELS.iter().any(|f| name.contains(f)),
                    "{} build: panic symbol {name} is not an allowlisted trap funnel",
                    build.name()
                );
            }
        }
        exports.sort();
        assert_eq!(
            exports,
            ["keelsign_digest", "keelsign_verify"],
            "{} build: exported functions",
            build.name()
        );
        let bytes = fs::read(&object).expect("read object");
        let text = String::from_utf8_lossy(&bytes);
        for needle in PANIC_STRINGS {
            assert!(
                !text.contains(needle),
                "{} build: the library holds panic text `{needle}`",
                build.name()
            );
        }
    }
    // The script's allowlist is this one.
    let script = read("scripts/staticlib_sizes.py");
    for funnel in PANIC_FUNNELS {
        let funnel = funnel.trim_end_matches("17h");
        assert!(
            script.contains(&format!("\"{funnel}\"")),
            "scripts/staticlib_sizes.py PANIC_ALLOWLIST must name {funnel}"
        );
    }
    assert!(script.contains("PANIC_FUNNEL_MAX = 32"));
}

/// TP2 (the CI `verify-cross` job runs the same per matrix entry): keelsign-ffi lints and
/// builds with the `ffi` profile for both Cortex-M targets in the four feature states,
/// and every archive passes `staticlib_sizes.py --check`.
#[test]
#[ignore = "needs the thumbv7em-none-eabihf and thumbv8m.main-none-eabihf targets; CI verify-cross job covers this"]
fn keelsign_ffi_cross_builds() {
    let root = workspace_root();
    let scratch = ScratchDir::new("ffi_cross");
    for target in ["thumbv7em-none-eabihf", "thumbv8m.main-none-eabihf"] {
        for features in ["", "ml-dsa", "ed25519", "ed25519,ml-dsa"] {
            let target_dir = scratch.path().join(if features.is_empty() {
                "none".to_owned()
            } else {
                features.replace(',', "-")
            });
            run_ok(
                cargo_in(&root, &target_dir)
                    .args(["clippy", "-p", "keelsign-ffi", "--lib", "--locked"])
                    .args(["--target", target, "--features", features])
                    .args(["--", "-D", "warnings"]),
            );
            run_ok(
                cargo_in(&root, &target_dir)
                    .args([
                        "build",
                        "-p",
                        "keelsign-ffi",
                        "--profile",
                        "ffi",
                        "--locked",
                    ])
                    .args(["--target", target, "--features", features]),
            );
            let archive = target_dir.join(target).join("ffi").join("libkeelsign.a");
            run_ok(
                repo_checks::python_script("staticlib_sizes.py")
                    .args(["--check", "--features", features])
                    .arg(&archive),
            );
        }
    }
}
