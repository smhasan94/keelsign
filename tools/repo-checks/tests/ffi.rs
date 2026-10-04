//! SHA-60: the C static library `libkeelsign.a` (keelsign-ffi), its cbindgen header,
//! the build profile and the CI steps that check them.

use repo_checks::{ScratchDir, workspace_root};
use std::fs;
use std::process::Command;

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
    ] {
        assert!(host.contains(needle.as_str()), "ci job must run `{needle}`");
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
