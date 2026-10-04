//! `keelsign-embassy` crate rules (SHA-55): `no_std`, no heap, no `unsafe`, and CI
//! builds it for both Cortex-M targets with its board modules.

use repo_checks::{
    EXAMPLES, LICENSED_CRATES, PUBLISHABLE_CRATES, SHIPPED_CRATES, ScratchDir, cargo_in, run_ok,
    workspace_root,
};
use std::fs;
use std::path::Path;

/// The keelsign-verify feature states CI builds keelsign-embassy with (its own features
/// of the same names forward to keelsign-verify).
const FEATURE_STATES: [&str; 4] = ["", "ml-dsa", "ed25519", "ed25519,ml-dsa"];

/// The board features per target: the keelsign-embassy module and the HAL chip.
const BOARD_FEATURES: [(&str, &str); 2] = [
    ("thumbv7em-none-eabihf", "nrf,embassy-nrf/nrf52840"),
    ("thumbv8m.main-none-eabihf", "rp,embassy-rp/rp235xa"),
];

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

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The Rust files under `dir` (relative to the workspace root), recursively, as (path
/// relative to the workspace root, text); none if `dir` does not exist.
fn rust_files(dir: &str) -> Vec<(String, String)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                if path.file_name().is_some_and(|n| n != "target") {
                    walk(root, &path, out);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path
                    .strip_prefix(root)
                    .expect("inside the repo")
                    .display()
                    .to_string();
                out.push((rel, fs::read_to_string(&path).expect("read source")));
            }
        }
    }
    let root = workspace_root();
    let mut out = Vec::new();
    let dir = root.join(dir);
    if dir.is_dir() {
        walk(&root, &dir, &mut out);
    }
    out
}

#[test]
fn keelsign_embassy_is_no_std_forbid_unsafe_no_alloc() {
    let lib = read("keelsign-embassy/src/lib.rs");
    for attr in [
        "#![no_std]",
        "#![forbid(unsafe_code)]",
        "#![deny(missing_docs)]",
    ] {
        assert!(
            lib.contains(attr),
            "keelsign-embassy/src/lib.rs must have `{attr}`"
        );
    }
    assert!(
        lib.contains("#[cfg(test)]\nextern crate std;"),
        "`std` may only be linked for tests"
    );
    assert_eq!(lib.matches("extern crate").count(), 1);
    let sources = rust_files("keelsign-embassy/src");
    assert!(sources.len() > 1, "keelsign-embassy/src has its modules");
    for (path, text) in sources
        .into_iter()
        .chain(rust_files("keelsign-embassy/tests"))
    {
        for forbidden in [
            "extern crate alloc",
            "alloc::",
            "unsafe {",
            "unsafe fn",
            "unsafe impl",
            "allow(unsafe_code)",
        ] {
            assert!(
                !text.contains(forbidden),
                "{path} must not contain `{forbidden}`"
            );
        }
    }
    let manifest = read("keelsign-embassy/Cargo.toml");
    assert!(
        manifest.contains("[lints]\nworkspace = true\n"),
        "keelsign-embassy must inherit the workspace lints"
    );
    for forbidden in ["\"alloc\"", "\"std\"", "publish = false"] {
        assert!(
            !manifest.contains(forbidden),
            "keelsign-embassy/Cargo.toml must not contain {forbidden}"
        );
    }
    // Shipped (linked into firmware) and licensed, but not published yet (SHA-166/281).
    assert!(SHIPPED_CRATES.contains(&"keelsign-embassy"));
    assert!(LICENSED_CRATES.contains(&"keelsign-embassy"));
    assert!(!PUBLISHABLE_CRATES.contains(&"keelsign-embassy"));
}

/// SHA-55 AC1: CI lints and tests keelsign-embassy on the host, and builds it for both
/// targets with every keelsign-verify feature state and its board module.
#[test]
fn ci_cross_builds_keelsign_embassy_and_boot_apps() {
    let ci = read(".github/workflows/ci.yml");
    let host = ci_job(&ci, "ci");
    for needle in [
        "cargo clippy -p keelsign-embassy --all-targets --locked -- -D warnings",
        "cargo test -p keelsign-embassy --locked\n",
    ] {
        assert!(host.contains(needle), "ci job must run `{needle}`");
    }
    let cross = ci_job(&ci, "verify-cross");
    let targets: Vec<&str> = EXAMPLES.iter().map(|e| e.target).collect();
    assert_eq!(
        targets,
        BOARD_FEATURES.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
    for (target, board) in BOARD_FEATURES {
        for features in FEATURE_STATES {
            let quoted = if features.is_empty() {
                "\"\"".to_owned()
            } else {
                features.to_owned()
            };
            let entry = format!(
                "- target: {target}\n            features: {quoted}\n            embassy_features: {board}\n"
            );
            assert!(
                cross.contains(&entry),
                "verify-cross matrix must include {target} / \"{features}\" with \
                 embassy_features {board}"
            );
        }
    }
    for needle in [
        "cargo clippy -p keelsign-embassy --lib --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\" --features \"${{ matrix.embassy_features }}\" -- -D warnings",
        "cargo build -p keelsign-embassy --lib --release --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\" --features \"${{ matrix.embassy_features }}\"",
    ] {
        assert!(
            cross.contains(needle),
            "verify-cross job must run `{needle}`"
        );
    }
    // The job names (required checks) do not change: no matrix key in the name is new.
    assert!(cross.contains(
        "name: keelsign-verify ${{ matrix.target }} (features \"${{ matrix.features }}\")"
    ));
}

#[test]
#[ignore = "needs the thumbv7em-none-eabihf and thumbv8m.main-none-eabihf targets; CI verify-cross job covers this"]
fn keelsign_embassy_cross_builds() {
    let root = workspace_root();
    let scratch = ScratchDir::new("embassy_cross");
    for (target, board) in BOARD_FEATURES {
        for features in FEATURE_STATES {
            for subcommand in [
                ["clippy", "-p", "keelsign-embassy", "--lib", "--locked"].as_slice(),
                [
                    "build",
                    "-p",
                    "keelsign-embassy",
                    "--lib",
                    "--release",
                    "--locked",
                ]
                .as_slice(),
            ] {
                let mut cmd = cargo_in(&root, scratch.path());
                cmd.args(subcommand).args([
                    "--target",
                    target,
                    "--features",
                    features,
                    "--features",
                    board,
                ]);
                if subcommand[0] == "clippy" {
                    cmd.args(["--", "-D", "warnings"]);
                }
                run_ok(&mut cmd);
            }
            let rlib = scratch
                .path()
                .join(target)
                .join("release")
                .join("libkeelsign_embassy.rlib");
            assert!(rlib.is_file(), "expected {}", rlib.display());
        }
    }
}
