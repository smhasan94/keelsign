//! `keelsign-embassy` crate rules (SHA-55): `no_std`, no heap, no `unsafe`.

use repo_checks::{LICENSED_CRATES, PUBLISHABLE_CRATES, SHIPPED_CRATES, workspace_root};
use std::fs;
use std::path::Path;

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
