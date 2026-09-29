//! A fresh checkout of the repository builds with `cargo build`.

use repo_checks::{ScratchDir, cargo_in, run_ok, workspace_root};
use std::fs;
use std::process::Command;

#[test]
fn fresh_checkout_builds_with_cargo_build() {
    let root = workspace_root();
    let listing = run_ok(Command::new("git").current_dir(&root).args([
        "ls-files",
        "-z",
        "--cached",
        "--others",
        "--exclude-standard",
    ]));

    let scratch = ScratchDir::new("fresh_clone");
    let checkout = scratch.path().join("checkout");
    let mut copied = 0usize;
    for rel in listing.split('\0').filter(|p| !p.is_empty()) {
        let src = root.join(rel);
        if !src.is_file() {
            // Tracked but deleted in the working tree: not part of a fresh clone.
            continue;
        }
        let dst = checkout.join(rel);
        fs::create_dir_all(dst.parent().expect("file has a parent")).expect("create dir");
        fs::copy(&src, &dst).unwrap_or_else(|e| panic!("copy {}: {e}", src.display()));
        copied += 1;
    }
    assert!(copied > 0, "git ls-files returned no files");
    assert!(
        checkout.join("Cargo.lock").is_file(),
        "Cargo.lock must be committed"
    );

    run_ok(cargo_in(&checkout, &scratch.path().join("target")).args([
        "build",
        "--locked",
        "--offline",
        "--workspace",
    ]));
}
