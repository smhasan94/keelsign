//! Packaging checks for the crates published to crates.io (`PUBLISHABLE_CRATES`).
//!
//! SHA-49 retired the SHA-31 name-reservation placeholder checks: keelsign now has real
//! sources and depends on keelsign-verify, so both crates are packaged and dry-run
//! published together.

use repo_checks::{PUBLISHABLE_CRATES, ScratchDir, cargo_in, run_ok, workspace_root};
use std::fs;

/// Top-level files a package may contain besides `src/` and `tests/`.
const ALLOWED_TOP_LEVEL: [&str; 7] = [
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
];

/// Files every published crate's package must contain.
const REQUIRED_FILES: [&str; 5] = [
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "Cargo.toml",
    "src/lib.rs",
];

/// Extra files a crate's package must contain: keelsign ships the CLI binary.
fn extra_required(krate: &str) -> &'static [&'static str] {
    if krate == "keelsign" {
        &["src/main.rs"]
    } else {
        &[]
    }
}

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn package_contents_have_readme_licences_and_sources() {
    let scratch = ScratchDir::new("package_list");
    for krate in PUBLISHABLE_CRATES {
        let listing = run_ok(
            cargo_in(&workspace_root(), scratch.path())
                .args(["package", "--list", "--allow-dirty", "--offline", "-p"])
                .arg(krate),
        );
        let files: Vec<&str> = listing
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        for file in &files {
            assert!(
                ALLOWED_TOP_LEVEL.contains(file)
                    || file.starts_with("src/")
                    || file.starts_with("tests/"),
                "{krate}: unexpected file `{file}` in package"
            );
        }
        for required in REQUIRED_FILES.iter().chain(extra_required(krate)) {
            assert!(
                files.contains(required),
                "{krate}: package is missing `{required}`"
            );
        }
    }
}

#[test]
fn publishable_versions_are_0_0_1() {
    let scratch = ScratchDir::new("pkgid");
    for krate in PUBLISHABLE_CRATES {
        let pkgid = run_ok(
            cargo_in(&workspace_root(), scratch.path())
                .args(["pkgid", "--offline", "-p"])
                .arg(krate),
        );
        let pkgid = pkgid.trim();
        assert!(
            pkgid.ends_with("#0.0.1") || pkgid.ends_with("@0.0.1"),
            "{krate}: expected version 0.0.1, got pkgid `{pkgid}`"
        );
    }
}

/// keelsign depends on keelsign-verify by path and by the exact workspace version, so
/// `cargo publish` rewrites the dependency to that version on crates.io. It enables no
/// keelsign-verify features: a feature here would be unified into every workspace build
/// and remove CI's feature-off runs.
#[test]
fn keelsign_requires_keelsign_verify_at_the_workspace_version() {
    let root = read("Cargo.toml");
    let workspace_version = root
        .split("[workspace.package]")
        .nth(1)
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("version = \"")))
        .and_then(|v| v.strip_suffix('"'))
        .expect("root Cargo.toml sets [workspace.package] version");

    let verify = read("keelsign-verify/Cargo.toml");
    assert!(
        verify
            .lines()
            .any(|l| l.trim() == "version.workspace = true"),
        "keelsign-verify must take the workspace version"
    );

    let manifest = read("keelsign/Cargo.toml");
    // Every place keelsign-verify could appear as a dependency: an inline or dotted key
    // (`keelsign-verify = ...`, `keelsign-verify.features = ...`) in any dependency
    // table, or a table header such as `[dependencies.keelsign-verify]` or
    // `[target.'cfg(unix)'.dev-dependencies.keelsign-verify]`. There must be exactly one,
    // the inline entry under `[dependencies]`.
    let mut section = String::new();
    let mut entries = Vec::new();
    for raw in manifest.lines() {
        let l = raw.trim();
        if l.starts_with('[') {
            section = l.to_owned();
            if l.contains("keelsign-verify") {
                entries.push((section.clone(), l.to_owned()));
            }
        } else if l.starts_with("keelsign-verify") || l.starts_with("\"keelsign-verify\"") {
            entries.push((section.clone(), l.to_owned()));
        }
    }
    assert_eq!(
        entries.len(),
        1,
        "keelsign/Cargo.toml must name keelsign-verify exactly once: {entries:?}"
    );
    let (section, line) = &entries[0];
    assert_eq!(
        section, "[dependencies]",
        "keelsign-verify must be a normal dependency: {entries:?}"
    );
    assert!(
        line.starts_with("keelsign-verify = {"),
        "keelsign-verify must be one inline table: `{line}`"
    );
    for needle in [
        "path = \"../keelsign-verify\"".to_owned(),
        format!("version = \"={workspace_version}\""),
    ] {
        assert!(
            line.contains(&needle),
            "keelsign: keelsign-verify must have `{needle}`: `{line}`"
        );
    }
    assert!(
        !line.contains("features"),
        "keelsign must enable no keelsign-verify features: `{line}`"
    );
}

#[test]
#[ignore = "needs network access to the crates.io index; run with `cargo test -p repo-checks -- --ignored`"]
fn publish_dry_run() {
    let scratch = ScratchDir::new("publish_dry_run");
    let mut cmd = cargo_in(&workspace_root(), scratch.path());
    cmd.args(["publish", "--dry-run", "--locked", "--allow-dirty"]);
    for krate in PUBLISHABLE_CRATES {
        cmd.args(["-p", krate]);
    }
    run_ok(&mut cmd);
}
