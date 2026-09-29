//! Packaging checks for the crates.io name-reservation placeholders.

use repo_checks::{PLACEHOLDER_CRATES, ScratchDir, cargo_in, run_ok, workspace_root};

const ALLOWED_FILES: [&str; 8] = [
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "README.md",
    "src/lib.rs",
];

const REQUIRED_FILES: [&str; 4] = ["LICENSE-APACHE", "LICENSE-MIT", "README.md", "src/lib.rs"];

#[test]
fn placeholder_package_contents_are_readme_and_licence_only() {
    let scratch = ScratchDir::new("package_list");
    for krate in PLACEHOLDER_CRATES {
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
                ALLOWED_FILES.contains(file),
                "{krate}: unexpected file `{file}` in package"
            );
        }
        for required in REQUIRED_FILES {
            assert!(
                files.contains(&required),
                "{krate}: package is missing `{required}`"
            );
        }
    }
}

#[test]
fn placeholder_version_is_0_0_1() {
    let scratch = ScratchDir::new("pkgid");
    for krate in PLACEHOLDER_CRATES {
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

#[test]
#[ignore = "needs network access to the crates.io index; run with `cargo test -p repo-checks -- --ignored`"]
fn placeholder_publish_dry_run() {
    let scratch = ScratchDir::new("publish_dry_run");
    for krate in PLACEHOLDER_CRATES {
        run_ok(
            cargo_in(&workspace_root(), scratch.path())
                .args(["publish", "--dry-run", "--locked", "--allow-dirty", "-p"])
                .arg(krate),
        );
    }
}
