//! Filesystem layout checks: licence files, README and CI workflow.

use repo_checks::{PLACEHOLDER_CRATES, workspace_root};
use std::fs;

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

#[test]
fn root_license_files_exist() {
    let apache = read("LICENSE-APACHE");
    assert!(apache.contains("Apache License"), "LICENSE-APACHE title");
    assert!(
        apache.contains("Version 2.0, January 2004"),
        "LICENSE-APACHE version"
    );
    assert!(
        apache.contains("END OF TERMS AND CONDITIONS"),
        "LICENSE-APACHE must be the full text"
    );

    let mit = read("LICENSE-MIT");
    assert!(mit.contains("MIT License"), "LICENSE-MIT title");
    assert!(
        mit.contains("Copyright (c) 2026 The keelsign contributors"),
        "LICENSE-MIT copyright line"
    );
    assert!(
        mit.contains("Permission is hereby granted, free of charge"),
        "LICENSE-MIT must be the full text"
    );
}

#[test]
fn root_readme_exists() {
    let readme = read("README.md");
    assert!(readme.starts_with("# keelsign"), "README heading");
    assert!(
        readme.contains("placeholder"),
        "README states placeholder status"
    );
    assert!(
        readme.contains("LICENSE-APACHE"),
        "README links LICENSE-APACHE"
    );
    assert!(readme.contains("LICENSE-MIT"), "README links LICENSE-MIT");
}

#[test]
fn ci_workflow_runs_fmt_clippy_test() {
    let ci = read(".github/workflows/ci.yml");
    for needle in ["cargo fmt", "cargo clippy", "cargo test", "-D warnings"] {
        assert!(ci.contains(needle), "ci.yml must contain `{needle}`");
    }
}

#[test]
fn crate_license_copies_match_root() {
    let root = workspace_root();
    for krate in PLACEHOLDER_CRATES {
        for file in ["LICENSE-APACHE", "LICENSE-MIT"] {
            let root_bytes = fs::read(root.join(file)).expect("read root licence");
            let copy_path = root.join(krate).join(file);
            let copy_bytes = fs::read(&copy_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", copy_path.display()));
            assert_eq!(
                root_bytes,
                copy_bytes,
                "{} must be byte-identical to the root {file}",
                copy_path.display()
            );
        }
    }
}
