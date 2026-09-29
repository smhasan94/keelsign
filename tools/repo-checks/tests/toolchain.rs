//! Local tool installs described in docs/setup.md. Ignored by default: they check the
//! developer machine, not the repository.

use repo_checks::{EXAMPLES, run_ok};
use std::process::Command;

#[test]
#[ignore = "needs local tool install (docs/setup.md)"]
fn cross_targets_installed() {
    let installed = run_ok(Command::new("rustup").args(["target", "list", "--installed"]));
    for example in &EXAMPLES {
        assert!(
            installed.lines().any(|l| l.trim() == example.target),
            "rustup target {} is not installed",
            example.target
        );
    }
}

#[test]
#[ignore = "needs local tool install (docs/setup.md)"]
fn probe_rs_is_0_32_0() {
    let version = run_ok(Command::new("probe-rs").arg("--version"));
    assert!(
        version.starts_with("probe-rs 0.32.0"),
        "expected probe-rs 0.32.0, got `{}`",
        version.trim()
    );
}

#[test]
#[ignore = "needs local tool install (docs/setup.md)"]
fn flip_link_on_path() {
    // `flip-link --version` exits non-zero outside a cargo build (it looks for
    // rust-lld), so look the binary up on PATH instead.
    let path = std::env::var_os("PATH").expect("PATH is set");
    let exe = if cfg!(windows) {
        "flip-link.exe"
    } else {
        "flip-link"
    };
    assert!(
        std::env::split_paths(&path).any(|dir| dir.join(exe).is_file()),
        "flip-link is not on PATH; run `cargo install flip-link --version 0.1.12 --locked`"
    );
}
