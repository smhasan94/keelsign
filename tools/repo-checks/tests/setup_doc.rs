//! Checks that docs/setup.md covers the development setup.

use repo_checks::{EXAMPLES, workspace_root};
use std::fs;

const REQUIRED_HEADINGS: [&str; 11] = [
    "# Development setup",
    "## Toolchain",
    "## Tools",
    "## Probe permissions",
    "## Runner configuration",
    "## Flash and run",
    "## Probe detection",
    "## Fresh-clone walkthrough",
    "## Troubleshooting",
    "## On-target tests (embedded-test)",
    "## CI",
];

const REQUIRED_TERMS: [&str; 10] = [
    "udev",
    ".cargo/config.toml",
    "probe-rs-tools",
    "flip-link",
    "probe-rs list",
    "probe-rs info",
    "hello from keelsign",
    "embedded-test",
    // SHA-47: the pinned dependency audit.
    "cargo-deny",
    // SHA-47: the on-target suite procedure.
    "on-target-tests.md",
];

#[test]
fn setup_md_has_required_sections() {
    let path = workspace_root().join("docs/setup.md");
    let doc = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with('#')).collect();
    for heading in REQUIRED_HEADINGS {
        assert!(
            headings.contains(&heading),
            "docs/setup.md is missing the heading `{heading}`"
        );
    }
    for term in REQUIRED_TERMS {
        assert!(doc.contains(term), "docs/setup.md must mention `{term}`");
    }
    for example in &EXAMPLES {
        for term in [example.target, example.chip, example.name] {
            assert!(doc.contains(term), "docs/setup.md must mention `{term}`");
        }
    }
}
