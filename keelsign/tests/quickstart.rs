//! SHA-53 AC4: the README's `## Quickstart` block runs verbatim, with the binary this test
//! builds, in under five minutes. `scripts/check-quickstart.sh` extracts and runs the block
//! (CI runs the same script after a release build).

mod common;

use common::*;
use predicates::prelude::*;
use std::path::Path;
use std::time::{Duration, Instant};

#[test]
fn readme_quickstart_runs_verbatim_with_the_built_binary_in_under_five_minutes() {
    let readme = std::fs::read_to_string(repo().join("README.md")).expect("read README.md");
    let section = readme
        .split("\n## Quickstart\n")
        .nth(1)
        .and_then(|rest| rest.split("\n## ").next())
        .expect("README.md has a `## Quickstart` section");
    let block = section
        .split("```sh\n")
        .nth(1)
        .and_then(|rest| rest.split("\n```").next())
        .expect("the Quickstart section has a ```sh block");
    for command in ["keygen", "pubkey", "sign", "verify", "inspect"] {
        assert!(
            block.contains(&format!("\nkeelsign {command} ")),
            "the quickstart runs `keelsign {command}`"
        );
    }

    let bin_dir = Path::new(env!("CARGO_BIN_EXE_keelsign"))
        .parent()
        .expect("binary directory");
    let started = Instant::now();
    assert_cmd::Command::new("bash")
        .arg(repo().join("scripts/check-quickstart.sh"))
        .arg("--keelsign")
        .arg(bin_dir)
        .current_dir(repo())
        .env_remove("KEELSIGN_TEST_PW")
        .assert()
        .code(0)
        .stdout(predicate::str::contains(format!(
            "running the README quickstart with {}",
            bin_dir.join("keelsign").display()
        )))
        .stdout(predicate::str::contains("\nverified: app.keelsign.bin\n"))
        .stdout(predicate::str::contains("\nformat: keelsign-inspect\n"))
        .stdout(predicate::str::contains("(budget 300 s)"));
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(300),
        "the quickstart took {elapsed:?}"
    );
}
