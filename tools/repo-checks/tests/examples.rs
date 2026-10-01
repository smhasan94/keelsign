//! Checks for the standalone embedded examples under `examples/`.

use repo_checks::{EXAMPLES, Example, ScratchDir, cargo_in, run_ok, workspace_root};
use std::fs;
use std::path::PathBuf;

/// Files every example project must have, relative to its directory.
const EXAMPLE_FILES: [&str; 7] = [
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "memory.x",
    "build.rs",
    "src/main.rs",
];

fn example_dir(example: &Example) -> PathBuf {
    workspace_root().join("examples").join(example.name)
}

fn read_example(example: &Example, rel: &str) -> String {
    let path = example_dir(example).join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The body of the TOML table `[header]`: everything up to the next table header.
fn toml_table<'a>(toml: &'a str, header: &str) -> Option<&'a str> {
    let start = toml
        .find(&format!("\n{header}\n"))
        .map(|i| i + 1)
        .or_else(|| toml.starts_with(&format!("{header}\n")).then_some(0))?;
    let body = &toml[start + header.len()..];
    Some(body.find("\n[").map_or(body, |end| &body[..end]))
}

/// The line declaring dependency `name` in a Cargo.toml.
fn dependency_line<'a>(cargo_toml: &'a str, name: &str) -> &'a str {
    cargo_toml
        .lines()
        .find(|l| l.starts_with(&format!("{name} =")))
        .unwrap_or_else(|| panic!("Cargo.toml must depend on `{name}`"))
}

fn example_by_name(name: &str) -> &'static Example {
    EXAMPLES
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no example named {name}"))
}

#[test]
fn example_projects_exist() {
    for example in &EXAMPLES {
        let dir = example_dir(example);
        for rel in EXAMPLE_FILES {
            assert!(dir.join(rel).is_file(), "{}: missing {rel}", example.name);
        }
        let cargo_toml = read_example(example, "Cargo.toml");
        assert!(
            toml_table(&cargo_toml, "[workspace]").is_some(),
            "{}: Cargo.toml needs an empty [workspace] table (standalone project)",
            example.name
        );
        assert!(
            cargo_toml.contains(&format!("name = \"{}\"", example.name)),
            "{}: package name",
            example.name
        );
        assert!(
            cargo_toml.contains("edition = \"2024\""),
            "{}: edition 2024",
            example.name
        );
        assert!(
            cargo_toml.contains("unsafe_code = \"forbid\""),
            "{}: must forbid unsafe_code",
            example.name
        );
    }
}

#[test]
fn examples_deny_panic_lints() {
    for example in &EXAMPLES {
        let cargo_toml = read_example(example, "Cargo.toml");
        let lints = toml_table(&cargo_toml, "[lints.clippy]")
            .unwrap_or_else(|| panic!("{}: Cargo.toml needs a [lints.clippy] table", example.name));
        for lint in ["panic", "unwrap_used", "expect_used", "indexing_slicing"] {
            assert!(
                lints.contains(&format!("{lint} = \"deny\"")),
                "{}: [lints.clippy] must deny `{lint}` (no panic paths in no_std code)",
                example.name
            );
        }
    }
}

#[test]
fn runner_config_pins_chip_and_target() {
    for example in &EXAMPLES {
        let config = read_example(example, ".cargo/config.toml");
        let target_table = toml_table(&config, &format!("[target.{}]", example.target))
            .unwrap_or_else(|| panic!("{}: no [target.{}] table", example.name, example.target));
        assert!(
            target_table.contains(&format!(
                "runner = \"probe-rs run --chip {}\"",
                example.chip
            )),
            "{}: runner must be `probe-rs run --chip {}`",
            example.name,
            example.chip
        );
        assert!(
            target_table.contains("linker=flip-link"),
            "{}: rustflags must link with flip-link",
            example.name
        );
        let build = toml_table(&config, "[build]")
            .unwrap_or_else(|| panic!("{}: no [build] table", example.name));
        assert!(
            build.contains(&format!("target = \"{}\"", example.target)),
            "{}: [build] target must be {}",
            example.name,
            example.target
        );
        let env = toml_table(&config, "[env]")
            .unwrap_or_else(|| panic!("{}: no [env] table", example.name));
        assert!(
            env.contains("DEFMT_LOG"),
            "{}: [env] must set DEFMT_LOG",
            example.name
        );
        let toolchain = read_example(example, "rust-toolchain.toml");
        assert!(
            toolchain.contains(example.target),
            "{}: rust-toolchain.toml must list {}",
            example.name,
            example.target
        );
    }
}

#[test]
fn hal_feature_selects_board() {
    let nrf = example_by_name("nrf52840-hello");
    let nrf_toml = read_example(nrf, "Cargo.toml");
    let nrf_hal = dependency_line(&nrf_toml, "embassy-nrf");
    assert!(
        nrf_hal.contains(&format!("\"{}\"", nrf.hal_feature)),
        "embassy-nrf must enable `{}`",
        nrf.hal_feature
    );

    let rp = example_by_name("rp2350-hello");
    let rp_toml = read_example(rp, "Cargo.toml");
    let rp_hal = dependency_line(&rp_toml, "embassy-rp");
    for feature in [rp.hal_feature, "executor-thread"] {
        assert!(
            rp_hal.contains(&format!("\"{feature}\"")),
            "embassy-rp must enable `{feature}`"
        );
    }
    let rp_executor = dependency_line(&rp_toml, "embassy-executor");
    assert!(
        !rp_executor.contains("platform-cortex-m"),
        "rp2350-hello: embassy-executor must not enable platform-cortex-m \
         (embassy-rp's executor-thread provides the executor and __pender)"
    );
}

#[test]
fn main_logs_hello_from_keelsign() {
    for example in &EXAMPLES {
        let main = read_example(example, "src/main.rs");
        for needle in ["hello from keelsign", "defmt_rtt as _", "panic_probe as _"] {
            assert!(
                main.contains(needle),
                "{}: src/main.rs must contain `{needle}`",
                example.name
            );
        }
    }
}

#[test]
fn excluded_from_root_workspace() {
    let root_toml = read("Cargo.toml");
    let exclude = root_toml
        .lines()
        .find(|l| l.starts_with("exclude ="))
        .expect("root Cargo.toml must have a workspace `exclude`");
    for example in &EXAMPLES {
        assert!(
            exclude.contains(&format!("\"examples/{}\"", example.name)),
            "root `exclude` must list examples/{}",
            example.name
        );
    }

    let scratch = ScratchDir::new("examples_metadata");
    let metadata = run_ok(cargo_in(&workspace_root(), scratch.path()).args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--offline",
    ]));
    for example in &EXAMPLES {
        assert!(
            !metadata.contains(&format!("\"name\":\"{}\"", example.name)),
            "{} must not be a root workspace member",
            example.name
        );
    }
}

#[test]
fn ci_cross_builds_both_targets() {
    let ci = read(".github/workflows/ci.yml");
    let start = ci
        .find("\n  cross-build:")
        .expect("ci.yml must have a `cross-build` job");
    // The job runs until the next job key (two-space indent) or the end of the file.
    let job: String = ci[start + 1..]
        .lines()
        .enumerate()
        .take_while(|(i, line)| {
            let next_job = line.starts_with("  ") && !line.starts_with("   ");
            let top_level = !line.is_empty() && !line.starts_with(' ');
            *i == 0 || !(next_job || top_level)
        })
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    for example in &EXAMPLES {
        assert!(
            job.contains(example.target),
            "cross-build job must build for {}",
            example.target
        );
        assert!(
            job.contains(example.name),
            "cross-build job must build {}",
            example.name
        );
    }
    for needle in ["cargo build", "--locked", "flip-link"] {
        assert!(
            job.contains(needle),
            "cross-build job must contain `{needle}`"
        );
    }
    for forbidden in ["probe-rs run", "cargo run"] {
        assert!(
            !ci.contains(forbidden),
            "CI must not flash boards (`{forbidden}` found)"
        );
    }
}

fn cross_build(name: &str) {
    let example = example_by_name(name);
    let dir = example_dir(example);
    run_ok(cargo_in(&dir, &dir.join("target")).args(["build", "--locked", "--release"]));
    let elf = dir
        .join("target")
        .join(example.target)
        .join("release")
        .join(example.name);
    assert!(elf.is_file(), "expected ELF at {}", elf.display());
}

#[test]
#[ignore = "needs thumbv* target and flip-link; CI cross-build job covers this"]
fn nrf52840_hello_cross_builds() {
    cross_build("nrf52840-hello");
}

#[test]
#[ignore = "needs thumbv* target and flip-link; CI cross-build job covers this"]
fn rp2350_hello_cross_builds() {
    cross_build("rp2350-hello");
}
