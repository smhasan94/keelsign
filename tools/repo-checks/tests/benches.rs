//! Checks for the standalone on-target benchmark projects under `benches/` (SHA-34).

use repo_checks::{
    BENCHES, Example, LMS_BENCH_FILES, LMS_ON_TARGET_TESTS, LMS_SIZE_BINS, LMS_STACK_LIMIT,
    ScratchDir, cargo_in, python_script, run_capture, run_ok, workspace_root,
};
use std::fs;
use std::path::PathBuf;

/// Files every bench project must have, relative to its directory.
const BENCH_FILES: [&str; 10] = [
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "memory.x",
    "build.rs",
    "tests/kat.rs",
    "src/bin/size_baseline.rs",
    "src/bin/size_mldsa44.rs",
    "src/bin/size_mldsa65.rs",
];

/// The on-target tests named in the SHA-34 plan.
const ON_TARGET_TESTS: [&str; 5] = [
    "dwt_cycle_counter_present",
    "mldsa44_kat",
    "mldsa65_kat",
    "mldsa44_bench",
    "mldsa65_bench",
];

const SIZE_BINS: [&str; 3] = ["size_baseline", "size_mldsa44", "size_mldsa65"];

fn bench_dir(bench: &Example) -> PathBuf {
    workspace_root().join("benches").join(bench.name)
}

fn read_bench(bench: &Example, rel: &str) -> String {
    let path = bench_dir(bench).join(rel);
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
fn dependency_line<'a>(cargo_toml: &'a str, name: &str) -> Option<&'a str> {
    cargo_toml
        .lines()
        .find(|l| l.starts_with(&format!("{name} =")))
}

fn bench_by_name(name: &str) -> &'static Example {
    BENCHES
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no bench named {name}"))
}

#[test]
fn bench_projects_exist() {
    for bench in &BENCHES {
        let dir = bench_dir(bench);
        for rel in BENCH_FILES.iter().chain(&LMS_BENCH_FILES) {
            assert!(dir.join(rel).is_file(), "{}: missing {rel}", bench.name);
        }
        let cargo_toml = read_bench(bench, "Cargo.toml");
        assert!(
            toml_table(&cargo_toml, "[workspace]").is_some(),
            "{}: Cargo.toml needs an empty [workspace] table (standalone project)",
            bench.name
        );
        for needle in [
            format!("name = \"{}\"", bench.name),
            "edition = \"2024\"".to_owned(),
            "publish = false".to_owned(),
            "unsafe_code = \"forbid\"".to_owned(),
        ] {
            assert!(
                cargo_toml.contains(&needle),
                "{}: Cargo.toml must contain `{needle}`",
                bench.name
            );
        }
        for (dep, path) in [
            ("mldsa-kat", "../mldsa-kat"),
            ("lms-kat", "../lms-kat"),
            ("stack-paint", "../stack-paint"),
        ] {
            let line = dependency_line(&cargo_toml, dep)
                .unwrap_or_else(|| panic!("{}: must depend on {dep}", bench.name));
            assert!(
                line.contains(&format!("path = \"{path}\"")),
                "{}: {dep} must be a path dependency on {path}",
                bench.name
            );
        }
        let hal = dependency_line(&cargo_toml, "embassy-nrf")
            .or_else(|| dependency_line(&cargo_toml, "embassy-rp"))
            .unwrap_or_else(|| panic!("{}: must depend on its embassy HAL", bench.name));
        assert!(
            hal.contains(&format!("\"{}\"", bench.hal_feature)),
            "{}: HAL must enable `{}`",
            bench.name,
            bench.hal_feature
        );

        let release = toml_table(&cargo_toml, "[profile.release]")
            .unwrap_or_else(|| panic!("{}: needs [profile.release]", bench.name));
        for needle in [
            "opt-level = 3",
            "lto = \"fat\"",
            "codegen-units = 1",
            "debug = 2",
        ] {
            assert!(
                release.contains(needle),
                "{}: [profile.release] must set `{needle}`",
                bench.name
            );
        }
        let size = toml_table(&cargo_toml, "[profile.size]")
            .unwrap_or_else(|| panic!("{}: needs [profile.size]", bench.name));
        for needle in ["inherits = \"release\"", "opt-level = \"s\""] {
            assert!(
                size.contains(needle),
                "{}: [profile.size] must set `{needle}`",
                bench.name
            );
        }
        for bin in SIZE_BINS.iter().chain(&LMS_SIZE_BINS) {
            assert!(
                cargo_toml.contains(&format!("[[bin]]\nname = \"{bin}\"\ntest = false\n")),
                "{}: bin {bin} must be declared with `test = false`",
                bench.name
            );
        }
    }
}

#[test]
fn benches_deny_panic_lints() {
    for bench in &BENCHES {
        let cargo_toml = read_bench(bench, "Cargo.toml");
        let lints = toml_table(&cargo_toml, "[lints.clippy]")
            .unwrap_or_else(|| panic!("{}: Cargo.toml needs a [lints.clippy] table", bench.name));
        for lint in ["panic", "unwrap_used", "expect_used", "indexing_slicing"] {
            assert!(
                lints.contains(&format!("{lint} = \"deny\"")),
                "{}: [lints.clippy] must deny `{lint}` (no panic paths in no_std code)",
                bench.name
            );
        }
    }
}

#[test]
fn bench_runner_config_pins_chip_and_target() {
    for bench in &BENCHES {
        let config = read_bench(bench, ".cargo/config.toml");
        let target_table = toml_table(&config, &format!("[target.{}]", bench.target))
            .unwrap_or_else(|| panic!("{}: no [target.{}] table", bench.name, bench.target));
        assert!(
            target_table.contains(&format!("runner = \"probe-rs run --chip {}\"", bench.chip)),
            "{}: runner must be `probe-rs run --chip {}`",
            bench.name,
            bench.chip
        );
        assert!(
            target_table.contains("linker=flip-link"),
            "{}: rustflags must link with flip-link",
            bench.name
        );
        let build = toml_table(&config, "[build]")
            .unwrap_or_else(|| panic!("{}: no [build] table", bench.name));
        assert!(
            build.contains(&format!("target = \"{}\"", bench.target)),
            "{}: [build] target must be {}",
            bench.name,
            bench.target
        );
        let env = toml_table(&config, "[env]")
            .unwrap_or_else(|| panic!("{}: no [env] table", bench.name));
        assert!(
            env.contains("DEFMT_LOG"),
            "{}: [env] must set DEFMT_LOG",
            bench.name
        );
        let toolchain = read_bench(bench, "rust-toolchain.toml");
        assert!(
            toolchain.contains(bench.target),
            "{}: rust-toolchain.toml must list {}",
            bench.name,
            bench.target
        );
    }
}

#[test]
fn bench_tests_use_embedded_test_harness() {
    for bench in &BENCHES {
        let cargo_toml = read_bench(bench, "Cargo.toml");
        assert!(
            cargo_toml.contains("[[test]]\nname = \"kat\"\nharness = false\n"),
            "{}: tests/kat.rs must be a `harness = false` test",
            bench.name
        );
        let et = dependency_line(&cargo_toml, "embedded-test")
            .unwrap_or_else(|| panic!("{}: must depend on embedded-test", bench.name));
        for needle in [
            "version = \"=0.7.2\"",
            "default-features = false",
            "\"semihosting\"",
            "\"panic-handler\"",
            "\"defmt\"",
        ] {
            assert!(
                et.contains(needle),
                "{}: embedded-test dependency must contain `{needle}`",
                bench.name
            );
        }
        assert!(
            !et.contains("embassy"),
            "{}: synchronous tests, no embedded-test embassy feature",
            bench.name
        );
        for dep in ["panic-probe", "embassy-executor", "embassy-time"] {
            assert!(
                dependency_line(&cargo_toml, dep).is_none(),
                "{}: must not depend on {dep}",
                bench.name
            );
        }

        let build_rs = read_bench(bench, "build.rs");
        for script in ["--nmagic", "-Tlink.x", "-Tdefmt.x", "-Tembedded-test.x"] {
            assert!(
                build_rs.contains(&format!("cargo:rustc-link-arg={script}")),
                "{}: build.rs must pass `cargo:rustc-link-arg={script}`",
                bench.name
            );
        }
        assert!(
            !build_rs.contains("rustc-link-arg-bins"),
            "{}: build.rs must use rustc-link-arg (tests link the same scripts)",
            bench.name
        );

        let kat = read_bench(bench, "tests/kat.rs");
        for needle in [
            "#![no_std]",
            "#![no_main]",
            "#[embedded_test::tests]",
            "#[init]",
            "compile_error!",
            "defmt_rtt as _",
            "BENCH board=",
        ] {
            assert!(
                kat.contains(needle),
                "{}: tests/kat.rs must contain `{needle}`",
                bench.name
            );
        }
        for test in ON_TARGET_TESTS {
            assert!(
                kat.contains(&format!("fn {test}(")),
                "{}: tests/kat.rs must define the on-target test `{test}`",
                bench.name
            );
        }

        // SHA-65: the LMS/HSS tests are a second embedded-test binary.
        assert!(
            cargo_toml.contains("[[test]]\nname = \"lms\"\nharness = false\n"),
            "{}: tests/lms.rs must be a `harness = false` test",
            bench.name
        );
        let lms = read_bench(bench, "tests/lms.rs");
        for needle in [
            "#![no_std]",
            "#![no_main]",
            "#[embedded_test::tests]",
            "#[init]",
            "compile_error!",
            "defmt_rtt as _",
            "BENCH board=",
            "stack_paint::paint",
            "check_rotation",
            "LMS_TARGET",
        ] {
            assert!(
                lms.contains(needle),
                "{}: tests/lms.rs must contain `{needle}`",
                bench.name
            );
        }
        assert_eq!(LMS_STACK_LIMIT, 32_768);
        assert!(
            lms.contains("const STACK_LIMIT: u32 = 32_768;")
                && lms.contains("mark.bytes <= STACK_LIMIT")
                && lms.contains("!mark.saturated"),
            "{}: lms_bench must assert peak_stack <= {LMS_STACK_LIMIT} and !saturated",
            bench.name
        );
        for test in LMS_ON_TARGET_TESTS {
            assert!(
                lms.contains(&format!("fn {test}(")),
                "{}: tests/lms.rs must define the on-target test `{test}`",
                bench.name
            );
        }
    }
}

#[test]
fn benches_excluded_from_root_workspace() {
    let root_toml = read("Cargo.toml");
    let exclude = root_toml
        .lines()
        .find(|l| l.starts_with("exclude ="))
        .expect("root Cargo.toml must have a workspace `exclude`");
    for bench in &BENCHES {
        assert!(
            exclude.contains(&format!("\"benches/{}\"", bench.name)),
            "root `exclude` must list benches/{}",
            bench.name
        );
    }

    let scratch = ScratchDir::new("benches_metadata");
    let metadata = run_ok(cargo_in(&workspace_root(), scratch.path()).args([
        "metadata",
        "--no-deps",
        "--format-version",
        "1",
        "--offline",
    ]));
    for bench in &BENCHES {
        assert!(
            !metadata.contains(&format!("\"name\":\"{}\"", bench.name)),
            "{} must not be a root workspace member",
            bench.name
        );
    }
    for member in ["mldsa-kat", "lms-kat", "stack-paint"] {
        assert!(
            metadata.contains(&format!("\"name\":\"{member}\"")),
            "{member} must be a root workspace member (host KATs run in `cargo test --workspace`)"
        );
    }
}

#[test]
fn ci_builds_bench_tests_for_both_targets() {
    let ci = read(".github/workflows/ci.yml");
    let start = ci
        .find("\n  cross-build:")
        .expect("ci.yml must have a `cross-build` job");
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
    for bench in &BENCHES {
        assert!(
            job.contains(&format!("benches/{}", bench.name)) || job.contains(bench.name),
            "cross-build job must build {}",
            bench.name
        );
        assert!(
            job.contains(bench.target),
            "cross-build job must build for {}",
            bench.target
        );
    }
    for needle in [
        "cargo fmt --check",
        "--all-targets -- -D warnings",
        "cargo test --no-run --release --locked",
        "--bins",
    ] {
        assert!(
            job.contains(needle),
            "cross-build job must contain `{needle}`"
        );
    }
}

fn cross_build(name: &str) {
    let bench = bench_by_name(name);
    let dir = bench_dir(bench);
    let target_dir = dir.join("target");
    run_ok(cargo_in(&dir, &target_dir).args(["test", "--no-run", "--release", "--locked"]));
    run_ok(cargo_in(&dir, &target_dir).args(["build", "--release", "--locked", "--bins"]));
    let release = target_dir.join(bench.target).join("release");
    for bin in SIZE_BINS.iter().chain(&LMS_SIZE_BINS) {
        assert!(
            release.join(bin).is_file(),
            "expected ELF at {}",
            release.join(bin).display()
        );
    }
    for test in ["kat", "lms"] {
        let found = fs::read_dir(release.join("deps"))
            .expect("read deps dir")
            .filter_map(Result::ok)
            .any(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with(&format!("{test}-")) && !name.contains('.')
            });
        assert!(
            found,
            "expected the {test} test ELF under {}",
            release.display()
        );
    }
}

#[test]
#[ignore = "needs thumbv* target and flip-link; CI cross-build job covers this"]
fn nrf52840_mldsa_cross_builds() {
    cross_build("nrf52840-mldsa");
}

#[test]
#[ignore = "needs thumbv* target and flip-link; CI cross-build job covers this"]
fn rp2350_mldsa_cross_builds() {
    cross_build("rp2350-mldsa");
}

#[test]
#[ignore = "needs thumbv* targets, flip-link and python3; builds both bench projects"]
fn flash_sizes_script_runs() {
    for bench in &BENCHES {
        let dir = bench_dir(bench);
        let target_dir = dir.join("target");
        run_ok(cargo_in(&dir, &target_dir).args(["build", "--release", "--locked", "--bins"]));
        let release = target_dir.join(bench.target).join("release");
        let (ok, stdout, stderr) = run_capture(
            python_script("elf_sizes.py")
                .arg("--label")
                .arg(format!("{}/release", bench.name))
                .arg("--baseline")
                .arg(release.join("size_baseline"))
                .args(SIZE_BINS.map(|b| release.join(b))),
        );
        assert!(ok, "elf_sizes.py failed:\n{stderr}");
        let rows: Vec<&str> = stdout.lines().skip(2).collect();
        assert_eq!(rows.len(), 3, "one row per bin:\n{stdout}");
        for (row, bin) in rows.iter().zip(SIZE_BINS) {
            assert!(row.contains(bin), "row for {bin}: {row}");
            let delta: i64 = row
                .split('|')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .nth(8)
                .and_then(|c| c.parse().ok())
                .unwrap_or_else(|| panic!("no Δ flash cell in `{row}`"));
            if bin == "size_baseline" {
                assert_eq!(delta, 0, "{}: baseline delta", bench.name);
            } else {
                assert!(
                    delta > 0,
                    "{}: {bin} must add flash over the baseline",
                    bench.name
                );
            }
        }

        // SHA-65: size_lms over size_lms_baseline.
        let (ok, stdout, stderr) = run_capture(
            python_script("elf_sizes.py")
                .arg("--baseline")
                .arg(release.join(LMS_SIZE_BINS[0]))
                .args(LMS_SIZE_BINS.map(|b| release.join(b))),
        );
        assert!(ok, "elf_sizes.py failed:\n{stderr}");
        let deltas: Vec<i64> = stdout
            .lines()
            .skip(2)
            .map(|row| {
                row.split('|')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .nth(7)
                    .and_then(|c| c.parse().ok())
                    .unwrap_or_else(|| panic!("no Δ flash cell in `{row}`"))
            })
            .collect();
        assert_eq!(deltas.len(), 2, "{stdout}");
        assert_eq!(deltas[0], 0, "{}: LMS baseline delta", bench.name);
        assert!(deltas[1] > 0, "{}: size_lms must add flash", bench.name);
    }
}
