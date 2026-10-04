//! `keelsign-embassy` crate rules (SHA-55): `no_std`, no heap, no `unsafe`; CI builds it
//! for both Cortex-M targets with its board modules, and builds the two embassy-boot
//! applications under `examples/` (`BOOT_EXAMPLES`).

use repo_checks::{
    BOOT_EXAMPLES, EXAMPLES, Example, LICENSED_CRATES, PUBLISHABLE_CRATES, SHIPPED_CRATES,
    ScratchDir, cargo_in, run_ok, workspace_root,
};
use std::fs;
use std::path::Path;

/// The keelsign-verify feature states CI builds keelsign-embassy with (its own features
/// of the same names forward to keelsign-verify).
const FEATURE_STATES: [&str; 4] = ["", "ml-dsa", "ed25519", "ed25519,ml-dsa"];

/// The board features per target: the keelsign-embassy module and the HAL chip.
const BOARD_FEATURES: [(&str, &str); 2] = [
    ("thumbv7em-none-eabihf", "nrf,embassy-nrf/nrf52840"),
    ("thumbv8m.main-none-eabihf", "rp,embassy-rp/rp235xa"),
];

/// The text of the CI job `name` (two-space indented key), up to the next job.
fn ci_job(ci: &str, name: &str) -> String {
    let start = ci
        .find(&format!("\n  {name}:"))
        .unwrap_or_else(|| panic!("ci.yml must have a `{name}` job"));
    ci[start + 1..]
        .lines()
        .enumerate()
        .take_while(|(i, line)| {
            let next_job = line.starts_with("  ") && !line.starts_with("   ");
            let top_level = !line.is_empty() && !line.starts_with(' ');
            *i == 0 || !(next_job || top_level)
        })
        .map(|(_, line)| format!("{line}\n"))
        .collect()
}

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

/// SHA-55 AC1: CI lints and tests keelsign-embassy on the host, and builds it for both
/// targets with every keelsign-verify feature state and its board module.
#[test]
fn ci_cross_builds_keelsign_embassy_and_boot_apps() {
    let ci = read(".github/workflows/ci.yml");
    let host = ci_job(&ci, "ci");
    for needle in [
        "cargo clippy -p keelsign-embassy --all-targets --locked -- -D warnings",
        "cargo test -p keelsign-embassy --locked\n",
    ] {
        assert!(host.contains(needle), "ci job must run `{needle}`");
    }
    let cross = ci_job(&ci, "verify-cross");
    let targets: Vec<&str> = EXAMPLES.iter().map(|e| e.target).collect();
    assert_eq!(
        targets,
        BOARD_FEATURES.iter().map(|(t, _)| *t).collect::<Vec<_>>()
    );
    for (target, board) in BOARD_FEATURES {
        for features in FEATURE_STATES {
            let quoted = if features.is_empty() {
                "\"\"".to_owned()
            } else {
                features.to_owned()
            };
            let entry = format!(
                "- target: {target}\n            features: {quoted}\n            embassy_features: {board}\n"
            );
            assert!(
                cross.contains(&entry),
                "verify-cross matrix must include {target} / \"{features}\" with \
                 embassy_features {board}"
            );
        }
    }
    for needle in [
        "cargo clippy -p keelsign-embassy --lib --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\" --features \"${{ matrix.embassy_features }}\" -- -D warnings",
        "cargo build -p keelsign-embassy --lib --release --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\" --features \"${{ matrix.embassy_features }}\"",
    ] {
        assert!(
            cross.contains(needle),
            "verify-cross job must run `{needle}`"
        );
    }
    // The job names (required checks) do not change: no matrix key in the name is new.
    assert!(cross.contains(
        "name: keelsign-verify ${{ matrix.target }} (features \"${{ matrix.features }}\")"
    ));
    // The boot apps are cross-build entries of their own (fmt, clippy, release build).
    let builds = ci_job(&ci, "cross-build");
    for app in &BOOT_EXAMPLES {
        let entry = format!(
            "- project: examples/{}\n            target: {}\n            bench: false\n",
            app.name, app.target
        );
        assert!(
            builds.contains(&entry),
            "cross-build matrix must build examples/{} for {}",
            app.name,
            app.target
        );
    }
    for needle in [
        "cargo fmt --check",
        "cargo clippy --locked --target ${{ matrix.target }} -- -D warnings",
        "cargo build --release --locked --target ${{ matrix.target }}",
        "flip-link",
    ] {
        assert!(
            builds.contains(needle),
            "cross-build job must run `{needle}`"
        );
    }
    for forbidden in ["probe-rs run", "probe-rs download", "cargo run"] {
        assert!(
            !ci.contains(forbidden),
            "CI must not flash boards (`{forbidden}` found)"
        );
    }
}

/// Files every boot app has, relative to its directory.
const BOOT_APP_FILES: [&str; 7] = [
    "Cargo.toml",
    "Cargo.lock",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    "memory.x",
    "build.rs",
    "src/main.rs",
];

fn read_app(app: &Example, rel: &str) -> String {
    read(&format!("examples/{}/{rel}", app.name))
}

/// The line declaring dependency `name` in a `[dependencies]` table of a Cargo.toml.
fn dependency_line<'a>(cargo_toml: &'a str, name: &str) -> &'a str {
    let mut section = "";
    for line in cargo_toml.lines() {
        if line.starts_with('[') {
            section = line;
        } else if section == "[dependencies]" && line.starts_with(&format!("{name} =")) {
            return line;
        }
    }
    panic!("Cargo.toml must depend on `{name}`")
}

/// The exact version (`"=X"`) a dependency line pins.
fn pin_of(line: &str) -> &str {
    line.split("\"=")
        .nth(1)
        .and_then(|v| v.split('"').next())
        .unwrap_or_else(|| panic!("not pinned exactly: {line}"))
}

/// Evaluates a linker-script size or address: `0x…`, `NK`, or `A - B` / `A + B` of those.
fn eval(expr: &str) -> u64 {
    let expr = expr.trim();
    for op in [" - ", " + "] {
        if let Some((a, b)) = expr.rsplit_once(op) {
            return if op == " - " {
                eval(a) - eval(b)
            } else {
                eval(a) + eval(b)
            };
        }
    }
    if let Some(hex) = expr.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("bad hex `{expr}`"));
    }
    if let Some(k) = expr.strip_suffix('K') {
        return k
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("bad size `{expr}`"))
            * 1024;
    }
    expr.parse()
        .unwrap_or_else(|_| panic!("bad number `{expr}`"))
}

/// The `NAME : ORIGIN = …, LENGTH = …` regions of a memory.x, as (name, origin, length).
fn memory_regions(memory_x: &str) -> Vec<(String, u64, u64)> {
    memory_x
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let rest = rest.trim().strip_prefix("ORIGIN =")?;
            let (origin, length) = rest.split_once(", LENGTH =")?;
            Some((name.trim().to_owned(), eval(origin), eval(length)))
        })
        .collect()
}

#[test]
fn boot_app_examples_are_standalone_and_link_past_the_header() {
    assert_eq!(eval("256K - 0x200"), 256 * 1024 - 0x200);
    assert_eq!(eval("0x10007200"), 0x1000_7200);
    let root_toml = read("Cargo.toml");
    let exclude = root_toml
        .lines()
        .find(|l| l.starts_with("exclude ="))
        .expect("root Cargo.toml must have a workspace `exclude`");
    let embassy_toml = read("keelsign-embassy/Cargo.toml");
    for (app, board) in BOOT_EXAMPLES.iter().zip(["nrf", "rp"]) {
        let name = app.name;
        let dir = workspace_root().join("examples").join(name);
        for rel in BOOT_APP_FILES {
            assert!(dir.join(rel).is_file(), "{name}: missing {rel}");
        }
        assert!(
            exclude.contains(&format!("\"examples/{name}\"")),
            "root `exclude` must list examples/{name}"
        );
        let cargo_toml = read_app(app, "Cargo.toml");
        for needle in [
            format!("name = \"{name}\""),
            "edition = \"2024\"".to_owned(),
            "publish = false".to_owned(),
            "\n[workspace]\n".to_owned(),
            "unsafe_code = \"forbid\"".to_owned(),
            "panic = \"deny\"".to_owned(),
            "unwrap_used = \"deny\"".to_owned(),
            "expect_used = \"deny\"".to_owned(),
            "indexing_slicing = \"deny\"".to_owned(),
            "\nb = []\n".to_owned(),
            "\nsoak = []\n".to_owned(),
        ] {
            assert!(
                cargo_toml.contains(&needle),
                "{name}: Cargo.toml must contain `{needle}`"
            );
        }
        let adapter = dependency_line(&cargo_toml, "keelsign-embassy");
        for needle in [
            "path = \"../../keelsign-embassy\"".to_owned(),
            format!("\"{board}\""),
            "\"defmt\"".to_owned(),
        ] {
            assert!(
                adapter.contains(&needle),
                "{name}: keelsign-embassy needs {needle}"
            );
        }
        // The board HAL, embassy-boot and the shared crates at keelsign-embassy's pins.
        let hal = if board == "nrf" {
            "embassy-nrf"
        } else {
            "embassy-rp"
        };
        for krate in [
            hal,
            "embassy-boot",
            "embassy-sync",
            "embassy-embedded-hal",
            "defmt",
        ] {
            let pin = pin_of(dependency_line(&embassy_toml, krate));
            let line = dependency_line(&cargo_toml, krate);
            assert_eq!(pin_of(line), pin, "{name}: {krate} must be ={pin}: {line}");
        }
        assert!(
            dependency_line(&cargo_toml, hal).contains(&format!("\"{}\"", app.hal_feature)),
            "{name}: {hal} must enable {}",
            app.hal_feature
        );
        assert!(
            !cargo_toml.contains("ed25519") && !cargo_toml.contains("salty"),
            "{name}: embassy-boot's verify features must stay off"
        );

        // The partitions: state after the bootloader, the application linked 0x200 (the
        // MCUboot header) past the start of the active slot, the DFU slot one page larger.
        let memory = read_app(app, "memory.x");
        let regions = memory_regions(&memory);
        let region = |n: &str| {
            regions
                .iter()
                .find(|(r, _, _)| r == n)
                .map(|(_, o, l)| (*o, *l))
                .unwrap_or_else(|| panic!("{name}: memory.x needs region {n}"))
        };
        let (boot, boot_len) = region("BOOTLOADER");
        let (state, state_len) = region("BOOTLOADER_STATE");
        let (flash, flash_len) = region("FLASH");
        let (dfu, dfu_len) = region("DFU");
        assert_eq!(
            state,
            boot + boot_len,
            "{name}: state follows the bootloader"
        );
        assert_eq!(state_len, 4096, "{name}: one state page");
        let active = state + state_len;
        assert_eq!(
            flash,
            active + 0x200,
            "{name}: application linked at ACTIVE + 0x200"
        );
        let active_len = flash_len + 0x200;
        assert_eq!(
            dfu,
            active + active_len,
            "{name}: DFU follows the active slot"
        );
        assert_eq!(dfu_len, active_len + 4096, "{name}: DFU is one page larger");
        for symbol in [
            "__bootloader_state_start = ORIGIN(BOOTLOADER_STATE) - ORIGIN(BOOTLOADER);",
            "__bootloader_state_end = ORIGIN(BOOTLOADER_STATE) + LENGTH(BOOTLOADER_STATE) - ORIGIN(BOOTLOADER);",
            "__bootloader_dfu_start = ORIGIN(DFU) - ORIGIN(BOOTLOADER);",
            "__bootloader_dfu_end = ORIGIN(DFU) + LENGTH(DFU) - ORIGIN(BOOTLOADER);",
        ] {
            assert!(
                memory.contains(symbol),
                "{name}: memory.x must define `{symbol}`"
            );
        }

        let config = read_app(app, ".cargo/config.toml");
        for needle in [
            format!("[target.{}]", app.target),
            format!("runner = \"probe-rs run --chip {}\"", app.chip),
            "linker=flip-link".to_owned(),
            format!("target = \"{}\"", app.target),
            "DEFMT_LOG".to_owned(),
        ] {
            assert!(
                config.contains(&needle),
                "{name}: .cargo/config.toml needs `{needle}`"
            );
        }
        assert!(read_app(app, "rust-toolchain.toml").contains(app.target));

        let main = read_app(app, "src/main.rs");
        for needle in [
            "#![no_std]",
            "#![no_main]",
            "hello from keelsign boot app",
            "defmt_rtt as _",
            "panic_probe as _",
            "Policy::PqOnly",
            "verify_and_mark_updated_if",
            "mark_booted",
            "from_linkerfile",
            "feature = \"soak\"",
            "feature = \"b\"",
        ] {
            assert!(
                main.contains(needle),
                "{name}: src/main.rs must contain `{needle}`"
            );
        }
    }
    // The nRF app uses the blocking updater, the RP2350 app the async one.
    assert!(read_app(&BOOT_EXAMPLES[0], "src/main.rs").contains("nrf::blocking_from_linkerfile"));
    assert!(read_app(&BOOT_EXAMPLES[1], "src/main.rs").contains("rp::async_from_linkerfile"));
}

/// The bytes of the `static TRUSTED_KEY: [u8; N] = [ … ];` array in a main.rs.
fn trusted_key_bytes(main: &str) -> Vec<u8> {
    let start = main
        .find("static TRUSTED_KEY: [u8; ")
        .expect("main.rs has a TRUSTED_KEY array");
    let body = &main[start..];
    let open = body.find("= [").expect("array literal") + 3;
    let close = body.find("];").expect("array end");
    body[open..close]
        .split(',')
        .map(str::trim)
        .filter(|b| !b.is_empty())
        .map(|b| {
            let hex = b.strip_prefix("0x").unwrap_or_else(|| panic!("byte `{b}`"));
            u8::from_str_radix(hex, 16).unwrap_or_else(|_| panic!("byte `{b}`"))
        })
        .collect()
}

/// The boot apps trust the key of `keelsign-lms-m32-h5.bin` (docs/embassy.md P1): the
/// TRUSTED_KEY arrays equal MANIFEST.json's `public_key_hex` for that image.
#[test]
fn boot_app_trusted_key_matches_fixture_manifest() {
    let manifest = read("tests/fixtures/images/MANIFEST.json");
    let entry = manifest
        .find("\"keelsign-lms-m32-h5.bin\": {")
        .expect("MANIFEST.json lists keelsign-lms-m32-h5.bin");
    let entry = &manifest[entry..];
    let entry = &entry[..entry.find("\n    }").expect("entry ends")];
    let hex = entry
        .split("\"public_key_hex\": \"")
        .nth(1)
        .and_then(|v| v.split('"').next())
        .expect("public_key_hex");
    assert_eq!(hex.len(), 120, "a 60-byte LMS/HSS key");
    let expected: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    for app in &BOOT_EXAMPLES {
        let main = read_app(app, "src/main.rs");
        assert!(main.contains("static TRUSTED_KEY: [u8; 60] = ["));
        assert_eq!(
            trusted_key_bytes(&main),
            expected,
            "{}: TRUSTED_KEY must be keelsign-lms-m32-h5.bin's key",
            app.name
        );
        assert!(
            main.contains("algorithm: Algorithm::LmsHss"),
            "{}",
            app.name
        );
    }
}

#[test]
#[ignore = "needs thumbv* targets and flip-link; CI cross-build job covers this"]
fn boot_app_examples_cross_build() {
    for app in &BOOT_EXAMPLES {
        let dir = workspace_root().join("examples").join(app.name);
        let target_dir = dir.join("target");
        for features in ["", "b", "soak"] {
            run_ok(cargo_in(&dir, &target_dir).args([
                "clippy",
                "--locked",
                "--target",
                app.target,
                "--features",
                features,
                "--",
                "-D",
                "warnings",
            ]));
        }
        run_ok(cargo_in(&dir, &target_dir).args([
            "build",
            "--locked",
            "--release",
            "--target",
            app.target,
        ]));
        let elf = target_dir.join(app.target).join("release").join(app.name);
        assert!(elf.is_file(), "expected ELF at {}", elf.display());
    }
}

#[test]
#[ignore = "needs the thumbv7em-none-eabihf and thumbv8m.main-none-eabihf targets; CI verify-cross job covers this"]
fn keelsign_embassy_cross_builds() {
    let root = workspace_root();
    let scratch = ScratchDir::new("embassy_cross");
    for (target, board) in BOARD_FEATURES {
        for features in FEATURE_STATES {
            for subcommand in [
                ["clippy", "-p", "keelsign-embassy", "--lib", "--locked"].as_slice(),
                [
                    "build",
                    "-p",
                    "keelsign-embassy",
                    "--lib",
                    "--release",
                    "--locked",
                ]
                .as_slice(),
            ] {
                let mut cmd = cargo_in(&root, scratch.path());
                cmd.args(subcommand).args([
                    "--target",
                    target,
                    "--features",
                    features,
                    "--features",
                    board,
                ]);
                if subcommand[0] == "clippy" {
                    cmd.args(["--", "-D", "warnings"]);
                }
                run_ok(&mut cmd);
            }
            let rlib = scratch
                .path()
                .join(target)
                .join("release")
                .join("libkeelsign_embassy.rlib");
            assert!(rlib.is_file(), "expected {}", rlib.display());
        }
    }
}
