//! `keelsign-verify` crate rules (SHA-171): `no_std`, no heap, no `unsafe`, and CI
//! cross-builds for both Cortex-M targets with the `ml-dsa` and (SHA-46) `ed25519`
//! features off and on.

use repo_checks::{EXAMPLES, ScratchDir, cargo_in, ci_job, run_ok, workspace_root};
use std::fs;
use std::path::Path;

/// The feature states CI builds `keelsign-verify` with.
const FEATURE_STATES: [&str; 4] = ["", "ml-dsa", "ed25519", "ed25519,ml-dsa"];

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The Rust sources of keelsign-verify, subdirectories included, as (path relative to
/// `keelsign-verify/src`, text).
fn sources() -> Vec<(String, String)> {
    fn walk(dir: &Path, rel: &str, out: &mut Vec<(String, String)>) {
        let entries = fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .expect("UTF-8 file name")
                .to_owned();
            let rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            if path.is_dir() {
                walk(&path, &rel, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push((rel, fs::read_to_string(&path).expect("read source")));
            }
        }
    }
    let mut out = Vec::new();
    walk(&workspace_root().join("keelsign-verify/src"), "", &mut out);
    assert!(!out.is_empty(), "keelsign-verify/src has no sources");
    out
}

#[test]
fn keelsign_verify_is_no_std_no_alloc_forbid_unsafe() {
    let lib = read("keelsign-verify/src/lib.rs");
    for attr in [
        "#![no_std]",
        "#![forbid(unsafe_code)]",
        "#![deny(missing_docs)]",
    ] {
        assert!(
            lib.contains(attr),
            "keelsign-verify/src/lib.rs must have `{attr}`"
        );
    }
    assert!(
        lib.contains("#[cfg(test)]\nextern crate std;"),
        "`std` may only be linked for tests"
    );
    assert_eq!(lib.matches("extern crate").count(), 1);

    let sources = sources();
    // SHA-65: the LMS/HSS verifier and the default backend are covered by these rules;
    // SHA-46: the Ed25519 half and the policy entry point too; SHA-44: the ML-DSA verifier.
    for required in [
        "lms.rs",
        "backend.rs",
        "ed25519.rs",
        "policy.rs",
        "mldsa.rs",
    ] {
        assert!(
            sources.iter().any(|(name, _)| name == required),
            "keelsign-verify/src/{required} must exist"
        );
    }
    // SHA-44: each ML-DSA parameter set verifies in its own non-inlined frame (about
    // 93 KB / 153 KB); inlined, every verify (LMS/HSS included) would reserve it.
    let mldsa = &sources
        .iter()
        .find(|(name, _)| name == "mldsa.rs")
        .expect("mldsa.rs")
        .1;
    assert!(
        mldsa.contains("#[inline(never)]\nfn verify_param<P: ml_dsa::MlDsaParams>("),
        "keelsign-verify/src/mldsa.rs: `verify_param` must be `#[inline(never)]`"
    );
    for (name, text) in sources {
        for forbidden in [
            "extern crate alloc",
            "alloc::",
            "unsafe ",
            "#[allow(unsafe_code)]",
        ] {
            assert!(
                !text.contains(forbidden),
                "keelsign-verify/src/{name} must not contain `{forbidden}`"
            );
        }
        // `std::` only inside test modules, which come last in each file.
        if let Some(pos) = text.find("std::") {
            let tests = text.find("#[cfg(test)]\nmod tests").unwrap_or(text.len());
            assert!(
                pos > tests,
                "keelsign-verify/src/{name}: `std::` outside the test module"
            );
        }
    }

    let manifest = read("keelsign-verify/Cargo.toml");
    assert!(
        manifest.contains("[lints]\nworkspace = true"),
        "keelsign-verify must inherit the workspace lints (forbid unsafe, deny panics)"
    );
    let workspace = read("Cargo.toml");
    for lint in [
        "unsafe_code = \"forbid\"",
        "panic = \"deny\"",
        "unwrap_used = \"deny\"",
        "expect_used = \"deny\"",
        "indexing_slicing = \"deny\"",
    ] {
        assert!(
            workspace.contains(lint),
            "workspace lints must set `{lint}`"
        );
    }
    assert!(
        manifest.contains("default = []"),
        "keelsign-verify has no default features"
    );
    // SHA-44: the ML-DSA verifier is an optional, off-by-default feature.
    assert!(
        manifest.contains("ml-dsa = [\"dep:ml-dsa\"]"),
        "`ml-dsa` feature enabling only `dep:ml-dsa`"
    );
    // SHA-46: the Ed25519 half is an optional, off-by-default feature.
    assert!(
        manifest.contains("ed25519 = [\"dep:ed25519-dalek\"]"),
        "`ed25519` feature enabling only `dep:ed25519-dalek`"
    );
    // Every dependency has its default features (and so `alloc`/`std`) turned off.
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("[dependencies] table");
    let deps = deps.split("\n[").next().unwrap_or(deps);
    for line in deps.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        assert!(
            line.contains("default-features = false"),
            "keelsign-verify dependency must disable default features: {line}"
        );
        assert!(!line.contains("\"alloc\""), "no `alloc` feature: {line}");
        assert!(!line.contains("\"std\""), "no `std` feature: {line}");
    }
    assert!(
        deps.contains("sha2 = { version = \"=0.11.0\", default-features = false }"),
        "sha2 pinned to =0.11.0 without default features"
    );
    // SHA-42: the NOR flash reader's trait crate, the version the embassy HALs use.
    assert!(
        deps.contains("embedded-storage = { version = \"=0.3.2\", default-features = false }"),
        "embedded-storage pinned to =0.3.2 without default features"
    );
    // SHA-46: the Ed25519 verifier, pinned, optional, without default features.
    assert!(
        deps.contains(
            "ed25519-dalek = { version = \"=3.0.0\", default-features = false, optional = true }"
        ),
        "ed25519-dalek pinned to =3.0.0, optional, without default features"
    );
    // SHA-44: the ML-DSA verifier, pinned (CLAUDE.md advisories), optional, without
    // default features (no alloc, getrandom, pkcs8).
    assert!(
        deps.contains(
            "ml-dsa = { version = \"=0.1.1\", default-features = false, optional = true }"
        ),
        "ml-dsa pinned to =0.1.1, optional, without default features"
    );
}

#[test]
fn ci_cross_builds_keelsign_verify_for_both_targets() {
    let ci = read(".github/workflows/ci.yml");
    let job = ci_job(&ci, "verify-cross");
    let targets: Vec<&str> = EXAMPLES.iter().map(|e| e.target).collect();
    assert_eq!(
        targets,
        ["thumbv7em-none-eabihf", "thumbv8m.main-none-eabihf"]
    );
    for target in &targets {
        for features in FEATURE_STATES {
            let entry = format!("- target: {target}\n            features: ");
            let found = job.match_indices(&entry).any(|(i, _)| {
                let value = job[i + entry.len()..].lines().next().unwrap_or("");
                value.trim_matches('"') == features
            });
            assert!(
                found,
                "verify-cross matrix must include {target} with features \"{features}\""
            );
        }
    }
    for needle in [
        "cargo clippy -p keelsign-verify --lib --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\" -- -D warnings",
        "cargo build -p keelsign-verify --release --locked --target ${{ matrix.target }} --features \"${{ matrix.features }}\"",
        "targets: ${{ matrix.target }}",
    ] {
        assert!(job.contains(needle), "verify-cross job must run `{needle}`");
    }

    // The host job tests and clippies keelsign-verify with the features off and on
    // (`-p keelsign-verify` alone, so no workspace member unifies a feature in).
    let host = ci_job(&ci, "ci");
    for needle in [
        "cargo clippy --workspace --all-targets --locked -- -D warnings",
        "cargo clippy --workspace --all-targets --locked --features keelsign-verify/ml-dsa -- -D warnings",
        "cargo clippy --workspace --all-targets --locked --features keelsign-verify/ed25519 -- -D warnings",
        "cargo clippy --workspace --all-targets --locked --features \"keelsign-verify/ed25519 keelsign-verify/ml-dsa\" -- -D warnings",
        "cargo clippy -p keelsign-verify --all-targets --locked -- -D warnings",
        "cargo clippy -p keelsign-verify --all-targets --locked --features ml-dsa -- -D warnings",
        "cargo test --workspace --locked",
        "cargo test -p keelsign-verify --locked\n",
        "cargo test -p keelsign-verify --locked --features ml-dsa",
        "cargo test -p keelsign-verify --locked --features ed25519\n",
        "cargo test -p keelsign-verify --locked --features ed25519,ml-dsa",
    ] {
        assert!(host.contains(needle), "ci job must run `{needle}`");
    }
}

fn cross_build(root: &Path, target_dir: &Path, target: &str, features: &str) {
    for subcommand in [
        ["clippy", "-p", "keelsign-verify", "--lib", "--locked"].as_slice(),
        ["build", "-p", "keelsign-verify", "--release", "--locked"].as_slice(),
    ] {
        let mut cmd = cargo_in(root, target_dir);
        cmd.args(subcommand)
            .args(["--target", target, "--features", features]);
        if subcommand[0] == "clippy" {
            cmd.args(["--", "-D", "warnings"]);
        }
        run_ok(&mut cmd);
    }
    let rlib = target_dir
        .join(target)
        .join("release")
        .join("libkeelsign_verify.rlib");
    assert!(rlib.is_file(), "expected {}", rlib.display());
}

#[test]
#[ignore = "needs the thumbv7em-none-eabihf and thumbv8m.main-none-eabihf targets; CI verify-cross job covers this"]
fn keelsign_verify_cross_builds() {
    let root = workspace_root();
    let scratch = ScratchDir::new("verify_cross");
    for example in &EXAMPLES {
        for features in FEATURE_STATES {
            cross_build(&root, scratch.path(), example.target, features);
        }
    }
}

/// The `cargo doc` arguments for keelsign-verify in feature state `features`.
fn doc_args(features: &str) -> Vec<&str> {
    let mut args = vec!["doc", "--no-deps", "-p", "keelsign-verify", "--locked"];
    if !features.is_empty() {
        args.extend(["--features", features]);
    }
    args
}

/// SHA-47 AC2: the `ci` job builds keelsign-verify's rustdoc with `-D warnings` in every
/// feature state.
#[test]
fn ci_builds_keelsign_verify_docs_without_warnings() {
    let ci = read(".github/workflows/ci.yml");
    let host = ci_job(&ci, "ci");
    let start = host
        .find("- name: cargo doc (keelsign-verify, -D warnings)")
        .expect("the ci job must have a `cargo doc (keelsign-verify, -D warnings)` step");
    let step: String = host[start..]
        .lines()
        .enumerate()
        .take_while(|(i, line)| *i == 0 || !line.trim_start().starts_with("- "))
        .map(|(_, line)| format!("{line}\n"))
        .collect();
    assert!(
        step.contains("RUSTDOCFLAGS: -D warnings"),
        "the cargo doc step must deny rustdoc warnings:\n{step}"
    );
    for features in FEATURE_STATES {
        let command = format!("{}\n", doc_args(features).join(" "));
        assert!(
            step.contains(&format!("cargo {command}")),
            "the cargo doc step must run `cargo {}`",
            command.trim_end()
        );
    }
}

/// SHA-47 AC2: `cargo doc --no-deps -p keelsign-verify` builds without a warning in every
/// feature state (`RUSTDOCFLAGS=-D warnings`).
#[test]
fn keelsign_verify_docs_build_without_warnings() {
    let root = workspace_root();
    let scratch = ScratchDir::new("verify_docs");
    for features in FEATURE_STATES {
        let mut cmd = cargo_in(&root, scratch.path());
        cmd.args(doc_args(features))
            .env("RUSTDOCFLAGS", "-D warnings")
            .env_remove("RUSTFLAGS");
        let out = cmd.output().expect("spawn cargo doc");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            out.status.success(),
            "cargo doc (features \"{features}\") failed:\n{stderr}"
        );
        assert!(
            !stderr.contains("warning"),
            "cargo doc (features \"{features}\") warned:\n{stderr}"
        );
        assert!(
            scratch
                .path()
                .join("doc/keelsign_verify/index.html")
                .is_file(),
            "cargo doc must write doc/keelsign_verify/index.html"
        );
    }
}

/// The lines of the first fenced code block in `text` after `heading`, without the
/// fences. `prefix` is stripped from every line first (`"//!"` for crate docs).
fn fenced_block(text: &str, heading: &str, prefix: &str) -> Vec<String> {
    let lines: Vec<String> = text
        .lines()
        .map(|l| {
            let l = l.strip_prefix(prefix).unwrap_or(l);
            l.strip_prefix(' ').unwrap_or(l).to_owned()
        })
        .collect();
    let start = lines
        .iter()
        .position(|l| l == heading)
        .unwrap_or_else(|| panic!("missing heading `{heading}`"));
    let open = lines[start..]
        .iter()
        .position(|l| l.starts_with("```"))
        .map(|i| start + i)
        .unwrap_or_else(|| panic!("no code block after `{heading}`"));
    lines[open + 1..]
        .iter()
        .take_while(|l| !l.starts_with("```"))
        .cloned()
        .collect()
}

/// SHA-47 AC2 / TP3: keelsign-verify/README.md shows exactly the visible lines of the
/// crate-level `# Example` doctest (a runnable doctest, not an ignored block), 12 to 20
/// lines that verify under a policy and run the anti-rollback check.
#[test]
fn readme_example_matches_crate_doctest() {
    let lib = read("keelsign-verify/src/lib.rs");
    let doc: String = lib
        .lines()
        .take_while(|l| l.starts_with("//!"))
        .map(|l| format!("{l}\n"))
        .collect();
    let fence = doc
        .lines()
        .skip_while(|l| *l != "//! # Example")
        .find(|l| l.starts_with("//! ```"))
        .expect("the `# Example` section must have a code block");
    assert_eq!(
        fence, "//! ```",
        "the example must be a plain (runnable) doctest, not `ignore`/`no_run`"
    );
    let doctest = fenced_block(&doc, "# Example", "//!");
    assert!(
        doctest
            .iter()
            .any(|l| l.starts_with("# ") && l.contains("include_bytes!")),
        "the hidden setup must embed the fixture image"
    );
    let visible: Vec<&String> = doctest
        .iter()
        .filter(|l| !(l.starts_with("# ") || *l == "#"))
        .collect();
    assert!(
        (12..=20).contains(&visible.len()),
        "the example must be 12 to 20 visible lines, not {}",
        visible.len()
    );
    for needle in [
        "TrustedKeys::",
        "Algorithm::LmsHss",
        "verify(&mut slot, &keys, Policy::PqOnly,",
        "security_counter",
        "cmp_ignoring_build_num",
    ] {
        assert!(
            visible.iter().any(|l| l.contains(needle)),
            "the example must show `{needle}`"
        );
    }

    let readme = read("keelsign-verify/README.md");
    assert!(
        readme.contains("\n## Example\n\n"),
        "keelsign-verify/README.md must have an `## Example` section"
    );
    let shown = fenced_block(&readme, "## Example", "");
    let fence = readme
        .lines()
        .skip_while(|l| *l != "## Example")
        .find(|l| l.starts_with("```"))
        .expect("README example block");
    assert_eq!(fence, "```rust", "the README example is a `rust` block");
    let visible: Vec<String> = visible.into_iter().cloned().collect();
    assert_eq!(
        shown, visible,
        "keelsign-verify/README.md `## Example` must be the doctest's visible lines verbatim"
    );
}
