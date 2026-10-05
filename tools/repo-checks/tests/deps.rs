//! Dependency rules: the ml-dsa pin (CLAUDE.md; bench crates and, since SHA-44,
//! keelsign-verify's `ml-dsa` feature, heap-free), the ed25519-dalek pin (SHA-46), the
//! keelsign CLI's JSON dependencies (SHA-51) and test dependencies (SHA-53), and the scoped
//! `unsafe` exception for the measurement-only `benches/stack-paint` crate.

use repo_checks::{SHIPPED_CRATES, workspace_root};
use std::fs;
use std::path::{Path, PathBuf};

/// The exact ml-dsa version the bench crates pin.
const ML_DSA_PIN: &str = "0.1.1";

/// First ml-dsa release with both advisory fixes: CVE-2026-24850 / GHSA-5x2r-hc65-25f9
/// (fixed in 0.1.0-rc.4) and GHSA-h37v-hp6w-2pp8 (fixed in 0.1.0-rc.5).
const ML_DSA_MIN_PATCHED: &str = "0.1.0-rc.5";

/// Lockfiles that resolve ml-dsa.
const LOCKFILES: [&str; 3] = [
    "Cargo.lock",
    "benches/nrf52840-mldsa/Cargo.lock",
    "benches/rp2350-mldsa/Cargo.lock",
];

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// `[[package]]` blocks of a Cargo.lock as (name, version, block text).
fn lock_packages(lock: &str) -> Vec<(String, String, String)> {
    lock.split("[[package]]")
        .skip(1)
        .map(|block| {
            let field = |key: &str| {
                block
                    .lines()
                    .find_map(|l| l.strip_prefix(&format!("{key} = \"")))
                    .and_then(|v| v.strip_suffix('"'))
                    .unwrap_or_default()
                    .to_owned()
            };
            (field("name"), field("version"), block.to_owned())
        })
        .collect()
}

/// A semver version as (major, minor, patch, pre-release identifiers).
type Version = (u64, u64, u64, Vec<String>);

fn parse_version(v: &str) -> Version {
    let (core, pre) = v.split_once('-').unwrap_or((v, ""));
    let nums: Vec<u64> = core
        .split('.')
        .map(|n| n.parse().unwrap_or_else(|_| panic!("bad version `{v}`")))
        .collect();
    assert_eq!(nums.len(), 3, "bad version `{v}`");
    let pre = if pre.is_empty() {
        Vec::new()
    } else {
        pre.split('.').map(str::to_owned).collect()
    };
    (nums[0], nums[1], nums[2], pre)
}

/// Semver precedence: `a >= b`.
fn version_at_least(a: &str, b: &str) -> bool {
    let (a, b) = (parse_version(a), parse_version(b));
    let core = (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2));
    if core != std::cmp::Ordering::Equal {
        return core.is_gt();
    }
    match (a.3.is_empty(), b.3.is_empty()) {
        (true, _) => true,
        (false, true) => false,
        (false, false) => {
            for (x, y) in a.3.iter().zip(&b.3) {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(x), Ok(y)) => x.cmp(&y),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != std::cmp::Ordering::Equal {
                    return ord.is_gt();
                }
            }
            a.3.len() >= b.3.len()
        }
    }
}

#[test]
fn ml_dsa_pinned_exact_and_patched() {
    assert!(version_at_least("0.1.0-rc.5", "0.1.0-rc.5"));
    assert!(version_at_least("0.1.0", "0.1.0-rc.5"));
    assert!(!version_at_least("0.1.0-rc.4", "0.1.0-rc.5"));
    assert!(
        version_at_least(ML_DSA_PIN, ML_DSA_MIN_PATCHED),
        "the pin must include both advisory fixes"
    );

    let manifest = read("benches/mldsa-kat/Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.starts_with("ml-dsa ="))
        .expect("benches/mldsa-kat must depend on ml-dsa");
    assert!(
        line.contains(&format!("version = \"={ML_DSA_PIN}\"")),
        "ml-dsa must be pinned exactly to ={ML_DSA_PIN}: `{line}`"
    );
    assert!(
        line.contains("default-features = false"),
        "ml-dsa must disable default features (no alloc / getrandom): `{line}`"
    );

    // SHA-44: keelsign-verify's optional `ml-dsa` dependency, pinned the same way.
    let manifest = read("keelsign-verify/Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.starts_with("ml-dsa = {"))
        .expect("keelsign-verify must depend on ml-dsa (the `ml-dsa` feature)");
    for needle in [
        format!("version = \"={ML_DSA_PIN}\""),
        "default-features = false".to_owned(),
        "optional = true".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "keelsign-verify: ml-dsa must have `{needle}`: `{line}`"
        );
    }

    // SHA-49: the keelsign host CLI's ml-dsa dependency (key generation), pinned the same
    // way.
    let manifest = read("keelsign/Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.starts_with("ml-dsa = {"))
        .expect("keelsign must depend on ml-dsa");
    for needle in [
        format!("version = \"={ML_DSA_PIN}\""),
        "default-features = false".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "keelsign: ml-dsa must have `{needle}`: `{line}`"
        );
    }

    for lockfile in LOCKFILES {
        let lock = read(lockfile);
        let versions: Vec<String> = lock_packages(&lock)
            .into_iter()
            .filter(|(name, _, _)| name == "ml-dsa")
            .map(|(_, version, _)| version)
            .collect();
        assert_eq!(
            versions,
            [ML_DSA_PIN],
            "{lockfile}: ml-dsa must resolve to exactly {ML_DSA_PIN}"
        );
    }
}

/// SHA-44 (AC5): keelsign-verify with `ml-dsa` on a Cortex-M target pulls in no `alloc`
/// or `std` feature of ml-dsa or the crates it builds on, so ML-DSA verify is heap-free,
/// and none of `getrandom`, `rand_core`, `pkcs8` or `zeroize`.
#[test]
fn ml_dsa_feature_tree_has_no_alloc() {
    let root = workspace_root();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = std::process::Command::new(cargo)
        .current_dir(&root)
        .args([
            "tree",
            "-p",
            "keelsign-verify",
            "--locked",
            "--offline",
            "--features",
            "ml-dsa",
            "-e",
            "normal,features",
            "--target",
            "thumbv7em-none-eabihf",
        ])
        .output()
        .expect("run cargo tree");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let tree = String::from_utf8(out.stdout).expect("UTF-8");
    assert!(
        tree.contains("ml-dsa v0.1.1"),
        "the feature pulls in ml-dsa:\n{tree}"
    );
    for krate in ["ml-dsa", "module-lattice", "hybrid-array", "signature"] {
        for feature in ["alloc", "std"] {
            let needle = format!("{krate} feature \"{feature}\"");
            assert!(
                !tree.contains(&needle),
                "keelsign-verify --features ml-dsa enables `{needle}`:\n{tree}"
            );
        }
    }
    // Verify only: no RNG, no PKCS #8 parsing, no zeroize, neither as packages nor as
    // enabled features of ml-dsa.
    for krate in ["getrandom", "rand_core", "pkcs8", "zeroize"] {
        assert!(
            !tree.contains(&format!("{krate} v")),
            "keelsign-verify --features ml-dsa pulls in the package `{krate}`:\n{tree}"
        );
        assert!(
            !tree.contains(&format!("ml-dsa feature \"{krate}\"")),
            "keelsign-verify --features ml-dsa enables ml-dsa's `{krate}` feature:\n{tree}"
        );
    }
    // No crate in the normal tree has an `alloc` or `std` feature on.
    for line in tree.lines() {
        assert!(
            !line.contains(" feature \"alloc\"") && !line.contains(" feature \"std\""),
            "heap or std feature in the keelsign-verify ml-dsa tree: {line}"
        );
    }
}

/// The exact ed25519-dalek version keelsign-verify pins for the `ed25519` feature
/// (SHA-46).
const ED25519_DALEK_PIN: &str = "3.0.0";

/// The curve25519-dalek it resolves; at least 4.1.3, the fix for RUSTSEC-2024-0344
/// (timing variability in `Scalar29::sub`).
const CURVE25519_DALEK: &str = "5.0.0";
const CURVE25519_DALEK_MIN_PATCHED: &str = "4.1.3";

#[test]
fn ed25519_dalek_pinned_exact() {
    assert!(version_at_least(
        CURVE25519_DALEK,
        CURVE25519_DALEK_MIN_PATCHED
    ));
    assert!(!version_at_least("4.1.2", CURVE25519_DALEK_MIN_PATCHED));
    let manifest = read("keelsign-verify/Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.starts_with("ed25519-dalek ="))
        .expect("keelsign-verify must depend on ed25519-dalek");
    for needle in [
        format!("version = \"={ED25519_DALEK_PIN}\""),
        "default-features = false".to_owned(),
        "optional = true".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "ed25519-dalek must have `{needle}`: `{line}`"
        );
    }
    // SHA-49: the keelsign host CLI's ed25519-dalek dependency, pinned the same way.
    let manifest = read("keelsign/Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.starts_with("ed25519-dalek = {"))
        .expect("keelsign must depend on ed25519-dalek");
    for needle in [
        format!("version = \"={ED25519_DALEK_PIN}\""),
        "default-features = false".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "keelsign: ed25519-dalek must have `{needle}`: `{line}`"
        );
    }
    // Every lockfile that builds keelsign-verify with `ed25519` resolves exactly these.
    for lockfile in LOCKFILES {
        let lock = read(lockfile);
        let packages = lock_packages(&lock);
        for (name, pin) in [
            ("ed25519-dalek", ED25519_DALEK_PIN),
            ("curve25519-dalek", CURVE25519_DALEK),
        ] {
            let versions: Vec<&str> = packages
                .iter()
                .filter(|(n, _, _)| n == name)
                .map(|(_, v, _)| v.as_str())
                .collect();
            assert_eq!(
                versions,
                [pin],
                "{lockfile}: {name} must resolve to exactly {pin}"
            );
        }
    }
}

/// The section and line of the dependency `name` in a manifest (`name = {` at the start
/// of a line), or panic.
fn dependency_line(manifest: &str, name: &str) -> (String, String) {
    let mut section = String::new();
    let mut found = Vec::new();
    for line in manifest.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            section = l.to_owned();
        } else if l.starts_with(&format!("{name} = {{")) {
            found.push((section.clone(), l.to_owned()));
        }
    }
    assert_eq!(found.len(), 1, "exactly one `{name}` dependency: {found:?}");
    found.remove(0)
}

/// SHA-51: `keelsign inspect --json` writes JSON with serde_json, pinned exactly with
/// default features off (`std` only: no `preserve_order`, no float tricks); its tests
/// validate it with jsonschema, a dev-dependency pinned exactly with default features off
/// (no HTTP or file resolving, no TLS). The lockfile resolves exactly those versions.
#[test]
fn cli_json_dependencies_pinned_exact() {
    const SERDE_JSON_PIN: &str = "1.0.151";
    const JSONSCHEMA_PIN: &str = "0.58.5";
    let manifest = read("keelsign/Cargo.toml");
    let (section, line) = dependency_line(&manifest, "serde_json");
    assert_eq!(
        section, "[dependencies]",
        "serde_json is a normal dependency"
    );
    for needle in [
        format!("version = \"={SERDE_JSON_PIN}\""),
        "default-features = false".to_owned(),
        "features = [\"std\"]".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "serde_json must have `{needle}`: `{line}`"
        );
    }
    let (section, line) = dependency_line(&manifest, "jsonschema");
    assert_eq!(
        section, "[dev-dependencies]",
        "jsonschema is a dev-dependency only"
    );
    for needle in [
        format!("version = \"={JSONSCHEMA_PIN}\""),
        "default-features = false".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "jsonschema must have `{needle}`: `{line}`"
        );
    }
    let lock = read("Cargo.lock");
    let packages = lock_packages(&lock);
    for (krate, pin) in [
        ("serde_json", SERDE_JSON_PIN),
        ("jsonschema", JSONSCHEMA_PIN),
    ] {
        let versions: Vec<&str> = packages
            .iter()
            .filter(|(name, _, _)| name == krate)
            .map(|(_, version, _)| version.as_str())
            .collect();
        assert_eq!(
            versions,
            [pin],
            "Cargo.lock: {krate} must resolve to exactly {pin}"
        );
    }
    // No HTTP client or TLS stack reaches the lockfile through jsonschema.
    for absent in ["reqwest", "rustls", "aws-lc-rs", "ring"] {
        assert!(
            !packages.iter().any(|(name, _, _)| name == absent),
            "Cargo.lock must not contain {absent}"
        );
    }
}

/// SHA-53: the CLI's integration tests use assert_cmd and predicates, dev-dependencies
/// only, pinned exactly with default features off. The lockfile resolves exactly those
/// versions, and predicates' optional default features (float comparison, line-ending
/// normalization) and assert_cmd's cargo-build helper stay out of it. (difflib is in it:
/// assert_cmd turns on predicates' `diff` feature unconditionally.)
#[test]
fn cli_test_dependencies_pinned_exact() {
    const ASSERT_CMD_PIN: &str = "2.2.2";
    const PREDICATES_PIN: &str = "3.1.4";
    let manifest = read("keelsign/Cargo.toml");
    for (krate, pin) in [
        ("assert_cmd", ASSERT_CMD_PIN),
        ("predicates", PREDICATES_PIN),
    ] {
        let (section, line) = dependency_line(&manifest, krate);
        assert_eq!(
            section, "[dev-dependencies]",
            "{krate} is a dev-dependency only"
        );
        for needle in [
            format!("version = \"={pin}\""),
            "default-features = false".to_owned(),
        ] {
            assert!(
                line.contains(&needle),
                "{krate} must have `{needle}`: `{line}`"
            );
        }
    }
    let lock = read("Cargo.lock");
    let packages = lock_packages(&lock);
    for (krate, pin) in [
        ("assert_cmd", ASSERT_CMD_PIN),
        ("predicates", PREDICATES_PIN),
    ] {
        let versions: Vec<&str> = packages
            .iter()
            .filter(|(name, _, _)| name == krate)
            .map(|(_, version, _)| version.as_str())
            .collect();
        assert_eq!(
            versions,
            [pin],
            "Cargo.lock: {krate} must resolve to exactly {pin}"
        );
    }
    for absent in ["float-cmp", "normalize-line-endings", "escargot"] {
        assert!(
            !packages.iter().any(|(name, _, _)| name == absent),
            "Cargo.lock must not contain {absent}"
        );
    }
}

/// Every Cargo.toml in the repository outside `target/` directories.
fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read dir").filter_map(Result::ok) {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" {
                manifests(&path, out);
            }
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// True when the manifest has `workspace = true` in its `[lints]` table.
fn lints_inherit_workspace(manifest: &str) -> bool {
    let mut section = "";
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
        } else if section == "[lints]" && line.replace(' ', "") == "workspace=true" {
            return true;
        }
    }
    false
}

/// The two `unsafe` exceptions of CLAUDE.md: `keelsign-ffi` (SHA-60) and the
/// measurement-only `stack-paint`, which no shipped crate depends on. Each denies (rather
/// than forbids) `unsafe_code` and allows it in exactly one module, with a `// SAFETY:`
/// comment on every `unsafe` block; every other manifest forbids it.
#[test]
fn unsafe_exceptions_are_stack_paint_and_keelsign_ffi() {
    assert!(lints_inherit_workspace(
        "[package]\n[lints]\nworkspace = true\n"
    ));
    assert!(!lints_inherit_workspace("[workspace]\nworkspace = true\n"));
    assert!(!lints_inherit_workspace("[package]\nname = \"x\"\n"));

    let root = workspace_root();
    let mut all = Vec::new();
    manifests(&root, &mut all);
    assert!(!all.is_empty());

    // Every manifest sets `unsafe_code` (or inherits the workspace lints), and only
    // stack-paint and keelsign-ffi relax it from "forbid".
    let exceptions = [
        Path::new("benches/stack-paint/Cargo.toml"),
        Path::new("keelsign-ffi/Cargo.toml"),
    ];
    let mut seen = 0;
    for manifest in &all {
        let rel = manifest.strip_prefix(&root).expect("inside the repo");
        let text = fs::read_to_string(manifest).expect("read manifest");
        let is_exception = exceptions.contains(&rel);
        seen += usize::from(is_exception);
        assert!(
            (lints_inherit_workspace(&text) && !is_exception)
                || text.lines().any(|l| l.starts_with("unsafe_code")),
            "{}: set `[lints] workspace = true` or an explicit `unsafe_code = \"forbid\"`",
            rel.display()
        );
        for line in text.lines().filter(|l| l.starts_with("unsafe_code")) {
            if is_exception {
                assert_eq!(line, "unsafe_code = \"deny\"", "{}: {line}", rel.display());
                assert!(
                    !lints_inherit_workspace(&text),
                    "{}: must not inherit the workspace's forbid",
                    rel.display()
                );
                assert!(
                    text.contains("undocumented_unsafe_blocks = \"deny\""),
                    "{}: every unsafe block needs a SAFETY comment",
                    rel.display()
                );
            } else {
                assert_eq!(
                    line,
                    "unsafe_code = \"forbid\"",
                    "{}: only benches/stack-paint and keelsign-ffi may relax unsafe_code",
                    rel.display()
                );
            }
        }
    }
    assert_eq!(seen, exceptions.len(), "both exception manifests exist");
    let stack_paint = read("benches/stack-paint/src/lib.rs");
    assert!(stack_paint.contains("#![deny(unsafe_code)]"));
    assert_eq!(
        stack_paint.matches("#[allow(unsafe_code)]").count(),
        1,
        "stack-paint has exactly one allowed unsafe module"
    );
    assert!(
        stack_paint.contains("#[cfg(target_arch = \"arm\")]\n#[allow(unsafe_code)]"),
        "the unsafe module is Arm-only"
    );
    assert_eq!(
        stack_paint.matches("unsafe {").count(),
        stack_paint.matches("// SAFETY:").count(),
        "every unsafe block in stack-paint carries a SAFETY comment"
    );

    // keelsign-ffi: `unsafe` only in `src/abi.rs`, the one module the crate root allows
    // it in; `unsafe_op_in_unsafe_fn` keeps every unsafe operation in a commented block.
    let ffi_manifest = read("keelsign-ffi/Cargo.toml");
    assert!(ffi_manifest.contains("unsafe_op_in_unsafe_fn = \"deny\""));
    let ffi_root = read("keelsign-ffi/src/lib.rs");
    assert!(ffi_root.contains("#![deny(unsafe_code)]"));
    assert_eq!(
        ffi_root.matches("#[allow(unsafe_code)]").count(),
        1,
        "keelsign-ffi has exactly one allowed unsafe module"
    );
    assert!(
        ffi_root.contains("#[allow(unsafe_code)]\nmod abi;"),
        "the allowed module is `abi`"
    );
    let ffi_src = root.join("keelsign-ffi/src");
    let mut sources: Vec<PathBuf> = fs::read_dir(&ffi_src)
        .expect("list keelsign-ffi/src")
        .map(|e| e.expect("dir entry").path())
        .collect();
    sources.sort();
    assert!(
        sources.iter().all(|p| p.is_file()),
        "keelsign-ffi/src is flat"
    );
    for path in &sources {
        let text = fs::read_to_string(path).expect("read source");
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        let code: String = text
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| format!("{l}\n"))
            .collect();
        if name == "abi.rs" {
            assert!(code.contains("unsafe {"), "abi.rs holds the unsafe code");
            assert_eq!(
                code.matches("unsafe {").count() + code.matches("unsafe extern \"C\" {").count(),
                text.lines()
                    .filter(|l| l.trim_start().starts_with("// SAFETY:"))
                    .count(),
                "every unsafe block and extern block in keelsign-ffi/src/abi.rs carries a SAFETY comment"
            );
        } else {
            for keyword in [
                "unsafe {",
                "unsafe fn",
                "unsafe extern",
                "unsafe impl",
                "unsafe trait",
                "unsafe(",
            ] {
                assert!(
                    !code.contains(keyword),
                    "keelsign-ffi/src/{name}: `{keyword}` belongs in abi.rs"
                );
            }
        }
    }

    // No shipped crate depends on stack-paint, directly or through the lockfile.
    for krate in SHIPPED_CRATES {
        let manifest = root.join(krate).join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&manifest) {
            assert!(
                !text.contains("stack-paint"),
                "{krate}/Cargo.toml must not depend on stack-paint"
            );
        }
    }
    let lock = read("Cargo.lock");
    let packages = lock_packages(&lock);
    for (name, _, block) in &packages {
        if SHIPPED_CRATES.contains(&name.as_str()) {
            assert!(
                !block.contains("\"stack-paint"),
                "Cargo.lock: shipped crate {name} must not depend on stack-paint"
            );
        }
    }
    // Nor does anything else in the root workspace; only the bench projects use it.
    for (name, _, block) in &packages {
        if name != "stack-paint" {
            assert!(
                !block.contains("\"stack-paint"),
                "Cargo.lock: {name} must not depend on stack-paint"
            );
        }
    }
}

/// SHA-67: the keelsign CLI's in-house LMS/HSS signer uses sha2, a normal dependency
/// pinned exactly with default features off, at the version keelsign-verify pins, so the
/// lockfile holds one sha2.
#[test]
fn sha2_pinned_exact_in_keelsign() {
    const SHA2_PIN: &str = "0.11.0";
    let manifest = read("keelsign/Cargo.toml");
    let (section, line) = dependency_line(&manifest, "sha2");
    assert_eq!(section, "[dependencies]", "sha2 is a normal dependency");
    for needle in [
        format!("version = \"={SHA2_PIN}\""),
        "default-features = false".to_owned(),
    ] {
        assert!(
            line.contains(&needle),
            "sha2 must have `{needle}`: `{line}`"
        );
    }
    let (_, verify_line) = dependency_line(&read("keelsign-verify/Cargo.toml"), "sha2");
    assert!(
        verify_line.contains(&format!("version = \"={SHA2_PIN}\"")),
        "keelsign and keelsign-verify pin the same sha2: `{verify_line}`"
    );
    let versions: Vec<String> = lock_packages(&read("Cargo.lock"))
        .into_iter()
        .filter(|(name, _, _)| name == "sha2")
        .map(|(_, version, _)| version)
        .collect();
    assert_eq!(versions, [SHA2_PIN], "Cargo.lock: one sha2, {SHA2_PIN}");
}

/// SHA-67: keelsign's signer KAT uses the unpublished benches/lms-kat crate as a
/// dev-dependency by path only (no version), so `cargo publish` drops it from the
/// published manifest, and never as a normal or build dependency.
#[test]
fn lms_kat_is_a_path_only_dev_dependency() {
    let manifest = read("keelsign/Cargo.toml");
    let (section, line) = dependency_line(&manifest, "lms-kat");
    assert_eq!(
        section, "[dev-dependencies]",
        "lms-kat is a dev-dependency only"
    );
    assert_eq!(line, "lms-kat = { path = \"../benches/lms-kat\" }");
    assert_eq!(
        manifest
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && l.contains("lms-kat"))
            .count(),
        1,
        "keelsign/Cargo.toml names lms-kat on one line"
    );
    let lms_kat = read("benches/lms-kat/Cargo.toml");
    assert!(
        lms_kat.lines().any(|l| l.trim() == "publish = false"),
        "lms-kat is never published"
    );
}

/// SHA-55: keelsign-embassy's dependencies, as (name, exact version). The HAL pins are the
/// ones `examples/*-hello` use; embassy-boot 0.7.0 is what embassy-boot-nrf 0.12.0 and
/// embassy-boot-rp 0.10.0 pair with those HALs.
const EMBASSY_PINS: [(&str, &str); 9] = [
    ("keelsign-verify", "0.0.1"),
    ("embassy-boot", "0.7.0"),
    ("embassy-embedded-hal", "0.6.0"),
    ("embassy-sync", "0.8.0"),
    ("embedded-storage", "0.3.2"),
    ("embedded-storage-async", "0.4.2"),
    ("defmt", "1.1.1"),
    ("embassy-nrf", "0.11.0"),
    ("embassy-rp", "0.10.0"),
];

/// Lockfiles that resolve keelsign-embassy's embassy-boot: the root workspace (every
/// pinned crate) and the boot-app examples (the crates their board needs).
const EMBASSY_LOCKFILES: [&str; 3] = [
    "Cargo.lock",
    "examples/nrf52840-boot-app/Cargo.lock",
    "examples/rp2350-boot-app/Cargo.lock",
];

/// SHA-55 AC1: keelsign-embassy pins every dependency exactly, its HAL pins match the
/// hello examples, and every lockfile resolves exactly the pinned embassy crates. embassy-
/// boot's own ed25519 features stay off: no `salty` and no ed25519-dalek 2.x in any lock
/// (they would remove `mark_updated`).
#[test]
fn embassy_dependencies_pinned_exact() {
    let manifest = read("keelsign-embassy/Cargo.toml");
    for (krate, pin) in EMBASSY_PINS {
        let (section, line) = dependency_line(&manifest, krate);
        assert_eq!(
            section, "[dependencies]",
            "{krate} is a normal dependency of keelsign-embassy"
        );
        assert!(
            line.contains(&format!("version = \"={pin}\"")),
            "keelsign-embassy: {krate} must be pinned to ={pin}: `{line}`"
        );
        if krate.starts_with("embassy-") || krate.starts_with("embedded-") {
            assert!(
                line.contains("default-features = false"),
                "keelsign-embassy: {krate} must disable default features: `{line}`"
            );
        }
    }
    for feature_line in manifest.lines().filter(|l| l.starts_with("defmt =")) {
        assert!(
            !feature_line.contains("ed25519") && !feature_line.contains("salty"),
            "the defmt feature must not turn on embassy-boot's verify: `{feature_line}`"
        );
    }
    assert!(
        !manifest.contains("embassy-boot/ed25519") && !manifest.contains("embassy-boot/_verify"),
        "keelsign-embassy must never enable embassy-boot's ed25519 features"
    );
    // The HAL pins equal the hello examples' pins.
    for (example, hal) in [
        ("examples/nrf52840-hello/Cargo.toml", "embassy-nrf"),
        ("examples/rp2350-hello/Cargo.toml", "embassy-rp"),
    ] {
        let pin = EMBASSY_PINS
            .iter()
            .find(|(k, _)| *k == hal)
            .map(|(_, v)| *v)
            .expect("HAL pinned");
        let text = read(example);
        let line = text
            .lines()
            .find(|l| l.starts_with(&format!("{hal} = {{")))
            .unwrap_or_else(|| panic!("{example} must depend on {hal}"));
        assert!(
            line.contains(&format!("version = \"={pin}\"")),
            "{example}: {hal} must be ={pin}, as keelsign-embassy pins it: `{line}`"
        );
    }
    for lockfile in EMBASSY_LOCKFILES {
        let lock = read(lockfile);
        let packages = lock_packages(&lock);
        for (krate, pin) in EMBASSY_PINS {
            if krate == "keelsign-verify" {
                continue;
            }
            let versions: Vec<&str> = packages
                .iter()
                .filter(|(name, _, _)| name == krate)
                .map(|(_, version, _)| version.as_str())
                .collect();
            // The root lock resolves every optional dependency; a boot app only its board's
            // HAL and (with its `defmt` feature) defmt.
            let required = lockfile == "Cargo.lock"
                || !matches!(krate, "embassy-nrf" | "embassy-rp")
                || lockfile.contains(if krate == "embassy-nrf" {
                    "nrf52840"
                } else {
                    "rp2350"
                });
            if required {
                assert_eq!(
                    versions,
                    [pin],
                    "{lockfile}: {krate} must resolve to exactly {pin}"
                );
            } else {
                assert!(versions.is_empty(), "{lockfile}: {krate} must not resolve");
            }
        }
        assert!(
            !packages.iter().any(|(name, _, _)| name == "salty"),
            "{lockfile}: embassy-boot's ed25519-salty feature must stay off"
        );
        let dalek: Vec<&str> = packages
            .iter()
            .filter(|(name, _, _)| name == "ed25519-dalek")
            .map(|(_, version, _)| version.as_str())
            .collect();
        assert!(
            dalek.iter().all(|v| *v == ED25519_DALEK_PIN),
            "{lockfile}: only keelsign-verify's ed25519-dalek {ED25519_DALEK_PIN} may resolve \
             (embassy-boot's ed25519-dalek feature must stay off): {dalek:?}"
        );
        let boot = packages
            .iter()
            .find(|(name, _, _)| name == "embassy-boot")
            .map(|(_, _, block)| block.as_str())
            .unwrap_or_else(|| panic!("{lockfile}: embassy-boot must resolve"));
        for absent in ["\"salty", "\"ed25519-dalek"] {
            assert!(
                !boot.contains(absent),
                "{lockfile}: embassy-boot must not depend on {absent}"
            );
        }
    }
}

/// The cargo-deny version CI installs and docs/setup.md pins (SHA-47).
const CARGO_DENY_PIN: &str = "0.20.2";

/// The SPDX licence IDs deny.toml allows (SHA-47): keelsign's own MIT and Apache-2.0
/// and the licences in the root workspace's dependency graph.
const DENY_LICENSES: [&str; 6] = [
    "Apache-2.0",
    "BSD-3-Clause",
    "MIT",
    "MIT-0",
    "Unicode-3.0",
    "Zlib",
];

/// The only advisory deny.toml ignores (SHA-47): `bare-metal` (unmaintained), reached
/// only through `cortex-m` 0.7.9 (follow-up SHA-323).
const DENY_IGNORED_ADVISORY: &str = "RUSTSEC-2026-0110";

/// The body of the TOML table `[header]`: everything up to the next table header.
fn toml_table<'a>(toml: &'a str, header: &str) -> &'a str {
    let start = toml
        .find(&format!("\n{header}\n"))
        .map(|i| i + 1)
        .or_else(|| toml.starts_with(&format!("{header}\n")).then_some(0))
        .unwrap_or_else(|| panic!("deny.toml must have a `{header}` table"));
    let body = &toml[start + header.len()..];
    body.find("\n[").map_or(body, |end| &body[..end])
}

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

/// SHA-47 TP2: deny.toml allows exactly the licences in use, denies yanked crates,
/// wildcard requirements and every source but crates.io, and ignores one advisory with a
/// reason that names its follow-up ticket; the `ci` job installs the pinned cargo-deny and
/// runs `cargo deny --locked check`, and docs/setup.md pins the same version.
#[test]
fn deny_toml_is_minimal_and_ci_runs_cargo_deny() {
    let deny = read("deny.toml");
    let tables: Vec<&str> = deny
        .lines()
        .filter(|l| l.starts_with('['))
        .map(str::trim)
        .collect();
    assert_eq!(
        tables,
        ["[licenses]", "[advisories]", "[bans]", "[sources]"],
        "deny.toml has exactly the four check tables, in order"
    );
    assert!(
        !deny.lines().any(|l| l.trim_start().starts_with("version")),
        "deny.toml must not set a `version` key (cargo-deny 0.20 has one config format)"
    );

    let licenses = toml_table(&deny, "[licenses]");
    let allow = licenses
        .split("allow = [")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .expect("[licenses] must have an `allow` list");
    let allowed: Vec<&str> = allow
        .split(',')
        .map(|s| s.trim().trim_matches('"'))
        .filter(|s| !s.is_empty())
        .collect();
    assert_eq!(allowed, DENY_LICENSES, "deny.toml licence allowlist");
    for project in ["MIT", "Apache-2.0"] {
        assert!(
            allowed.contains(&project),
            "keelsign's own licence {project} must be allowed"
        );
    }

    let advisories = toml_table(&deny, "[advisories]");
    assert!(
        advisories.contains("yanked = \"deny\""),
        "[advisories] must deny yanked crates"
    );
    let ignores: Vec<&str> = advisories
        .lines()
        .filter(|l| l.contains("id = \""))
        .collect();
    assert_eq!(
        ignores.len(),
        1,
        "exactly one ignored advisory: {ignores:?}"
    );
    let ignore = ignores[0];
    assert!(
        ignore.contains(&format!("id = \"{DENY_IGNORED_ADVISORY}\"")),
        "the ignored advisory is {DENY_IGNORED_ADVISORY}: `{ignore}`"
    );
    for needle in ["reason = \"", "bare-metal", "cortex-m 0.7.9", "SHA-323"] {
        assert!(
            ignore.contains(needle),
            "the {DENY_IGNORED_ADVISORY} ignore's reason must mention `{needle}`: `{ignore}`"
        );
    }
    let bans = toml_table(&deny, "[bans]");
    for needle in [
        "multiple-versions = \"warn\"",
        "wildcards = \"deny\"",
        "allow-wildcard-paths = true",
    ] {
        assert!(bans.contains(needle), "[bans] must set `{needle}`");
    }
    let sources = toml_table(&deny, "[sources]");
    for needle in [
        "unknown-registry = \"deny\"",
        "unknown-git = \"deny\"",
        "allow-registry = [\"https://github.com/rust-lang/crates.io-index\"]",
        "allow-git = []",
    ] {
        assert!(sources.contains(needle), "[sources] must set `{needle}`");
    }

    let ci = read(".github/workflows/ci.yml");
    let job = ci_job(&ci, "ci");
    let install = format!(
        "uses: taiki-e/install-action@v2\n        with:\n          tool: cargo-deny@{CARGO_DENY_PIN}\n"
    );
    assert!(
        job.contains(&install),
        "the ci job must install cargo-deny {CARGO_DENY_PIN} with taiki-e/install-action"
    );
    let run = "run: cargo deny --locked check\n";
    assert!(
        job.contains(run),
        "the ci job must run `cargo deny --locked check`"
    );
    assert!(
        job.find(&install) < job.find(run),
        "cargo-deny must be installed before it runs"
    );

    let setup = read("docs/setup.md");
    let pin = format!("cargo install cargo-deny --version {CARGO_DENY_PIN} --locked");
    assert!(setup.contains(&pin), "docs/setup.md must pin `{pin}`");
}

/// SHA-47 TP2: `cargo deny --locked check` passes on the root workspace. Ignored: it needs
/// cargo-deny 0.20.2 on `PATH` and fetches the RustSec advisory database.
#[test]
#[ignore = "needs cargo-deny 0.20.2 and the network (advisory database); CI's ci job runs it"]
fn cargo_deny_check_is_clean() {
    let root = workspace_root();
    let version = std::process::Command::new("cargo")
        .args(["deny", "--version"])
        .output()
        .expect("run `cargo deny --version` (install cargo-deny 0.20.2)");
    assert!(version.status.success(), "cargo-deny must be installed");
    let version = String::from_utf8_lossy(&version.stdout);
    assert_eq!(
        version.trim(),
        format!("cargo-deny {CARGO_DENY_PIN}"),
        "the pinned cargo-deny version"
    );
    // `--show-stats` prints one `<check> ok|FAILED` line per check on stdout (the
    // one-line summary is only printed to a terminal).
    let out = std::process::Command::new("cargo")
        .current_dir(&root)
        .args([
            "deny",
            "--color",
            "never",
            "--locked",
            "check",
            "--show-stats",
        ])
        .output()
        .expect("run `cargo deny --locked check`");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "cargo deny --locked check failed:\n{stdout}\n{stderr}"
    );
    for check in ["advisories", "bans", "licenses", "sources"] {
        assert!(
            stdout.contains(&format!("{check} ok: 0 errors")),
            "cargo-deny's {check} check must pass:\n{stdout}"
        );
    }
}
