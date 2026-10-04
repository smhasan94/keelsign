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

#[test]
fn stack_paint_is_only_unsafe_exception_and_not_shipped() {
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
    // stack-paint relaxes it from "forbid".
    for manifest in &all {
        let rel = manifest.strip_prefix(&root).expect("inside the repo");
        let text = fs::read_to_string(manifest).expect("read manifest");
        let is_stack_paint = rel == Path::new("benches/stack-paint/Cargo.toml");
        assert!(
            (lints_inherit_workspace(&text) && !is_stack_paint)
                || text.lines().any(|l| l.starts_with("unsafe_code")),
            "{}: set `[lints] workspace = true` or an explicit `unsafe_code = \"forbid\"`",
            rel.display()
        );
        for line in text.lines().filter(|l| l.starts_with("unsafe_code")) {
            if is_stack_paint {
                assert_eq!(line, "unsafe_code = \"deny\"", "stack-paint: {line}");
            } else {
                assert_eq!(
                    line,
                    "unsafe_code = \"forbid\"",
                    "{}: only benches/stack-paint may relax unsafe_code",
                    rel.display()
                );
            }
        }
    }
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
