//! Dependency rules: the ml-dsa pin (CLAUDE.md; bench crates and, since SHA-44,
//! keelsign-verify's `ml-dsa` feature, heap-free), the ed25519-dalek pin (SHA-46) and the
//! scoped `unsafe` exception for the measurement-only `benches/stack-paint` crate.

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
