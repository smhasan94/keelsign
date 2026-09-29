//! Shared helpers for the keelsign repository checks. Not published.
//!
//! The checks themselves live in `tests/`.
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Crates that are published to crates.io as name-reservation placeholders.
pub const PLACEHOLDER_CRATES: [&str; 2] = ["keelsign", "keelsign-verify"];

/// Absolute path of the workspace root (two levels above this crate).
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root must exist")
}

/// A per-test scratch directory under the system temp dir, unique per process
/// and test name. It is removed when dropped.
pub struct ScratchDir(PathBuf);

impl ScratchDir {
    pub fn new(test_name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "keelsign-repo-checks-{}-{}",
            std::process::id(),
            test_name
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A `cargo` command run in `dir` with its own `CARGO_TARGET_DIR`, so it does not
/// contend for the build lock of the outer `cargo test`.
pub fn cargo_in(dir: &Path, target_dir: &Path) -> Command {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(dir).env("CARGO_TARGET_DIR", target_dir);
    cmd
}

/// Run `cmd`, panicking with its output if it fails; returns stdout.
pub fn run_ok(cmd: &mut Command) -> String {
    let out = cmd.output().expect("spawn command");
    assert!(
        out.status.success(),
        "command {:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
        cmd,
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("stdout is UTF-8")
}
