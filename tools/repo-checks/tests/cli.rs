//! SHA-51: the keelsign CLI's `sign` and `inspect` commands — the CI steps they need, the
//! inspect JSON schema, the inspect snapshot generator and the exit codes in
//! docs/signing.md.

use repo_checks::workspace_root;
use std::fs;

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
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

/// keelsign enables keelsign-verify's `ml-dsa` feature, so `cargo test --workspace`
/// runs policy-kat with ML-DSA on; the `ci` job runs it alone for the off state.
#[test]
fn ci_runs_policy_kat_with_ml_dsa_off_and_the_imgtool_tests() {
    let ci = read(".github/workflows/ci.yml");
    let host = ci_job(&ci, "ci");
    for needle in [
        "cargo test -p policy-kat --locked\n",
        "cargo test -p policy-kat --locked --features keelsign-verify/ml-dsa",
    ] {
        assert!(host.contains(needle), "ci job must run `{needle}`");
    }
}
