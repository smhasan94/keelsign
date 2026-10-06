//! SHA-303: every workspace crate's rustdoc builds without a warning on the host, and the
//! required `ci` job checks it. keelsign-ffi is documented on its own: its lib target is
//! named `keelsign`, like the CLI's, so one `cargo doc --workspace` refuses both
//! (SHA-313, docs/ffi.md). When SHA-313 lands, drop `--exclude keelsign-ffi` and the
//! second command here, in ci.yml and in docs/ffi.md.

use repo_checks::{
    ScratchDir, cargo_in, job_steps, squash, step_with, workflow_job, workspace_root,
};
use std::fs;

/// The `ci` job's check name, a required check of ruleset 24334615.
const CI_JOB_NAME: &str = "name: fmt, clippy, test, publish dry-run";
/// The name of the CI step this ticket adds.
const STEP_NAME: &str = "name: cargo doc (workspace, -D warnings)";
/// The step's commands, in order, as `cargo` arguments.
const COMMANDS: [&[&str]; 2] = [
    &[
        "doc",
        "--workspace",
        "--no-deps",
        "--locked",
        "--exclude",
        "keelsign-ffi",
    ],
    &["doc", "--no-deps", "-p", "keelsign-ffi", "--locked"],
];
/// The pages each of [`COMMANDS`] must write, checked right after it runs: the second
/// command overwrites `doc/keelsign/` (both lib targets are named `keelsign`), so the
/// CLI's pages are checked after the first and a keelsign-ffi-only page after the second.
const OUTPUTS: [&[&str]; 2] = [
    &[
        "doc/stack_paint/index.html",
        "doc/keelsign_verify/index.html",
        "doc/keelsign/index.html",
    ],
    &["doc/keelsign/fn.keelsign_verify.html"],
];

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// SHA-303 AC2, TP1: the `ci` job (name unchanged) has a `cargo doc (workspace,
/// -D warnings)` step that denies rustdoc warnings and runs both commands, after the
/// SHA-47 keelsign-verify doc step.
#[test]
fn ci_builds_workspace_docs_without_warnings() {
    let wf = read(".github/workflows/ci.yml");
    let job = workflow_job(&wf, "ci");
    let header = squash(&job[..job.find("steps:").expect("steps:")]);
    assert!(
        header.contains(&squash(CI_JOB_NAME)),
        "the ci job keeps its required check name `{CI_JOB_NAME}` (ruleset 24334615)"
    );
    let steps = job_steps(job);
    let commands: Vec<String> = COMMANDS
        .iter()
        .map(|args| format!("cargo {}", args.join(" ")))
        .collect();
    let mut tokens = vec![STEP_NAME, "RUSTDOCFLAGS: -D warnings"];
    tokens.extend(commands.iter().map(String::as_str));
    let doc = step_with(&steps, "ci", &tokens);
    let verify_doc = step_with(
        &steps,
        "ci",
        &["name: cargo doc (keelsign-verify, -D warnings)"],
    );
    assert!(
        verify_doc < doc,
        "the workspace doc step follows the SHA-47 keelsign-verify one"
    );
}

/// SHA-303 AC1: the CI step's two commands document every workspace crate with
/// `RUSTDOCFLAGS=-D warnings` and no warning.
#[test]
fn workspace_docs_build_without_warnings() {
    let root = workspace_root();
    let scratch = ScratchDir::new("workspace_docs");
    for (args, outputs) in COMMANDS.into_iter().zip(OUTPUTS) {
        let mut cmd = cargo_in(&root, scratch.path());
        cmd.args(args)
            .env("RUSTDOCFLAGS", "-D warnings")
            .env_remove("RUSTFLAGS");
        let out = cmd.output().expect("spawn cargo doc");
        let stderr = String::from_utf8_lossy(&out.stderr);
        let command = args.join(" ");
        assert!(out.status.success(), "cargo {command} failed:\n{stderr}");
        assert!(
            !stderr.contains("warning"),
            "cargo {command} warned:\n{stderr}"
        );
        for page in outputs {
            assert!(
                scratch.path().join(page).is_file(),
                "cargo {command} must write {page}"
            );
        }
    }
}
