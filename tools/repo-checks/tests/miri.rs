//! SHA-327: keelsign-ffi's Miri passes run in their own workflow
//! (.github/workflows/miri.yml), off the required `ci` job: on pull requests that change
//! keelsign-ffi, on every push to main, nightly and on demand; docs/ffi.md#miri and
//! docs/setup.md describe that cadence.

use repo_checks::{ci_job, job_steps, squash, step_with, workflow_job, workspace_root};
use std::fs;

/// The nightly Miri runs on, also named in docs/ffi.md and docs/setup.md.
const MIRI_TOOLCHAIN: &str = "nightly-2026-09-29";
/// The two check names the matrix produces (ruleset 24334615 lists them as required).
const JOB_NAMES: [&str; 2] = [
    "miri keelsign-ffi (features \"\")",
    "miri keelsign-ffi (features \"ed25519,ml-dsa\")",
];
/// The nightly schedule.
const CRON: &str = "cron: \"47 3 * * *\"";
/// The PR gate: the paths whose change makes a pull request run Miri. Assigned to a
/// variable before the test so a git error (no `HEAD^1`) fails the step under `bash -e`
/// instead of reading as "unchanged".
const GATE: &str =
    "changed=\"$(git diff --name-only HEAD^1 HEAD -- keelsign-ffi .github/workflows/miri.yml)\"";
/// The step condition every Miri step carries.
const RUN_IF: &str = "if: steps.changes.outputs.run == 'true'";

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of the markdown section starting at the line `heading`, up to the next
/// heading of level 2 or 3.
fn section<'a>(doc: &'a str, file: &str, heading: &str) -> &'a str {
    let start = doc
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("{file} lacks {heading}"));
    let body = &doc[start + 1 + heading.len()..];
    let end = body
        .match_indices('\n')
        .map(|(i, _)| i)
        .find(|&i| body[i + 1..].starts_with("## ") || body[i + 1..].starts_with("### "))
        .unwrap_or(body.len());
    &body[..end]
}

/// SHA-327 TP1, AC2, AC3 (and the static half of AC1): miri.yml runs both feature passes
/// with the docs/ffi.md#miri commands on pull requests (gated by a step on
/// keelsign-ffi/** and the workflow itself), on every push to main, nightly and on
/// workflow_dispatch, with a read-only token; the gate is a step condition (no job-level
/// `if:`, no `continue-on-error`), so both jobs always report and a failing pass fails
/// the run; and the required `ci` job no longer runs Miri.
#[test]
fn miri_workflow_runs_both_passes_on_ffi_changes_main_and_nightly() {
    let wf = read(".github/workflows/miri.yml");
    let all = squash(&wf);
    for token in [
        "on:pull_request:",
        "push:branches: [main]",
        &format!("schedule:- {CRON}"),
        "workflow_dispatch:",
        // One group per PR; every push, schedule and dispatch run has its own group, so
        // runs on main never cancel each other.
        "group: miri-${{ github.event.pull_request.number || github.run_id }}",
        "cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    ] {
        assert!(all.contains(&squash(token)), "miri.yml lacks {token:?}");
    }
    // No workflow-level `paths:` filter: it would leave a required check pending.
    assert!(!all.contains("paths:"), "miri.yml must not filter by paths");
    assert!(
        !all.contains("continue-on-error"),
        "a failing Miri pass must fail the run"
    );
    // A top-level, read-only token: the `permissions:` line at column 0 and its
    // indented block.
    let mut lines = wf.lines().skip_while(|l| l.trim_end() != "permissions:");
    let mut block = lines.next().expect("top-level permissions").to_owned();
    for line in lines.take_while(|l| l.is_empty() || l.starts_with(' ') || l.starts_with('#')) {
        block.push('\n');
        block.push_str(line);
    }
    assert_eq!(squash(&block), "permissions:contents:read");

    let job = workflow_job(&wf, "miri");
    let header = squash(&job[..job.find("steps:").expect("steps:")]);
    for token in [
        "name: miri keelsign-ffi (features \"${{ matrix.features }}\")",
        "timeout-minutes: 30",
        "fail-fast: false",
        "features: [\"\", \"ed25519,ml-dsa\"]",
    ] {
        assert!(header.contains(&squash(token)), "miri job lacks {token:?}");
    }
    assert!(
        !header.contains("if:"),
        "the miri job has no job-level `if:`: it runs on every event"
    );

    let steps = job_steps(job);
    let checkout = step_with(
        &steps,
        "miri",
        &["uses: actions/checkout@v4", "fetch-depth: 2"],
    );
    // The default PR checkout is the merge commit, whose first parent is the base.
    assert!(
        !steps[checkout].contains("ref:"),
        "checkout must keep the default ref (the PR merge commit)"
    );
    let changes = step_with(
        &steps,
        "miri",
        &[
            "id: changes",
            "[ \"$GITHUB_EVENT_NAME\" != \"pull_request\" ]",
            GATE,
            "if [ -n \"$changed\" ]",
            "echo \"run=true\" >> \"$GITHUB_OUTPUT\"",
            "echo \"run=false\" >> \"$GITHUB_OUTPUT\"",
        ],
    );
    assert!(
        !steps[changes].contains("if:") && !steps[checkout].contains("if:"),
        "checkout and the change detection always run"
    );
    assert!(
        !steps[changes].contains(&squash("-n \"$(git diff")),
        "the gate must not test a command substitution directly (it masks git errors)"
    );
    assert!(
        !steps[changes].contains("${{"),
        "the gate reads the event from the environment, not an expression"
    );
    let toolchain = step_with(
        &steps,
        "miri",
        &[
            "uses: dtolnay/rust-toolchain@master",
            &format!("toolchain: {MIRI_TOOLCHAIN}"),
            "components: miri, rust-src",
            RUN_IF,
        ],
    );
    let miri = step_with(
        &steps,
        "miri",
        &[
            "name: miri (keelsign-ffi)",
            RUN_IF,
            "RUSTFLAGS: --cfg sha2_backend=\"soft\"",
            "MIRIFLAGS: -Zmiri-symbolic-alignment-check",
            "FEATURES: ${{ matrix.features }}",
            &format!("cargo +{MIRI_TOOLCHAIN} miri setup"),
            &format!(
                "cargo +{MIRI_TOOLCHAIN} miri test -p keelsign-ffi --locked --features \"$FEATURES\""
            ),
        ],
    );
    assert!(
        checkout < changes && changes < toolchain && toolchain < miri,
        "miri step order: {checkout} {changes} {toolchain} {miri}"
    );

    // The required `ci` job no longer installs the nightly or runs Miri.
    let ci = squash(&ci_job(&read(".github/workflows/ci.yml"), "ci")).to_lowercase();
    assert!(!ci.contains("miri"), "the ci job must not run Miri");
    assert!(
        !ci.contains("rust-toolchain@master"),
        "the ci job must not install the Miri nightly"
    );
}

/// SHA-327 TP1 and AC3: docs/ffi.md#miri keeps the two commands CI runs and describes
/// the cadence (the PR gate, push to main, the nightly schedule, workflow_dispatch, the
/// timeout and how a failure shows), with the verification procedure; docs/setup.md's
/// CI section names miri.yml and no longer puts Miri in the `ci` job.
#[test]
fn ffi_doc_describes_the_miri_cadence() {
    assert!(
        read(".github/workflows/miri.yml").contains(&format!("toolchain: {MIRI_TOOLCHAIN}")),
        "miri.yml and the docs pin the same nightly"
    );
    let ffi = read("docs/ffi.md");
    let miri = section(&ffi, "docs/ffi.md", "### Miri");
    for text in [
        &format!("rustup component add --toolchain {MIRI_TOOLCHAIN} miri rust-src"),
        &format!("cargo +{MIRI_TOOLCHAIN} miri test -p keelsign-ffi --locked\n"),
        &format!(
            "cargo +{MIRI_TOOLCHAIN} miri test -p keelsign-ffi --locked --features ed25519,ml-dsa\n"
        ),
        "MIRIFLAGS=\"-Zmiri-symbolic-alignment-check\"",
        "RUSTFLAGS='--cfg sha2_backend=\"soft\"'",
        "`.github/workflows/miri.yml`",
        "`keelsign-ffi/**`",
        &format!("`{}`", JOB_NAMES[0]),
        &format!("`{}`", JOB_NAMES[1]),
        "step `miri (keelsign-ffi)`",
        "push to `main`",
        &format!("`{CRON}`"),
        "`workflow_dispatch`",
        "gh workflow run miri.yml --ref main",
        "`timeout-minutes: 30`",
        "failed-workflow notification",
    ] {
        assert!(miri.contains(text), "docs/ffi.md#miri lacks {text:?}");
    }

    let verify = section(
        &ffi,
        "docs/ffi.md",
        "### Verifying the Miri cadence (SHA-327)",
    );
    for text in [
        "cargo test -p repo-checks --locked --test miri",
        "gh api repos/smhasan94/keelsign/actions/runs/<run>/jobs",
        "select(.name==\"fmt, clippy, test, publish dry-run\")",
        "gh run list --workflow miri.yml --event pull_request",
        "gh run list --workflow miri.yml --event workflow_dispatch --limit 1",
        "gh run list --workflow miri.yml --event schedule --limit 1",
        "gh run view <run> --json jobs",
        "select(.name==\"miri (keelsign-ffi)\")",
        "keelsign-ffi/src/abi.rs",
    ] {
        assert!(
            verify.contains(text),
            "docs/ffi.md Miri verification lacks {text:?}"
        );
    }

    let setup = read("docs/setup.md");
    let ci = section(&setup, "docs/setup.md", "## CI");
    for text in [
        "`.github/workflows/miri.yml`",
        MIRI_TOOLCHAIN,
        &format!("`{}`", JOB_NAMES[0]),
        &format!("`{}`", JOB_NAMES[1]),
        "`keelsign-ffi/**`",
        "(ffi.md#miri)",
    ] {
        assert!(ci.contains(text), "docs/setup.md ## CI lacks {text:?}");
    }
    let ci_bullet = &ci[ci.find("\n- `ci`:").expect("the `ci` bullet")..];
    let ci_bullet = &ci_bullet[..ci_bullet[1..].find("\n- `").expect("the next bullet") + 1];
    assert!(
        !ci_bullet.to_lowercase().contains("miri"),
        "docs/setup.md: the `ci` job no longer runs Miri"
    );
}
