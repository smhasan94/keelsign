//! The on-target test suite (SHA-47): docs/on-target-tests.md defines it, and
//! `scripts/suite_results.py` checks saved board runs of it.

use repo_checks::{
    BENCHES, DIGEST_ON_TARGET_TESTS, LMS_ON_TARGET_TESTS, MLDSA_KAT_ON_TARGET_TESTS,
    MLDSA_ON_TARGET_TESTS, POLICY_ON_TARGET_TESTS, ScratchDir, python_script, run_capture,
    workspace_root,
};
use std::collections::BTreeSet;
use std::fs;

const SUITE_DOC: &str = "docs/on-target-tests.md";

/// The suite's test binaries (`tests/<name>.rs` in each bench project), with their tests
/// and whether they need the bench `ml-dsa` feature.
fn binaries() -> [(&'static str, &'static [&'static str], bool); 5] {
    [
        ("kat", &MLDSA_KAT_ON_TARGET_TESTS, false),
        ("lms", &LMS_ON_TARGET_TESTS, false),
        ("image", &DIGEST_ON_TARGET_TESTS, false),
        ("policy", &POLICY_ON_TARGET_TESTS, false),
        ("mldsa_verify", &MLDSA_ON_TARGET_TESTS, true),
    ]
}

/// The suite's tests in one feature state: every binary's without `ml-dsa`, all of them
/// with it.
fn suite_tests(mldsa: bool) -> Vec<&'static str> {
    binaries()
        .into_iter()
        .filter(|(_, _, needs_mldsa)| mldsa || !needs_mldsa)
        .flat_map(|(_, tests, _)| tests.iter().copied())
        .collect()
}

fn read(rel: &str) -> String {
    let path = workspace_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The names of the `#[test]` functions in an embedded-test source file.
fn defined_tests(source: &str) -> Vec<String> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    lines
        .windows(2)
        .filter(|w| w[0] == "#[test]")
        .filter_map(|w| {
            let rest = w[1].strip_prefix("fn ")?;
            Some(rest[..rest.find('(')?].to_owned())
        })
        .collect()
}

/// The log file name of one suite run.
fn log_name(board: &str, mldsa: bool, run: u32) -> String {
    let feature = if mldsa { "-mldsa" } else { "" };
    format!("{board}-suite{feature}-run{run}.txt")
}

/// The board name the logs use: the bench directory without `-mldsa`.
fn board_name(bench: &str) -> &str {
    bench.strip_suffix("-mldsa").unwrap_or(bench)
}

/// SHA-47 AC1: docs/on-target-tests.md lists every on-target test the two bench projects
/// define (and nothing else), every test binary, and the run, check and repo-check
/// commands for both boards in both feature states.
#[test]
fn suite_doc_lists_every_test_and_command() {
    let doc = read(SUITE_DOC);
    let listed: BTreeSet<&str> = binaries()
        .iter()
        .flat_map(|(_, tests, _)| tests.iter().copied())
        .collect();
    assert_eq!(listed.len(), 12, "the suite has 12 tests");
    assert_eq!(suite_tests(false).len(), 11);
    assert_eq!(suite_tests(true).len(), 12);

    for bench in &BENCHES {
        let dir = format!("benches/{}", bench.name);
        let mut defined = BTreeSet::new();
        let tests_dir = workspace_root().join(&dir).join("tests");
        let mut files: Vec<String> = fs::read_dir(&tests_dir)
            .unwrap_or_else(|e| panic!("read {}: {e}", tests_dir.display()))
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".rs"))
            .collect();
        files.sort();
        let mut expected_files: Vec<String> = binaries()
            .iter()
            .map(|(b, _, _)| format!("{b}.rs"))
            .collect();
        expected_files.sort();
        assert_eq!(
            files, expected_files,
            "{dir}/tests must hold exactly the suite's test binaries"
        );
        for (binary, tests, _) in binaries() {
            let source = read(&format!("{dir}/tests/{binary}.rs"));
            let found: BTreeSet<String> = defined_tests(&source).into_iter().collect();
            let expected: BTreeSet<String> = tests.iter().map(|t| (*t).to_owned()).collect();
            assert_eq!(
                found, expected,
                "{dir}/tests/{binary}.rs must define exactly the suite's tests"
            );
            defined.extend(found);
        }
        let listed: BTreeSet<String> = listed.iter().map(|t| (*t).to_owned()).collect();
        assert_eq!(defined, listed, "{dir}: suite tests");

        let board = board_name(bench.name);
        for needle in [
            format!("`{dir}`"),
            format!("cd {dir}\n"),
            format!(
                "cargo test --release --locked 2>&1 | tee ../../docs/bench-logs/{}\n",
                log_name(board, false, 1)
            ),
            format!(
                "cargo test --release --locked --features ml-dsa --target-dir target/mldsa 2>&1 | tee ../../docs/bench-logs/{}\n",
                log_name(board, true, 1)
            ),
            bench.target.to_owned(),
        ] {
            assert!(doc.contains(&needle), "{SUITE_DOC} must contain `{needle}`");
        }
        for mldsa in [false, true] {
            let logs: Vec<String> = (1..=3)
                .map(|run| format!("docs/bench-logs/{}", log_name(board, mldsa, run)))
                .collect();
            let command = format!(
                "python3 scripts/suite_results.py --check-identical {}\n",
                logs.join(" ")
            );
            assert!(
                doc.contains(&command),
                "{SUITE_DOC} must contain `{}`",
                command.trim_end()
            );
        }
    }

    for (binary, tests, mldsa) in binaries() {
        let row = doc
            .lines()
            .find(|l| l.starts_with(&format!("| `tests/{binary}.rs` |")))
            .unwrap_or_else(|| panic!("{SUITE_DOC}: no suite table row for tests/{binary}.rs"));
        for test in tests {
            assert!(
                row.contains(&format!("`{test}`")),
                "{SUITE_DOC}: the tests/{binary}.rs row must list `{test}`"
            );
        }
        let state = if mldsa {
            "`--features ml-dsa` only"
        } else {
            "both"
        };
        assert!(
            row.contains(&format!("| {state} |")),
            "{SUITE_DOC}: tests/{binary}.rs feature state must be `{state}`"
        );
    }
    for needle in [
        "## P1: three identical runs per board (NEEDS-HARDWARE)",
        "## P2: peak stack and cycles (NEEDS-HARDWARE)",
        "cargo test -p repo-checks --locked --test on_target -- --ignored three_suite_runs_identical_per_board",
        "python3 scripts/bench_summarize.py",
        "`POLICY board=… passed=156/156`",
        "`MLDSA board=… passed=5/5`",
        "pending (SHA-69)",
        "E8.1",
    ] {
        assert!(doc.contains(needle), "{SUITE_DOC} must contain `{needle}`");
    }
    let setup = read("docs/setup.md");
    assert!(
        setup.contains("(on-target-tests.md)"),
        "docs/setup.md must link on-target-tests.md"
    );
    let readme = read("README.md");
    assert!(
        readme.contains("(docs/on-target-tests.md)"),
        "README.md must link docs/on-target-tests.md"
    );
}

/// A synthetic suite log for one board: probe-rs output with defmt lines and one
/// libtest result line per test of `tests`, each with `verdict`.
fn synthetic_log(tests: &[&str], verdict: &str) -> String {
    let mut log = String::from("      Erasing ✔ 100%\n     Finished in 1.2s\nrunning tests\n");
    for test in tests {
        log += "0.000123 [INFO ] KAT board=nrf52840 set=X result=ok (x.rs:1)\n";
        log += &format!("test tests::{test} ... {verdict}\n");
    }
    log += "test result: ok.\n";
    log
}

/// SHA-47 TP1: `scripts/suite_results.py --check-identical` passes identical runs in which
/// every test is `ok`, and fails on a missing test, a verdict that differs between runs,
/// a failed test, a missing `--expect` test and a log without test lines.
#[test]
fn suite_results_checks_synthetic_logs() {
    let scratch = ScratchDir::new("suite_results");
    let write = |name: &str, text: &str| {
        let path = scratch.path().join(name);
        fs::write(&path, text).expect("write synthetic log");
        path
    };
    let tests = suite_tests(false);
    let expect = format!("--expect={}", tests.join(","));
    let good: Vec<_> = (1..=3)
        .map(|run| write(&format!("run{run}.txt"), &synthetic_log(&tests, "ok")))
        .collect();

    let (ok, stdout, stderr) = run_capture(
        python_script("suite_results.py")
            .args(["--check-identical", &expect])
            .args(&good),
    );
    assert!(ok, "identical passing runs rejected:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains(&format!(
            "identical: {} tests ok in all 3 logs",
            tests.len()
        )),
        "{stdout}"
    );

    // One log on its own: every test and its verdict.
    let (ok, stdout, stderr) = run_capture(python_script("suite_results.py").arg(&good[0]));
    assert!(ok, "{stderr}");
    for test in &tests {
        assert!(stdout.contains(&format!("{test} ok\n")), "{stdout}");
    }

    let check = |logs: &[std::path::PathBuf], needle: &str| {
        let (ok, stdout, stderr) = run_capture(
            python_script("suite_results.py")
                .args(["--check-identical", &expect])
                .args(logs),
        );
        assert!(!ok, "expected a failure mentioning `{needle}`:\n{stdout}");
        assert!(stderr.contains(needle), "expected `{needle}` in:\n{stderr}");
    };

    // A run that lost a test.
    let missing = write("missing.txt", &synthetic_log(&tests[1..], "ok"));
    check(
        &[good[0].clone(), good[1].clone(), missing.clone()],
        &format!("test {} is missing", tests[0]),
    );
    // The same loss in every run is still caught by --expect.
    check(
        &[missing.clone(), missing.clone(), missing],
        &format!("test {} is missing", tests[0]),
    );
    // A test that fails in one run: a failed verdict and a difference between runs.
    let failed_text = synthetic_log(&tests, "ok").replacen(
        &format!("test tests::{} ... ok", tests[2]),
        &format!("test tests::{} ... FAILED", tests[2]),
        1,
    );
    let failed = write("failed.txt", &failed_text);
    check(
        &[good[0].clone(), failed.clone(), good[2].clone()],
        &format!("test {} ... FAILED (expected ok)", tests[2]),
    );
    check(
        &[good[0].clone(), failed.clone(), good[2].clone()],
        &format!("test {} differs between runs", tests[2]),
    );
    // Failing identically every time is not a pass.
    check(
        &[failed.clone(), failed.clone(), failed],
        &format!("test {} ... FAILED (expected ok)", tests[2]),
    );
    // A test listed twice and a log without test lines are errors.
    let twice = write(
        "twice.txt",
        &format!("{}test {} ... ok\n", synthetic_log(&tests, "ok"), tests[0]),
    );
    check(&[good[0].clone(), twice], "is listed twice");
    let empty = write("empty.txt", "Error: no probe found\n");
    check(&[good[0].clone(), empty], "no test result lines");

    // --check-identical needs two or more logs.
    let (ok, _, stderr) = run_capture(
        python_script("suite_results.py")
            .arg("--check-identical")
            .arg(&good[0]),
    );
    assert!(!ok && stderr.contains("at least two logs"), "{stderr}");
}

/// SHA-47 TP1 (NEEDS-HARDWARE): three saved suite runs per board and feature state
/// (docs/on-target-tests.md, P1) are identical and every test passes.
#[test]
#[ignore = "needs board logs: save docs/bench-logs/<board>-suite[-mldsa]-run{1,2,3}.txt (docs/on-target-tests.md, P1)"]
fn three_suite_runs_identical_per_board() {
    let dir = workspace_root().join("docs/bench-logs");
    let mut missing = Vec::new();
    for bench in &BENCHES {
        for mldsa in [false, true] {
            for run in 1..=3 {
                let name = log_name(board_name(bench.name), mldsa, run);
                if !dir.join(&name).is_file() {
                    missing.push(format!("docs/bench-logs/{name}"));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "no suite logs yet: run the suite on the boards and save {} ({SUITE_DOC}, P1)",
        missing.join(", ")
    );
    for bench in &BENCHES {
        let board = board_name(bench.name);
        for mldsa in [false, true] {
            let logs: Vec<_> = (1..=3)
                .map(|run| dir.join(log_name(board, mldsa, run)))
                .collect();
            let (ok, stdout, stderr) = run_capture(
                python_script("suite_results.py")
                    .arg("--check-identical")
                    .arg(format!("--expect={}", suite_tests(mldsa).join(",")))
                    .args(&logs),
            );
            assert!(
                ok,
                "{board} (ml-dsa {mldsa}): suite runs differ or fail:\n{stdout}\n{stderr}"
            );
        }
    }
}
