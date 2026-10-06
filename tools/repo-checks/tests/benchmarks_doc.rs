//! Checks that docs/benchmarks.md records the SHA-34 results, the reproduction commands
//! and the go/no-go decision, and that the benchmark log tooling works.

use repo_checks::{
    BENCHES, Example, ScratchDir, bench_target_lock, python_script, run_capture, run_ok,
    workspace_root,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const REQUIRED_HEADINGS: [&str; 18] = [
    "# ML-DSA verify benchmarks (SHA-34)",
    "## Method",
    "## Prerequisites",
    "## Reproduce",
    "### On-target KATs",
    "### Cycles and peak stack",
    "### Three-run consistency",
    "### Flash footprint",
    "### Static stack frame estimate",
    "## Results",
    "## Three-run consistency",
    "## Static stack frame estimate (provisional)",
    "## pqm4 comparison",
    "## Decision",
    "## Follow-ups",
    "## C static library (SHA-60)",
    "## RAM/flash budget (SHA-47)",
    "## Recorded figures (SHA-275)",
];

const BOARDS: [&str; 2] = ["nrf52840", "rp2350"];
const SETS: [&str; 2] = ["ML-DSA-44", "ML-DSA-65"];
const PENDING: &str = "pending (hardware)";
const DECISIONS: [&str; 3] = [
    "Decision: GO",
    "Decision: NO-GO",
    "Decision: PENDING (needs hardware)",
];

fn doc() -> String {
    let path = workspace_root().join("docs/benchmarks.md");
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The text of the section starting at the heading line `heading`, up to the next heading
/// of the same or a higher level.
fn section<'a>(doc: &'a str, heading: &str) -> &'a str {
    let level = heading.chars().take_while(|&c| c == '#').count();
    let start = doc
        .find(&format!("\n{heading}\n"))
        .unwrap_or_else(|| panic!("docs/benchmarks.md has no `{heading}` heading"))
        + 1;
    let body = &doc[start + heading.len()..];
    let mut offset = 0;
    let mut in_code = false;
    for line in body.split_inclusive('\n') {
        if line.starts_with("```") {
            in_code = !in_code;
        }
        let hashes = line.chars().take_while(|&c| c == '#').count();
        if !in_code && hashes > 0 && hashes <= level && line[hashes..].starts_with(' ') {
            break;
        }
        offset += line.len();
    }
    &body[..offset]
}

/// Cells of the markdown table rows in `text` (header and separator rows excluded).
fn table_rows(text: &str) -> Vec<Vec<String>> {
    text.lines()
        .filter(|l| l.starts_with('|') && !l.starts_with("|---"))
        .skip(1)
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect()
        })
        .collect()
}

/// A byte count cell such as `34,164 B`.
fn parse_bytes(cell: &str) -> Option<u64> {
    cell.trim_end_matches(" B").replace(',', "").parse().ok()
}

#[test]
fn benchmarks_md_has_required_sections() {
    let doc = doc();
    let headings: Vec<&str> = doc.lines().filter(|l| l.starts_with('#')).collect();
    for heading in &REQUIRED_HEADINGS {
        assert!(
            headings.contains(heading),
            "docs/benchmarks.md is missing the heading `{heading}`"
        );
    }
    for term in [
        "=0.1.1",
        "CVE-2026-24850",
        "GHSA-h37v-hp6w-2pp8",
        "CYCCNT",
        "stack_paint",
        "flip-link",
        "64 MHz",
        "150 MHz",
        "90bfb630e53603b4e273a131cd09a025e51540a5",
        "provisional",
    ] {
        assert!(
            doc.contains(term),
            "docs/benchmarks.md must mention `{term}`"
        );
    }
    for bench in &BENCHES {
        assert!(
            doc.contains(&format!("benches/{}", bench.name)),
            "docs/benchmarks.md must name benches/{}",
            bench.name
        );
    }
    let follow_ups = section(&doc, "## Follow-ups");
    for ticket in ["SHA-169", "SHA-170"] {
        assert!(
            follow_ups.contains(ticket),
            "## Follow-ups must reference {ticket}"
        );
    }
    let pqm4 = section(&doc, "## pqm4 comparison");
    for number in [
        "2,063,096",
        "1,421,623",
        "3,377,305",
        "2,415,944",
        "36,308",
        "8,912",
        "57,736",
        "9,888",
        "2,712",
        "8,212",
        "19,592",
        "7,724",
        "19,328",
    ] {
        assert!(pqm4.contains(number), "pqm4 comparison must cite {number}");
    }
}

#[test]
fn results_table_covers_boards_and_sets() {
    let doc = doc();
    let results = section(&doc, "## Results");
    let header = results
        .lines()
        .find(|l| l.starts_with("| Board | Set |"))
        .expect("## Results needs the board × set table");
    for column in [
        "Verify cycles",
        "Peak stack (measured)",
        "Static frame",
        "Flash Δ release",
        "Flash Δ size",
    ] {
        assert!(
            header.contains(column),
            "results table needs a `{column}` column"
        );
    }
    let table: String = results
        .lines()
        .skip_while(|l| !l.starts_with("| Board | Set |"))
        .take_while(|l| l.starts_with('|'))
        .map(|l| format!("{l}\n"))
        .collect();
    let rows = table_rows(&table);
    assert_eq!(rows.len(), 4, "one row per board × set");
    for board in BOARDS {
        for set in SETS {
            let row = rows
                .iter()
                .find(|r| r[0] == board && r[1] == set)
                .unwrap_or_else(|| panic!("results table has no row for {board} {set}"));
            assert_eq!(row.len(), 9, "{board} {set}: 9 columns");
            // Cycles, time, measured stack and peak RAM: a value or pending hardware.
            for (i, cell) in [(2, &row[2]), (3, &row[3]), (4, &row[4]), (8, &row[8])] {
                assert!(
                    !cell.is_empty()
                        && (cell == PENDING || cell.chars().any(|c| c.is_ascii_digit())),
                    "{board} {set} column {i}: `{cell}` must be a value or `{PENDING}`"
                );
            }
            // Static frame and flash are measured without hardware and must be filled in.
            for i in [5, 6, 7] {
                let value = parse_bytes(&row[i]).unwrap_or_else(|| {
                    panic!(
                        "{board} {set} column {i}: `{}` must be a byte count",
                        row[i]
                    )
                });
                assert!(value > 0, "{board} {set} column {i} must be positive");
            }
        }
    }
}

#[test]
fn records_decision_rule() {
    let doc = doc();
    let decision = section(&doc, "## Decision");
    for needle in [
        "ML-DSA-44",
        "32 KB",
        "watermark",
        "static reserved frame",
        "both",
    ] {
        assert!(
            decision.contains(needle),
            "## Decision must state the rule (missing `{needle}`)"
        );
    }
    let recorded: Vec<&str> = decision
        .lines()
        .filter(|l| l.starts_with("Decision: "))
        .collect();
    assert_eq!(
        recorded.len(),
        1,
        "## Decision must record exactly one decision line, found {recorded:?}"
    );
    let line = recorded[0].trim();
    assert!(
        DECISIONS
            .iter()
            .any(|d| line == *d || line.starts_with(&format!("{d} "))),
        "decision line `{line}` must be one of {DECISIONS:?}"
    );
    let others = DECISIONS
        .iter()
        .filter(|d| !line.starts_with(*d))
        .filter(|d| doc.lines().any(|l| l.trim_start().starts_with(*d)));
    assert_eq!(others.count(), 0, "only one decision may be recorded");
    if line.starts_with("Decision: NO-GO") {
        let link = line
            .split("SHA-")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .filter(|n| !n.is_empty());
        assert!(
            link.is_some(),
            "a NO-GO decision must link its SHA- follow-up on the decision line"
        );
    }
    assert!(
        decision.contains("SHA-170"),
        "the rule names SHA-170 for NO-GO"
    );
}

#[test]
fn reproduce_section_lists_exact_commands() {
    let doc = doc();
    let reproduce = section(&doc, "## Reproduce");
    for command in [
        "cargo test --workspace --locked",
        "python3 scripts/gen_mldsa_vectors.py --check",
        "cargo test --release --locked -- mldsa44_kat",
        "cargo test --release --locked -- mldsa65_kat",
        "cargo test --release --locked -- dwt_cycle_counter_present",
        "cargo test --release --locked -- _bench",
        "docs/bench-logs/nrf52840-run1.txt",
        "python3 scripts/bench_summarize.py --check-consistency 0.05",
        "cargo build --release --locked --bins",
        "cargo build --profile size --locked --bins",
        "python3 ../../scripts/elf_sizes.py --label nrf52840/release --baseline",
        "cargo +nightly rustc --release --locked --bin size_mldsa44 --target-dir target/nightly -- -Z emit-stack-sizes",
        "python3 ../../scripts/stack_frames.py",
    ] {
        assert!(
            reproduce.contains(command),
            "## Reproduce must list the command `{command}`"
        );
    }
    for bench in &BENCHES {
        assert!(
            reproduce.contains(&format!("benches/{}", bench.name)),
            "## Reproduce must name benches/{}",
            bench.name
        );
    }
    for script in [
        "gen_mldsa_vectors.py",
        "bench_summarize.py",
        "elf_sizes.py",
        "stack_frames.py",
    ] {
        assert!(
            workspace_root().join("scripts").join(script).is_file(),
            "scripts/{script} must exist"
        );
    }
}

/// A synthetic nRF52840 Wycheproof log: one `BENCH` line per case, as the on-target tests
/// log it behind a defmt prefix, with cycles and stack scaled by the given factors.
fn synthetic_log(cycles_scale: f64, stack_scale: f64) -> String {
    let mut log = String::from("      Erasing ✔ 100%\nrunning 2 tests\n");
    for (set, tc, msg_len, valid, cycles, stack) in [
        ("ML-DSA-44", 147, 11, true, 4_000_000u32, 90_000u32),
        ("ML-DSA-44", 18, 32, false, 3_900_000, 89_000),
        ("ML-DSA-65", 161, 11, true, 6_500_000, 150_000),
    ] {
        let cycles = (f64::from(cycles) * cycles_scale) as u32;
        let stack = (f64::from(stack) * stack_scale) as u32;
        log += &format!(
            "0.123456 [INFO ] BENCH board=nrf52840 set={set} src=wycheproof tc={tc} \
             msg_len={msg_len} expect_valid={valid} ok=true cycles={cycles} us={} \
             peak_stack={stack} saturated=false (kat tests/kat.rs:100)\n",
            cycles / 64
        );
    }
    log += "test mldsa44_bench ... ok\n";
    log
}

#[test]
fn bench_summarize_checks_synthetic_logs() {
    let scratch = ScratchDir::new("bench_summarize");
    let write = |name: &str, text: &str| {
        let path = scratch.path().join(name);
        fs::write(&path, text).expect("write synthetic log");
        path
    };

    // Three runs within 5 %: consistent, with one results row per board × set.
    let good = [
        write("run1.txt", &synthetic_log(1.0, 1.0)),
        write("run2.txt", &synthetic_log(1.01, 1.0)),
        write("run3.txt", &synthetic_log(1.03, 1.04)),
    ];
    let (ok, stdout, stderr) = run_capture(
        python_script("bench_summarize.py")
            .args(["--check-consistency", "0.05"])
            .args(&good),
    );
    assert!(ok, "consistent logs rejected:\n{stdout}\n{stderr}");
    assert!(
        stdout.contains("consistent: 3 cases within 5.0% across 3 logs"),
        "{stdout}"
    );
    assert!(
        stdout.contains("| nrf52840 | ML-DSA-44 |") && stdout.contains("| nrf52840 | ML-DSA-65 |"),
        "one results row per set:\n{stdout}"
    );
    assert!(
        stdout.contains("(tc 147, 11 B msg)"),
        "headline is the short Wycheproof valid case:\n{stdout}"
    );

    // A 10 % stack difference fails the check.
    let bad = [
        good[0].clone(),
        good[1].clone(),
        write("run3-bad.txt", &synthetic_log(1.0, 1.10)),
    ];
    let (ok, _, stderr) = run_capture(
        python_script("bench_summarize.py")
            .args(["--check-consistency", "0.05"])
            .args(&bad),
    );
    assert!(!ok, "a 10 % peak_stack spread must fail");
    assert!(stderr.contains("peak_stack"), "{stderr}");

    // A failed KAT case and a log without BENCH lines are errors.
    let failed = write(
        "failed.txt",
        &synthetic_log(1.0, 1.0).replacen("ok=true", "ok=false", 1),
    );
    let (ok, _, stderr) = run_capture(python_script("bench_summarize.py").arg(&failed));
    assert!(!ok && stderr.contains("failed its KAT"), "{stderr}");
    let empty = write("empty.txt", "no benchmark output\n");
    let (ok, _, stderr) = run_capture(python_script("bench_summarize.py").arg(&empty));
    assert!(!ok && stderr.contains("no BENCH lines"), "{stderr}");
}

#[test]
#[ignore = "needs board logs: save docs/bench-logs/<board>-run{1,2,3}.txt (docs/benchmarks.md)"]
fn three_run_logs_consistent_within_5_percent() {
    let dir = workspace_root().join("docs/bench-logs");
    let mut missing = Vec::new();
    for board in BOARDS {
        for run in 1..=3 {
            let log = dir.join(format!("{board}-run{run}.txt"));
            if !log.is_file() {
                missing.push(format!("docs/bench-logs/{board}-run{run}.txt"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "no logs yet: run the benches on the boards and save {} (docs/benchmarks.md#three-run-consistency)",
        missing.join(", ")
    );
    for board in BOARDS {
        let logs: Vec<_> = (1..=3)
            .map(|run| dir.join(format!("{board}-run{run}.txt")))
            .collect();
        let (ok, stdout, stderr) = run_capture(
            python_script("bench_summarize.py")
                .args(["--check-consistency", "0.05"])
                .args(&logs),
        );
        assert!(ok, "{board}: runs not within 5 %:\n{stdout}\n{stderr}");
    }
}

// ---- SHA-65: LMS/HSS ------------------------------------------------------------------

const LMS_SECTION: &str = "## LMS/HSS verify (SHA-65)";
const LMS_SETS: [(&str, usize, usize); 2] = [
    // (set, n = m, p for W8)
    ("LMS SHA-256 M32/W8", 32, 34),
    ("LMS SHA-256/192 M24/W8", 24, 26),
];

/// RFC 8554 §5.4: an LMS signature is `4 + (4 + n * (p + 1)) + 4 + m * h` bytes (m = n).
fn lms_signature_len(n: usize, p: usize, h: usize) -> usize {
    4 + (4 + n * (p + 1)) + 4 + n * h
}

#[test]
fn lms_results_table_covers_boards_and_sets() {
    let doc = doc();
    // The LMS section comes after the SHA-34 sections, which stay intact.
    let follow_ups = doc.find("\n## Follow-ups\n").expect("## Follow-ups");
    let lms_at = doc
        .find(&format!("\n{LMS_SECTION}\n"))
        .unwrap_or_else(|| panic!("docs/benchmarks.md needs `{LMS_SECTION}`"));
    assert!(lms_at > follow_ups, "the LMS section follows ## Follow-ups");
    let lms = section(&doc, LMS_SECTION);
    for heading in [
        "### Crate choice",
        "### Known-answer evidence",
        "### LMS method",
        "### LMS results",
        "### LMS reproduce",
    ] {
        assert!(
            lms.contains(&format!("\n{heading}\n")),
            "{LMS_SECTION} needs `{heading}`"
        );
    }
    let results = section(&doc, "### LMS results");
    let header = results
        .lines()
        .find(|l| l.starts_with("| Board | Set |"))
        .expect("### LMS results needs the board × set table");
    for column in [
        "Verify cycles",
        "Peak stack (measured)",
        "Static frame",
        "Flash Δ release",
        "Flash Δ size",
        "LMS signature (H10)",
        "HSS signature (H10+H10, L=2)",
    ] {
        assert!(
            header.contains(column),
            "LMS table needs a `{column}` column"
        );
    }
    let table: String = results
        .lines()
        .skip_while(|l| !l.starts_with("| Board | Set |"))
        .take_while(|l| l.starts_with('|'))
        .map(|l| format!("{l}\n"))
        .collect();
    let rows = table_rows(&table);
    assert_eq!(rows.len(), 4, "one row per board × set");
    for board in BOARDS {
        for (set, n, p) in LMS_SETS {
            let row = rows
                .iter()
                .find(|r| r[0] == board && r[1] == set)
                .unwrap_or_else(|| panic!("LMS table has no row for {board} {set}"));
            assert_eq!(row.len(), 10, "{board} {set}: 10 columns");
            // Cycles, time and measured stack: a value or pending hardware.
            for i in [2, 3, 4] {
                let cell = &row[i];
                assert!(
                    cell == PENDING || cell.chars().any(|c| c.is_ascii_digit()),
                    "{board} {set} column {i}: `{cell}` must be a value or `{PENDING}`"
                );
            }
            // Static frame and flash are measured without hardware.
            for i in [5, 6, 7] {
                let value = parse_bytes(&row[i])
                    .unwrap_or_else(|| panic!("{board} {set} column {i}: `{}`", row[i]));
                assert!(value > 0, "{board} {set} column {i} must be positive");
            }
            let frame = parse_bytes(&row[5]).unwrap();
            assert!(frame <= 32_768, "{board} {set}: static frame over 32 KB");
            // Signature sizes follow RFC 8554 for H10.
            let lms_sig = lms_signature_len(n, p, 10);
            assert_eq!(
                parse_bytes(&row[8]),
                Some(lms_sig as u64),
                "{board} {set} LMS"
            );
            assert_eq!(
                parse_bytes(&row[9]),
                Some((4 + 2 * lms_sig + 24 + n) as u64),
                "{board} {set} HSS-2"
            );
        }
    }
    // The plan's reference sizes.
    assert_eq!(lms_signature_len(32, 34, 10), 1452);
    assert_eq!(lms_signature_len(24, 26, 10), 900);
    assert_eq!(lms_signature_len(32, 34, 20), 1772);
    assert_eq!(lms_signature_len(24, 26, 20), 1140);

    let reproduce = section(&doc, "### LMS reproduce");
    for command in [
        "python3 scripts/gen_lms_vectors.py --check",
        "cargo test --release --locked --test lms -- lms_kat",
        "cargo test --release --locked --test lms -- lms_bench",
        "cargo test --release --locked --test lms -- lms_rotation_key_b_verifies_against_a_b_and_fails_against_a",
        "--baseline target/thumbv7em-none-eabihf/release/size_lms_baseline",
        "cargo +nightly rustc --release --locked --bin size_lms --target-dir target/nightly -- -Z emit-stack-sizes",
    ] {
        assert!(
            reproduce.contains(command),
            "### LMS reproduce must list `{command}`"
        );
    }
}

#[test]
fn lms_crate_choice_recorded() {
    let doc = doc();
    let choice = section(&doc, "### Crate choice");
    for candidate in ["hbs-lms 0.1.1", "lms-signature 0.1.0-rc.2", "in-house"] {
        assert!(
            choice.contains(candidate),
            "### Crate choice must compare `{candidate}`"
        );
    }
    let recorded: Vec<&str> = choice
        .lines()
        .filter(|l| l.starts_with("Choice: "))
        .collect();
    assert_eq!(
        recorded.len(),
        1,
        "exactly one `Choice:` line: {recorded:?}"
    );
    assert!(
        recorded[0].starts_with("Choice: in-house"),
        "{}",
        recorded[0]
    );
    assert!(
        choice.contains("no new dependency; sha2 =0.11.0 already pinned"),
        "### Crate choice must carry the E8.2 justification"
    );
    assert!(choice.contains("E8.2"));
    let evidence = section(&doc, "### Known-answer evidence");
    for needle in ["hsslms 0.1.3", "Test Case 1", "SHA-256/192", "No NIST"] {
        assert!(
            evidence.contains(needle),
            "### Known-answer evidence must record `{needle}`"
        );
    }
    // The crate choice matches the code: no LMS crate among keelsign-verify's dependencies.
    let manifest = fs::read_to_string(workspace_root().join("keelsign-verify/Cargo.toml"))
        .expect("read keelsign-verify/Cargo.toml");
    for krate in ["hbs-lms", "lms-signature"] {
        assert!(
            !manifest.contains(krate),
            "keelsign-verify must not depend on {krate}"
        );
    }
    assert!(
        workspace_root()
            .join("keelsign-verify/src/lms.rs")
            .is_file()
    );
}

/// SHA-240: the LMS section names the default and the strict CNSA 2.0 policy, how the
/// strict one is selected, and the fixtures' three expectations.
#[test]
fn lms_section_names_both_policies() {
    let doc = doc();
    let lms = section(&doc, LMS_SECTION);
    for needle in [
        "keelsign_default()",
        "cnsa_2_0()",
        "DefaultBackend::cnsa_2_0()",
        "three expectations",
        "expect_cnsa2=",
    ] {
        assert!(
            lms.contains(needle),
            "the LMS section must mention `{needle}`"
        );
    }
    assert!(
        !lms.contains("renamed or split"),
        "the LMS section must not describe the policy split as future work"
    );
    assert!(
        !lms.contains("expect_cnsa=…"),
        "the LMS section must describe the current lms_kat log line"
    );
}

/// A synthetic LMS log: no Wycheproof cases, so the headline is the shortest-message
/// valid case of each set.
#[test]
fn bench_summarize_headline_for_lms_logs() {
    let scratch = ScratchDir::new("bench_summarize_lms");
    let mut log = String::new();
    for (set, src, tc, msg_len, valid, cycles) in [
        ("LMS-M32_H5-W8-L2", "rfc8554", 1, 162, true, 9_000_000u32),
        ("LMS-M32_H5-W8-L2", "hsslms", 302, 32, true, 8_500_000),
        ("LMS-M32_H5-W8-L2", "rfc8554", 401, 162, false, 9_100_000),
        ("LMS-M24_H5-W8-L1", "hsslms", 311, 32, true, 3_000_000),
    ] {
        log += &format!(
            "0.1 [INFO ] BENCH board=rp2350 set={set} src={src} tc={tc} msg_len={msg_len} \
             sig_len=2644 expect_valid={valid} ok=true result=Ok cycles={cycles} us={} \
             peak_stack=2000 saturated=false (lms tests/lms.rs:1)\n",
            cycles / 150
        );
    }
    let path = scratch.path().join("lms.txt");
    fs::write(&path, log).expect("write synthetic log");
    let (ok, stdout, stderr) = run_capture(python_script("bench_summarize.py").arg(&path));
    assert!(ok, "{stdout}\n{stderr}");
    assert!(
        stdout.contains("| rp2350 | LMS-M32_H5-W8-L2 | 8500000 (tc 302, 32 B msg)"),
        "{stdout}"
    );
    assert!(
        stdout.contains("| rp2350 | LMS-M24_H5-W8-L1 | 3000000 (tc 311, 32 B msg)"),
        "{stdout}"
    );
}

/// SHA-42 AC2: the image-digest section records the RAM bound (chunk + SHA-256 state +
/// frame, default 256 B), the static frames, the flash delta against its baseline, and
/// the on-target procedure with its results pending hardware.
#[test]
fn image_digest_section_records_ram_bound() {
    let doc = doc();
    let digest = section(&doc, "## Image digest (SHA-42)");
    let method = section(&doc, "### Digest method");
    for term in [
        "`chunk.len()` + the SHA-256 state",
        "108 B",
        "DEFAULT_CHUNK_LEN` = 256 B",
        "BOOT_TMPBUF_SZ",
        "bootutil_priv.h:53",
        "Nothing scales with the image",
        "-Z emit-stack-sizes",
        "sha2::sha256::compress256",
        "size_digest_baseline",
        "mcuboot-ed25519-200k.bin",
        "link_section",
        "SHA-55",
        "DIGEST board=… bytes=204800 chunk=256 cycles=… us=… peak_stack=… saturated=false",
        "4,096 B",
    ] {
        assert!(
            method.contains(term),
            "### Digest method must mention `{term}`"
        );
    }
    assert!(digest.contains("NorFlashReader") && digest.contains("READ_SIZE == 1"));

    let results = section(&doc, "### Digest results");
    let rows = table_rows(results);
    for bench in &BENCHES {
        let board = bench.name.split('-').next().unwrap();
        let row = rows
            .iter()
            .find(|r| r[0] == board)
            .unwrap_or_else(|| panic!("### Digest results has no row for {board}"));
        assert_eq!(row.len(), 8, "{board}: {row:?}");
        for cell in &row[1..4] {
            assert_eq!(cell, "pending (hardware)", "{board}: {row:?}");
        }
        let frame = parse_bytes(&row[4]).expect("static frame in bytes");
        let bound = parse_bytes(&row[5]).expect("RAM bound in bytes");
        assert_eq!(
            bound,
            256 + frame,
            "{board}: RAM bound = 256 B chunk + frame"
        );
        assert!(bound <= 4096, "{board}: within the on-target stack limit");
        for cell in &row[6..8] {
            assert!(
                parse_bytes(cell).is_some_and(|d| d > 0),
                "{board}: flash delta `{cell}`"
            );
        }
        // The flash detail rows add up.
        for profile in ["release", "size"] {
            let label = format!("{board} / {profile}");
            let detail = rows
                .iter()
                .find(|r| r[0] == label)
                .unwrap_or_else(|| panic!("no flash detail row `{label}`"));
            let n: Vec<u64> = detail[1..4]
                .iter()
                .map(|c| c.replace(',', "").parse().unwrap())
                .collect();
            assert_eq!(n[1] - n[0], n[2], "{label}: {detail:?}");
            let column = if profile == "release" { 6 } else { 7 };
            assert_eq!(parse_bytes(&row[column]), Some(n[2]), "{label}");
        }
    }

    let reproduce = section(&doc, "### Digest reproduce");
    for command in [
        "cargo test --release --locked --test image -- image_digest_200k_from_flash",
        "cargo test --release --locked --test image -- image_digest_bench",
        "size_digest_baseline target/thumbv7em-none-eabihf/release/size_digest",
        "cargo +nightly rustc --release --locked --bin size_digest --target-dir target/nightly -- -Z emit-stack-sizes",
    ] {
        assert!(
            reproduce.contains(command),
            "### Digest reproduce must list `{command}`"
        );
    }
}

/// SHA-46: the hybrid verify section records the flash delta of `size_verify` over its
/// baseline on both boards and profiles, the static frame, cycles and peak stack as
/// values or `pending (hardware)` (SHA-69: measured by `hybrid_verify_bench`), and the
/// reproduce commands.
#[test]
fn hybrid_verify_section_records_flash_delta() {
    let doc = doc();
    let hybrid = section(&doc, "## Hybrid verify entry point (SHA-46)");
    for term in [
        "Policy::Hybrid",
        "ed25519-dalek",
        "verify_strict",
        "size_verify_baseline",
        "keelsign-hybrid-ed25519-lms.bin",
        "policy-matrix.bin",
        "-Z emit-stack-sizes",
        "POLICY board=",
        "NorFlashReader",
        "docs/policy.md",
        // SHA-69: the on-target hybrid measurement.
        "hybrid_verify_bench",
        "keelsign-hybrid-ed25519-hss2.bin",
        "BENCH board=nrf52840 set=Hybrid-Ed25519+LMS-M32_H5-L1",
        "set=Hybrid-Ed25519+HSS-M32_H5x2-L2",
        "CYCCNT",
        "stack_paint",
        "passed=171/171",
    ] {
        assert!(
            hybrid.contains(term),
            "the hybrid section must mention `{term}`"
        );
    }
    let results = section(&doc, "### Hybrid results");
    let rows = table_rows(results);
    for bench in &BENCHES {
        let board = bench.name.split('-').next().unwrap();
        let row = rows
            .iter()
            .find(|r| r[0] == board)
            .unwrap_or_else(|| panic!("### Hybrid results has no row for {board}"));
        assert_eq!(row.len(), 6, "{board}: {row:?}");
        for cell in &row[1..4] {
            assert!(
                parse_bytes(cell).is_some_and(|b| b > 0),
                "{board}: `{cell}` must be a positive byte count"
            );
        }
        for cell in &row[4..6] {
            assert!(
                cell == PENDING || !cell.is_empty() && !cell.contains("pending"),
                "{board}: `{cell}` must be a value or `{PENDING}`"
            );
        }
        for profile in ["release", "size"] {
            let label = format!("{board} / {profile}");
            let detail = rows
                .iter()
                .find(|r| r[0] == label)
                .unwrap_or_else(|| panic!("no flash detail row `{label}`"));
            let n: Vec<u64> = detail[1..4]
                .iter()
                .map(|c| c.replace(',', "").parse().unwrap())
                .collect();
            assert!(n.iter().all(|&v| v > 0), "{label}: {detail:?}");
            assert_eq!(n[1] - n[0], n[2], "{label}: {detail:?}");
            let column = if profile == "release" { 1 } else { 2 };
            assert_eq!(parse_bytes(&row[column]), Some(n[2]), "{label}");
        }
    }
    let reproduce = section(&doc, "### Hybrid reproduce");
    for command in [
        "cargo test --release --locked --test policy -- policy_matrix_from_flash",
        "size_verify_baseline target/thumbv7em-none-eabihf/release/size_verify",
        "size_verify_baseline target/thumbv7em-none-eabihf/size/size_verify",
        "cargo +nightly rustc --release --locked --bin size_verify --target-dir target/nightly -- -Z emit-stack-sizes",
        "cargo test -p keelsign-verify --locked --features ed25519 --test policy_matrix",
        // SHA-69: the suite log is the one recorded source of the hybrid figures.
        "python3 scripts/bench_summarize.py docs/bench-logs/nrf52840-suite-run1.txt",
        "cargo test --release --locked --test policy -- hybrid_verify_bench\n",
    ] {
        assert!(
            reproduce.contains(command),
            "### Hybrid reproduce must list `{command}`"
        );
    }
}

/// A scalar field of the MANIFEST.json output `name`, without quotes.
fn manifest_output_field(name: &str, field: &str) -> String {
    let path = workspace_root().join("tests/fixtures/images/MANIFEST.json");
    let manifest =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let start = manifest
        .find(&format!("\n    \"{name}\": {{"))
        .unwrap_or_else(|| panic!("MANIFEST.json has no output `{name}`"));
    let entry = &manifest[start..];
    let entry = &entry[..entry.find("\n    }").expect("entry closes")];
    let needle = format!("\"{field}\": ");
    let at = entry
        .find(&needle)
        .unwrap_or_else(|| panic!("{name}: no field `{field}`"))
        + needle.len();
    let rest = &entry[at..];
    rest[..rest.find([',', '\n']).unwrap_or(rest.len())]
        .trim()
        .trim_matches('"')
        .to_owned()
}

/// SHA-69 AC3: the per-image hybrid table has one row per board and hybrid Ed25519 +
/// LMS/HSS image; each image is a hybrid LMS/HSS output of MANIFEST.json with the HSS
/// level count the row names, its signature bytes are the 64-byte Ed25519 signature plus
/// the manifest's HSS signature length, its flash cells copy [Hybrid results], and its
/// cycles and peak stack are values or `pending (hardware)`.
#[test]
fn hybrid_per_image_table_matches_manifest_and_hybrid_results() {
    let doc = doc();
    let per_image = section(&doc, "### Hybrid per-image results");
    let table = table_with_header(per_image, "| Board | Image |")
        .expect("### Hybrid per-image results has a `| Board | Image |` table");
    assert_eq!(
        table[0],
        [
            "Board",
            "Image",
            "PQ half",
            "Signature bytes (Ed25519 + PQ)",
            "Flash Δ release",
            "Flash Δ size",
            "Cycles",
            "Peak stack",
        ],
        "### Hybrid per-image results: table columns"
    );
    let headline = table_with_header(
        section(&doc, "### Hybrid results"),
        "| Board | Flash Δ release |",
    )
    .expect("### Hybrid results table");
    const IMAGES: [(&str, &str); 2] = [
        ("keelsign-hybrid-ed25519-lms.bin", "HSS L=1"),
        ("keelsign-hybrid-ed25519-hss2.bin", "HSS L=2"),
    ];
    assert_eq!(
        table.len() - 1,
        BOARDS.len() * IMAGES.len(),
        "one row per board × hybrid image"
    );
    for board in BOARDS {
        let source = row_with_key(&headline, &[board]);
        for (image, levels) in IMAGES {
            let row = row_with_key(&table, &[board, &format!("`{image}`")]);
            assert_eq!(manifest_output_field(image, "ed25519"), "true", "{image}");
            assert_eq!(
                manifest_output_field(image, "algorithm"),
                "LmsHss",
                "{image}"
            );
            let level_count: u32 = levels.trim_start_matches("HSS L=").parse().unwrap();
            assert!(
                manifest_output_field(image, "public_key_hex")
                    .starts_with(&format!("{level_count:08x}")),
                "{image}: an HSS key with L={level_count}"
            );
            assert!(
                row[column_index(&table, "PQ half")].starts_with(levels),
                "{board} {image}: PQ half must start with `{levels}`"
            );
            let pq: u64 = manifest_output_field(image, "signature_lens")
                .parse()
                .expect("one PQ signature");
            assert_eq!(
                parse_bytes(&row[column_index(&table, "Signature bytes (Ed25519 + PQ)")]),
                Some(64 + pq),
                "{board} {image}: signature bytes"
            );
            for column in ["Flash Δ release", "Flash Δ size"] {
                assert_eq!(
                    row[column_index(&table, column)],
                    source[column_index(&headline, column)],
                    "{board} {image}: {column} must copy ### Hybrid results"
                );
            }
            for column in ["Cycles", "Peak stack"] {
                let cell = &row[column_index(&table, column)];
                assert!(
                    cell == PENDING || !cell.is_empty() && !cell.contains("pending"),
                    "{board} {image}: {column} `{cell}` must be a value or `{PENDING}`"
                );
            }
        }
        // The headline table is the L=1 image.
        let l1 = row_with_key(&table, &[board, "`keelsign-hybrid-ed25519-lms.bin`"]);
        for column in ["Cycles", "Peak stack"] {
            assert_eq!(
                l1[column_index(&table, column)],
                source[column_index(&headline, column)],
                "{board}: ### Hybrid results {column} is the L=1 image's"
            );
        }
    }
}

/// SHA-44: the ML-DSA verify section states the stack the `ml-dsa` feature needs (both
/// static frames, over the 32 KB budget), names SHA-169, and records the results per
/// board and set as values or `pending (hardware)`, with the reproduce commands.
#[test]
fn mldsa_verify_section_records_stack() {
    let doc = doc();
    let mldsa = section(&doc, "## ML-DSA verify (SHA-44)");
    for term in [
        "SHA-169",
        "32 KB",
        "32,768 B",
        "`ml-dsa`",
        "#[inline(never)]",
        "mldsa::verify_param",
        "mldsa_images_from_flash",
        "MLDSA board=",
        "stack_paint",
        "CYCCNT",
        "NorFlashReader",
        "-Z emit-stack-sizes",
        "passed=171/171",
    ] {
        assert!(
            mldsa.contains(term),
            "the ML-DSA verify section must mention `{term}`"
        );
    }
    let stack = section(&doc, "### Stack the feature needs");
    let results = section(&doc, "### ML-DSA verify results");
    let rows = table_rows(results);
    for board in BOARDS {
        for set in SETS {
            let row = rows
                .iter()
                .find(|r| r[0] == board && r[1] == set)
                .unwrap_or_else(|| panic!("### ML-DSA verify results has no row {board} {set}"));
            assert_eq!(row.len(), 8, "{board} {set}: {row:?}");
            // The static frames (release, size) exceed the 32 KB budget, and the stated
            // stack names the release frame.
            for cell in &row[2..4] {
                let bytes = parse_bytes(cell)
                    .unwrap_or_else(|| panic!("{board} {set}: `{cell}` must be a byte count"));
                assert!(bytes > 32_768, "{board} {set}: {cell} is not over 32 KB");
            }
            assert!(
                stack.contains(row[2].trim_end_matches(" B")),
                "### Stack the feature needs must state {}",
                row[2]
            );
            // verify_with on / off, flash Δ release / size: two byte counts each.
            for cell in &row[4..6] {
                let parts: Vec<&str> = cell.split(" / ").collect();
                assert_eq!(parts.len(), 2, "{board} {set}: `{cell}`");
                for part in parts {
                    assert!(
                        parse_bytes(part).is_some_and(|b| b > 0),
                        "{board} {set}: `{part}` must be a positive byte count"
                    );
                }
            }
            for cell in &row[6..8] {
                assert!(
                    cell == PENDING || !cell.is_empty() && !cell.contains("pending"),
                    "{board} {set}: `{cell}` must be a value or `{PENDING}`"
                );
            }
        }
        // The flash detail rows add up and match the results table.
        for (profile, at) in [("release", 0), ("size", 1)] {
            let label = format!("{board} / {profile}");
            let detail = rows
                .iter()
                .find(|r| r[0] == label)
                .unwrap_or_else(|| panic!("no ML-DSA flash detail row `{label}`"));
            let n: Vec<u64> = detail[1..4]
                .iter()
                .map(|c| c.replace(',', "").parse().unwrap())
                .collect();
            assert_eq!(n[1] - n[0], n[2], "{label}: {detail:?}");
            let row = rows.iter().find(|r| r[0] == board).unwrap();
            let delta: Vec<&str> = row[5].split(" / ").collect();
            assert_eq!(parse_bytes(delta[at]), Some(n[2]), "{label}");
        }
    }
    let reproduce = section(&doc, "### ML-DSA verify reproduce");
    for command in [
        "cargo test --release --locked --features ml-dsa --test mldsa_verify",
        "cargo test --release --locked --features ml-dsa --test policy -- policy_matrix_from_flash",
        "cargo build --release --locked --bins --features ml-dsa --target-dir target/mldsa",
        "cargo +nightly rustc --release --locked --features ml-dsa --bin size_verify --target-dir target/nightly-mldsa -- -Z emit-stack-sizes",
        "cargo test -p keelsign-verify --locked --features ml-dsa",
    ] {
        assert!(
            reproduce.contains(command),
            "### ML-DSA verify reproduce must list `{command}`"
        );
    }
    // The SHA-34 decision points at this section.
    assert!(section(&doc, "## Decision").contains("(#ml-dsa-verify-sha-44)"));
}

// ---- SHA-275: recorded flash and frame figures -----------------------------------------

const FRAME_DETAIL: &str = "### Static frame detail";
const LARGEST_OTHER: &str = "(largest other frame)";

/// The sections holding a "Flash detail" table (`| Board / profile | …`).
const FLASH_DETAIL_SECTIONS: [&str; 5] = [
    "## Results",
    "### LMS results",
    "### Digest results",
    "### Hybrid results",
    "### ML-DSA verify results",
];

/// Collapses every run of whitespace (line breaks and indentation included) to one space,
/// so prose wrapped over several lines can be searched for a phrase.
fn normalized(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A plain byte count cell such as `47,276` (or `47,276 B`).
fn parse_count(cell: &str) -> Option<u64> {
    parse_bytes(cell.trim())
}

/// Header and body rows of the markdown table in `text` whose header line starts with
/// `header_prefix`: element 0 is the header's cells.
fn table_with_header(text: &str, header_prefix: &str) -> Option<Vec<Vec<String>>> {
    let lines: Vec<&str> = text
        .lines()
        .skip_while(|l| !l.starts_with(header_prefix))
        .take_while(|l| l.starts_with('|'))
        .collect();
    let header = lines.first()?;
    let cells = |l: &str| -> Vec<String> {
        l.trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_owned())
            .collect()
    };
    let mut table = vec![cells(header)];
    table.extend(
        lines
            .iter()
            .skip(1)
            .filter(|l| !l.starts_with("|---"))
            .map(|l| cells(l)),
    );
    Some(table)
}

/// The first backticked span of `text`.
fn backticked(text: &str) -> Option<&str> {
    let start = text.find('`')? + 1;
    let len = text[start..].find('`')?;
    Some(&text[start..start + len])
}

/// One flash cell of a "Flash detail" table: the `flash` of `bin` in the row
/// `board / profile`, built with or without the bench `ml-dsa` feature.
#[derive(Clone, Debug, PartialEq)]
struct FlashCell {
    section: String,
    /// The row label, `nrf52840 / release`.
    row: String,
    bin: String,
    ml_dsa: bool,
    bytes: u64,
}

impl FlashCell {
    fn board(&self) -> &str {
        self.row.split(" / ").next().unwrap_or_default()
    }

    fn profile(&self) -> &str {
        self.row.split(" / ").nth(1).unwrap_or_default()
    }

    fn key(&self) -> FlashKey {
        (
            self.board().to_owned(),
            self.profile().to_owned(),
            self.ml_dsa,
            self.bin.clone(),
        )
    }
}

/// (board, profile, `ml-dsa` feature, bin) of a measured ELF.
type FlashKey = (String, String, bool, String);

/// A "Flash detail" table: its section, header and rows.
struct FlashTable {
    section: &'static str,
    header: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl FlashTable {
    /// Indices of the `… flash` columns (the first is the baseline) and of the `Δ …`
    /// columns, in table order.
    fn columns(&self) -> (Vec<usize>, Vec<usize>) {
        let flash = (0..self.header.len())
            .filter(|&i| self.header[i].contains(" flash"))
            .collect();
        let delta = (0..self.header.len())
            .filter(|&i| self.header[i].starts_with('Δ'))
            .collect();
        (flash, delta)
    }

    fn row(&self, label: &str) -> &[String] {
        self.rows
            .iter()
            .find(|r| r[0] == label)
            .unwrap_or_else(|| panic!("{}: no flash detail row `{label}`", self.section))
    }

    /// The `Δ` cells of row `label`, in table order.
    fn deltas(&self, label: &str) -> Vec<u64> {
        let row = self.row(label);
        self.columns()
            .1
            .iter()
            .map(|&i| {
                parse_count(&row[i]).unwrap_or_else(|| panic!("{}: `{}`", self.section, row[i]))
            })
            .collect()
    }
}

fn flash_tables(doc: &str) -> Vec<FlashTable> {
    FLASH_DETAIL_SECTIONS
        .iter()
        .map(|&heading| {
            let mut table = table_with_header(section(doc, heading), "| Board / profile |")
                .unwrap_or_else(|| panic!("{heading} has no `| Board / profile |` table"));
            let header = table.remove(0);
            FlashTable {
                section: heading,
                header,
                rows: table,
            }
        })
        .collect()
}

/// Every flash cell (not the Δ cells, which `flash_tables_are_consistent` checks) of the
/// five "Flash detail" tables.
fn flash_detail_cells(doc: &str) -> Vec<FlashCell> {
    let mut cells = Vec::new();
    for table in flash_tables(doc) {
        for &i in &table.columns().0 {
            let column = &table.header[i];
            let bin = backticked(column)
                .unwrap_or_else(|| panic!("{}: column `{column}` names no bin", table.section));
            for row in &table.rows {
                cells.push(FlashCell {
                    section: table.section.to_owned(),
                    row: row[0].clone(),
                    bin: bin.to_owned(),
                    ml_dsa: column.contains("(ml-dsa on)"),
                    bytes: parse_count(&row[i]).unwrap_or_else(|| {
                        panic!("{}: `{}` is not a byte count", table.section, row[i])
                    }),
                });
            }
        }
    }
    cells
}

/// One line per flash cell that differs from (or is missing in) `measured`.
fn compare_flash(cells: &[FlashCell], measured: &BTreeMap<FlashKey, u64>) -> Vec<String> {
    let mut report = Vec::new();
    for cell in cells {
        let column = format!(
            "`{}` flash{}",
            cell.bin,
            if cell.ml_dsa { " (ml-dsa on)" } else { "" }
        );
        match measured.get(&cell.key()) {
            Some(&m) if m == cell.bytes => {}
            Some(&m) => report.push(format!(
                "{}: row `{}`, column {column}: doc {}, measured {m}",
                cell.section, cell.row, cell.bytes
            )),
            None => report.push(format!(
                "{}: row `{}`, column {column}: doc {}, not measured",
                cell.section, cell.row, cell.bytes
            )),
        }
    }
    report
}

/// One row of the `### Static frame detail` table.
#[derive(Clone, Debug, PartialEq)]
struct FrameRow {
    bin: String,
    /// The raw "Build" cell, for messages.
    build: String,
    profile: String,
    ml_dsa: bool,
    stable_prologue: bool,
    /// A substring of exactly one demangled function name, or `(largest other frame)`;
    /// for a stable-prologue row, the description of the `verify_param` instance.
    function: String,
    /// The frame on each board, in `BOARDS` order.
    frames: [u64; 2],
}

impl FrameRow {
    fn key(&self, board: &str) -> FrameKey {
        (
            board.to_owned(),
            self.bin.clone(),
            self.profile.clone(),
            self.ml_dsa,
        )
    }

    fn same_build(&self, other: &FrameRow) -> bool {
        self.bin == other.bin
            && self.profile == other.profile
            && self.ml_dsa == other.ml_dsa
            && self.stable_prologue == other.stable_prologue
    }
}

/// (board, bin, profile, `ml-dsa` feature) of a nightly-built ELF.
type FrameKey = (String, String, String, bool);

fn frame_rows(doc: &str) -> Vec<FrameRow> {
    let mut table = table_with_header(section(doc, FRAME_DETAIL), "| Bin | Build | Function |")
        .unwrap_or_else(|| panic!("{FRAME_DETAIL} needs the `| Bin | Build | Function |` table"));
    let header = table.remove(0);
    assert_eq!(
        header[3..],
        BOARDS.map(String::from),
        "{FRAME_DETAIL}: one column per board"
    );
    table
        .iter()
        .map(|r| {
            assert_eq!(r.len(), 5, "{FRAME_DETAIL}: {r:?}");
            let frame = |cell: &str| {
                parse_count(cell)
                    .unwrap_or_else(|| panic!("{FRAME_DETAIL}: `{cell}` is not a byte count"))
            };
            let function = if r[2] == LARGEST_OTHER || r[1].contains("stable prologue") {
                r[2].clone()
            } else {
                backticked(&r[2])
                    .unwrap_or_else(|| panic!("{FRAME_DETAIL}: `{}` is not backticked", r[2]))
                    .to_owned()
            };
            FrameRow {
                bin: backticked(&r[0])
                    .unwrap_or_else(|| panic!("{FRAME_DETAIL}: bin `{}`", r[0]))
                    .to_owned(),
                build: r[1].clone(),
                profile: r[1].split(',').next().unwrap_or_default().trim().to_owned(),
                ml_dsa: r[1].contains("ml-dsa"),
                stable_prologue: r[1].contains("stable prologue"),
                function,
                frames: [frame(&r[3]), frame(&r[4])],
            }
        })
        .collect()
}

/// One line per nightly frame row (not the stable prologues) that differs from
/// `measured` (own-frame sizes and demangled names per ELF), or whose function cell does
/// not name exactly one function.
fn compare_frames(
    rows: &[FrameRow],
    measured: &BTreeMap<FrameKey, Vec<(u64, String)>>,
) -> Vec<String> {
    let mut report = Vec::new();
    for row in rows.iter().filter(|r| !r.stable_prologue) {
        for (b, board) in BOARDS.iter().enumerate() {
            let at = format!(
                "{FRAME_DETAIL}: `{}` {}, `{}`, {board}",
                row.bin, row.build, row.function
            );
            let Some(frames) = measured.get(&row.key(board)) else {
                report.push(format!("{at}: doc {}, not measured", row.frames[b]));
                continue;
            };
            let value = if row.function == LARGEST_OTHER {
                let named: Vec<&str> = rows
                    .iter()
                    .filter(|o| o.same_build(row) && o.function != LARGEST_OTHER)
                    .map(|o| o.function.as_str())
                    .collect();
                frames
                    .iter()
                    .filter(|(_, name)| !named.iter().any(|n| name.contains(n)))
                    .map(|&(size, _)| size)
                    .max()
            } else {
                let matching: Vec<&(u64, String)> = frames
                    .iter()
                    .filter(|(_, name)| name.contains(&row.function))
                    .collect();
                match matching.as_slice() {
                    [(size, _)] => Some(*size),
                    [] => {
                        report.push(format!("{at}: matches no function"));
                        continue;
                    }
                    many => {
                        let names: Vec<&str> = many.iter().map(|(_, n)| n.as_str()).collect();
                        report.push(format!(
                            "{at}: matches {} functions, lengthen it: {names:?}",
                            many.len()
                        ));
                        continue;
                    }
                }
            };
            match value {
                Some(m) if m == row.frames[b] => {}
                Some(m) => report.push(format!("{at}: doc {}, measured {m}", row.frames[b])),
                None => report.push(format!("{at}: no other frame")),
            }
        }
    }
    report
}

/// The frame row of `bin`, `build` (the raw cell) whose function cell is `function`.
fn frame_row<'a>(rows: &'a [FrameRow], bin: &str, build: &str, function: &str) -> &'a FrameRow {
    rows.iter()
        .find(|r| r.bin == bin && r.build == build && r.function == function)
        .unwrap_or_else(|| panic!("{FRAME_DETAIL} has no row `{bin}` {build} `{function}`"))
}

/// The figure of a row that the prose quotes once for both boards.
fn both_boards(row: &FrameRow) -> u64 {
    assert_eq!(
        row.frames[0], row.frames[1],
        "{FRAME_DETAIL}: `{}` differs between the boards, but the prose quotes one figure",
        row.function
    );
    row.frames[0]
}

/// `93448` as the document writes it, `93,448`.
fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The cell of the results-table row whose first cells are `key`.
fn results_cell<'a>(rows: &'a [Vec<String>], key: &[&str], column: usize) -> &'a str {
    rows.iter()
        .find(|r| r.len() > column && key.iter().zip(r.iter()).all(|(k, c)| k == c))
        .map(|r| r[column].as_str())
        .unwrap_or_else(|| panic!("no results row {key:?}"))
}

/// The bytes of a results-table cell, or of one half (`at`) of an `a / b` cell.
fn cell_part(cell: &str, at: usize) -> u64 {
    cell.split(" / ")
        .nth(at)
        .and_then(parse_bytes)
        .unwrap_or_else(|| panic!("`{cell}`: no byte count at {at}"))
}

/// AC1/AC2 (CI): every "Flash detail" row adds up, the results tables quote their detail
/// table, the crate-choice in-house figure is the nrf52840 LMS delta, and the SHA-44
/// `ml-dsa off` column is the same build as the SHA-46 `size_verify` column.
#[test]
fn flash_tables_are_consistent() {
    let doc = doc();
    let tables = flash_tables(&doc);
    let table = |heading: &str| tables.iter().find(|t| t.section == heading).unwrap();
    for t in &tables {
        let (flash, delta) = t.columns();
        assert!(
            flash.len() >= 2 && delta.len() == flash.len() - 1,
            "{}: one Δ column per non-baseline flash column: {:?}",
            t.section,
            t.header
        );
        assert_eq!(
            t.rows.len(),
            4,
            "{}: one row per board × profile",
            t.section
        );
        for board in BOARDS {
            for profile in ["release", "size"] {
                let label = format!("{board} / {profile}");
                let row = t.row(&label);
                let n: Vec<u64> = flash
                    .iter()
                    .map(|&i| parse_count(&row[i]).unwrap())
                    .collect();
                for (k, d) in t.deltas(&label).into_iter().enumerate() {
                    assert_eq!(
                        n[k + 1].checked_sub(n[0]),
                        Some(d),
                        "{}: `{label}` {} − {} ≠ {d}",
                        t.section,
                        t.header[flash[k + 1]],
                        t.header[flash[0]]
                    );
                }
            }
        }
        assert!(
            normalized(section(&doc, t.section)).contains("static RAM delta is 0 in every row"),
            "{}: the flash detail must state that the static RAM delta is 0",
            t.section
        );
    }

    // SHA-34 and LMS results quote their detail Δ.
    let results = table_rows(section(&doc, "## Results"));
    let lms_results = table_rows(section(&doc, "### LMS results"));
    for board in BOARDS {
        for (profile, column) in [("release", 6), ("size", 7)] {
            let label = format!("{board} / {profile}");
            let d = table("## Results").deltas(&label);
            for (k, set) in SETS.iter().enumerate() {
                assert_eq!(
                    parse_bytes(results_cell(&results, &[board, set], column)),
                    Some(d[k]),
                    "## Results {board} {set} {profile} ≠ flash detail Δ"
                );
            }
            let d = table("### LMS results").deltas(&label)[0];
            for (set, _, _) in LMS_SETS {
                assert_eq!(
                    parse_bytes(results_cell(&lms_results, &[board, set], column)),
                    Some(d),
                    "### LMS results {board} {set} {profile} ≠ flash detail Δ"
                );
            }
        }
    }

    // The crate choice quotes the nrf52840 LMS delta.
    let lms = table("### LMS results");
    let expected = format!(
        "+{} / +{} B (whole `verify_pq` path)",
        grouped(lms.deltas("nrf52840 / release")[0]),
        grouped(lms.deltas("nrf52840 / size")[0])
    );
    assert!(
        section(&doc, "### Crate choice").contains(&expected),
        "### Crate choice must quote the in-house delta as `{expected}`"
    );

    // SHA-44's `ml-dsa off` column is SHA-46's `size_verify` build.
    let cells = flash_detail_cells(&doc);
    for board in BOARDS {
        for profile in ["release", "size"] {
            let row = format!("{board} / {profile}");
            let find = |section: &str| {
                cells
                    .iter()
                    .find(|c| {
                        c.section == section && c.row == row && c.bin == "size_verify" && !c.ml_dsa
                    })
                    .unwrap_or_else(|| panic!("{section}: no `size_verify` cell for `{row}`"))
                    .bytes
            };
            assert_eq!(
                find("### ML-DSA verify results"),
                find("### Hybrid results"),
                "`{row}`: the SHA-44 `ml-dsa off` size_verify must equal the SHA-46 size_verify"
            );
        }
    }
}

/// AC1/AC2 (CI): every frame figure in the results tables and the prose is a row of
/// `### Static frame detail` or a sum of rows.
#[test]
fn static_frames_match_the_frame_detail_table() {
    let doc = doc();
    let rows = frame_rows(&doc);
    assert!(!rows.is_empty(), "{FRAME_DETAIL} has no rows");
    let f = |bin: &str, build: &str, function: &str| frame_row(&rows, bin, build, function);
    let sum = |chain: &[&FrameRow], b: usize| chain.iter().map(|r| r.frames[b]).sum::<u64>();

    // LMS: the deepest chain below `verify_with_keys`.
    let lms_chain: Vec<(&str, &FrameRow)> = [
        ("`verify_with_keys`", "lms_kat::verify_with_keys<2>"),
        (
            "`DefaultBackend::verify`",
            "<keelsign_verify::backend::DefaultBackend as keelsign_verify::dispatch::Backend>::verify",
        ),
        ("`lms::walk`", "keelsign_verify::lms::walk"),
        ("`lms::lms_verify`", "keelsign_verify::lms::lms_verify"),
        ("`lms::hash`", "keelsign_verify::lms::hash"),
        ("`finalize_fixed_core`", "finalize_fixed_core"),
        ("`sha2::sha256::compress256`", "sha2::sha256::compress256"),
    ]
    .map(|(label, needle)| (label, f("size_lms", "release", needle)))
    .to_vec();
    let lms_rows: Vec<&FrameRow> = lms_chain.iter().map(|&(_, r)| r).collect();
    let lms_results = table_rows(section(&doc, "### LMS results"));
    for (b, board) in BOARDS.iter().enumerate() {
        for (set, _, _) in LMS_SETS {
            assert_eq!(
                parse_bytes(results_cell(&lms_results, &[board, set], 5)),
                Some(sum(&lms_rows, b)),
                "### LMS results {board} {set}: static frame ≠ the chain in {FRAME_DETAIL}"
            );
        }
    }
    let lms_total = grouped(sum(&lms_rows, 0));
    assert_eq!(
        sum(&lms_rows, 0),
        sum(&lms_rows, 1),
        "LMS chain differs by board"
    );
    let method = normalized(section(&doc, "### LMS method"));
    for (label, row) in &lms_chain {
        let quoted = format!("{label} {}", grouped(both_boards(row)));
        assert!(
            method.contains(&quoted),
            "### LMS method must quote `{quoted}`"
        );
    }
    for (heading, phrase) in [
        ("### LMS method", format!("= {lms_total} B")),
        ("### Crate choice", format!("{lms_total} B call chain")),
        (
            "### LMS results",
            format!("compiled call chain is {lms_total} B"),
        ),
    ] {
        assert!(
            normalized(section(&doc, heading)).contains(&phrase),
            "{heading} must quote `{phrase}`"
        );
    }

    // Hybrid: the Ed25519 chain, and the LMS half on top of the wrapper.
    let hybrid_chain: Vec<(&str, &FrameRow)> = [
        ("`size_verify::verify_hybrid`", "size_verify::verify_hybrid<"),
        (
            "`keelsign_verify::ed25519::verify_signature`",
            "keelsign_verify::ed25519::verify_signature",
        ),
        (
            "`NafLookupTable5::from`",
            "NafLookupTable5<curve25519_dalek::backend::serial::curve_models::ProjectiveNielsPoint> as core::convert::From",
        ),
        ("`FieldElement2625::pow22501`", "FieldElement2625>::pow22501"),
    ]
    .map(|(label, needle)| (label, f("size_verify", "release", needle)))
    .to_vec();
    let hybrid_rows: Vec<&FrameRow> = hybrid_chain.iter().map(|&(_, r)| r).collect();
    let hybrid_results = table_rows(section(&doc, "### Hybrid results"));
    for (b, board) in BOARDS.iter().enumerate() {
        assert_eq!(
            parse_bytes(results_cell(&hybrid_results, &[board], 3)),
            Some(sum(&hybrid_rows, b)),
            "### Hybrid results {board}: static frame ≠ the chain in {FRAME_DETAIL}"
        );
    }
    let method = normalized(section(&doc, "### Hybrid method"));
    for (label, row) in &hybrid_chain {
        let quoted = format!("{label} {} B", grouped(both_boards(row)));
        assert!(
            method.contains(&quoted),
            "### Hybrid method must quote `{quoted}`"
        );
    }
    let total = format!(
        "≈ {} KB ({} B)",
        kilobytes(sum(&hybrid_rows, 0)),
        grouped(sum(&hybrid_rows, 0))
    );
    assert!(
        method.contains(&total),
        "### Hybrid method must quote `{total}`"
    );
    for (label, needle) in [
        ("`lms_verify`", "keelsign_verify::lms::lms_verify"),
        ("`lms::hash`", "keelsign_verify::lms::hash"),
        ("`compress256`", "sha2::sha256::compress256"),
    ] {
        let quoted = format!(
            "{label} {} B",
            grouped(both_boards(f("size_verify", "release", needle)))
        );
        assert!(
            method.contains(&quoted),
            "### Hybrid method must quote `{quoted}`"
        );
    }

    // Digest: `image_digest` and `Image::read_from`.
    let digest = f("size_digest", "release", "size_digest::digest<");
    let compress = f("size_digest", "release", "sha2::sha256::compress256");
    let read_image = f("size_digest", "release", "size_digest::read_image<");
    let parse_parts = f(
        "size_digest",
        "release",
        "<keelsign_verify::image::Image>::parse_parts",
    );
    let digest_results = table_rows(section(&doc, "### Digest results"));
    for (b, board) in BOARDS.iter().enumerate() {
        assert_eq!(
            parse_bytes(results_cell(&digest_results, &[board], 4)),
            Some(digest.frames[b] + compress.frames[b]),
            "### Digest results {board}: static frame ≠ digest + compress256"
        );
    }
    let method = normalized(section(&doc, "### Digest method"));
    let digest_frame = both_boards(digest) + both_boards(compress);
    for phrase in [
        format!("{} B (`image_digest`", grouped(both_boards(digest))),
        format!(
            "`sha2::sha256::compress256` {} B = {} B",
            grouped(both_boards(compress)),
            grouped(digest_frame)
        ),
        format!(
            "256 + {} = {} B",
            grouped(digest_frame),
            grouped(256 + digest_frame)
        ),
        format!(
            "`size_digest::read_image<…>` {} B + `Image::parse_parts` {} B = {} B",
            grouped(both_boards(read_image)),
            grouped(both_boards(parse_parts)),
            grouped(both_boards(read_image) + both_boards(parse_parts))
        ),
    ] {
        assert!(
            method.contains(&phrase),
            "### Digest method must quote `{phrase}`"
        );
    }
    let bound = format!(
        "compiled bound with a 256 B chunk is {} B",
        grouped(256 + digest_frame)
    );
    assert!(
        normalized(section(&doc, "### Digest results")).contains(&bound),
        "### Digest results must quote `{bound}`"
    );

    // SHA-34: `verify_case` and the largest other frame.
    let results = table_rows(section(&doc, "## Results"));
    let frame_table = table_rows(section(
        &doc,
        "## Static stack frame estimate (provisional)",
    ));
    for (set, bin, needle) in [
        (
            "ML-DSA-44",
            "size_mldsa44",
            "mldsa_kat::verify_case<ml_dsa::MlDsa44>",
        ),
        (
            "ML-DSA-65",
            "size_mldsa65",
            "mldsa_kat::verify_case<ml_dsa::MlDsa65>",
        ),
    ] {
        let case = f(bin, "release", needle);
        let other = f(bin, "release", LARGEST_OTHER);
        for (b, board) in BOARDS.iter().enumerate() {
            let key = [*board, set];
            assert_eq!(
                parse_bytes(results_cell(&results, &key, 5)),
                Some(case.frames[b]),
                "## Results {board} {set}: static frame"
            );
            assert_eq!(
                parse_bytes(results_cell(&frame_table, &key, 2)),
                Some(case.frames[b]),
                "## Static stack frame estimate {board} {set}: `verify_case` frame"
            );
            assert_eq!(
                parse_bytes(results_cell(&frame_table, &key, 3)),
                Some(other.frames[b]),
                "## Static stack frame estimate {board} {set}: largest other frame"
            );
        }
    }
    let quoted = format!(
        "`verify_case<MlDsa44>` frame is {} B",
        grouped(both_boards(f(
            "size_mldsa44",
            "release",
            "mldsa_kat::verify_case<ml_dsa::MlDsa44>"
        )))
    );
    assert!(
        normalized(section(&doc, "## Decision")).contains(&quoted),
        "## Decision must quote `{quoted}`"
    );
    let ratio = format!(
        "{:.1}",
        both_boards(f(
            "size_mldsa44",
            "release",
            "mldsa_kat::verify_case<ml_dsa::MlDsa44>"
        )) as f64
            / 32_768.0
    );
    for (heading, phrase) in [
        (
            "## Decision",
            format!("about {ratio} times the 32,768 B limit"),
        ),
        (
            "## Static stack frame estimate (provisional)",
            format!("about {ratio} times the 32 KB limit"),
        ),
    ] {
        assert!(
            normalized(section(&doc, heading)).contains(&phrase),
            "{heading} must quote `{phrase}`"
        );
    }

    // SHA-44: `verify_param` per set and profile, `verify_with` on / off.
    let mldsa_results = table_rows(section(&doc, "### ML-DSA verify results"));
    let hybrid_on = f(
        "size_verify",
        "release, `ml-dsa`",
        "size_verify::verify_hybrid<",
    );
    let hybrid_off = f("size_verify", "release", "size_verify::verify_hybrid<");
    for (set, param) in [("ML-DSA-44", "MlDsa44"), ("ML-DSA-65", "MlDsa65")] {
        let needle = format!("keelsign_verify::mldsa::verify_param<ml_dsa::{param}>");
        let release = f("size_verify", "release, `ml-dsa`", &needle);
        let size = f("size_verify", "size, `ml-dsa`", &needle);
        for (b, board) in BOARDS.iter().enumerate() {
            let key = [*board, set];
            assert_eq!(
                parse_bytes(results_cell(&mldsa_results, &key, 2)),
                Some(release.frames[b]),
                "### ML-DSA verify results {board} {set}: static frame release"
            );
            assert_eq!(
                parse_bytes(results_cell(&mldsa_results, &key, 3)),
                Some(size.frames[b]),
                "### ML-DSA verify results {board} {set}: static frame size"
            );
            let with = results_cell(&mldsa_results, &key, 4);
            assert_eq!(
                [cell_part(with, 0), cell_part(with, 1)],
                [hybrid_on.frames[b], hybrid_off.frames[b]],
                "### ML-DSA verify results {board} {set}: `verify_with` frame on / off"
            );
        }
    }

    // The stable prologues are the figures "### Stack the feature needs" tells to budget.
    let stack = normalized(section(&doc, "### Stack the feature needs"));
    let prologue = |set: &str| {
        both_boards(
            rows.iter()
                .find(|r| r.stable_prologue && r.function.contains(set))
                .unwrap_or_else(|| panic!("{FRAME_DETAIL} has no stable-prologue row for {set}")),
        )
    };
    for set in SETS {
        let quoted = format!("{} B ({set})", grouped(prologue(set)));
        assert!(
            stack.contains(&quoted),
            "### Stack the feature needs must quote `{quoted}`"
        );
    }
    let param = |build: &str, set: &str| {
        both_boards(f(
            "size_verify",
            build,
            &format!("keelsign_verify::mldsa::verify_param<ml_dsa::{set}>"),
        ))
    };
    let case = |bin: &str, set: &str| {
        both_boards(f(
            bin,
            "release",
            &format!("mldsa_kat::verify_case<ml_dsa::{set}>"),
        ))
    };
    let (p44, p65) = (prologue("ML-DSA-44"), prologue("ML-DSA-65"));
    let (c44, c65) = (
        case("size_mldsa44", "MlDsa44"),
        case("size_mldsa65", "MlDsa65"),
    );
    let (r44, r65) = (
        param("release, `ml-dsa`", "MlDsa44"),
        param("release, `ml-dsa`", "MlDsa65"),
    );
    let case_gap = r44.abs_diff(c44).max(r65.abs_diff(c65));
    let hybrid_gap = both_boards(hybrid_on).abs_diff(both_boards(hybrid_off));
    for (heading, phrase) in [
        (
            "### Stack the feature needs",
            format!(
                "{} / {} B in release and {} / {} B at",
                grouped(r44),
                grouped(r65),
                grouped(param("size, `ml-dsa`", "MlDsa44")),
                grouped(param("size, `ml-dsa`", "MlDsa65"))
            ),
        ),
        (
            "### Stack the feature needs",
            format!("minus the {} B stable frame", grouped(p65)),
        ),
        (
            "### Stack the feature needs",
            format!("cannot spare {} KB", p65 / 1000),
        ),
        (
            "### Stack the feature needs",
            format!(
                "about {} KB with the buffers",
                kilobytes(both_boards(hybrid_on))
            ),
        ),
        (
            "### ML-DSA verify results",
            format!("are {} / {} B", grouped(p44), grouped(p65)),
        ),
        (
            "### ML-DSA verify results",
            format!(
                "({} / {} B) within {case_gap} B",
                grouped(c44),
                grouped(c65)
            ),
        ),
        (
            "### ML-DSA verify method",
            format!("within {hybrid_gap} B of its feature-off size"),
        ),
    ] {
        assert!(
            normalized(section(&doc, heading)).contains(&phrase),
            "{heading} must quote `{phrase}`"
        );
    }
}

/// `12760` as the prose rounds it, `12.8` (KB of 1,000 B, one decimal).
fn kilobytes(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1000.0)
}

/// The two `rustc --version` strings recorded under `### Measurement toolchains`:
/// (stable, nightly).
fn recorded_toolchains(doc: &str) -> (String, String) {
    let text = normalized(section(doc, "### Measurement toolchains"));
    let spans: Vec<&str> = text
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|s| s.starts_with("rustc 1."))
        .collect();
    let stable: Vec<&str> = spans
        .iter()
        .copied()
        .filter(|s| !s.contains("-nightly"))
        .collect();
    let nightly: Vec<&str> = spans
        .iter()
        .copied()
        .filter(|s| s.contains("-nightly"))
        .collect();
    assert!(
        stable.len() == 1 && nightly.len() == 1,
        "### Measurement toolchains must record one stable and one nightly `rustc 1.…` \
         string, found {spans:?}"
    );
    (stable[0].to_owned(), nightly[0].to_owned())
}

/// AC2 (CI): the compilers the figures were measured with are recorded once, and every
/// compiler named in the document is one of them.
#[test]
fn measurement_toolchains_are_recorded() {
    let doc = doc();
    let (stable, nightly) = recorded_toolchains(&doc);
    assert_eq!(stable, "rustc 1.91.1 (ed61e7d7e 2025-11-07)");
    assert_eq!(nightly, "rustc 1.101.0-nightly (c1070d693 2026-09-28)");
    assert!(
        section(&doc, "### Measurement toolchains").contains("nightly-2026-09-29"),
        "### Measurement toolchains must name the installable `nightly-2026-09-29`"
    );
    let text = normalized(&doc);
    for (at, _) in text.match_indices("rustc 1.") {
        let named = &text[at..];
        let end = named.find(')').map_or(named.len(), |e| e + 1);
        let named = &named[..end];
        assert!(
            named == stable || named == nightly,
            "docs/benchmarks.md names `{named}`, which is not a recorded toolchain"
        );
    }
    let version = stable.split(' ').nth(1).unwrap();
    for (at, _) in text.match_indices("Rust 1.") {
        let named = text[at + "Rust ".len()..]
            .split(|c: char| !(c.is_ascii_digit() || c == '.'))
            .next()
            .unwrap()
            .trim_end_matches('.');
        assert_eq!(
            named, version,
            "docs/benchmarks.md names stable Rust {named}; the recorded stable is {version}"
        );
    }
}

/// Whether `text` contains the number `n` (as written, `1,488`) not as part of a longer
/// number.
fn contains_number(text: &str, n: &str) -> bool {
    text.match_indices(n).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + n.len()..].chars().next();
        !before.is_some_and(|c| c.is_ascii_digit() || c == ',' || c == '.')
            && !after.is_some_and(|c| {
                c.is_ascii_digit()
                    || (c == ','
                        && text[at + n.len() + 1..].starts_with(|d: char| d.is_ascii_digit()))
            })
    })
}

/// AC2 (CI): the figures SHA-275 replaced, the drift paragraph and the commit hashes that
/// dangle after a rebase are gone, and the figures no command rebuilds are labelled
/// historical.
#[test]
fn superseded_figures_are_gone() {
    let doc = doc();
    for text in ["Feature-off drift", "861abce", "2152d0c"] {
        assert!(
            !doc.contains(text),
            "docs/benchmarks.md still contains `{text}`"
        );
    }
    // 7,224, 48,412 and 14,772 were replaced too, but are current figures elsewhere
    // (rp2350 LMS Δ release, rp2350 LMS baseline, nrf52840 `size_digest` size).
    for n in [
        "1,488", "4,896", "12,752", "74,376", "74,264", "59,144", "59,152", "14,940", "89,316",
        "14,132", "73,276", "16,092", "90,356", "73,924", "7,295", "7,228", "5,348", "5,340",
        "47,272", "54,496", "47,260", "52,608", "55,640", "47,908", "53,248", "7,180", "5,328",
        "7,192", "5,332", "6,740", "5,136", "6,756", "5,144", "10,200", "9,964", "10,240",
        "10,004",
    ] {
        assert!(
            !contains_number(&doc, n),
            "docs/benchmarks.md still quotes the superseded figure {n}"
        );
    }

    let historical = normalized(section(&doc, "### Historical figures"));
    for needle in [
        "hbs-lms 0.1.1",
        "lms-signature 0.1.0-rc.2",
        "43 KB",
        "57 KB",
        "156,448 B",
        "pqm4",
    ] {
        assert!(
            historical.contains(needle),
            "### Historical figures must name `{needle}`"
        );
    }
    // Each passage quoting a historical figure says so.
    assert!(
        normalized(section(&doc, "### Crate choice")).contains("historical planning measurement"),
        "### Crate choice must label the hbs-lms / lms-signature columns historical"
    );
    for (heading, figure) in [
        ("### Hybrid results", "43 KB"),
        ("### ML-DSA verify method", "156,448 B"),
    ] {
        let passage = section(&doc, heading)
            .split("\n\n")
            .flat_map(|p| p.split("\n- "))
            .find(|p| normalized(p).contains(figure))
            .unwrap_or_else(|| panic!("{heading} no longer quotes {figure}"));
        assert!(
            passage.contains("historical"),
            "{heading}: the passage quoting {figure} must call it historical"
        );
    }
}

/// AC2: the drift reports name every mismatch (section, row or function, recorded and
/// measured value) and nothing else.
#[test]
fn drift_reports_name_every_mismatch() {
    let doc = "\n### LMS results\n\nFlash detail:\n\n\
        | Board / profile | `size_lms_baseline` flash | `size_lms` flash | Δ LMS/HSS |\n\
        |---|---|---|---|\n\
        | nrf52840 / release | 47,276 | 54,492 | 7,216 |\n\
        \n### Static frame detail\n\n\
        | Bin | Build | Function | nrf52840 | rp2350 |\n\
        |---|---|---|---|---|\n\
        | `size_lms` | release | `keelsign_verify::lms::walk` | 144 | 144 |\n\
        | `size_lms` | release | `sha2::sha256::compress256` | 176 | 176 |\n\
        | `size_lms` | release | (largest other frame) | 640 | 640 |\n\
        | `size_verify` | release, `ml-dsa`, stable prologue | `verify_param` ML-DSA-44 (`cmp.w r1, #0x520`) | 97,544 | 97,544 |\n";
    let section_of = |heading: &str| section(doc, heading).to_owned();

    // Flash: one table, two cells.
    let table = table_with_header(&section_of("### LMS results"), "| Board / profile |").unwrap();
    let cells: Vec<FlashCell> = [(1, "size_lms_baseline"), (2, "size_lms")]
        .map(|(i, bin)| FlashCell {
            section: "### LMS results".into(),
            row: table[1][0].clone(),
            bin: bin.into(),
            ml_dsa: false,
            bytes: parse_count(&table[1][i]).unwrap(),
        })
        .to_vec();
    let key = |bin: &str| {
        (
            "nrf52840".to_owned(),
            "release".to_owned(),
            false,
            bin.to_owned(),
        )
    };
    let mut measured = BTreeMap::from([
        (key("size_lms_baseline"), 47_276),
        (key("size_lms"), 54_492),
    ]);
    assert_eq!(compare_flash(&cells, &measured), Vec::<String>::new());
    measured.insert(key("size_lms"), 54_500);
    assert_eq!(
        compare_flash(&cells, &measured),
        [
            "### LMS results: row `nrf52840 / release`, column `size_lms` flash: doc 54492, measured 54500"
        ]
    );
    measured.remove(&key("size_lms_baseline"));
    assert_eq!(
        compare_flash(&cells, &measured).len(),
        2,
        "a missing ELF is reported"
    );

    // Frames: two named rows and the largest other frame, on both boards.
    let rows = frame_rows(doc);
    assert_eq!(rows.len(), 4);
    assert!(rows[3].stable_prologue && rows[3].frames == [97_544, 97_544]);
    let frames = |walk: u64, extra: Vec<(u64, String)>| {
        let mut list = vec![
            (walk, "keelsign_verify::lms::walk".to_owned()),
            (176, "sha2::sha256::compress256".to_owned()),
            (640, "keelsign_verify::lms::lms_verify".to_owned()),
            (32, "_defmt_acquire".to_owned()),
        ];
        list.extend(extra);
        list
    };
    let measured_frames = |nrf: Vec<(u64, String)>, rp: Vec<(u64, String)>| {
        BTreeMap::from([
            (
                (
                    "nrf52840".to_owned(),
                    "size_lms".to_owned(),
                    "release".to_owned(),
                    false,
                ),
                nrf,
            ),
            (
                (
                    "rp2350".to_owned(),
                    "size_lms".to_owned(),
                    "release".to_owned(),
                    false,
                ),
                rp,
            ),
        ])
    };
    let same = measured_frames(frames(144, vec![]), frames(144, vec![]));
    assert_eq!(compare_frames(&rows, &same), Vec::<String>::new());
    let one_off = measured_frames(frames(144, vec![]), frames(152, vec![]));
    assert_eq!(
        compare_frames(&rows, &one_off),
        [
            "### Static frame detail: `size_lms` release, `keelsign_verify::lms::walk`, rp2350: doc 144, measured 152"
        ]
    );
    // A bigger unnamed frame changes the largest other frame.
    let bigger = measured_frames(
        frames(144, vec![(700, "size_lms::__cortex_m_rt_main".to_owned())]),
        frames(144, vec![]),
    );
    assert_eq!(
        compare_frames(&rows, &bigger),
        [
            "### Static frame detail: `size_lms` release, `(largest other frame)`, nrf52840: doc 640, measured 700"
        ]
    );
    // A function cell matching zero or two functions is an error, not a figure.
    let none = measured_frames(
        frames(144, vec![])
            .into_iter()
            .filter(|(_, n)| !n.contains("walk"))
            .collect(),
        frames(144, vec![]),
    );
    let report = compare_frames(&rows, &none);
    assert_eq!(report.len(), 1, "{report:?}");
    assert!(
        report[0].contains("`keelsign_verify::lms::walk`, nrf52840: matches no function"),
        "{report:?}"
    );
    let two = measured_frames(
        frames(
            144,
            vec![(96, "keelsign_verify::lms::walk_inner".to_owned())],
        ),
        frames(144, vec![]),
    );
    let report = compare_frames(&rows, &two);
    assert_eq!(report.len(), 1, "{report:?}");
    assert!(
        report[0].contains("nrf52840: matches 2 functions, lengthen it"),
        "{report:?}"
    );

    // Stable prologues: objdump listings in, one line per altered figure or bad listing.
    let listing = |cmp: &str, sub: &str| {
        format!(
            "0000784c <_ZN15keelsign_verify5mldsa12verify_param17h1216eb02e5073f09E>:\n\
             \x20   784c:      \tpush\t{{r4, r5, r6, r7, lr}}\n\
             \x20   7850:      \tpush.w\t{{r8, r9, r10, r11}}\n\
             \x20   7854:      \tsub.w\tsp, sp, #0x17c00\n\
             \x20   7858:      \tsub\tsp, #{sub}\n\
             \x20   785a:      \t{cmp}\n\n"
        )
    };
    let good = listing("cmp.w\tr1, #0x520", "0xe4");
    let mut measured = BTreeMap::new();
    let mut report = Vec::new();
    for board in BOARDS {
        collect_prologues(board, &good, &mut measured, &mut report);
    }
    assert_eq!(report, Vec::<String>::new());
    assert_eq!(compare_prologues(&rows, &measured), Vec::<String>::new());
    let mut altered = BTreeMap::new();
    collect_prologues("nrf52840", &good, &mut altered, &mut report);
    collect_prologues(
        "rp2350",
        &listing("cmp.w\tr1, #0x520", "0xe8"),
        &mut altered,
        &mut report,
    );
    assert_eq!(
        compare_prologues(&rows, &altered),
        [
            "### Static frame detail: `size_verify` release, `ml-dsa`, stable prologue, \
          `verify_param` ML-DSA-44 (`cmp.w r1, #0x520`), rp2350: doc 97544, measured 97548"
        ]
    );
    // No key-length compare, or two instances of one set: error lines.
    let mut report = Vec::new();
    collect_prologues(
        "nrf52840",
        &listing("mov\tr4, r0", "0xe4"),
        &mut BTreeMap::new(),
        &mut report,
    );
    assert_eq!(report.len(), 1, "{report:?}");
    assert!(
        report[0].contains("has no key-length compare"),
        "{report:?}"
    );
    let mut report = Vec::new();
    collect_prologues(
        "nrf52840",
        &format!("{good}{good}"),
        &mut BTreeMap::new(),
        &mut report,
    );
    assert_eq!(
        report,
        ["nrf52840: two `verify_param` instances for ML-DSA-44"]
    );
}

// ---- SHA-275: ignored drift checks (rebuild and compare exactly) -----------------------

fn bench_dir(bench: &Example) -> PathBuf {
    workspace_root().join("benches").join(bench.name)
}

fn board_of(bench: &Example) -> &'static str {
    bench.name.split('-').next().unwrap_or(bench.name)
}

/// The rustup proxy for `tool` (`$CARGO_HOME/bin/<tool>`), not the toolchain binary that
/// `$CARGO` names inside `cargo test`: only the proxy honours `RUSTUP_TOOLCHAIN` and the
/// bench projects' `rust-toolchain.toml`.
fn rustup_proxy(tool: &str) -> PathBuf {
    std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo")))
        .map(|home| home.join("bin").join(tool))
        .filter(|p| p.is_file())
        .unwrap_or_else(|| PathBuf::from(tool))
}

/// `tool` run through the rustup proxy in `benches/<name>`, with the outer environment's
/// toolchain, target dir, compiler flags and profile overrides removed (the documented
/// commands assume none, and their target dirs are relative to the bench project) and
/// `toolchain` selected if given (otherwise the bench's toolchain file applies).
fn bench_tool(bench: &Example, tool: &str, toolchain: Option<&str>) -> Command {
    let mut cmd = Command::new(rustup_proxy(tool));
    cmd.current_dir(bench_dir(bench));
    for var in [
        "RUSTUP_TOOLCHAIN",
        "CARGO_TARGET_DIR",
        "CARGO_BUILD_TARGET_DIR",
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
    ] {
        cmd.env_remove(var);
    }
    for (var, _) in std::env::vars_os() {
        if var.to_string_lossy().starts_with("CARGO_PROFILE_") {
            cmd.env_remove(var);
        }
    }
    if let Some(toolchain) = toolchain {
        cmd.env("RUSTUP_TOOLCHAIN", toolchain);
    }
    cmd
}

fn bench_cargo(bench: &Example, toolchain: Option<&str>) -> Command {
    bench_tool(bench, "cargo", toolchain)
}

/// `KEELSIGN_BENCH_STABLE`, else the bench projects' toolchain file.
fn stable_toolchain() -> Option<String> {
    std::env::var("KEELSIGN_BENCH_STABLE")
        .ok()
        .filter(|t| !t.is_empty())
}

/// `KEELSIGN_BENCH_NIGHTLY`, else `nightly` (the documented `cargo +nightly`).
fn nightly_toolchain() -> String {
    std::env::var("KEELSIGN_BENCH_NIGHTLY")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "nightly".to_owned())
}

/// Fails unless the compiler `bench` builds with is the recorded one.
fn assert_recorded_rustc(bench: &Example, toolchain: Option<&str>, recorded: &str, variable: &str) {
    let active = run_ok(bench_tool(bench, "rustc", toolchain).arg("--version"));
    let active = active.trim();
    assert!(
        active == recorded,
        "{}: the active compiler is `{active}` but docs/benchmarks.md recorded `{recorded}`. \
         Re-measure every table and update the recorded toolchains, or select the recorded \
         toolchain with {variable} (docs/benchmarks.md#checking-the-recorded-figures)",
        bench.name
    );
}

fn fail_on_drift(what: &str, report: &[String]) {
    assert!(
        report.is_empty(),
        "docs/benchmarks.md {what} differ from a fresh build ({} mismatches); re-run the \
         documented commands and update every listed table \
         (docs/benchmarks.md#checking-the-recorded-figures):\n{}",
        report.len(),
        report.join("\n")
    );
}

/// AC1/AC2: every cell of every "Flash detail" table is what the documented builds give
/// today, and each table's static RAM delta is 0.
#[test]
#[ignore = "builds both bench projects with the recorded stable rustc (thumb targets, flip-link, python3); docs/benchmarks.md#checking-the-recorded-figures"]
fn recorded_flash_tables_match_a_fresh_build() {
    let doc = doc();
    let cells = flash_detail_cells(&doc);
    assert!(
        !cells.is_empty(),
        "docs/benchmarks.md has no flash detail cells"
    );
    let (stable, _) = recorded_toolchains(&doc);
    let toolchain = stable_toolchain();
    let mut flash = BTreeMap::new();
    let mut ram = BTreeMap::new();
    for bench in &BENCHES {
        let _guard = bench_target_lock(bench);
        assert_recorded_rustc(
            bench,
            toolchain.as_deref(),
            &stable,
            "KEELSIGN_BENCH_STABLE",
        );
        let board = board_of(bench);
        for ml_dsa in [false, true] {
            let feature: &[&str] = if ml_dsa {
                &["--features", "ml-dsa", "--target-dir", "target/mldsa"]
            } else {
                &["--target-dir", "target"]
            };
            for profile in ["release", "size"] {
                let profile_args: &[&str] = if profile == "release" {
                    &["--release"]
                } else {
                    &["--profile", "size"]
                };
                run_ok(
                    bench_cargo(bench, toolchain.as_deref())
                        .arg("build")
                        .args(profile_args)
                        .args(["--locked", "--bins"])
                        .args(feature),
                );
                let bins: BTreeSet<&str> = cells
                    .iter()
                    .filter(|c| c.ml_dsa == ml_dsa && c.board() == board && c.profile() == profile)
                    .map(|c| c.bin.as_str())
                    .collect();
                if bins.is_empty() {
                    continue;
                }
                let dir = bench_dir(bench)
                    .join(if ml_dsa { "target/mldsa" } else { "target" })
                    .join(bench.target)
                    .join(profile);
                let elves: Vec<PathBuf> = bins.iter().map(|bin| dir.join(bin)).collect();
                let sizes = run_ok(python_script("elf_sizes.py").args(&elves));
                let rows = table_rows(&sizes);
                assert_eq!(rows.len(), bins.len(), "elf_sizes.py output:\n{sizes}");
                for (bin, row) in bins.iter().zip(&rows) {
                    // | label | elf | .text | .rodata | .data | .bss | flash | static RAM |
                    assert_eq!(row[1], *bin, "elf_sizes.py row order:\n{sizes}");
                    let key = (
                        board.to_owned(),
                        profile.to_owned(),
                        ml_dsa,
                        (*bin).to_owned(),
                    );
                    let value = |i: usize| -> u64 {
                        row[i]
                            .parse()
                            .unwrap_or_else(|_| panic!("elf_sizes.py row {row:?}"))
                    };
                    flash.insert(key.clone(), value(6));
                    ram.insert(key, value(7));
                }
            }
        }
    }
    let mut report = compare_flash(&cells, &flash);
    // Static RAM delta 0: every bin of a detail row has the static RAM of the row's
    // baseline (its first flash column).
    let mut baseline: BTreeMap<(&str, &str), (&FlashCell, u64)> = BTreeMap::new();
    for cell in &cells {
        let Some(&r) = ram.get(&cell.key()) else {
            continue;
        };
        match baseline.get(&(cell.section.as_str(), cell.row.as_str())) {
            None => {
                baseline.insert((&cell.section, &cell.row), (cell, r));
            }
            Some(&(base, base_ram)) if base_ram != r => report.push(format!(
                "{}: row `{}`: static RAM of `{}` is {r}, of baseline `{}` {base_ram}; the doc \
                 says the static RAM delta is 0",
                cell.section, cell.row, cell.bin, base.bin
            )),
            Some(_) => {}
        }
    }
    fail_on_drift("flash figures", &report);
}

/// Own-frame sizes and demangled names from `stack_frames.py ELF --top N --match …`: the
/// top-N list, before the `# functions matching` part.
fn parse_frames(output: &str) -> Vec<(u64, String)> {
    output
        .lines()
        .skip(1)
        .take_while(|l| !l.starts_with("# functions matching"))
        .filter_map(|l| {
            let (size, name) = l.trim_start().split_once(' ')?;
            Some((size.parse().ok()?, name.trim_start().to_owned()))
        })
        .collect()
}

/// AC1/AC2: every nightly row of `### Static frame detail` is what the documented
/// `-Z emit-stack-sizes` builds give today, on both boards.
#[test]
#[ignore = "needs the recorded nightly (nightly-2026-09-29) with both thumb targets"]
fn recorded_static_frames_match_a_fresh_nightly_build() {
    let doc = doc();
    let rows = frame_rows(&doc);
    assert!(
        rows.iter().any(|r| !r.stable_prologue),
        "{FRAME_DETAIL} has no nightly rows"
    );
    let (_, nightly) = recorded_toolchains(&doc);
    let toolchain = nightly_toolchain();
    let builds: BTreeSet<(&str, &str, bool)> = rows
        .iter()
        .filter(|r| !r.stable_prologue)
        .map(|r| (r.bin.as_str(), r.profile.as_str(), r.ml_dsa))
        .collect();
    let mut measured = BTreeMap::new();
    for bench in &BENCHES {
        assert_recorded_rustc(bench, Some(&toolchain), &nightly, "KEELSIGN_BENCH_NIGHTLY");
        for &(bin, profile, ml_dsa) in &builds {
            let target_dir = if ml_dsa {
                "target/nightly-mldsa"
            } else {
                "target/nightly"
            };
            let mut cmd = bench_cargo(bench, Some(&toolchain));
            cmd.arg("rustc");
            if profile == "release" {
                cmd.arg("--release");
            } else {
                cmd.args(["--profile", profile]);
            }
            cmd.arg("--locked");
            if ml_dsa {
                cmd.args(["--features", "ml-dsa"]);
            }
            cmd.args(["--bin", bin, "--target-dir", target_dir]).args([
                "--",
                "-Z",
                "emit-stack-sizes",
            ]);
            run_ok(&mut cmd);
            let elf = bench_dir(bench)
                .join(target_dir)
                .join(bench.target)
                .join(profile)
                .join(bin);
            let output = run_ok(
                python_script("stack_frames.py")
                    .arg(&elf)
                    .args(["--top", "100000", "--match", bin]),
            );
            measured.insert(
                (
                    board_of(bench).to_owned(),
                    bin.to_owned(),
                    profile.to_owned(),
                    ml_dsa,
                ),
                parse_frames(&output),
            );
        }
    }
    fail_on_drift("static frames", &compare_frames(&rows, &measured));
}

/// The stack each `keelsign_verify::mldsa::verify_param` instance in an `objdump -d
/// --no-show-raw-insn` listing reserves in its prologue (4 B per pushed register plus
/// every `sub sp` immediate), keyed by the set its key-length compare names
/// (`cmp.w r1, #0x520` = ML-DSA-44, `#0x7a0` = ML-DSA-65).
fn mldsa_prologues(disassembly: &str) -> Result<Vec<(&'static str, u64)>, String> {
    let mut found = Vec::new();
    let mut lines = disassembly.lines();
    while let Some(line) = lines.next() {
        if !(line.ends_with(">:") && line.contains("5mldsa12verify_param")) {
            continue;
        }
        let (mut frame, mut set) = (0u64, None);
        for insn in lines.by_ref().take(12) {
            let Some((_, text)) = insn.split_once(':') else {
                break;
            };
            let text = text.trim();
            let mnemonic = text.split_whitespace().next().unwrap_or_default();
            let operands = text[mnemonic.len()..].trim();
            let immediate = || -> Result<u64, String> {
                let imm = operands
                    .rsplit_once('#')
                    .map(|(_, imm)| imm.trim())
                    .ok_or_else(|| format!("no immediate in `{text}`"))?;
                match imm.strip_prefix("0x") {
                    Some(hex) => u64::from_str_radix(hex, 16),
                    None => imm.parse(),
                }
                .map_err(|e| format!("`{text}`: {e}"))
            };
            match mnemonic {
                "push" | "push.w" => {
                    if operands.contains('-') {
                        return Err(format!("register range in `{text}`"));
                    }
                    frame += 4 * operands.split(',').count() as u64;
                }
                "sub" | "sub.w" | "subw" if operands.starts_with("sp,") => frame += immediate()?,
                "cmp" | "cmp.w" => {
                    set = match immediate()? {
                        0x520 => Some("ML-DSA-44"),
                        0x7a0 => Some("ML-DSA-65"),
                        _ => None,
                    };
                    break;
                }
                _ => {}
            }
        }
        let set = set.ok_or_else(|| format!("{line} has no key-length compare in its prologue"))?;
        found.push((set, frame));
    }
    Ok(found)
}

/// Adds the `verify_param` prologues of `board`'s `objdump` listing to `measured`
/// ((board, set) → frame); a listing it cannot read or two instances of one set become
/// report lines.
fn collect_prologues(
    board: &str,
    listing: &str,
    measured: &mut BTreeMap<(String, String), u64>,
    report: &mut Vec<String>,
) {
    match mldsa_prologues(listing) {
        Ok(prologues) => {
            for (set, frame) in prologues {
                if measured
                    .insert((board.to_owned(), set.to_owned()), frame)
                    .is_some()
                {
                    report.push(format!("{board}: two `verify_param` instances for {set}"));
                }
            }
        }
        Err(e) => report.push(format!("{board}: {e}")),
    }
}

/// One line per stable-prologue row that differs from `measured` ((board, set) → frame).
fn compare_prologues(rows: &[FrameRow], measured: &BTreeMap<(String, String), u64>) -> Vec<String> {
    let mut report = Vec::new();
    for row in rows.iter().filter(|r| r.stable_prologue) {
        let Some(set) = SETS.iter().find(|s| row.function.contains(*s)) else {
            report.push(format!(
                "{FRAME_DETAIL}: `{}` names no ML-DSA set",
                row.function
            ));
            continue;
        };
        for (b, board) in BOARDS.iter().enumerate() {
            let at = format!(
                "{FRAME_DETAIL}: `{}` {}, {}, {board}",
                row.bin, row.build, row.function
            );
            match measured.get(&((*board).to_owned(), (*set).to_owned())) {
                Some(&m) if m == row.frames[b] => {}
                Some(&m) => report.push(format!("{at}: doc {}, measured {m}", row.frames[b])),
                None => report.push(format!("{at}: doc {}, not found by objdump", row.frames[b])),
            }
        }
    }
    report
}

/// AC1/AC2: the stable release prologues of both `verify_param` instances, the figures
/// "Stack the feature needs" tells integrators to budget with, are what the documented
/// `objdump` command shows today.
#[test]
#[ignore = "needs LLVM objdump (macOS /usr/bin/objdump, or OBJDUMP=llvm-objdump)"]
fn recorded_stable_mldsa_prologues_match_objdump() {
    let doc = doc();
    let rows = frame_rows(&doc);
    assert!(
        rows.iter().any(|r| r.stable_prologue),
        "{FRAME_DETAIL} has no stable-prologue rows"
    );
    let (stable, _) = recorded_toolchains(&doc);
    let toolchain = stable_toolchain();
    let objdump = std::env::var("OBJDUMP").unwrap_or_else(|_| "objdump".to_owned());
    let mut measured = BTreeMap::new();
    let mut report = Vec::new();
    for bench in &BENCHES {
        let _guard = bench_target_lock(bench);
        assert_recorded_rustc(
            bench,
            toolchain.as_deref(),
            &stable,
            "KEELSIGN_BENCH_STABLE",
        );
        run_ok(bench_cargo(bench, toolchain.as_deref()).args([
            "build",
            "--release",
            "--locked",
            "--bins",
            "--features",
            "ml-dsa",
            "--target-dir",
            "target/mldsa",
        ]));
        let elf = bench_dir(bench)
            .join("target/mldsa")
            .join(bench.target)
            .join("release/size_verify");
        let (ok, listing, stderr) = run_capture(
            Command::new(&objdump)
                .args(["-d", "--no-show-raw-insn"])
                .arg(&elf),
        );
        assert!(
            ok,
            "`{objdump} -d` failed on {} (needs LLVM objdump; set OBJDUMP=llvm-objdump):\n{stderr}",
            elf.display()
        );
        collect_prologues(board_of(bench), &listing, &mut measured, &mut report);
    }
    report.extend(compare_prologues(&rows, &measured));
    fail_on_drift("stable ML-DSA prologues", &report);
}

// ---- SHA-60: C static library sizes -----------------------------------------------------

const FFI_SECTION: &str = "## C static library (SHA-60)";
const FFI_HEADER: &str = "| Target | Features | `.text` | `.rodata` | Total |";
const FFI_TARGETS: [&str; 2] = ["thumbv7em-none-eabihf", "thumbv8m.main-none-eabihf"];
/// The feature states, as `--features` takes them and as the table labels them.
const FFI_FEATURES: [(&str, &str); 4] = [
    ("", "(none)"),
    ("ed25519", "`ed25519`"),
    ("ml-dsa", "`ml-dsa`"),
    ("ed25519,ml-dsa", "`ed25519,ml-dsa`"),
];

/// The rows of the C static library table, as written.
fn ffi_rows(doc: &str) -> Vec<String> {
    let text = section(doc, FFI_SECTION);
    let start = text
        .find(&format!("{FFI_HEADER}\n|---|---|---|---|---|\n"))
        .unwrap_or_else(|| panic!("{FFI_SECTION} has no `{FFI_HEADER}` table"));
    text[start..]
        .lines()
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(str::to_owned)
        .collect()
}

/// AC3: docs/benchmarks.md records `libkeelsign.a` for both Cortex-M targets in the four
/// feature states, each total the sum of its `.text` and `.rodata`, with the script and
/// the reproduce commands named.
#[test]
fn ffi_size_table_is_well_formed() {
    let doc = doc();
    let rows = ffi_rows(&doc);
    assert_eq!(
        rows.len(),
        8,
        "{FFI_SECTION}: one row per target and feature state"
    );
    let mut i = 0;
    for target in FFI_TARGETS {
        let mut totals = Vec::new();
        for (_, label) in FFI_FEATURES {
            let cells: Vec<&str> = rows[i]
                .trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect();
            assert_eq!(cells.len(), 5, "row `{}`", rows[i]);
            assert_eq!(cells[0], format!("`{target}`"), "row {i} target");
            assert_eq!(cells[1], label, "row {i} features");
            let text = parse_bytes(cells[2]).unwrap_or_else(|| panic!("row {i}: `{}`", cells[2]));
            let rodata = parse_bytes(cells[3]).unwrap_or_else(|| panic!("row {i}: `{}`", cells[3]));
            let total = parse_bytes(cells[4]).unwrap_or_else(|| panic!("row {i}: `{}`", cells[4]));
            assert_eq!(
                text + rodata,
                total,
                "row `{}`: total is .text + .rodata",
                rows[i]
            );
            for cell in &cells[2..] {
                let digits = cell.trim_end_matches(" B");
                assert_eq!(
                    digits,
                    grouped(parse_bytes(cell).unwrap()),
                    "row {i}: `{cell}` is written with thousands separators"
                );
            }
            totals.push(total);
            i += 1;
        }
        // Each feature adds code: none < each single feature < both.
        assert!(
            totals[0] < totals[1] && totals[0] < totals[2],
            "{target}: {totals:?}"
        );
        assert!(
            totals[1] < totals[3] && totals[2] < totals[3],
            "{target}: {totals:?}"
        );
    }
    let text = normalized(section(&doc, FFI_SECTION));
    for needle in [
        "scripts/staticlib_sizes.py",
        "[profile.ffi]",
        "stable Rust 1.91.1",
        "keelsign-*",
        "cargo build -p keelsign-ffi --profile ffi --locked --target thumbv7em-none-eabihf --target-dir target/ffi-sizes/none",
        "python3 scripts/staticlib_sizes.py --check --features ed25519,ml-dsa target/ffi-sizes/ed25519-ml-dsa/thumbv7em-none-eabihf/ffi/libkeelsign.a",
    ] {
        assert!(
            text.contains(needle),
            "{FFI_SECTION} must mention `{needle}`"
        );
    }
    assert!(
        normalized(section(&doc, "### Checking the recorded figures"))
            .contains("recorded_ffi_library_sizes_match_a_fresh_build"),
        "### Checking the recorded figures must name the SHA-60 drift check"
    );
}

/// AC3: every row of the C static library table is what the documented build and
/// `staticlib_sizes.py` give today with the recorded stable compiler.
#[test]
#[ignore = "builds libkeelsign.a for both thumb targets in four feature states with the recorded stable rustc (python3); docs/benchmarks.md#checking-the-recorded-figures"]
fn recorded_ffi_library_sizes_match_a_fresh_build() {
    let doc = doc();
    let rows = ffi_rows(&doc);
    let (stable, _) = recorded_toolchains(&doc);
    let toolchain = stable_toolchain();
    let root = workspace_root();
    let tool = |name: &str| {
        let mut cmd = Command::new(rustup_proxy(name));
        cmd.current_dir(&root);
        for var in [
            "RUSTUP_TOOLCHAIN",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET_DIR",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
        ] {
            cmd.env_remove(var);
        }
        for (var, _) in std::env::vars_os() {
            if var.to_string_lossy().starts_with("CARGO_PROFILE_") {
                cmd.env_remove(var);
            }
        }
        if let Some(t) = &toolchain {
            cmd.env("RUSTUP_TOOLCHAIN", t);
        }
        cmd
    };
    let active = run_ok(tool("rustc").arg("--version"));
    assert!(
        active.trim() == stable,
        "the active compiler is `{}` but docs/benchmarks.md recorded `{stable}`; select it \
         with KEELSIGN_BENCH_STABLE (docs/benchmarks.md#checking-the-recorded-figures)",
        active.trim()
    );
    let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("ffi-sizes");
    let mut report = Vec::new();
    let mut i = 0;
    for target in FFI_TARGETS {
        for (features, _) in FFI_FEATURES {
            let dir_name = if features.is_empty() {
                "none".to_owned()
            } else {
                features.replace(',', "-")
            };
            let target_dir = base.join(&dir_name);
            let mut build = tool("cargo");
            build
                .args([
                    "build",
                    "-p",
                    "keelsign-ffi",
                    "--profile",
                    "ffi",
                    "--locked",
                ])
                .args(["--target", target])
                .arg("--target-dir")
                .arg(&target_dir);
            if !features.is_empty() {
                build.args(["--features", features]);
            }
            run_ok(&mut build);
            let archive = target_dir.join(target).join("ffi").join("libkeelsign.a");
            let mut script = python_script("staticlib_sizes.py");
            script.arg("--check");
            if !features.is_empty() {
                script.args(["--features", features]);
            }
            let measured = run_ok(script.arg(&archive));
            let measured = measured.trim();
            if measured != rows[i] {
                report.push(format!(
                    "{FFI_SECTION}: {target} features `{features}`: recorded `{}`, measured `{measured}`",
                    rows[i]
                ));
            }
            i += 1;
        }
    }
    fail_on_drift("C static library sizes", &report);
}

// ---- SHA-47: RAM/flash budget -------------------------------------------------------------

const BUDGET_SECTION: &str = "## RAM/flash budget (SHA-47)";

/// The index of column `name` in a table's header row (element 0 of `table_with_header`).
fn column_index(table: &[Vec<String>], name: &str) -> usize {
    table[0]
        .iter()
        .position(|c| c == name)
        .unwrap_or_else(|| panic!("no column `{name}` in {:?}", table[0]))
}

/// The body row of `table` whose first cells are `key`.
fn row_with_key<'a>(table: &'a [Vec<String>], key: &[&str]) -> &'a [String] {
    table[1..]
        .iter()
        .find(|r| key.iter().zip(r.iter()).all(|(k, c)| k == c))
        .unwrap_or_else(|| panic!("no row {key:?} in {:?}", table[0]))
}

/// One budget-table column's source: the source column and, for an `a / b` cell, which
/// half.
type ColumnSource = (&'static str, &'static str, Option<usize>);

/// One budget-table verify path: its name, the source heading, the source table's header
/// prefix, the source row key after the board (the set, if any) and its columns.
type BudgetPath = (
    &'static str,
    &'static str,
    &'static str,
    Option<&'static str>,
    &'static [ColumnSource],
);

/// SHA-47 AC3 (CI): the RAM/flash budget only copies figures already recorded. Every cell
/// of its per-path table equals the cell of the source table its Source column links (the
/// pending hardware cells included, so filling one in the source fills it here), every row
/// of its library table equals the C static library table, and every byte figure in the
/// section's prose is quoted elsewhere in the document.
#[test]
fn budget_table_matches_source_tables() {
    let doc = doc();
    let budget_at = doc
        .find(&format!("\n{BUDGET_SECTION}\n"))
        .expect("budget section");
    let recorded_at = doc
        .find("\n## Recorded figures (SHA-275)\n")
        .expect("recorded figures section");
    assert!(
        budget_at < recorded_at,
        "{BUDGET_SECTION} must come before ## Recorded figures (SHA-275)"
    );
    let budget = section(&doc, BUDGET_SECTION);
    let table = table_with_header(budget, "| Board | Verify path |")
        .unwrap_or_else(|| panic!("{BUDGET_SECTION} has no `| Board | Verify path |` table"));
    assert_eq!(
        table[0],
        [
            "Board",
            "Verify path",
            "Flash Δ release",
            "Flash Δ size",
            "Static frame (compiled)",
            "Peak stack (measured)",
            "Cycles",
            "Source",
        ],
        "{BUDGET_SECTION}: table columns"
    );

    const DIGEST_COLUMNS: [ColumnSource; 5] = [
        ("Flash Δ release", "Flash Δ release", None),
        ("Flash Δ size", "Flash Δ size", None),
        ("Static frame (compiled)", "Static frame (compiled)", None),
        ("Peak stack (measured)", "Peak stack (measured)", None),
        ("Cycles", "Digest cycles (200 KB, 256 B chunk)", None),
    ];
    const LMS_COLUMNS: [ColumnSource; 5] = [
        ("Flash Δ release", "Flash Δ release", None),
        ("Flash Δ size", "Flash Δ size", None),
        ("Static frame (compiled)", "Static frame (compiled)", None),
        ("Peak stack (measured)", "Peak stack (measured)", None),
        ("Cycles", "Verify cycles (headline)", None),
    ];
    const HYBRID_COLUMNS: [ColumnSource; 5] = [
        ("Flash Δ release", "Flash Δ release", None),
        ("Flash Δ size", "Flash Δ size", None),
        (
            "Static frame (compiled)",
            "Static frame (compiled, deepest chain)",
            None,
        ),
        ("Peak stack (measured)", "Peak stack", None),
        ("Cycles", "Cycles", None),
    ];
    const MLDSA_COLUMNS: [ColumnSource; 5] = [
        (
            "Flash Δ release",
            "Flash Δ ml-dsa (release / size)",
            Some(0),
        ),
        ("Flash Δ size", "Flash Δ ml-dsa (release / size)", Some(1)),
        ("Static frame (compiled)", "Static frame release", None),
        ("Peak stack (measured)", "Peak stack (measured)", None),
        ("Cycles", "Cycles", None),
    ];
    let paths: [BudgetPath; 6] = [
        (
            "Image digest (200 KB, 256 B chunk)",
            "### Digest results",
            "| Board | Digest cycles",
            None,
            &DIGEST_COLUMNS,
        ),
        (
            "LMS SHA-256 M32/W8",
            "### LMS results",
            "| Board | Set |",
            Some("LMS SHA-256 M32/W8"),
            &LMS_COLUMNS,
        ),
        (
            "LMS SHA-256/192 M24/W8",
            "### LMS results",
            "| Board | Set |",
            Some("LMS SHA-256/192 M24/W8"),
            &LMS_COLUMNS,
        ),
        (
            "Hybrid Ed25519 + LMS",
            "### Hybrid results",
            "| Board | Flash Δ release |",
            None,
            &HYBRID_COLUMNS,
        ),
        (
            "ML-DSA-44",
            "### ML-DSA verify results",
            "| Board | Set |",
            Some("ML-DSA-44"),
            &MLDSA_COLUMNS,
        ),
        (
            "ML-DSA-65",
            "### ML-DSA verify results",
            "| Board | Set |",
            Some("ML-DSA-65"),
            &MLDSA_COLUMNS,
        ),
    ];
    assert_eq!(
        table.len() - 1,
        BOARDS.len() * paths.len(),
        "{BUDGET_SECTION}: one row per board × verify path"
    );
    for board in BOARDS {
        for (path, heading, header, set, columns) in paths {
            let row = row_with_key(&table, &[board, path]);
            let source = table_with_header(section(&doc, heading), header)
                .unwrap_or_else(|| panic!("{heading} has no `{header}` table"));
            let mut key = vec![board];
            key.extend(set);
            let source_row = row_with_key(&source, &key);
            for &(budget_column, source_column, part) in columns {
                let cell = &row[column_index(&table, budget_column)];
                let source_cell = &source_row[column_index(&source, source_column)];
                let expected = match part {
                    Some(at) => source_cell
                        .split(" / ")
                        .nth(at)
                        .unwrap_or_else(|| panic!("`{source_cell}` has no part {at}")),
                    None => source_cell.as_str(),
                };
                assert_eq!(
                    cell, expected,
                    "{BUDGET_SECTION}: {board} `{path}` {budget_column} must copy {heading} \
                     `{source_column}`"
                );
            }
            let anchor = heading
                .trim_start_matches('#')
                .trim()
                .to_lowercase()
                .replace(' ', "-")
                .replace(['(', ')', '/'], "");
            let link = format!("[{}](#{anchor})", heading.trim_start_matches('#').trim());
            assert_eq!(
                row[column_index(&table, "Source")],
                link,
                "{BUDGET_SECTION}: {board} `{path}` must link its source"
            );
        }
    }

    // The library sizes are the C static library table's totals.
    let library = table_with_header(budget, "| Target | Features | Total |")
        .unwrap_or_else(|| panic!("{BUDGET_SECTION} has no `| Target | Features | Total |` table"));
    let ffi = table_with_header(section(&doc, FFI_SECTION), FFI_HEADER)
        .unwrap_or_else(|| panic!("{FFI_SECTION} has no `{FFI_HEADER}` table"));
    assert_eq!(
        library.len() - 1,
        FFI_TARGETS.len() * FFI_FEATURES.len(),
        "{BUDGET_SECTION}: one library row per target × feature state"
    );
    for row in &library[1..] {
        let source = row_with_key(&ffi, &[&row[0], &row[1]]);
        assert_eq!(
            row[2],
            source[column_index(&ffi, "Total")],
            "{BUDGET_SECTION}: libkeelsign.a {} {} total must copy {FFI_SECTION}",
            row[0],
            row[1]
        );
    }

    // Every byte figure in the section is quoted elsewhere: nothing is re-derived.
    let elsewhere = format!(
        "{}{}",
        &doc[..budget_at],
        &doc[budget_at + 1 + BUDGET_SECTION.len() + budget.len()..]
    );
    let words: Vec<&str> = budget.split_whitespace().collect();
    for pair in words.windows(2) {
        let number = pair[0].trim_start_matches(['(', '|']);
        if pair[1].starts_with('B') && number.starts_with(|c: char| c.is_ascii_digit()) {
            assert!(
                contains_number(&elsewhere, number),
                "{BUDGET_SECTION} quotes {number} B, which no other section records"
            );
        }
    }
    assert!(
        budget.contains("hybrid_verify_bench") && budget.contains("on-target-tests.md"),
        "{BUDGET_SECTION} must name the hybrid measurement (SHA-69) and point at the suite's P2"
    );
    assert!(
        !doc.contains("pending (SHA-69)"),
        "docs/benchmarks.md: SHA-69 measures the hybrid verify; its cells are `{PENDING}`"
    );
}
