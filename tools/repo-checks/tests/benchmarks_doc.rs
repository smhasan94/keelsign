//! Checks that docs/benchmarks.md records the SHA-34 results, the reproduction commands
//! and the go/no-go decision, and that the benchmark log tooling works.

use repo_checks::{BENCHES, ScratchDir, python_script, run_capture, workspace_root};
use std::fs;

const REQUIRED_HEADINGS: [&str; 15] = [
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
        "bootutil_priv.h:86",
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
