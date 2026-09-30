//! On-target LMS/HSS verify KATs, benchmark and key-rotation check for the nRF52840-DK
//! (SHA-65).
//!
//! Synchronous embedded-test cases, no embassy executor. Run from this directory with
//! `cargo test --release --test lms` (docs/benchmarks.md). Every case is logged over
//! defmt; `lms_bench` logs one `BENCH …` line per case for `scripts/bench_summarize.py`.
#![no_std]
#![no_main]

// `not(clippy)`: `cargo clippy` checks the dev profile; the guard is for builds and runs.
#[cfg(all(debug_assertions, not(clippy)))]
compile_error!("run the on-target KATs and benchmarks with `cargo test --release`");

use core::hint::black_box;
use cortex_m::peripheral::DWT;
use defmt::info;
use defmt_rtt as _;
use lms_kat::{
    Case, Error, Expect, Fixture, KeyInfo, LMS_TARGET, TARGET_CASES, check_rotation, ids,
    result_name, run_fixture, verify_case,
};
use mldsa_kat::measure::Cycles;
use stack_paint::Watermark;

/// Board name in the `KAT` / `BENCH` log lines.
const BOARD: &str = "nrf52840";
/// Core clock after `embassy_nrf::init` (HFCLK, 64 MHz).
const CPU_HZ: u32 = 64_000_000;
/// Bytes left unpainted below the stack pointer inside `stack_paint::paint`, covering
/// that function's own frame.
const PAINT_MARGIN: u32 = 256;
/// Peak-stack limit for LMS/HSS verify (SHA-65, docs/benchmarks.md).
const STACK_LIMIT: u32 = 32_768;

/// State handed from `#[init]` to the tests.
pub struct Board {
    dwt_present: bool,
}

fn init_board() -> Board {
    // Core peripherals first: embassy_nrf::init does not take them.
    let dwt_present = match cortex_m::Peripherals::take() {
        Some(mut cp) => {
            cp.DCB.enable_trace();
            cp.DWT.enable_cycle_counter();
            DWT::has_cycle_counter()
        }
        None => false,
    };
    let _p = embassy_nrf::init(Default::default());
    Board { dwt_present }
}

/// Runs every case of the on-target fixture under both policies and logs each outcome.
fn kat() -> Result<(), &'static str> {
    let summary = run_fixture(LMS_TARGET, |case, outcome| {
        info!(
            "KAT board={=str} set=LMS src={=str} tc={=u16} expect_cnsa={=str} cnsa={=str} expect_rfc={=str} rfc={=str} result={=str}",
            BOARD,
            case.source.name(),
            case.id,
            result_name(outcome.expect_cnsa.result()),
            result_name(outcome.cnsa),
            result_name(outcome.expect_rfc_all_sets.result()),
            result_name(outcome.rfc_all_sets),
            if outcome.passed() { "ok" } else { "FAIL" }
        );
    })
    .map_err(|_| "fixture does not parse")?;
    info!(
        "KAT board={=str} set=LMS passed={=u32}/{=u32}",
        BOARD, summary.passed, summary.total
    );
    if summary.total != TARGET_CASES {
        return Err("fixture does not hold the expected number of cases");
    }
    if summary.all_passed() {
        Ok(())
    } else {
        Err("a KAT case did not match its expectation")
    }
}

/// The key-rotation check with the fixture's keys A and B.
fn rotation() -> Result<(), &'static str> {
    let fixture = Fixture::parse(LMS_TARGET).map_err(|_| "fixture does not parse")?;
    let a = fixture.case(ids::ROTATION_A).ok_or("no rotation key A")?;
    let b = fixture.case(ids::ROTATION_B).ok_or("no rotation key B")?;
    check_rotation(&a, &b)?;
    info!(
        "ROTATION board={=str} {{A,B}} accepts B and A, {{A}} rejects B: ok",
        BOARD
    );
    Ok(())
}

/// Paints the stack, then times one `verify_pq` and measures its stack high-water mark.
#[inline(never)]
fn measure_case(case: &Case<'_>) -> (Result<(), Error>, u32, Watermark) {
    let sp0 = cortex_m::register::msp::read();
    stack_paint::paint(PAINT_MARGIN);
    let timer = Cycles::start();
    let result = black_box(verify_case(black_box(case)));
    let cycles = timer.elapsed();
    (result, cycles, stack_paint::high_water(sp0))
}

/// Measures every case of the on-target fixture and logs one `BENCH` line per case.
fn bench() -> Result<(), &'static str> {
    let fixture = Fixture::parse(LMS_TARGET).map_err(|_| "fixture does not parse")?;
    let mut all_ok = true;
    for case in fixture.cases() {
        let case = case.map_err(|_| "fixture case does not parse")?;
        let (result, cycles, mark) = measure_case(&case);
        let passed = result == case.expect_cnsa.result();
        let info = KeyInfo::of(case.pk).ok_or("public key too short for its typecodes")?;
        info!(
            "BENCH board={=str} set=LMS-{=str}-{=str}-L{=u32} src={=str} tc={=u16} msg_len={=usize} sig_len={=usize} expect_valid={=bool} ok={=bool} result={=str} cycles={=u32} us={=u32} peak_stack={=u32} saturated={=bool}",
            BOARD,
            info.lms_name(),
            info.lmots_name(),
            info.levels,
            case.source.name(),
            case.id,
            case.msg.len(),
            case.sig.len(),
            case.expect_cnsa == Expect::Ok,
            passed,
            result_name(result),
            cycles,
            cycles / (CPU_HZ / 1_000_000),
            mark.bytes,
            mark.saturated
        );
        all_ok &= passed && !mark.saturated && mark.bytes <= STACK_LIMIT;
    }
    if all_ok {
        Ok(())
    } else {
        Err("a case failed its KAT, saturated the painted stack or used more than 32 KB")
    }
}

#[embedded_test::tests]
mod tests {
    use super::{Board, bench, init_board, kat, rotation};

    #[init]
    fn init() -> Board {
        init_board()
    }

    #[test]
    fn lms_kat() -> Result<(), &'static str> {
        kat()?;
        // Board copy of the host rotation test (SHA-171 TP3).
        rotation()
    }

    #[test]
    fn lms_rotation_key_b_verifies_against_a_b_and_fails_against_a() -> Result<(), &'static str> {
        rotation()
    }

    #[test]
    fn lms_bench(board: Board) -> Result<(), &'static str> {
        if !board.dwt_present {
            return Err("DWT has no cycle counter");
        }
        bench()
    }
}
