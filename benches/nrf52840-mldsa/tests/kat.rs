//! On-target ML-DSA-44/65 verify KATs and benchmarks for the nRF52840-DK (SHA-34).
//!
//! Synchronous embedded-test cases, no embassy executor. Run from this directory with
//! `cargo test --release` (docs/benchmarks.md). Every case is logged over defmt; the
//! `*_bench` tests log one `BENCH …` line per case for `scripts/bench_summarize.py`.
#![no_std]
#![no_main]

// `not(clippy)`: `cargo clippy` checks the dev profile; the guard is for builds and runs.
#[cfg(all(debug_assertions, not(clippy)))]
compile_error!("run the on-target KATs and benchmarks with `cargo test --release`");

use core::hint::black_box;
use cortex_m::peripheral::DWT;
use defmt::info;
use defmt_rtt as _;
use mldsa_kat::measure::Cycles;
use mldsa_kat::{Case, Fixture, Outcome, ParamSet, run_fixture, verify_for};
use stack_paint::Watermark;

/// Board name in the `KAT` / `BENCH` log lines.
const BOARD: &str = "nrf52840";
/// Core clock after `embassy_nrf::init` (HFCLK, 64 MHz).
const CPU_HZ: u32 = 64_000_000;
/// Bytes left unpainted below the stack pointer inside `stack_paint::paint`, covering
/// that function's own frame.
const PAINT_MARGIN: u32 = 256;

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

/// Runs every case of `fixture` and logs each outcome.
fn kat(param_set: ParamSet, fixture: &[u8]) -> Result<(), &'static str> {
    let summary = run_fixture(fixture, param_set, |case, outcome| {
        info!(
            "KAT board={=str} set=ML-DSA-{=u16} src={=str} tc={=u32} expect_valid={=bool} verified={=bool} result={=str}",
            BOARD,
            param_set.number(),
            case.source.name(),
            case.tc_id,
            outcome.expected_valid,
            outcome.verified,
            if outcome.passed() { "ok" } else { "FAIL" }
        );
    })
    .map_err(|_| "fixture does not parse")?;
    info!(
        "KAT board={=str} set=ML-DSA-{=u16} passed={=u32}/{=u32}",
        BOARD,
        param_set.number(),
        summary.passed,
        summary.total
    );
    if summary.all_passed() {
        Ok(())
    } else {
        Err("a KAT case did not match its expectation")
    }
}

/// Paints the stack, then times one verify and measures its stack high-water mark.
#[inline(never)]
fn measure_case(param_set: ParamSet, case: &Case<'_>) -> (bool, u32, Watermark) {
    let sp0 = cortex_m::register::msp::read();
    stack_paint::paint(PAINT_MARGIN);
    let timer = Cycles::start();
    let verified = black_box(verify_for(param_set, black_box(case)));
    let cycles = timer.elapsed();
    (verified, cycles, stack_paint::high_water(sp0))
}

/// Measures every case of `fixture` and logs one `BENCH` line per case.
fn bench(param_set: ParamSet, fixture: &[u8]) -> Result<(), &'static str> {
    let parsed = Fixture::parse(fixture).map_err(|_| "fixture does not parse")?;
    if parsed.param_set != param_set {
        return Err("fixture is for another parameter set");
    }
    let mut all_ok = true;
    for case in parsed.cases() {
        let case = case.map_err(|_| "fixture case does not parse")?;
        let (verified, cycles, mark) = measure_case(param_set, &case);
        let outcome = Outcome::new(&case, verified);
        info!(
            "BENCH board={=str} set=ML-DSA-{=u16} src={=str} tc={=u32} msg_len={=usize} expect_valid={=bool} ok={=bool} cycles={=u32} us={=u32} peak_stack={=u32} saturated={=bool}",
            BOARD,
            param_set.number(),
            case.source.name(),
            case.tc_id,
            case.msg.len(),
            case.expect_valid,
            outcome.passed(),
            cycles,
            cycles / (CPU_HZ / 1_000_000),
            mark.bytes,
            mark.saturated
        );
        all_ok &= outcome.passed() && !mark.saturated;
    }
    if all_ok {
        Ok(())
    } else {
        Err("a case failed its KAT or saturated the painted stack")
    }
}

#[embedded_test::tests]
mod tests {
    use super::{Board, bench, init_board, kat};
    use defmt::info;
    use mldsa_kat::measure::Cycles;
    use mldsa_kat::{MLDSA44_TARGET, MLDSA65_TARGET, ParamSet};

    #[init]
    fn init() -> Board {
        init_board()
    }

    #[test]
    fn dwt_cycle_counter_present(board: Board) -> Result<(), &'static str> {
        if !board.dwt_present {
            return Err("DWT has no cycle counter");
        }
        let timer = Cycles::start();
        cortex_m::asm::delay(1_000);
        let elapsed = timer.elapsed();
        info!(
            "DWT CYCCNT advanced {=u32} cycles over asm::delay(1000)",
            elapsed
        );
        if elapsed >= 1_000 {
            Ok(())
        } else {
            Err("CYCCNT did not advance")
        }
    }

    #[test]
    fn mldsa44_kat() -> Result<(), &'static str> {
        kat(ParamSet::MlDsa44, MLDSA44_TARGET)
    }

    #[test]
    fn mldsa65_kat() -> Result<(), &'static str> {
        kat(ParamSet::MlDsa65, MLDSA65_TARGET)
    }

    #[test]
    fn mldsa44_bench() -> Result<(), &'static str> {
        bench(ParamSet::MlDsa44, MLDSA44_TARGET)
    }

    #[test]
    fn mldsa65_bench() -> Result<(), &'static str> {
        bench(ParamSet::MlDsa65, MLDSA65_TARGET)
    }
}
