//! On-target SHA-46 policy matrix on the Pico 2 W / RP2350: every case of
//! `tests/fixtures/images/policy-matrix.bin` under every `Policy`, through
//! `keelsign_verify::verify` with each image read from flash.
//!
//! Synchronous embedded-test case, no embassy executor. Run from this directory with
//! `cargo test --release --locked --test policy -- policy_matrix_from_flash`
//! (57 cases, 171 cells: `passed=171/171`; with `--features ml-dsa` the ML-DSA cells verify,
//! without it they expect the `ml-dsa`-off verdicts, SHA-44)
//! (docs/benchmarks.md, "Hybrid verify entry point (SHA-46)"); it logs one
//! `POLICY board=… case=… policy=… expect=… got=… result=…` line per cell and a
//! `POLICY board=rp2350 passed=N/N` summary.
//!
//! `hybrid_verify_bench` (SHA-69) times one `verify` under `Policy::Hybrid` of each hybrid
//! Ed25519 + LMS/HSS image (L=1 and L=2) from flash with the DWT cycle counter and
//! measures its peak stack with stack painting. Run it with
//! `cargo test --release --locked --test policy -- hybrid_verify_bench`; it logs one
//! `BENCH board=rp2350 set=Hybrid-… src=policy tc=… msg_len=32 sig_len=… expect_valid=true
//! ok=… result=… cycles=… us=… peak_stack=… saturated=…` line per image for
//! `scripts/bench_summarize.py`, and fails on a verdict other than `Ok`, a saturated paint
//! or a peak stack over 32 KB.
//!
//! Each image is embedded in this test binary's `.rodata` once (`policy_kat::IMAGES`,
//! `include_bytes!`) and read back through the HAL's `ReadNorFlash` (the blocking
//! `embassy_rp::flash::Flash`) at its flash offset (its address minus the XIP base) with
//! `NorFlashReader`, as `tests/image.rs` does for the 200 KB image.
#![no_std]
#![no_main]

// `not(clippy)`: `cargo clippy` checks the dev profile; the guard is for builds and runs.
#[cfg(all(debug_assertions, not(clippy)))]
compile_error!("run the on-target tests with `cargo test --release`");

use core::hint::black_box;
use cortex_m::peripheral::DWT;
use defmt::info;
use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use keelsign_verify::{
    DEFAULT_CHUNK_LEN, DefaultBackend, Error, ImageReader, NorFlashReader, Policy, TrustedKeys,
    verify,
};
use mldsa_kat::measure::Cycles;
use policy_kat::{
    Fixture, POLICY_TARGET, Slots, TARGET_CASES, policy_name, run_fixture, trusted_keys,
};
use stack_paint::Watermark;

/// Board name in the `POLICY` / `BENCH` log lines.
const BOARD: &str = "rp2350";
/// Core clock after `embassy_rp::init(Default::default())` (150 MHz).
const CPU_HZ: u32 = 150_000_000;

/// External QSPI flash of the Pico 2 W: 4 MiB (the linker script uses only the first 2).
const FLASH_SIZE: usize = 4 * 1024 * 1024;
/// Where the XIP window maps the flash (`embassy_rp::flash::FLASH_BASE`).
const XIP_BASE: u32 = 0x1000_0000;

/// The blocking flash driver.
type Nvm = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

/// Bytes left unpainted below the stack pointer inside `stack_paint::paint`, covering
/// that function's own frame.
const PAINT_MARGIN: u32 = 256;
/// Peak-stack limit of a verify on the device (docs/benchmarks.md).
const STACK_LIMIT: u32 = 32_768;
/// The hybrid Ed25519 + LMS/HSS images `hybrid_verify_bench` measures: (MANIFEST.json
/// name, `BENCH` set, `BENCH` tc, signature bytes: the 64-byte Ed25519 signature plus the
/// HSS signature).
const HYBRID_IMAGES: [(&str, &str, u16, usize); 2] = [
    (
        "keelsign-hybrid-ed25519-lms.bin",
        "Hybrid-Ed25519+LMS-M32_H5-L1",
        1,
        64 + 1296,
    ),
    (
        "keelsign-hybrid-ed25519-hss2.bin",
        "Hybrid-Ed25519+HSS-M32_H5x2-L2",
        2,
        64 + 2644,
    ),
];
/// The image digest every signature of a keelsign image signs (SHA-256), in bytes.
const MSG_LEN: usize = 32;

/// State handed from `#[init]` to the tests.
pub struct Board {
    dwt_present: bool,
    flash: Nvm,
}

fn init_board() -> Board {
    // Core peripherals first: embassy_rp::init does not take them.
    let dwt_present = match cortex_m::Peripherals::take() {
        Some(mut cp) => {
            cp.DCB.enable_trace();
            cp.DWT.enable_cycle_counter();
            DWT::has_cycle_counter()
        }
        None => false,
    };
    let p = embassy_rp::init(Default::default());
    Board {
        dwt_present,
        flash: Flash::new_blocking(p.FLASH),
    }
}

/// Every image of the matrix as a slot: `NorFlashReader` over `&mut` the flash driver at
/// the image's flash offset (the driver takes offsets from the start of the flash, not
/// XIP addresses).
struct FlashSlots {
    flash: Nvm,
}

impl Slots for FlashSlots {
    type Reader<'s> = NorFlashReader<&'s mut Nvm>;

    fn slot(&mut self, _: &str, image: &'static [u8]) -> Option<Self::Reader<'_>> {
        let base = (image.as_ptr() as u32).checked_sub(XIP_BASE)?;
        let len = u32::try_from(image.len()).ok()?;
        NorFlashReader::new(&mut self.flash, base, len).ok()
    }
}

/// Runs the whole matrix from flash and logs every cell.
fn policy_matrix(flash: Nvm) -> Result<(), &'static str> {
    let mut slots = FlashSlots { flash };
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    let summary = run_fixture(
        POLICY_TARGET,
        &DefaultBackend::new(),
        &mut slots,
        &mut tlv_buf,
        &mut chunk,
        |case, outcome| {
            info!(
                "POLICY board={=str} case={=str} policy={=str} expect={=str} got={=str} result={=str}",
                BOARD,
                case.name,
                policy_name(outcome.policy),
                outcome.expect.name(),
                outcome.got_name(),
                if outcome.passed() { "ok" } else { "FAIL" }
            );
        },
    )
    .map_err(|_| "policy-matrix.bin does not parse")?;
    info!(
        "POLICY board={=str} passed={=u32}/{=u32}",
        BOARD, summary.passed, summary.total
    );
    if summary.total != TARGET_CASES * Policy::ALL.len() as u32 {
        return Err("not every cell of the matrix ran");
    }
    if !summary.all_passed() {
        return Err("a policy-matrix cell differs from its expectation");
    }
    Ok(())
}

/// One `verify` with its 4 KiB TLV buffer and 256-byte chunk on this frame, so that both
/// count towards the measured peak stack.
#[inline(never)]
fn verify_once<R: ImageReader>(
    reader: &mut R,
    keys: &TrustedKeys<'_, 1, 1>,
    policy: Policy,
) -> Result<(), Error> {
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    verify(
        black_box(reader),
        black_box(keys),
        policy,
        black_box(&mut tlv_buf),
        black_box(&mut chunk),
    )
    .map(|_| ())
}

/// Paints the stack, then times one verify and measures its stack high-water mark.
#[inline(never)]
fn measure<R: ImageReader>(
    reader: &mut R,
    keys: &TrustedKeys<'_, 1, 1>,
    policy: Policy,
) -> (Result<(), Error>, u32, Watermark) {
    let sp0 = cortex_m::register::msp::read();
    stack_paint::paint(PAINT_MARGIN);
    let timer = Cycles::start();
    let result = black_box(verify_once(reader, keys, policy));
    let cycles = timer.elapsed();
    (result, cycles, stack_paint::high_water(sp0))
}

/// The verdict string of a result (defmt cannot format [`Error`]).
fn result_name(result: &Result<(), Error>) -> &'static str {
    match result {
        Ok(()) => "Ok",
        Err(e) => policy_kat::verdict_name(&Err(*e)),
    }
}

/// Verifies each hybrid Ed25519 + LMS/HSS image from flash under `Policy::Hybrid` (its
/// LMS key and the Ed25519 test key trusted), timed and stack-painted, and logs one
/// `BENCH` line per image.
fn hybrid_bench(flash: Nvm) -> Result<(), &'static str> {
    let fixture = Fixture::parse(POLICY_TARGET).map_err(|_| "policy-matrix.bin does not parse")?;
    let mut slots = FlashSlots { flash };
    let mut all_ok = true;
    for (name, set, tc, sig_len) in HYBRID_IMAGES {
        let case = fixture
            .case(name)
            .ok_or("image missing from policy-matrix.bin")?;
        let keys = trusted_keys(&case).map_err(|_| "key set")?;
        let image = policy_kat::image(name).ok_or("image not embedded")?;
        let mut reader = slots.slot(name, image).ok_or("slot outside the flash")?;
        let (result, cycles, mark) = measure(&mut reader, &keys, Policy::Hybrid);
        let ok = result.is_ok();
        info!(
            "BENCH board={=str} set={=str} src=policy tc={=u16} msg_len={=usize} sig_len={=usize} expect_valid=true ok={=bool} result={=str} cycles={=u32} us={=u32} peak_stack={=u32} saturated={=bool}",
            BOARD,
            set,
            tc,
            MSG_LEN,
            sig_len,
            ok,
            result_name(&result),
            cycles,
            cycles / (CPU_HZ / 1_000_000),
            mark.bytes,
            mark.saturated
        );
        all_ok &= ok && !mark.saturated && mark.bytes <= STACK_LIMIT;
    }
    if all_ok {
        Ok(())
    } else {
        Err("a hybrid image did not verify, saturated the painted stack or used more than 32 KB")
    }
}

#[embedded_test::tests]
mod tests {
    use super::{Board, hybrid_bench, init_board, policy_matrix};

    #[init]
    fn init() -> Board {
        init_board()
    }

    #[test]
    fn policy_matrix_from_flash(board: Board) -> Result<(), &'static str> {
        policy_matrix(board.flash)
    }

    #[test]
    fn hybrid_verify_bench(board: Board) -> Result<(), &'static str> {
        if !board.dwt_present {
            return Err("DWT has no cycle counter");
        }
        hybrid_bench(board.flash)
    }
}
