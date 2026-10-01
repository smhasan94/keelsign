//! On-target ML-DSA-44/65 image verify on the Pico 2 W / RP2350 (SHA-44): each valid ML-DSA
//! image of the policy matrix through `keelsign_verify::verify`, read from flash, timed
//! with the DWT cycle counter and measured with stack painting.
//!
//! Needs the bench's `ml-dsa` feature (`required-features`). Synchronous embedded-test
//! case, no embassy executor. Run from this directory with
//! `cargo test --release --locked --features ml-dsa --test mldsa_verify`
//! (docs/benchmarks.md, "ML-DSA verify (SHA-44)"); it logs one
//! `MLDSA board=… image=… set=… policy=… result=… cycles=… us=… peak_stack=… saturated=…`
//! line per image and a `MLDSA board=rp2350 passed=N/N` summary.
//!
//! The peak stack is far over the 32 KB device budget (about 93 KB for ML-DSA-44 and
//! 153 KB for ML-DSA-65 in the verify frame alone); that is the documented SHA-169
//! finding, not a test failure. The test fails on a verdict other than `Ok` or a
//! saturated paint.
//!
//! Each image is embedded in this test binary's `.rodata` once (`policy_kat::IMAGES`,
//! `include_bytes!`) and read back through the HAL's `ReadNorFlash` (the blocking
//! `embassy_rp::flash::Flash`) at its flash offset (its address minus the XIP base) with
//! `NorFlashReader`, as `tests/policy.rs` does.
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
    DEFAULT_CHUNK_LEN, Error, ImageReader, NorFlashReader, Policy, TrustedKeys, verify,
};
use mldsa_kat::measure::Cycles;
use policy_kat::{Fixture, POLICY_TARGET, policy_name, trusted_keys};
use stack_paint::Watermark;

/// Board name in the `MLDSA` log lines.
const BOARD: &str = "rp2350";
/// Core clock after `embassy_rp::init(Default::default())` (150 MHz).
const CPU_HZ: u32 = 150_000_000;
/// Bytes left unpainted below the stack pointer inside `stack_paint::paint`, covering
/// that function's own frame.
const PAINT_MARGIN: u32 = 256;

/// External QSPI flash of the Pico 2 W: 4 MiB (the linker script uses only the first 2).
const FLASH_SIZE: usize = 4 * 1024 * 1024;
/// Where the XIP window maps the flash (`embassy_rp::flash::FLASH_BASE`).
const XIP_BASE: u32 = 0x1000_0000;

/// The blocking flash driver.
type Nvm = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

/// The valid ML-DSA images: (MANIFEST.json name, parameter set, policy).
const IMAGES: [(&str, &str, Policy); 5] = [
    ("keelsign-mldsa44.bin", "ML-DSA-44", Policy::PqOnly),
    (
        "keelsign-mldsa44-protected-tlvs.bin",
        "ML-DSA-44",
        Policy::PqOnly,
    ),
    ("keelsign-mldsa65.bin", "ML-DSA-65", Policy::PqOnly),
    (
        "keelsign-mldsa65-protected-tlvs.bin",
        "ML-DSA-65",
        Policy::PqOnly,
    ),
    (
        "keelsign-hybrid-ed25519-mldsa44.bin",
        "ML-DSA-44",
        Policy::Hybrid,
    ),
];

/// State handed from `#[init]` to the test.
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

/// The image `name` as a slot: `NorFlashReader` over `&mut` the flash driver at its flash
/// offset (the driver takes offsets from the start of the flash, not XIP addresses).
fn slot<'f>(
    flash: &'f mut Nvm,
    image: &'static [u8],
) -> Result<NorFlashReader<&'f mut Nvm>, &'static str> {
    let base = (image.as_ptr() as u32)
        .checked_sub(XIP_BASE)
        .ok_or("image is not in the XIP flash window")?;
    let len = u32::try_from(image.len()).map_err(|_| "image too large")?;
    NorFlashReader::new(flash, base, len).map_err(|_| "slot outside the flash")
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

/// Verifies every valid ML-DSA image from flash and logs each.
fn mldsa_images(mut flash: Nvm) -> Result<(), &'static str> {
    let fixture = Fixture::parse(POLICY_TARGET).map_err(|_| "policy-matrix.bin does not parse")?;
    let mut passed = 0u32;
    for (name, set, policy) in IMAGES {
        let case = fixture
            .case(name)
            .ok_or("image missing from policy-matrix.bin")?;
        let keys = trusted_keys(&case).map_err(|_| "key set")?;
        let image = policy_kat::image(name).ok_or("image not embedded")?;
        let mut reader = slot(&mut flash, image)?;
        let (result, cycles, mark) = measure(&mut reader, &keys, policy);
        let ok = result.is_ok() && !mark.saturated;
        info!(
            "MLDSA board={=str} image={=str} set={=str} policy={=str} result={=str} cycles={=u32} us={=u32} peak_stack={=u32} saturated={=bool}",
            BOARD,
            name,
            set,
            policy_name(policy),
            result_name(&result),
            cycles,
            cycles / (CPU_HZ / 1_000_000),
            mark.bytes,
            mark.saturated
        );
        passed += u32::from(ok);
    }
    info!(
        "MLDSA board={=str} passed={=u32}/{=u32}",
        BOARD,
        passed,
        IMAGES.len() as u32
    );
    if passed != IMAGES.len() as u32 {
        return Err("an ML-DSA image did not verify or saturated the painted stack");
    }
    Ok(())
}

#[embedded_test::tests]
mod tests {
    use super::{Board, init_board, mldsa_images};

    #[init]
    fn init() -> Board {
        init_board()
    }

    #[test]
    fn mldsa_images_from_flash(board: Board) -> Result<(), &'static str> {
        if !board.dwt_present {
            return Err("DWT has no cycle counter");
        }
        mldsa_images(board.flash)
    }
}
