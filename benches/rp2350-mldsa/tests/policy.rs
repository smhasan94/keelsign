//! On-target SHA-46 policy matrix on the Pico 2 W / RP2350: every case of
//! `tests/fixtures/images/policy-matrix.bin` under every `Policy`, through
//! `keelsign_verify::verify` with each image read from flash.
//!
//! Synchronous embedded-test case, no embassy executor. Run from this directory with
//! `cargo test --release --locked --test policy -- policy_matrix_from_flash`
//! (docs/benchmarks.md, "Hybrid verify entry point (SHA-46)"); it logs one
//! `POLICY board=… case=… policy=… expect=… got=… result=…` line per cell and a
//! `POLICY board=rp2350 passed=N/N` summary.
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

use defmt::info;
use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use keelsign_verify::{DEFAULT_CHUNK_LEN, DefaultBackend, NorFlashReader, Policy};
use policy_kat::{POLICY_TARGET, Slots, TARGET_CASES, policy_name, run_fixture};

/// Board name in the `POLICY` log lines.
const BOARD: &str = "rp2350";

/// External QSPI flash of the Pico 2 W: 4 MiB (the linker script uses only the first 2).
const FLASH_SIZE: usize = 4 * 1024 * 1024;
/// Where the XIP window maps the flash (`embassy_rp::flash::FLASH_BASE`).
const XIP_BASE: u32 = 0x1000_0000;

/// The blocking flash driver.
type Nvm = Flash<'static, FLASH, Blocking, FLASH_SIZE>;

/// State handed from `#[init]` to the test.
pub struct Board {
    flash: Nvm,
}

fn init_board() -> Board {
    let p = embassy_rp::init(Default::default());
    Board {
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

#[embedded_test::tests]
mod tests {
    use super::{Board, init_board, policy_matrix};

    #[init]
    fn init() -> Board {
        init_board()
    }

    #[test]
    fn policy_matrix_from_flash(board: Board) -> Result<(), &'static str> {
        policy_matrix(board.flash)
    }
}
