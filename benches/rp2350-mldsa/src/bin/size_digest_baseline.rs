//! Flash-footprint baseline for the image digest on the Pico 2 W / RP2350 (SHA-42): HAL init,
//! the blocking flash driver, one defmt line and a black-boxed reference to the small golden image
//! `mcuboot-ed25519.bin` (2,315 B in `.rodata`). The image bytes and the HAL cancel out of
//! the `size_digest` delta, which leaves `NorFlashReader`, `Image::read_from` (the image
//! parser) and `image_digest` with SHA-256 (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;

/// External QSPI flash of the Pico 2 W: 4 MiB.
const FLASH_SIZE: usize = 4 * 1024 * 1024;

static IMAGE: &[u8] = include_bytes!("../../../../tests/fixtures/images/mcuboot-ed25519.bin");

#[entry]
fn main() -> ! {
    let p = embassy_rp::init(Default::default());
    let _flash = black_box(Flash::<'_, FLASH, Blocking, FLASH_SIZE>::new_blocking(
        p.FLASH,
    ));
    let image = black_box(IMAGE);
    info!(
        "size_digest_baseline image={=usize} at={=u32}",
        image.len(),
        image.as_ptr() as u32
    );
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
