//! Flash-footprint baseline for the image digest on the nRF52840-DK (SHA-42): HAL init,
//! the NVMC driver, one defmt line and a black-boxed reference to the small golden image
//! `mcuboot-ed25519.bin` (2,315 B in `.rodata`). The image bytes and the HAL cancel out of
//! the `size_digest` delta, which leaves `NorFlashReader`, `Image::read_from` (the image
//! parser) and `image_digest` with SHA-256 (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use embassy_nrf::nvmc::Nvmc;

static IMAGE: &[u8] = include_bytes!("../../../../tests/fixtures/images/mcuboot-ed25519.bin");

#[entry]
fn main() -> ! {
    let p = embassy_nrf::init(Default::default());
    let _flash = black_box(Nvmc::new(p.NVMC));
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
