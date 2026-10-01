//! Flash-footprint baseline for the hybrid verify entry point on the Pico 2 W / RP2350 (SHA-46):
//! HAL init, the blocking flash driver, one defmt line and black-boxed references to the hybrid
//! image `keelsign-hybrid-ed25519-lms.bin`, its LMS public key (found in
//! `policy-matrix.bin`) and the Ed25519 test key. The image, the keys, the index parser and
//! the HAL cancel out of the `size_verify` delta, which leaves `verify` with the image
//! rules, `NorFlashReader`, the parser, the digest, Ed25519 (`ed25519-dalek`) and LMS/HSS
//! (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use policy_kat::{ED25519_TEST_KEY, Fixture, POLICY_TARGET};

/// External QSPI flash of the Pico 2 W: 4 MiB.
const FLASH_SIZE: usize = 4 * 1024 * 1024;

static IMAGE: &[u8] =
    include_bytes!("../../../../tests/fixtures/images/keelsign-hybrid-ed25519-lms.bin");

#[entry]
fn main() -> ! {
    let p = embassy_rp::init(Default::default());
    let _flash = black_box(Flash::<'_, FLASH, Blocking, FLASH_SIZE>::new_blocking(
        p.FLASH,
    ));
    let image = black_box(IMAGE);
    let pk = Fixture::parse(black_box(POLICY_TARGET))
        .ok()
        .and_then(|f| f.case("keelsign-hybrid-ed25519-lms.bin"))
        .map_or(&[][..], |case| case.public_key);
    let pk = black_box(pk);
    let ed = black_box(&ED25519_TEST_KEY);
    info!(
        "size_verify_baseline image={=usize} at={=u32} pk={=usize} ed={=u8}",
        image.len(),
        image.as_ptr() as u32,
        pk.len(),
        ed[0]
    );
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
