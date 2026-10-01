//! Flash-footprint baseline for the hybrid verify entry point on the nRF52840-DK (SHA-46):
//! HAL init, the NVMC driver, one defmt line and black-boxed references to the hybrid
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
use embassy_nrf::nvmc::Nvmc;
use policy_kat::{ED25519_TEST_KEY, Fixture, POLICY_TARGET};

static IMAGE: &[u8] =
    include_bytes!("../../../../tests/fixtures/images/keelsign-hybrid-ed25519-lms.bin");

#[entry]
fn main() -> ! {
    let p = embassy_nrf::init(Default::default());
    let _flash = black_box(Nvmc::new(p.NVMC));
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
