//! Flash footprint of the hybrid verify entry point on the Pico 2 W / RP2350 (SHA-46):
//! `size_verify_baseline` plus one black-boxed `keelsign_verify::verify` of the hybrid
//! image `keelsign-hybrid-ed25519-lms.bin` under `Policy::Hybrid` (4 KiB TLV buffer,
//! 256-byte chunk), in its own `#[inline(never)]` wrapper so that its static frame can be
//! read, through `NorFlashReader` over the blocking flash driver (docs/benchmarks.md).
#![no_std]
#![no_main]

use core::hint::black_box;
use cortex_m_rt::entry;
use defmt::info;
use defmt_rtt as _;
use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use keelsign_verify::{
    Algorithm, DEFAULT_CHUNK_LEN, Ed25519Key, ImageReader, NorFlashReader, Policy, TrustedKey,
    TrustedKeys, verify,
};
use policy_kat::{ED25519_TEST_KEY, Fixture, POLICY_TARGET};

/// External QSPI flash of the Pico 2 W: 4 MiB.
const FLASH_SIZE: usize = 4 * 1024 * 1024;
/// Where the XIP window maps the flash.
const XIP_BASE: u32 = 0x1000_0000;

static IMAGE: &[u8] =
    include_bytes!("../../../../tests/fixtures/images/keelsign-hybrid-ed25519-lms.bin");

/// `verify` under `Policy::Hybrid` on its own frame, for the static-frame figure
/// (docs/benchmarks.md). Returns the security counter + 1 (0 on failure).
#[inline(never)]
fn verify_hybrid<R: ImageReader>(reader: &mut R, keys: &TrustedKeys<'_, 1, 1>) -> u32 {
    let mut tlv_buf = [0u8; 4096];
    let mut chunk = [0u8; DEFAULT_CHUNK_LEN];
    verify(
        reader,
        keys,
        Policy::Hybrid,
        black_box(&mut tlv_buf),
        black_box(&mut chunk),
    )
    .map_or(0, |v| v.security_counter.unwrap_or(0).wrapping_add(1))
}

#[entry]
fn main() -> ! {
    let p = embassy_rp::init(Default::default());
    let flash = black_box(Flash::<'_, FLASH, Blocking, FLASH_SIZE>::new_blocking(
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
        "size_verify image={=usize} at={=u32} pk={=usize} ed={=u8}",
        image.len(),
        image.as_ptr() as u32,
        pk.len(),
        ed[0]
    );
    let len = u32::try_from(image.len()).unwrap_or(0);
    let result = TrustedKeys::<1, 1>::with_ed25519(
        &[TrustedKey {
            algorithm: Algorithm::LmsHss,
            public_key: pk,
        }],
        &[Ed25519Key { public_key: ed }],
    )
    .ok()
    .and_then(|keys| {
        let base = (image.as_ptr() as u32).checked_sub(XIP_BASE)?;
        let mut reader = NorFlashReader::new(flash, base, len).ok()?;
        Some(verify_hybrid(&mut reader, &keys))
    })
    .unwrap_or(0);
    info!("size_verify result={=u32}", black_box(result));
    loop {
        cortex_m::asm::wfi();
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    cortex_m::asm::udf()
}
